"""
Zorynex — Webhook HMAC + Replay Protection
============================================
Every outbound webhook is signed. Every inbound webhook is verified.

Signing algorithm: HMAC-SHA256 over "timestamp.nonce.body"
  - timestamp: Unix epoch seconds
  - nonce:     UUID4 (unique per delivery)
  - body:      canonical JSON string

Inbound verification steps (in order):
  1. Required headers present
  2. Timestamp within ±TIMESTAMP_TOLERANCE_S (default 5min)
  3. Nonce not seen before (replay protection)
  4. HMAC matches (constant-time compare)

Replay protection:
  In-memory nonce store with TTL eviction.
  Phase 3 upgrade: replace with Redis SETEX — interface unchanged.
  Known limitation: nonces reset on process restart (restart = new nonce epoch).

Secret:
  ZORYNEX_WEBHOOK_SECRET env var.
  Falls back to insecure dev secret with a warning if not set.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from fastapi import HTTPException, Request, status

logger = logging.getLogger("zorynex.webhook")

# ── Config ────────────────────────────────────────────────────────────────────

TIMESTAMP_TOLERANCE_S: int = int(os.environ.get("ZORYNEX_WEBHOOK_TOLERANCE_S", "300"))

_SECRET_RAW = os.environ.get("ZORYNEX_WEBHOOK_SECRET", "")
if not _SECRET_RAW:
    _SECRET_RAW = "dev-only-insecure-secret-change-in-production"
    logger.warning(
        "ZORYNEX_WEBHOOK_SECRET is not set. "
        "Using insecure dev secret. Set this env var before production."
    )
_SECRET: bytes = _SECRET_RAW.encode("utf-8")


# ── Nonce store ───────────────────────────────────────────────────────────────

@dataclass
class _NonceStore:
    """
    In-memory nonce store with TTL-based eviction.
    Phase 3 upgrade: replace with Redis SETEX (nonce → expiry).
    """
    _store: dict[str, float] = field(default_factory=dict)
    _lock:  Lock              = field(default_factory=Lock)

    def check_and_store(self, nonce: str, ttl_s: int | None = None) -> bool:
        """
        Returns True if nonce is new (stores it).
        Returns False if nonce was seen before — replay detected.
        TTL defaults to 2x the timestamp tolerance.
        """
        if ttl_s is None:
            ttl_s = TIMESTAMP_TOLERANCE_S * 2
        now = time.time()
        with self._lock:
            # Evict expired entries
            self._store = {n: exp for n, exp in self._store.items() if exp > now}
            if nonce in self._store:
                return False
            self._store[nonce] = now + ttl_s
            return True

    def size(self) -> int:
        with self._lock:
            return len(self._store)


_nonce_store = _NonceStore()


# ── HMAC helpers ──────────────────────────────────────────────────────────────

def _compute_hmac(timestamp: str, nonce: str, body: str) -> str:
    """
    HMAC-SHA256 over "{timestamp}.{nonce}.{body}".
    The separator prevents length-extension ambiguity.
    """
    payload = f"{timestamp}.{nonce}.{body}".encode("utf-8")
    return hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()


def _ct_equal(a: str, b: str) -> bool:
    """Constant-time string comparison — prevents timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ── Outbound signing ──────────────────────────────────────────────────────────

@dataclass
class SignedWebhookPayload:
    body:    str
    headers: dict[str, str]


def sign_webhook(event_type: str, data: dict[str, Any]) -> SignedWebhookPayload:
    """
    Sign an outbound webhook payload.

    The receiver calls verify_webhook_request() to authenticate.
    The nonce in the envelope IS the nonce in the header — they must match.

    Returns SignedWebhookPayload with .body (str) and .headers (dict).
    """
    ts    = int(time.time())
    nonce = str(uuid.uuid4())

    envelope = {
        "event":     event_type,
        "timestamp": ts,
        "nonce":     nonce,
        "data":      data,
    }
    body      = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    signature = _compute_hmac(str(ts), nonce, body)

    headers = {
        "Content-Type":        "application/json",
        "X-Zorynex-Signature": f"sha256={signature}",
        "X-Zorynex-Timestamp": str(ts),
        "X-Zorynex-Nonce":     nonce,
        "X-Zorynex-Event":     event_type,
    }
    return SignedWebhookPayload(body=body, headers=headers)


# ── Inbound verification ──────────────────────────────────────────────────────

async def verify_webhook_request(request: Request) -> dict[str, Any]:
    """
    FastAPI dependency. Verifies an inbound signed webhook.

    Steps (in order):
      1. Required headers present
      2. Timestamp within tolerance window
      3. Nonce not seen before (replay protection)
      4. HMAC matches (constant-time)

    Returns parsed body dict on success.
    Raises 401 on any failure — always with a specific error code.
    """
    sig_header = request.headers.get("X-Zorynex-Signature", "")
    ts_header  = request.headers.get("X-Zorynex-Timestamp", "")
    nonce      = request.headers.get("X-Zorynex-Nonce", "")

    # ── Step 1: Required headers ──────────────────────────────────────────────
    if not all([sig_header, ts_header, nonce]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error":   "WEBHOOK_MISSING_HEADERS",
                "message": (
                    "Signed webhooks require X-Zorynex-Signature, "
                    "X-Zorynex-Timestamp, and X-Zorynex-Nonce headers."
                ),
            },
        )

    # ── Step 2: Timestamp tolerance ───────────────────────────────────────────
    try:
        ts = int(ts_header)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "WEBHOOK_INVALID_TIMESTAMP",
                    "message": "X-Zorynex-Timestamp must be a Unix epoch integer."},
        )

    age = abs(time.time() - ts)
    if age > TIMESTAMP_TOLERANCE_S:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error":     "WEBHOOK_TIMESTAMP_EXPIRED",
                "message":   f"Webhook is {int(age)}s old. Maximum: {TIMESTAMP_TOLERANCE_S}s.",
                "age_s":     int(age),
                "tolerance": TIMESTAMP_TOLERANCE_S,
            },
        )

    # ── Step 3: Replay protection ─────────────────────────────────────────────
    if not _nonce_store.check_and_store(nonce):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error":   "WEBHOOK_REPLAY_DETECTED",
                "message": "This nonce has been seen before. Replay attack blocked.",
                "nonce":   nonce,
            },
        )

    # ── Step 4: HMAC verification ─────────────────────────────────────────────
    body_bytes = await request.body()
    body_str   = body_bytes.decode("utf-8")

    if not sig_header.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "WEBHOOK_INVALID_SIG_FORMAT",
                    "message": "X-Zorynex-Signature must start with 'sha256='."},
        )

    claimed_sig  = sig_header[len("sha256="):]
    expected_sig = _compute_hmac(ts_header, nonce, body_str)

    if not _ct_equal(claimed_sig, expected_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error":   "WEBHOOK_SIGNATURE_INVALID",
                "message": (
                    "HMAC-SHA256 signature does not match. "
                    "Verify ZORYNEX_WEBHOOK_SECRET matches the sender's secret."
                ),
            },
        )

    # ── Parse and return ──────────────────────────────────────────────────────
    try:
        return json.loads(body_str)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "WEBHOOK_INVALID_JSON", "message": str(e)},
        )


def nonce_store_size() -> int:
    return _nonce_store.size()