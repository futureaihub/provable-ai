from __future__ import annotations
"""
Zorynex — KMS Failover Signer
================================
Production signer with automatic failover from primary KMS key to fallback,
and automatic failback once the primary recovers.

Design:
    Primary:  AWSKmsSigner (or any BaseSigner) — preferred for all signing
    Fallback: EnvSigner or another AWSKmsSigner in a different region/account
    Failback: after ZORYNEX_KMS_FAILBACK_INTERVAL seconds, attempt primary again

    When primary fails (KMSUnavailable, InvalidKeyId):
        → Mark primary unhealthy
        → Switch to fallback immediately
        → Record failover event in metrics
        → Schedule health probe every N seconds
        → When probe succeeds: failback to primary, record failback event

    Signing:
        All proofs record the ACTUAL key_id that signed them (embedded in proof).
        Failover is transparent to callers — the returned proof always has
        the correct key_id for whichever key signed it.
        Verification always uses the public_key embedded in the proof, so
        chain verification continues to work regardless of which key was active.

    What does NOT change during failover:
        - Proof chain integrity (hashes still link correctly)
        - Verification (each proof embeds its own public_key)
        - Data stored in the ledger

    What DOES change during failover:
        - key_id in new proofs changes from primary to fallback key_id
        - Public key in new proofs changes accordingly
        - Auditors can see which key signed which proof

Environment variables:
    ZORYNEX_KMS_KEY_ID            Primary KMS key ID or alias
    ZORYNEX_KMS_FALLBACK_KEY_ID   Fallback key ID (KMS or "env" for EnvSigner)
    ZORYNEX_KMS_REGION            Primary KMS region (default: us-east-1)
    ZORYNEX_KMS_FALLBACK_REGION   Fallback KMS region (default: us-west-2)
    ZORYNEX_KMS_FAILBACK_INTERVAL Seconds before retrying primary (default: 60)
    ZORYNEX_KMS_MAX_CONSECUTIVE_FAILURES  Before switching (default: 2)

Usage:
    from provable_ai.signer_failover import FailoverSigner, FailoverMetrics

    signer  = FailoverSigner.from_env()
    metrics = signer.metrics()

    # Signing — transparent, uses whichever key is healthy
    sig = signer.sign_hash(hash_bytes)

    # Check current state
    print(metrics)
    # {
    #   "mode":               "primary" | "fallback",
    #   "primary_healthy":    True | False,
    #   "failover_count":     int,
    #   "failback_count":     int,
    #   "consecutive_failures": int,
    #   "last_failover_at":   ISO-8601 | None,
    #   "last_failback_at":   ISO-8601 | None,
    #   "primary_key_id":     str,
    #   "fallback_key_id":    str,
    # }
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .exceptions import KMSUnavailable, InvalidKeyId, SigningFailed
from .signer import BaseSigner, EnvSigner, AWSKmsSigner

logger = logging.getLogger("zorynex.signer_failover")


# ── Metrics container ─────────────────────────────────────────────────────────

class FailoverMetrics:
    """
    Thread-safe metrics for failover events.
    All attributes are immutable snapshots when read via .snapshot().
    """

    def __init__(self) -> None:
        self._lock                 = threading.Lock()
        self.failover_count:   int = 0
        self.failback_count:   int = 0
        self.primary_errors:   int = 0
        self.fallback_errors:  int = 0
        self.total_signs:      int = 0
        self.consecutive_failures: int = 0
        self.last_failover_at: str | None = None
        self.last_failback_at: str | None = None

    def record_sign(self) -> None:
        with self._lock:
            self.total_signs += 1

    def record_primary_error(self) -> None:
        with self._lock:
            self.primary_errors       += 1
            self.consecutive_failures += 1

    def record_failover(self) -> None:
        with self._lock:
            self.failover_count   += 1
            self.last_failover_at = _utcnow()

    def record_failback(self) -> None:
        with self._lock:
            self.failback_count       += 1
            self.consecutive_failures  = 0
            self.last_failback_at      = _utcnow()

    def record_fallback_error(self) -> None:
        with self._lock:
            self.fallback_errors += 1

    def reset_consecutive(self) -> None:
        with self._lock:
            self.consecutive_failures = 0

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "failover_count":           self.failover_count,
                "failback_count":           self.failback_count,
                "primary_errors":           self.primary_errors,
                "fallback_errors":          self.fallback_errors,
                "total_signs":              self.total_signs,
                "consecutive_failures":     self.consecutive_failures,
                "last_failover_at":         self.last_failover_at,
                "last_failback_at":         self.last_failback_at,
            }


# ── Main failover signer ──────────────────────────────────────────────────────

_FAILOVER_EXCEPTIONS = (KMSUnavailable, InvalidKeyId)


class FailoverSigner(BaseSigner):
    """
    Transparent failover signer: primary → fallback → (failback).

    Thread-safe. All state mutations are lock-protected.
    The background health probe runs in a daemon thread — it stops when the
    process exits without needing explicit cleanup.
    """

    def __init__(
        self,
        primary:                  BaseSigner,
        fallback:                 BaseSigner,
        max_consecutive_failures: int   = 2,
        failback_interval:        float = 60.0,
    ) -> None:
        self._primary   = primary
        self._fallback  = fallback
        self._metrics   = FailoverMetrics()
        self._lock      = threading.RLock()

        self._max_consecutive    = max_consecutive_failures
        self._failback_interval  = failback_interval

        # State
        self._primary_healthy       = True
        self._probe_thread: threading.Thread | None = None

        logger.info(
            "FailoverSigner ready: primary=%s fallback=%s max_failures=%d failback_interval=%.0fs",
            primary.get_key_id(), fallback.get_key_id(),
            max_consecutive_failures, failback_interval,
        )

    # ── BaseSigner interface ──────────────────────────────────────────────────

    def sign_hash(self, hash_bytes: bytes) -> str:
        """
        Sign hash_bytes. Transparently falls over to the fallback signer
        if the primary raises KMSUnavailable or InvalidKeyId.
        """
        self._validate_hash_bytes(hash_bytes)
        self._metrics.record_sign()

        with self._lock:
            use_primary = self._primary_healthy

        if use_primary:
            try:
                result = self._primary.sign_hash(hash_bytes)
                self._metrics.reset_consecutive()
                return result
            except _FAILOVER_EXCEPTIONS as e:
                self._handle_primary_failure(e)
                # Fall through to fallback below
            # Non-failover exceptions (SigningFailed) propagate immediately

        # Use fallback
        try:
            result = self._fallback.sign_hash(hash_bytes)
            logger.debug("Signed with fallback key %s", self._fallback.get_key_id())
            return result
        except Exception as e:
            self._metrics.record_fallback_error()
            logger.error("Fallback signer also failed: %s", e)
            raise SigningFailed(
                key_id=self._fallback.get_key_id(),
                underlying_error=f"Both primary and fallback failed. Fallback error: {e}",
            )

    def get_public_key(self) -> str:
        with self._lock:
            active = self._primary if self._primary_healthy else self._fallback
        return active.get_public_key()

    def get_key_id(self) -> str:
        with self._lock:
            active = self._primary if self._primary_healthy else self._fallback
        return active.get_key_id()

    # ── Failover / failback ───────────────────────────────────────────────────

    def _handle_primary_failure(self, error: Exception) -> None:
        """
        Record primary failure. If consecutive failures exceed threshold,
        switch to fallback and start background health probe.
        """
        self._metrics.record_primary_error()

        with self._lock:
            consec = self._metrics.consecutive_failures
            if consec >= self._max_consecutive and self._primary_healthy:
                self._primary_healthy = False
                self._metrics.record_failover()
                logger.warning(
                    "PRIMARY KMS UNAVAILABLE after %d failures (%s). "
                    "Switching to fallback key %s. Will retry primary in %.0fs.",
                    consec, error, self._fallback.get_key_id(), self._failback_interval,
                )
                self._start_health_probe()

    def _start_health_probe(self) -> None:
        """Start a daemon thread that probes the primary and failbacks when healthy."""
        if self._probe_thread and self._probe_thread.is_alive():
            return  # already running

        self._probe_thread = threading.Thread(
            target=self._health_probe_loop,
            daemon=True,
            name="zorynex-kms-health-probe",
        )
        self._probe_thread.start()

    def _health_probe_loop(self) -> None:
        """Periodically probe primary. Failback when it responds."""
        while True:
            time.sleep(self._failback_interval)

            with self._lock:
                if self._primary_healthy:
                    return  # already recovered (race — shouldn't happen, but safe)

            try:
                # Probe: get_public_key is a safe read-only KMS call
                self._primary.get_public_key()
                # Primary responded → failback
                with self._lock:
                    self._primary_healthy = True
                self._metrics.record_failback()
                logger.info(
                    "PRIMARY KMS recovered. Failing back to primary key %s.",
                    self._primary.get_key_id(),
                )
                return
            except _FAILOVER_EXCEPTIONS as e:
                logger.debug("Primary still unhealthy (%s), will retry in %.0fs", e, self._failback_interval)
            except Exception as e:
                logger.debug("Primary probe unexpected error: %s", e)

    # ── Observability ─────────────────────────────────────────────────────────

    def metrics(self) -> dict[str, Any]:
        """
        Return a snapshot of failover metrics plus current mode.

        Prometheus counters (expose via /metrics):
            zorynex_kms_failover_total     — how many times we failed over
            zorynex_kms_failback_total     — how many times we failed back
            zorynex_kms_primary_errors     — total primary signing errors
            zorynex_kms_fallback_errors    — total fallback signing errors
        """
        with self._lock:
            mode            = "primary" if self._primary_healthy else "fallback"
            primary_healthy = self._primary_healthy
            primary_key_id  = self._primary.get_key_id()
            fallback_key_id = self._fallback.get_key_id()

        snap = self._metrics.snapshot()
        return {
            "mode":             mode,
            "primary_healthy":  primary_healthy,
            "primary_key_id":   primary_key_id,
            "fallback_key_id":  fallback_key_id,
            **snap,
        }

    def force_failover(self) -> None:
        """
        Manually trigger failover to fallback (e.g. for planned maintenance).
        Starts the health probe so failback happens automatically.
        """
        with self._lock:
            if not self._primary_healthy:
                logger.info("Already in fallback mode — force_failover is a no-op")
                return
            self._primary_healthy = False
            self._metrics.record_failover()

        logger.info(
            "Manual failover to fallback key %s", self._fallback.get_key_id()
        )
        self._start_health_probe()

    def force_failback(self) -> None:
        """
        Manually fail back to primary (e.g. after confirming KMS is healthy).
        """
        with self._lock:
            self._primary_healthy = True
        self._metrics.record_failback()
        logger.info("Manual failback to primary key %s", self._primary.get_key_id())

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "FailoverSigner":
        """
        Create FailoverSigner from environment variables.

        Primary:  ZORYNEX_KMS_KEY_ID → AWSKmsSigner(us-east-1)
                  or falls back to EnvSigner if no KMS key set

        Fallback: ZORYNEX_KMS_FALLBACK_KEY_ID → AWSKmsSigner(us-west-2)
                  "env" or not set              → EnvSigner (from ZORYNEX_SIGNING_KEY)
        """
        primary_key_id  = os.environ.get("ZORYNEX_KMS_KEY_ID", "")
        fallback_key_id = os.environ.get("ZORYNEX_KMS_FALLBACK_KEY_ID", "")
        primary_region  = os.environ.get("ZORYNEX_KMS_REGION",          "us-east-1")
        fallback_region = os.environ.get("ZORYNEX_KMS_FALLBACK_REGION", "us-west-2")
        max_failures    = int(os.environ.get("ZORYNEX_KMS_MAX_CONSECUTIVE_FAILURES", "2"))
        failback_s      = float(os.environ.get("ZORYNEX_KMS_FAILBACK_INTERVAL", "60"))

        # Primary signer
        if primary_key_id:
            primary: BaseSigner = AWSKmsSigner(key_id=primary_key_id, region=primary_region)
        else:
            primary = EnvSigner()

        # Fallback signer
        if fallback_key_id and fallback_key_id.lower() != "env":
            fallback: BaseSigner = AWSKmsSigner(key_id=fallback_key_id, region=fallback_region)
        else:
            fallback = EnvSigner()

        return cls(
            primary=primary,
            fallback=fallback,
            max_consecutive_failures=max_failures,
            failback_interval=failback_s,
        )

    def prometheus_metrics(self) -> str:
        """Prometheus text format for the failover metrics."""
        m = self.metrics()
        lines = [
            "# HELP zorynex_kms_failover_total Times primary KMS failed over to fallback",
            "# TYPE zorynex_kms_failover_total counter",
            f"zorynex_kms_failover_total {m['failover_count']}",
            "",
            "# HELP zorynex_kms_failback_total Times failback to primary succeeded",
            "# TYPE zorynex_kms_failback_total counter",
            f"zorynex_kms_failback_total {m['failback_count']}",
            "",
            "# HELP zorynex_kms_primary_errors_total Signing errors on primary key",
            "# TYPE zorynex_kms_primary_errors_total counter",
            f"zorynex_kms_primary_errors_total {m['primary_errors']}",
            "",
            "# HELP zorynex_kms_fallback_errors_total Signing errors on fallback key",
            "# TYPE zorynex_kms_fallback_errors_total counter",
            f"zorynex_kms_fallback_errors_total {m['fallback_errors']}",
            "",
            "# HELP zorynex_kms_primary_healthy 1 if primary is healthy, 0 if in fallback",
            "# TYPE zorynex_kms_primary_healthy gauge",
            f"zorynex_kms_primary_healthy {1 if m['primary_healthy'] else 0}",
            "",
            "# HELP zorynex_kms_consecutive_failures Consecutive primary failures",
            "# TYPE zorynex_kms_consecutive_failures gauge",
            f"zorynex_kms_consecutive_failures {m['consecutive_failures']}",
        ]
        return "\n".join(lines) + "\n"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Singleton ─────────────────────────────────────────────────────────────────

_failover_signer: FailoverSigner | None = None


def get_failover_signer() -> FailoverSigner:
    """Return the process-level FailoverSigner singleton."""
    global _failover_signer
    if _failover_signer is None:
        _failover_signer = FailoverSigner.from_env()
    return _failover_signer