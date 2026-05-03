
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from .exceptions import CanonicalJsonError


# ── Allowed / forbidden types ─────────────────────────────────────────────────

_ALLOWED_TYPES = (str, int, bool, list, dict, type(None))

_FORBIDDEN: dict[type, str] = {
    float:    "float — use int or str",
    Decimal:  "Decimal — convert to str",
    datetime: "datetime — use ISO 8601 str",
    date:     "date — use ISO 8601 str",
    UUID:     "UUID — convert to str",
    Enum:     "Enum — use .value str",
    bytes:    "bytes — convert to hex str",
    set:      "set — convert to sorted list",
    tuple:    "tuple — convert to list",
}

# Required top-level fields for a valid hash payload
_REQUIRED_HASH_FIELDS = frozenset({
    "decision",
    "decision_context",
    "governance",
    "determinism",
    "previous_hash",
    "sequence_id",
})

# Fields that must NEVER appear in the hash payload
_EXCLUDED_HASH_FIELDS = frozenset({
    "timestamp",       # excluded for replay safety
    "current_hash",    # this IS the hash output
    "signature",       # cannot include itself
    "public_key",      # signature metadata only
    "key_id",          # signature metadata only
    "type",            # schema label only
    "instance_id",     # identifier only
    "proof_id",        # derived field — never hashed
    "tenant_id",       # routing metadata — not part of decision proof
})


# ── Payload validation ────────────────────────────────────────────────────────

def _validate_payload(payload: Any, path: str = "root") -> None:
    """
    Recursively validate every value is a canonical-safe primitive.

    Raises CanonicalJsonError on the first forbidden type found.
    """
    # bool must come before int (bool is subclass of int in Python)
    if isinstance(payload, bool):
        return

    if isinstance(payload, dict):
        for key, value in payload.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(
                    field=f"{path}[key={key!r}]",
                    value_type=type(key).__name__,
                )
            _validate_payload(value, path=f"{path}.{key}")
        return

    if isinstance(payload, list):
        for i, item in enumerate(payload):
            _validate_payload(item, path=f"{path}[{i}]")
        return

    for forbidden_type, reason in _FORBIDDEN.items():
        if isinstance(payload, forbidden_type):
            raise CanonicalJsonError(
                field=path,
                value_type=f"{type(payload).__name__} ({reason})",
            )

    if not isinstance(payload, _ALLOWED_TYPES):
        raise CanonicalJsonError(
            field=path,
            value_type=type(payload).__name__,
        )


def validate_hash_payload(payload: dict) -> None:
    """
    Validate hash payload:
    1. Contains all required fields (exactly the 6 defined)
    2. Contains no excluded fields
    3. Contains NO UNKNOWN fields (prevents silent hash changes)
    4. All values are canonical-safe primitives

    Rule 3 rationale:
        If a future developer adds a field to the hash payload,
        the hash changes silently — breaking all cross-version verification.
        Unknown fields are rejected so that any schema change is explicit.

    Raises:
        ValueError: missing required, excluded present, or unknown fields
        CanonicalJsonError: forbidden type in any value
    """
    if not isinstance(payload, dict):
        raise ValueError(f"Hash payload must be dict, got {type(payload).__name__}")

    missing = _REQUIRED_HASH_FIELDS - payload.keys()
    if missing:
        raise ValueError(
            f"Hash payload missing required fields: {sorted(missing)}. "
            f"Required: {sorted(_REQUIRED_HASH_FIELDS)}"
        )

    present_excluded = _EXCLUDED_HASH_FIELDS & payload.keys()
    if present_excluded:
        raise ValueError(
            f"Hash payload contains excluded fields: {sorted(present_excluded)}. "
            f"These must never be hashed: {sorted(_EXCLUDED_HASH_FIELDS)}"
        )

    unknown = payload.keys() - _REQUIRED_HASH_FIELDS
    if unknown:
        raise ValueError(
            f"Hash payload contains unknown fields: {sorted(unknown)}. "
            f"Unknown fields are rejected to prevent silent hash changes. "
            f"Only these fields are allowed: {sorted(_REQUIRED_HASH_FIELDS)}"
        )

    _validate_payload(payload)


# ── Core functions ────────────────────────────────────────────────────────────

def canonical_encode(payload: dict) -> bytes:
    """
    Encode a payload dict to canonical UTF-8 JSON bytes.

    Identical inputs → identical bytes across Python versions and OS.
    Validates all values are canonical-safe primitives before encoding.

    Args:
        payload: dict with only canonical-safe primitives

    Returns:
        UTF-8 encoded bytes of canonical JSON string

    Raises:
        CanonicalJsonError: if any value is a forbidden type
    """
    _validate_payload(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_hash(payload: dict) -> str:
    """
    Compute SHA-256 of the canonical JSON encoding of a payload.

    This is the ONLY authoritative hash function in Zorynex.
    Never call hashlib.sha256 directly on proof payloads.

    Args:
        payload: dict with only canonical-safe primitives

    Returns:
        64-character lowercase hex string (SHA-256 digest)

    Raises:
        CanonicalJsonError: if any value is a forbidden type
    """
    return hashlib.sha256(canonical_encode(payload)).hexdigest()


def build_hash_payload(
    decision: dict,
    decision_context: dict,
    governance: dict,
    determinism: dict,
    previous_hash: str,
    sequence_id: int,
) -> dict:
    """
    Construct the exact payload dict that gets hashed to produce current_hash.

    This function is the canonical definition of hash scope.
    Must be used identically by:
      - engine.py (creating proofs)
      - verifier.py (verifying proofs)
      - TypeScript verifier (same field selection)

    INCLUDED:  decision, decision_context, governance, determinism,
               previous_hash, sequence_id

    EXCLUDED:  timestamp, current_hash, signature fields, type, instance_id
    """
    payload = {
        "decision": decision,
        "decision_context": decision_context,
        "governance": governance,
        "determinism": determinism,
        "previous_hash": previous_hash,
        "sequence_id": sequence_id,
    }
    # Validate structure before returning
    validate_hash_payload(payload)
    return payload


def canonical_string(payload: dict) -> str:
    """Return canonical JSON as a human-readable string (for debugging)."""
    return canonical_encode(payload).decode("utf-8")


def genesis_hash() -> str:
    """
    The previous_hash for the first ledger entry (sequence_id=1).
    Always "0" * 64. Hardcoded. Never changes.

    Invariant: always exactly 64 lowercase hex characters.
    """
    h = "0" * 64
    assert len(h) == 64, "genesis_hash invariant violated"
    assert all(c in "0123456789abcdef" for c in h), "genesis_hash invariant violated"
    return h


def is_valid_hash(value: str) -> bool:
    """True if value is exactly 64 lowercase hex characters."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


# ── Proof ID ──────────────────────────────────────────────────────────────────

def compute_proof_id(current_hash: str, sequence_id: int) -> str:
    """
    Compute deterministic proof identifier.

    EXACT ENCODING (cross-language contract — do not change):
        raw = f"{current_hash}:{sequence_id}".encode("utf-8")
        proof_id = sha256(raw).hexdigest()

    Rules:
        - current_hash: 64 lowercase hex chars
        - sequence_id: integer (no leading zeros, no padding)
        - separator: ":" (single colon)
        - encoding: UTF-8
        - output: 64 lowercase hex chars

    This formula is identical in Python, TypeScript, Go, Rust.
    It is part of the canonical specification and must not change.

    Args:
        current_hash: ledger.current_hash (64 hex chars)
        sequence_id:  ledger.sequence_id (integer >= 1)

    Returns:
        64-char lowercase hex SHA-256 digest
    """
    raw = f"{current_hash}:{sequence_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()