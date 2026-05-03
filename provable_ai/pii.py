
import hashlib
import json
from typing import Any

# ── Known PII field names ─────────────────────────────────────────────────────
# Add to this set when new sensitive fields are identified.

SENSITIVE_FIELDS: frozenset[str] = frozenset({
    # Identity
    "name", "full_name", "first_name", "last_name", "given_name", "surname",
    "ssn", "social_security_number", "national_id", "passport", "passport_number",
    "driver_license", "tax_id", "ein",
    # Contact
    "email", "email_address", "phone", "phone_number", "mobile",
    "address", "street_address", "city", "zip_code", "postal_code",
    # Financial
    "account_number", "bank_account", "routing_number",
    "card_number", "credit_card", "cvv", "card_cvv",
    # Medical (for healthcare use cases)
    "dob", "date_of_birth", "birth_date", "diagnosis", "condition",
})


# ── Core hash function ────────────────────────────────────────────────────────

def hash_sensitive(value: Any) -> str:
    """
    Hash a sensitive value using SHA-256.

    The input is first serialized to canonical JSON (sort_keys, no spaces)
    so that dict/list inputs are deterministic.

    Returns a prefixed hex string: "sha256:<64 hex chars>"
    The prefix makes it clear in the DB that this field was hashed.

    Example:
        hash_sensitive("john@example.com")
        → "sha256:3d4f9c2b..."

        hash_sensitive({"credit_score": 720})
        → "sha256:7a8b1c..."
    """
    if isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        # Serialize to canonical JSON for non-string types
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")

    digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{digest}"


def is_hashed(value: str) -> bool:
    """Return True if this value is already hashed (has our prefix)."""
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71


# ── Dict scrubbing ────────────────────────────────────────────────────────────

def scrub_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    """
    Return a copy of inputs with all PII fields replaced by their hashes.

    Non-sensitive fields are preserved as-is.
    Already-hashed values (sha256: prefix) are not double-hashed.

    Example:
        scrub_inputs({
            "credit_score": 720,
            "email": "john@example.com",
            "dti": "0.28",
        })
        →  {
            "credit_score": 720,
            "email": "sha256:3d4f...",
            "dti": "0.28",
        }
    """
    result: dict[str, Any] = {}
    for key, val in inputs.items():
        if key.lower() in SENSITIVE_FIELDS:
            if isinstance(val, str) and is_hashed(val):
                result[key] = val  # already hashed — don't double-hash
            else:
                result[key] = hash_sensitive(val)
        else:
            result[key] = val
    return result


def scrub_inputs_full(inputs: dict[str, Any]) -> str:
    """
    Scrub all PII and return the SHA-256 hash of the entire cleaned dict.
    This is what gets stored in ledger.inputs_hash.

    Two-phase:
        1. scrub_inputs()  — replace known PII fields with hashes
        2. hash the entire result → one 64-char hex string in the ledger

    The auditor can verify inputs_hash = SHA-256(canonical_json(scrubbed_inputs))
    if they have the original data.
    """
    scrubbed = scrub_inputs(inputs)
    canonical = json.dumps(scrubbed, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assert_no_pii(data: dict[str, Any]) -> None:
    """
    Assert that a dict contains no raw PII.
    Raises ValueError if a sensitive field is found with an unhashed value.

    Use before writing to the DB.
    """
    violations: list[str] = []
    for key, val in data.items():
        if key.lower() in SENSITIVE_FIELDS:
            if isinstance(val, str) and not is_hashed(val):
                violations.append(f"  {key!r}: raw value present (not hashed)")
            elif not isinstance(val, str):
                violations.append(f"  {key!r}: non-string sensitive value (must be hashed first)")

    if violations:
        raise ValueError(
            "PII violation — the following sensitive fields contain raw values:\n"
            + "\n".join(violations)
            + "\nCall scrub_inputs() before writing to DB."
        )