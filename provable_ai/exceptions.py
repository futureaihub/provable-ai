

# ── Base ──────────────────────────────────────────────────────────────────────

class ZorynexError(Exception):
    """
    Base class for all Zorynex exceptions.

    NEVER raise this directly. Always raise a specific subclass.
    Every subclass carries message + context for structured audit logging.
    """
    code: str = "ZORYNEX_ERROR"

    def __init__(self, message: str, context: dict | None = None):
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def to_audit_dict(self) -> dict:
        """Structured dict for audit log emission."""
        return {
            "error_code": self.code,
            "error_class": self.__class__.__name__,
            "message": self.message,
            "context": self.context,
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"


# ── Governance ────────────────────────────────────────────────────────────────

class GovernanceError(ZorynexError):
    """
    A governance rule was violated — unauthorized model, policy, or agent.
    ALERT-level in production. These must trigger immediate notification.
    """
    code = "GOVERNANCE_ERROR"


class UnauthorizedModelVersion(GovernanceError):
    """Model version not in the approved governance whitelist."""
    code = "UNAUTHORIZED_MODEL_VERSION"

    def __init__(self, model_version: str, approved_versions: list[str],
                 tenant_id: str | None = None):
        super().__init__(
            message=(
                f"Model version '{model_version}' is not approved. "
                f"Approved: {approved_versions}"
            ),
            context={
                "model_version": model_version,
                "approved_versions": approved_versions,
                "tenant_id": tenant_id,
            },
        )


class PolicyViolation(GovernanceError):
    """A decision violated an active governance policy rule."""
    code = "POLICY_VIOLATION"

    def __init__(self, policy_rule: str, decision_context: str,
                 tenant_id: str | None = None):
        super().__init__(
            message=f"Policy violation: rule '{policy_rule}' — {decision_context}",
            context={
                "policy_rule": policy_rule,
                "decision_context": decision_context,
                "tenant_id": tenant_id,
            },
        )


class AgentVersionMismatch(GovernanceError):
    """Agent version does not match the governance-approved version."""
    code = "AGENT_VERSION_MISMATCH"

    def __init__(self, agent_version: str, approved_version: str):
        super().__init__(
            message=(
                f"Agent version '{agent_version}' does not match "
                f"approved version '{approved_version}'"
            ),
            context={
                "agent_version": agent_version,
                "approved_version": approved_version,
            },
        )


# ── Signing ───────────────────────────────────────────────────────────────────

class SigningError(ZorynexError):
    """
    Cryptographic signing failed.
    CRITICAL — a proof artifact could not be produced.
    Decision must NOT be considered proven until signing succeeds.
    """
    code = "SIGNING_ERROR"


class KMSUnavailable(SigningError):
    """KMS cannot be reached. Queue for retry — do not drop the decision."""
    code = "KMS_UNAVAILABLE"

    def __init__(self, key_id: str, underlying_error: str):
        super().__init__(
            message=f"KMS unavailable for key '{key_id}': {underlying_error}",
            context={"key_id": key_id, "underlying_error": underlying_error},
        )


class InvalidKeyId(SigningError):
    """Requested key_id does not exist or has been revoked."""
    code = "INVALID_KEY_ID"

    def __init__(self, key_id: str, tenant_id: str | None = None):
        super().__init__(
            message=f"Key ID '{key_id}' not found or revoked",
            context={"key_id": key_id, "tenant_id": tenant_id},
        )


class SigningFailed(SigningError):
    """Signing operation failed after the key was available."""
    code = "SIGNING_FAILED"

    def __init__(self, key_id: str, underlying_error: str):
        super().__init__(
            message=f"Signing failed for key '{key_id}': {underlying_error}",
            context={"key_id": key_id, "underlying_error": underlying_error},
        )


# ── Ledger ────────────────────────────────────────────────────────────────────

class LedgerError(ZorynexError):
    """
    Ledger integrity violated.
    ChainBroken = SECURITY INCIDENT — treat as tamper event.
    """
    code = "LEDGER_ERROR"


class ChainBroken(LedgerError):
    """
    Hash chain is broken — previous_hash does not match last entry's
    current_hash. SECURITY INCIDENT: trigger immediate alerting.
    """
    code = "CHAIN_BROKEN"

    def __init__(self, sequence_id: int, expected_hash: str, actual_hash: str,
                 tenant_id: str | None = None):
        super().__init__(
            message=(
                f"Hash chain broken at sequence_id={sequence_id}. "
                f"Expected prev='{expected_hash[:16]}...', "
                f"got '{actual_hash[:16]}...'"
            ),
            context={
                "sequence_id": sequence_id,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "tenant_id": tenant_id,
            },
        )


class SequenceGap(LedgerError):
    """Gap detected in sequence_ids — one or more entries are missing."""
    code = "SEQUENCE_GAP"

    def __init__(self, expected_sequence_id: int, actual_sequence_id: int,
                 tenant_id: str | None = None):
        super().__init__(
            message=(
                f"Sequence gap: expected {expected_sequence_id}, "
                f"got {actual_sequence_id}"
            ),
            context={
                "expected_sequence_id": expected_sequence_id,
                "actual_sequence_id": actual_sequence_id,
                "tenant_id": tenant_id,
            },
        )


class DuplicateSequenceId(LedgerError):
    """Attempt to write a ledger entry with an already-existing sequence_id."""
    code = "DUPLICATE_SEQUENCE_ID"

    def __init__(self, sequence_id: int, tenant_id: str | None = None):
        super().__init__(
            message=f"Duplicate sequence_id={sequence_id} in ledger",
            context={"sequence_id": sequence_id, "tenant_id": tenant_id},
        )


# ── Verification ──────────────────────────────────────────────────────────────

class VerificationError(ZorynexError):
    """
    Proof verification failed.
    Not always tamper — could be key rotation mismatch or schema issue.
    Check failure_reason to determine severity.
    """
    code = "VERIFICATION_ERROR"


class SignatureMismatch(VerificationError):
    """
    Ed25519 signature does not verify against expected hash + public key.
    May indicate tampering OR key mismatch after rotation.
    """
    code = "SIGNATURE_MISMATCH"

    def __init__(self, key_id: str, instance_id: str):
        super().__init__(
            message=(
                f"Signature verification failed for instance '{instance_id}' "
                f"using key '{key_id}'"
            ),
            context={"key_id": key_id, "instance_id": instance_id},
        )


class HashMismatch(VerificationError):
    """
    Recomputed canonical hash does not match stored current_hash.
    Strongly indicates the proof payload was modified after signing.
    """
    code = "HASH_MISMATCH"

    def __init__(self, instance_id: str, expected_hash: str, stored_hash: str):
        super().__init__(
            message=(
                f"Hash mismatch for instance '{instance_id}': "
                f"recomputed='{expected_hash[:16]}...', "
                f"stored='{stored_hash[:16]}...'"
            ),
            context={
                "instance_id": instance_id,
                "expected_hash": expected_hash,
                "stored_hash": stored_hash,
            },
        )


class SequenceOrderViolation(VerificationError):
    """sequence_ids in the proof chain are not in strictly ascending order."""
    code = "SEQUENCE_ORDER_VIOLATION"

    def __init__(self, instance_id: str, sequence_id: int,
                 previous_sequence_id: int):
        super().__init__(
            message=(
                f"Sequence order violation at '{instance_id}': "
                f"sequence_id={sequence_id} not > previous={previous_sequence_id}"
            ),
            context={
                "instance_id": instance_id,
                "sequence_id": sequence_id,
                "previous_sequence_id": previous_sequence_id,
            },
        )


class KeyIdNotFound(VerificationError):
    """
    key_id in proof cannot be found in the key registry.
    Keys must never be deleted — only rotated and marked inactive.
    """
    code = "KEY_ID_NOT_FOUND"

    def __init__(self, key_id: str, instance_id: str):
        super().__init__(
            message=(
                f"Key '{key_id}' not found in registry. "
                f"Cannot verify proof '{instance_id}'. "
                f"Keys must never be deleted."
            ),
            context={"key_id": key_id, "instance_id": instance_id},
        )


# ── Canonical JSON ────────────────────────────────────────────────────────────

class CanonicalJsonError(ZorynexError):
    """
    Payload contains a non-serializable type.
    Only str, int, bool, list, dict, None are allowed.
    Floats must be int or string. Datetimes must be ISO 8601 strings.
    """
    code = "CANONICAL_JSON_ERROR"

    def __init__(self, field: str, value_type: str):
        super().__init__(
            message=(
                f"Field '{field}' has non-canonical type '{value_type}'. "
                f"Allowed: str, int, bool, list, dict, None. "
                f"Floats → int or str. Datetimes → ISO 8601 str."
            ),
            context={"field": field, "value_type": value_type},
        )
        
        
