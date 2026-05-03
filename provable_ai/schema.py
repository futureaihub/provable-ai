
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

PROOF_VERSION = "zorynex-proof-v1"


# ── Enums ─────────────────────────────────────────────────────────────────────

class DeterminismMode(str, Enum):
    STRICT_DETERMINISTIC   = "strict_deterministic"
    REPLAY_WITH_SEED       = "replay_with_seed"
    REPLAY_WITH_RECORDED_IO = "replay_with_recorded_io"


class SignatureAlgorithm(str, Enum):
    """
    Only Ed25519 is supported.
    KMS-backed signing still uses Ed25519 keys — same algorithm,
    different key storage. No separate enum value needed.
    The key_id prefix ("env-" vs "kms-") tells you which backend signed.
    """
    ED25519     = "ed25519"
    KMS_ED25519 = "ed25519"   # alias — KMS uses Ed25519 algorithm, key_id prefix identifies backend


# ── Sub-models ────────────────────────────────────────────────────────────────

class Decision(BaseModel):
    from_state: str = Field(..., min_length=1)
    to_state:   str = Field(..., min_length=1)
    model_config = {"frozen": True}


class DecisionContext(BaseModel):
    """
    Explainability context for this decision.

    Type enforcement:
        - threshold_used: str or None ONLY — never int, never float
        - feature_contributions[].contribution: str ONLY — never float
        - inputs_hash: exactly 64 lowercase hex characters
        - metadata: only canonical-safe primitives (validated externally)
    """
    reason_code:           str                  = Field(..., min_length=1)
    policy_rule:           str                  = Field(..., min_length=1)
    model_version:         str                  = Field(..., min_length=1)
    inputs_hash:           str                  = Field(..., min_length=64, max_length=64)
    feature_contributions: list[dict[str, str]] = Field(default_factory=list)
    threshold_used:        str | None           = Field(default=None)
    metadata:              dict[str, Any]        = Field(default_factory=dict)

    model_config = {"frozen": True, "protected_namespaces": ()}

    @field_validator("inputs_hash")
    @classmethod
    def validate_inputs_hash(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError(f"inputs_hash must be 64 hex chars, got {len(v)}")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("inputs_hash must be valid hex")
        return v.lower()

    @field_validator("feature_contributions")
    @classmethod
    def validate_feature_contributions(cls, v: list) -> list:
        for i, item in enumerate(v):
            if not isinstance(item, dict):
                raise ValueError(f"feature_contributions[{i}] must be dict")
            for k, val in item.items():
                if not isinstance(k, str) or not isinstance(val, str):
                    raise ValueError(
                        f"feature_contributions[{i}] keys and values must be str. "
                        f"Never use float for contribution — convert to str first."
                    )
        return v

    @field_validator("threshold_used", mode="before")
    @classmethod
    def validate_threshold_used(cls, v: Any) -> str | None:
        if v is None:
            return None
        if isinstance(v, bool):
            raise ValueError("threshold_used must be str or None, not bool")
        if isinstance(v, (int, float)):
            raise ValueError(
                f"threshold_used must be str or None, not {type(v).__name__}. "
                f"Convert to string first: str({v!r})"
            )
        if not isinstance(v, str):
            raise ValueError(f"threshold_used must be str or None, got {type(v).__name__}")
        return v


class Governance(BaseModel):
    model_version:  str = Field(..., min_length=1)
    agent_version:  str = Field(..., min_length=1)
    policy_version: str = Field(..., min_length=1)
    model_config = {"frozen": True, "protected_namespaces": ()}


class Determinism(BaseModel):
    mode:                DeterminismMode = Field(...)
    seed:                str | None      = Field(default=None)
    external_calls_hash: str | None      = Field(default=None)
    model_config = {"frozen": True}

    @model_validator(mode="after")
    def validate_mode_fields(self) -> "Determinism":
        if self.mode == DeterminismMode.REPLAY_WITH_SEED and self.seed is None:
            raise ValueError("seed is required when mode=replay_with_seed")
        if self.mode == DeterminismMode.REPLAY_WITH_RECORDED_IO:
            if self.external_calls_hash is None:
                raise ValueError(
                    "external_calls_hash is required when mode=replay_with_recorded_io"
                )
            if len(self.external_calls_hash) != 64:
                raise ValueError("external_calls_hash must be 64 hex chars")
        return self


def _validate_hash_field(v: str, field_name: str) -> str:
    """Shared validator for 64-char hex hash fields."""
    if len(v) != 64:
        raise ValueError(f"{field_name} must be 64 hex chars, got {len(v)}")
    try:
        int(v, 16)
    except ValueError:
        raise ValueError(f"{field_name} must be valid hex")
    return v.lower()


class Ledger(BaseModel):
    sequence_id:   int = Field(..., ge=1)
    previous_hash: str = Field(..., min_length=64, max_length=64)
    current_hash:  str = Field(..., min_length=64, max_length=64)
    timestamp:     str = Field(..., min_length=20)
    model_config = {"frozen": True}

    @field_validator("previous_hash")
    @classmethod
    def val_prev(cls, v: str) -> str:
        return _validate_hash_field(v, "previous_hash")

    @field_validator("current_hash")
    @classmethod
    def val_curr(cls, v: str) -> str:
        return _validate_hash_field(v, "current_hash")

    @field_validator("timestamp")
    @classmethod
    def val_ts(cls, v: str) -> str:
        if not v.endswith("Z"):
            raise ValueError(
                f"timestamp must be UTC ISO 8601 ending in Z, got '{v}'"
            )
        return v


class Signature(BaseModel):
    """
    Ed25519 (or KMS-backed Ed25519) signature.

    algorithm:
        Always ed25519 or kms-ed25519. Both use Ed25519 verification.
        kms-ed25519 signals the key never left KMS — same crypto,
        different key storage. Auditors can verify either with public key.

    key_id:
        Non-empty. Required for key rotation — auditors need it.
        EnvSigner format: "env-{16-char-pubkey-prefix}"
        KMS format:       "kms-{key_alias_or_id}"

    public_key:
        Hex-encoded 32-byte Ed25519 public key (64 hex chars).
        ALWAYS included so proof is self-contained.
        Auditor needs no external key store to verify offline.

    value:
        128 hex chars = 64-byte Ed25519 signature.
        Signs bytes.fromhex(ledger.current_hash) — the 32 raw SHA-256 bytes.
    """
    algorithm:  SignatureAlgorithm = Field(default=SignatureAlgorithm.ED25519)
    key_id:     str                = Field(..., min_length=1)
    public_key: str                = Field(..., min_length=64, max_length=64)
    value:      str                = Field(..., min_length=128, max_length=128)
    model_config = {"frozen": True}

    @field_validator("key_id")
    @classmethod
    def val_key_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("key_id must not be empty or whitespace")
        return v

    @field_validator("public_key")
    @classmethod
    def val_public_key(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError(f"public_key must be 64 hex chars (32-byte Ed25519), got {len(v)}")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("public_key must be valid hex")
        return v.lower()

    @field_validator("value")
    @classmethod
    def val_signature_value(cls, v: str) -> str:
        if len(v) != 128:
            raise ValueError(
                f"Ed25519 signature must be 128 hex chars (64 bytes), got {len(v)}"
            )
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("signature value must be valid hex")
        return v.lower()


# ── Root proof model ──────────────────────────────────────────────────────────

class ProofV1(BaseModel):
    """
    Zorynex Proof Schema v1 — FROZEN

    The complete proof artifact for an AI decision.
    Immutable after creation (frozen=True).

    Schema version lock:
        type must be exactly "zorynex-proof-v1".
        Any other value is rejected — use ProofV2 for future schemas.

    Cross-field invariant:
        decision_context.model_version must equal governance.model_version.
        This ensures the explainability context matches the governance record.
    """
    type:             str             = Field(default=PROOF_VERSION)
    instance_id:      str             = Field(..., min_length=1)
    decision:         Decision
    decision_context: DecisionContext
    governance:       Governance
    determinism:      Determinism
    ledger:           Ledger
    signature:        Signature

    model_config = {"frozen": True}

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v != PROOF_VERSION:
            raise ValueError(
                f"Proof type must be '{PROOF_VERSION}', got '{v}'. "
                f"This schema is frozen. Use ProofV2 for new schemas."
            )
        return v

    @model_validator(mode="after")
    def validate_model_version_consistency(self) -> "ProofV1":
        """decision_context.model_version must match governance.model_version."""
        dc_ver = self.decision_context.model_version
        gov_ver = self.governance.model_version
        if dc_ver != gov_ver:
            raise ValueError(
                f"decision_context.model_version '{dc_ver}' must match "
                f"governance.model_version '{gov_ver}'"
            )
        return self

    def to_hash_payload(self) -> dict:
        """
        Returns the exact dict that was hashed to produce ledger.current_hash.
        Use in verification to recompute and compare.
        mode='json' ensures enums serialize to strings (canonical-safe).
        """
        from .canonical import build_hash_payload
        return build_hash_payload(
            decision=self.decision.model_dump(mode="json"),
            decision_context=self.decision_context.model_dump(mode="json"),
            governance=self.governance.model_dump(mode="json"),
            determinism=self.determinism.model_dump(mode="json"),
            previous_hash=self.ledger.previous_hash,
            sequence_id=self.ledger.sequence_id,
        )

    def to_sign_bytes(self) -> bytes:
        """
        Returns the exact bytes that were signed by Ed25519.
        32 raw bytes = bytes.fromhex(ledger.current_hash)
        NOT the hex string — the actual 32 bytes.
        """
        return bytes.fromhex(self.ledger.current_hash)

    @property
    def proof_id(self) -> str:
        """
        Deterministic proof identifier.

        Exact encoding (cross-language contract):
            proof_id = sha256(f"{current_hash}:{sequence_id}".encode("utf-8")).hexdigest()

        See canonical.compute_proof_id() for the authoritative implementation.
        See tests/test_vectors.json["proof_id_vectors"] for golden test vectors.

        Rules:
            - Never include proof_id in hash payload
            - Never treat proof_id as authoritative in DB (recomputable)
            - Store in API responses and proof.json for convenience only
        """
        from .canonical import compute_proof_id
        return compute_proof_id(self.ledger.current_hash, self.ledger.sequence_id)


# ── Verification result ───────────────────────────────────────────────────────

class VerificationResult(BaseModel):
    """
    Output of proof verification. Returned to auditors and logged.

    valid:                True if ALL checks passed
    final_state:          Decision to_state (populated when valid=True)
    verified_at:          UTC ISO 8601 timestamp of verification
    key_id:               Which key was used for verification
    sequence_verified:    sequence_id of the verified proof
    chain_intact:         Hash chain from this entry back to genesis is unbroken
    governance_compliant: model_version was in approved whitelist
    failure_reason:       Human-readable failure description (None when valid)
    """
    valid:                bool
    final_state:          str | None  = None
    verified_at:          str
    key_id:               str
    sequence_verified:    int
    chain_intact:         bool
    governance_compliant: bool
    failure_reason:       dict | str | None = None

    model_config = {"frozen": True}

    def to_audit_dict(self) -> dict:
        return {
            "valid":                self.valid,
            "final_state":         self.final_state,
            "verified_at":         self.verified_at,
            "key_id":              self.key_id,
            "sequence_verified":   self.sequence_verified,
            "chain_intact":        self.chain_intact,
            "governance_compliant": self.governance_compliant,
            "failure_reason":      self.failure_reason,
        }