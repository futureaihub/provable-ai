
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.canonical import genesis_hash
from provable_ai.schema import (
    PROOF_VERSION,
    Decision,
    DecisionContext,
    Determinism,
    DeterminismMode,
    Governance,
    Ledger,
    ProofV1,
    Signature,
    SignatureAlgorithm,
    VerificationResult,
)

V_HASH = "a" * 64
V_SIG  = "b" * 128
V_TS   = "2026-04-28T14:33:01Z"


def make_decision(**kw):
    return Decision(**{"from_state": "pending", "to_state": "approved", **kw})


def make_context(**kw):
    return DecisionContext(**{
        "reason_code": "SCORE_ABOVE_THRESHOLD",
        "policy_rule": "credit_policy_v2.rule_7",
        "model_version": "credit_model_v3.1",
        "inputs_hash": V_HASH,
        "feature_contributions": [],
        "threshold_used": "700",
        "metadata": {},
        **kw,
    })


def make_governance(**kw):
    return Governance(**{
        "model_version": "credit_model_v3.1",
        "agent_version": "agent_v1.0",
        "policy_version": "credit_policy_v2",
        **kw,
    })


def make_determinism(**kw):
    return Determinism(**{"mode": DeterminismMode.STRICT_DETERMINISTIC, **kw})


def make_ledger(**kw):
    return Ledger(**{
        "sequence_id": 1,
        "previous_hash": genesis_hash(),
        "current_hash": V_HASH,
        "timestamp": V_TS,
        **kw,
    })


def make_signature(**kw):
    return Signature(**{
        "algorithm": SignatureAlgorithm.ED25519,
        "key_id": "env-abc1234567890123",
        "public_key": "c" * 64,
        "value": V_SIG,
        **kw,
    })


def make_proof(**kw):
    defaults = dict(
        instance_id="loan_9284",
        decision=make_decision(),
        decision_context=make_context(),
        governance=make_governance(),
        determinism=make_determinism(),
        ledger=make_ledger(),
        signature=make_signature(),
    )
    defaults.update(kw)
    return ProofV1(**defaults)


# ── Decision ──────────────────────────────────────────────────────────────────

class TestDecision:

    def test_valid(self):
        d = make_decision()
        assert d.from_state == "pending"
        assert d.to_state == "approved"

    def test_empty_from_state_fails(self):
        with pytest.raises(ValidationError):
            Decision(from_state="", to_state="approved")

    def test_empty_to_state_fails(self):
        with pytest.raises(ValidationError):
            Decision(from_state="pending", to_state="")

    def test_missing_field_fails(self):
        with pytest.raises(ValidationError):
            Decision(from_state="pending")

    def test_frozen(self):
        d = make_decision()
        with pytest.raises(ValidationError):
            d.from_state = "changed"


# ── DecisionContext ───────────────────────────────────────────────────────────

class TestDecisionContext:

    def test_valid(self):
        ctx = make_context()
        assert ctx.reason_code == "SCORE_ABOVE_THRESHOLD"
        assert ctx.threshold_used == "700"
        assert ctx.feature_contributions == []

    # Hash field validation
    def test_inputs_hash_wrong_length_fails(self):
        with pytest.raises(ValidationError):
            make_context(inputs_hash="a" * 63)

    def test_inputs_hash_too_long_fails(self):
        with pytest.raises(ValidationError):
            make_context(inputs_hash="a" * 65)

    def test_inputs_hash_non_hex_fails(self):
        with pytest.raises(ValidationError):
            make_context(inputs_hash="z" * 64)

    def test_inputs_hash_normalized_lowercase(self):
        ctx = make_context(inputs_hash="A" * 64)
        assert ctx.inputs_hash == "a" * 64

    # threshold_used strict type tests
    def test_threshold_used_string_valid(self):
        ctx = make_context(threshold_used="700")
        assert ctx.threshold_used == "700"

    def test_threshold_used_none_valid(self):
        ctx = make_context(threshold_used=None)
        assert ctx.threshold_used is None

    def test_threshold_used_int_rejected(self):
        """threshold_used must be str, never int."""
        with pytest.raises(ValidationError) as e:
            make_context(threshold_used=700)
        assert "str" in str(e.value).lower() or "threshold" in str(e.value).lower()

    def test_threshold_used_float_rejected(self):
        """threshold_used must be str, never float."""
        with pytest.raises(ValidationError):
            make_context(threshold_used=700.0)

    def test_threshold_used_bool_rejected(self):
        with pytest.raises(ValidationError):
            make_context(threshold_used=True)

    # feature_contributions strict type tests
    def test_feature_contributions_string_values_valid(self):
        ctx = make_context(feature_contributions=[
            {"feature": "credit_score", "contribution": "0.65"},
            {"feature": "dti", "contribution": "-0.15"},
        ])
        assert len(ctx.feature_contributions) == 2

    def test_feature_contributions_empty_valid(self):
        ctx = make_context(feature_contributions=[])
        assert ctx.feature_contributions == []

    def test_feature_contributions_float_value_rejected(self):
        """contribution must be str, never float."""
        with pytest.raises(ValidationError) as e:
            make_context(feature_contributions=[
                {"feature": "score", "contribution": 0.8}
            ])
        assert "str" in str(e.value).lower() or "contribution" in str(e.value).lower()

    def test_feature_contributions_int_value_rejected(self):
        with pytest.raises(ValidationError):
            make_context(feature_contributions=[
                {"feature": "score", "contribution": 1}
            ])

    def test_feature_contributions_non_dict_item_rejected(self):
        with pytest.raises(ValidationError):
            make_context(feature_contributions=["not a dict"])

    # Required field tests
    def test_empty_reason_code_fails(self):
        with pytest.raises(ValidationError):
            make_context(reason_code="")

    def test_empty_policy_rule_fails(self):
        with pytest.raises(ValidationError):
            make_context(policy_rule="")

    def test_empty_model_version_fails(self):
        with pytest.raises(ValidationError):
            make_context(model_version="")


# ── Governance ────────────────────────────────────────────────────────────────

class TestGovernance:

    def test_valid(self):
        g = make_governance()
        assert g.model_version == "credit_model_v3.1"

    def test_empty_model_version_fails(self):
        with pytest.raises(ValidationError):
            Governance(model_version="", agent_version="v1", policy_version="v1")

    def test_empty_agent_version_fails(self):
        with pytest.raises(ValidationError):
            Governance(model_version="v1", agent_version="", policy_version="v1")

    def test_empty_policy_version_fails(self):
        with pytest.raises(ValidationError):
            Governance(model_version="v1", agent_version="v1", policy_version="")

    def test_frozen(self):
        g = make_governance()
        with pytest.raises(ValidationError):
            g.model_version = "changed"


# ── Determinism ───────────────────────────────────────────────────────────────

class TestDeterminism:

    def test_strict_valid(self):
        d = make_determinism()
        assert d.mode == DeterminismMode.STRICT_DETERMINISTIC
        assert d.seed is None

    def test_replay_with_seed_requires_seed(self):
        with pytest.raises(ValidationError) as e:
            Determinism(mode=DeterminismMode.REPLAY_WITH_SEED)
        assert "seed" in str(e.value).lower()

    def test_replay_with_seed_valid(self):
        d = Determinism(mode=DeterminismMode.REPLAY_WITH_SEED, seed="abc123")
        assert d.seed == "abc123"

    def test_replay_with_recorded_io_requires_hash(self):
        with pytest.raises(ValidationError):
            Determinism(mode=DeterminismMode.REPLAY_WITH_RECORDED_IO)

    def test_replay_with_recorded_io_hash_wrong_length_fails(self):
        with pytest.raises(ValidationError):
            Determinism(
                mode=DeterminismMode.REPLAY_WITH_RECORDED_IO,
                external_calls_hash="a" * 63,
            )

    def test_replay_with_recorded_io_valid(self):
        d = Determinism(
            mode=DeterminismMode.REPLAY_WITH_RECORDED_IO,
            external_calls_hash="c" * 64,
        )
        assert d.external_calls_hash == "c" * 64

    def test_invalid_mode_fails(self):
        with pytest.raises(ValidationError):
            Determinism(mode="not_a_mode")


# ── Ledger ────────────────────────────────────────────────────────────────────

class TestLedger:

    def test_valid(self):
        l = make_ledger()
        assert l.sequence_id == 1

    def test_sequence_id_zero_fails(self):
        with pytest.raises(ValidationError):
            make_ledger(sequence_id=0)

    def test_sequence_id_negative_fails(self):
        with pytest.raises(ValidationError):
            make_ledger(sequence_id=-1)

    def test_previous_hash_wrong_length_fails(self):
        with pytest.raises(ValidationError):
            make_ledger(previous_hash="a" * 63)

    def test_current_hash_wrong_length_fails(self):
        with pytest.raises(ValidationError):
            make_ledger(current_hash="a" * 65)

    def test_previous_hash_non_hex_fails(self):
        with pytest.raises(ValidationError):
            make_ledger(previous_hash="z" * 64)

    def test_current_hash_non_hex_fails(self):
        with pytest.raises(ValidationError):
            make_ledger(current_hash="z" * 64)

    def test_hashes_normalized_lowercase(self):
        l = make_ledger(previous_hash="A" * 64, current_hash="B" * 64)
        assert l.previous_hash == "a" * 64
        assert l.current_hash == "b" * 64

    def test_timestamp_must_end_z(self):
        with pytest.raises(ValidationError):
            make_ledger(timestamp="2026-04-28T14:33:01")
        with pytest.raises(ValidationError):
            make_ledger(timestamp="2026-04-28T14:33:01+00:00")

    def test_genesis_hash_valid_previous(self):
        l = make_ledger(previous_hash=genesis_hash())
        assert l.previous_hash == "0" * 64

    def test_frozen(self):
        l = make_ledger()
        with pytest.raises(ValidationError):
            l.sequence_id = 999


# ── Signature ─────────────────────────────────────────────────────────────────

class TestSignature:

    def test_valid_ed25519(self):
        s = make_signature()
        assert s.algorithm == SignatureAlgorithm.ED25519

    def test_ed25519_is_only_algorithm(self):
        """Only Ed25519 is supported. KMS_ED25519 is an alias that maps to ED25519."""
        s = make_signature(algorithm=SignatureAlgorithm.ED25519)
        assert s.algorithm == SignatureAlgorithm.ED25519
        # KMS_ED25519 is an alias — KMS backend still uses Ed25519 algorithm
        # The key_id prefix ("env-" vs "kms-") identifies which backend signed
        if hasattr(SignatureAlgorithm, "KMS_ED25519"):
            assert SignatureAlgorithm.KMS_ED25519 == SignatureAlgorithm.ED25519

    def test_value_wrong_length_fails(self):
        with pytest.raises(ValidationError):
            make_signature(value="a" * 127)
        with pytest.raises(ValidationError):
            make_signature(value="a" * 129)

    def test_value_non_hex_fails(self):
        with pytest.raises(ValidationError):
            make_signature(value="z" * 128)

    def test_value_normalized_lowercase(self):
        s = make_signature(value="A" * 128)
        assert s.value == "a" * 128

    def test_empty_key_id_fails(self):
        with pytest.raises(ValidationError):
            make_signature(key_id="")

    def test_whitespace_key_id_fails(self):
        with pytest.raises(ValidationError):
            make_signature(key_id="   ")


# ── ProofV1 ───────────────────────────────────────────────────────────────────

class TestProofV1:

    def test_valid_proof(self):
        proof = make_proof()
        assert proof.type == PROOF_VERSION
        assert proof.instance_id == "loan_9284"

    # Schema version lock
    def test_wrong_version_rejected(self):
        """Schema version lock — any type other than v1 is rejected."""
        with pytest.raises(ValidationError) as e:
            make_proof(type="zorynex-proof-v2")
        assert "v1" in str(e.value) or "frozen" in str(e.value).lower()

    def test_unknown_version_rejected(self):
        with pytest.raises(ValidationError):
            make_proof(type="unknown-schema")

    def test_empty_type_rejected(self):
        with pytest.raises(ValidationError):
            make_proof(type="")

    # Cross-field consistency
    def test_model_version_mismatch_rejected(self):
        """decision_context.model_version must match governance.model_version."""
        with pytest.raises(ValidationError) as e:
            make_proof(
                decision_context=make_context(model_version="model_OLD"),
                governance=make_governance(model_version="model_NEW"),
            )
        assert "model_version" in str(e.value)

    # Required field tests
    def test_empty_instance_id_fails(self):
        with pytest.raises(ValidationError):
            make_proof(instance_id="")

    def test_missing_decision_fails(self):
        with pytest.raises((ValidationError, TypeError)):
            ProofV1(
                instance_id="x",
                decision_context=make_context(),
                governance=make_governance(),
                determinism=make_determinism(),
                ledger=make_ledger(),
                signature=make_signature(),
            )

    # Immutability
    def test_proof_frozen(self):
        proof = make_proof()
        with pytest.raises(ValidationError):
            proof.instance_id = "changed"

    # Serialization
    def test_roundtrip(self):
        proof = make_proof()
        data = proof.model_dump()
        reconstructed = ProofV1.model_validate(data)
        assert reconstructed == proof

    # Hash payload
    def test_to_hash_payload_includes_required(self):
        proof = make_proof()
        payload = proof.to_hash_payload()
        for field in ["decision", "decision_context", "governance",
                      "determinism", "previous_hash", "sequence_id"]:
            assert field in payload

    def test_to_hash_payload_excludes_forbidden(self):
        proof = make_proof()
        payload = proof.to_hash_payload()
        for field in ["timestamp", "current_hash", "signature",
                      "type", "instance_id"]:
            assert field not in payload

    def test_to_sign_bytes_is_32_bytes(self):
        proof = make_proof()
        b = proof.to_sign_bytes()
        assert isinstance(b, bytes)
        assert len(b) == 32

    def test_to_sign_bytes_matches_hash(self):
        proof = make_proof()
        assert proof.to_sign_bytes() == bytes.fromhex(proof.ledger.current_hash)


# ── VerificationResult ────────────────────────────────────────────────────────

class TestVerificationResult:

    def test_valid_result(self):
        r = VerificationResult(
            valid=True, final_state="approved",
            verified_at=V_TS, key_id="env-abc",
            sequence_verified=1, chain_intact=True,
            governance_compliant=True, failure_reason=None,
        )
        assert r.valid is True
        assert r.failure_reason is None

    def test_invalid_result(self):
        r = VerificationResult(
            valid=False, final_state=None,
            verified_at=V_TS, key_id="env-abc",
            sequence_verified=1, chain_intact=False,
            governance_compliant=True,
            failure_reason="Hash mismatch at sequence 1",
        )
        assert r.valid is False
        assert "Hash mismatch" in r.failure_reason

    def test_to_audit_dict(self):
        r = VerificationResult(
            valid=True, final_state="approved",
            verified_at=V_TS, key_id="env-abc",
            sequence_verified=42, chain_intact=True,
            governance_compliant=True,
        )
        d = r.to_audit_dict()
        assert d["sequence_verified"] == 42
        assert d["failure_reason"] is None

    def test_frozen(self):
        r = VerificationResult(
            valid=True, final_state="approved",
            verified_at=V_TS, key_id="env-abc",
            sequence_verified=1, chain_intact=True,
            governance_compliant=True,
        )
        with pytest.raises(ValidationError):
            r.valid = False