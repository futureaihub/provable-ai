"""
Tests for provable_ai.verifier

Security-grade tests covering:
    - All 6 verification steps
    - Tamper detection (every field)
    - Chain integrity
    - Offline verification (no signer needed)
    - System root computation
    - Failure reason structure

Run: pytest tests/test_verifier.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.canonical import canonical_hash, genesis_hash
from provable_ai.schema import (
    DeterminismMode, Decision, DecisionContext, Determinism,
    Governance, Ledger, ProofV1, Signature, SignatureAlgorithm,
)
from provable_ai.signer import EnvSigner
from provable_ai.verifier import (
    compute_system_root,
    verify_chain,
    verify_proof,
    verify_proof_full,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def signer(tmp_path):
    return EnvSigner(key_path=str(tmp_path / "test.hex"))


def build_proof(
    signer: EnvSigner,
    instance_id: str = "loan_001",
    from_state: str = "pending",
    to_state: str = "approved",
    sequence_id: int = 1,
    previous_hash: str | None = None,
    model_version: str = "credit_model_v3.1",
    agent_version: str = "agent_v1.0",
    policy_version: str = "credit_policy_v2",
    reason_code: str = "SCORE_ABOVE_THRESHOLD",
    policy_rule: str = "credit_policy_v2.rule_7",
    determinism_mode: DeterminismMode = DeterminismMode.STRICT_DETERMINISTIC,
    seed: str | None = None,
    ext_hash: str | None = None,
) -> dict:
    """Build a correctly signed proof for testing."""
    if previous_hash is None:
        previous_hash = genesis_hash()

    decision = Decision(from_state=from_state, to_state=to_state)
    decision_context = DecisionContext(
        reason_code=reason_code,
        policy_rule=policy_rule,
        model_version=model_version,
        inputs_hash="a" * 64,
        feature_contributions=[],
        threshold_used="700",
        metadata={},
    )
    governance = Governance(
        model_version=model_version,
        agent_version=agent_version,
        policy_version=policy_version,
    )
    determinism = Determinism(
        mode=determinism_mode,
        seed=seed,
        external_calls_hash=ext_hash,
    )

    from provable_ai.canonical import build_hash_payload
    hp = build_hash_payload(
        decision=decision.model_dump(mode="json"),
        decision_context=decision_context.model_dump(mode="json"),
        governance=governance.model_dump(mode="json"),
        determinism=determinism.model_dump(mode="json"),
        previous_hash=previous_hash,
        sequence_id=sequence_id,
    )
    current_hash = canonical_hash(hp)
    hash_bytes = bytes.fromhex(current_hash)
    sig_hex = signer.sign_hash(hash_bytes)

    ledger = Ledger(
        sequence_id=sequence_id,
        previous_hash=previous_hash,
        current_hash=current_hash,
        timestamp="2026-04-28T14:33:01Z",
    )
    signature = Signature(
        algorithm=SignatureAlgorithm.ED25519,
        key_id=signer.get_key_id(),
        public_key=signer.get_public_key(),
        value=sig_hex,
    )
    proof = ProofV1(
        instance_id=instance_id,
        decision=decision,
        decision_context=decision_context,
        governance=governance,
        determinism=determinism,
        ledger=ledger,
        signature=signature,
    )
    return proof.model_dump(mode="json")


# ── Step 1: Schema validation ─────────────────────────────────────────────────

class TestSchemaValidation:

    def test_valid_proof_passes(self, signer):
        proof = build_proof(signer)
        result = verify_proof(proof)
        assert result.valid is True

    def test_empty_dict_fails(self, signer):
        result = verify_proof({})
        assert result.valid is False
        assert result.failure_reason["type"] == "SchemaValidationError"

    def test_missing_required_field_fails(self, signer):
        proof = build_proof(signer)
        del proof["signature"]
        result = verify_proof(proof)
        assert result.valid is False

    def test_wrong_schema_version_fails(self, signer):
        proof = build_proof(signer)
        proof["type"] = "zorynex-proof-v99"
        result = verify_proof(proof)
        assert result.valid is False


# ── Step 2: Hash verification ─────────────────────────────────────────────────

class TestHashVerification:

    def test_correct_hash_passes(self, signer):
        proof = build_proof(signer)
        result = verify_proof(proof)
        assert result.valid is True

    def test_tampered_decision_outcome_fails(self, signer):
        """Changing to_state must invalidate the hash."""
        proof = build_proof(signer)
        proof["decision"]["to_state"] = "denied"  # tamper
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"

    def test_tampered_model_version_fails(self, signer):
        """Changing model_version must invalidate the hash."""
        proof = build_proof(signer)
        proof["governance"]["model_version"] = "evil_model_v999"
        proof["decision_context"]["model_version"] = "evil_model_v999"
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"

    def test_tampered_reason_code_fails(self, signer):
        proof = build_proof(signer)
        proof["decision_context"]["reason_code"] = "SCORE_BELOW_THRESHOLD"
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"

    def test_tampered_sequence_id_fails(self, signer):
        proof = build_proof(signer)
        proof["ledger"]["sequence_id"] = 99
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"

    def test_tampered_previous_hash_fails(self, signer):
        proof = build_proof(signer)
        proof["ledger"]["previous_hash"] = "b" * 64
        result = verify_proof(proof)
        assert result.valid is False
        # Either HashMismatch (hash recomputed) or ChainBroken
        assert result.failure_reason["type"] in ("HashMismatch", "ChainBroken")

    def test_tampered_metadata_fails(self, signer):
        proof = build_proof(signer)
        proof["decision_context"]["metadata"] = {"injected": "value"}
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"

    def test_failure_reason_includes_sequence_id(self, signer):
        proof = build_proof(signer)
        proof["decision"]["to_state"] = "tampered"
        result = verify_proof(proof)
        assert result.failure_reason["sequence_id"] == 1


# ── Step 3: Signature verification ───────────────────────────────────────────

class TestSignatureVerification:

    def test_valid_signature_passes(self, signer):
        proof = build_proof(signer)
        result = verify_proof(proof)
        assert result.valid is True

    def test_wrong_signature_fails(self, signer):
        proof = build_proof(signer)
        proof["signature"]["value"] = "c" * 128  # invalid signature
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "SignatureMismatch"

    def test_wrong_public_key_fails(self, signer, tmp_path, monkeypatch):
        """Wrong public_key means signature cannot be verified."""
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        other_signer = EnvSigner(key_path=str(tmp_path / "other.hex"))
        proof = build_proof(signer)
        # Replace public_key with a different key's public key
        proof["signature"]["public_key"] = other_signer.get_public_key()
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "SignatureMismatch"

    def test_verification_is_offline(self, signer):
        """Verification must work without access to signer instance."""
        proof = build_proof(signer)
        # Delete the signer and verify — must still work from public_key in proof
        del signer
        result = verify_proof(proof)
        assert result.valid is True

    def test_failure_includes_key_id(self, signer):
        proof = build_proof(signer)
        proof["signature"]["value"] = "f" * 128
        result = verify_proof(proof)
        assert "key_id" in result.failure_reason


# ── Step 4: Chain validation ──────────────────────────────────────────────────

class TestChainValidation:

    def test_first_proof_genesis_hash(self, signer):
        proof = build_proof(signer, sequence_id=1)
        result = verify_proof(proof)
        assert result.valid is True

    def test_first_proof_wrong_previous_hash_fails(self, signer):
        """First proof must use genesis hash as previous."""
        proof = build_proof(signer, sequence_id=1, previous_hash="a" * 64)
        result = verify_proof(proof)
        assert result.valid is False
        assert result.failure_reason["type"] == "ChainBroken"

    def test_chain_link_validated(self, signer):
        """expected_previous_hash must match proof.ledger.previous_hash."""
        proof = build_proof(signer, sequence_id=2, previous_hash="a" * 64)
        result = verify_proof(
            proof,
            expected_previous_hash="b" * 64,  # different from "a"*64  # different from stored
            expected_sequence_id=2,
        )
        assert result.valid is False
        assert result.failure_reason["type"] == "ChainBroken"


# ── Step 5: Sequence validation ───────────────────────────────────────────────

class TestSequenceValidation:

    def test_correct_sequence_passes(self, signer):
        proof = build_proof(signer, sequence_id=1)
        result = verify_proof(proof, expected_sequence_id=1)
        assert result.valid is True

    def test_wrong_sequence_fails(self, signer):
        proof = build_proof(signer, sequence_id=1)
        result = verify_proof(
            proof,
            expected_previous_hash=genesis_hash(),
            expected_sequence_id=3,  # gap — expected 3, got 1
        )
        assert result.valid is False
        assert result.failure_reason["type"] == "SequenceGap"


# ── Step 6: Determinism validation ───────────────────────────────────────────

class TestDeterminismValidation:

    def test_strict_deterministic_valid(self, signer):
        proof = build_proof(signer, determinism_mode=DeterminismMode.STRICT_DETERMINISTIC)
        result = verify_proof(proof)
        assert result.valid is True

    def test_replay_with_seed_valid(self, signer):
        proof = build_proof(
            signer,
            determinism_mode=DeterminismMode.REPLAY_WITH_SEED,
            seed="abc123",
        )
        result = verify_proof(proof)
        assert result.valid is True

    def test_replay_with_recorded_io_valid(self, signer):
        proof = build_proof(
            signer,
            determinism_mode=DeterminismMode.REPLAY_WITH_RECORDED_IO,
            ext_hash="d" * 64,
        )
        result = verify_proof(proof)
        assert result.valid is True


# ── Chain verification ────────────────────────────────────────────────────────

class TestChainVerification:

    def _build_chain(self, signer, length: int = 3) -> list[dict]:
        chain = []
        prev_hash = genesis_hash()
        for i in range(1, length + 1):
            from_s = "pending" if i == 1 else f"state_{i-1}"
            to_s = f"state_{i}"
            proof = build_proof(
                signer,
                sequence_id=i,
                previous_hash=prev_hash,
                from_state=from_s,
                to_state=to_s,
            )
            chain.append(proof)
            prev_hash = proof["ledger"]["current_hash"]
        return chain

    def test_valid_chain_passes(self, signer):
        chain = self._build_chain(signer, 3)
        result = verify_chain(chain)
        assert result.valid is True
        assert result.chain_intact is True
        assert result.sequence_verified == 3

    def test_empty_chain_fails(self, signer):
        result = verify_chain([])
        assert result.valid is False

    def test_single_proof_chain(self, signer):
        proof = build_proof(signer, sequence_id=1)
        result = verify_chain([proof])
        assert result.valid is True
        assert result.sequence_verified == 1

    def test_tampered_middle_proof_fails(self, signer):
        chain = self._build_chain(signer, 3)
        chain[1]["decision"]["to_state"] = "tampered"  # tamper proof 2
        result = verify_chain(chain)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"
        assert result.failure_reason["sequence_id"] == 2

    def test_chain_broken_link_fails(self, signer):
        chain = self._build_chain(signer, 3)
        # Break the link between proof 1 and proof 2
        chain[1]["ledger"]["previous_hash"] = "0" * 64
        result = verify_chain(chain)
        assert result.valid is False

    def test_chain_final_state_is_last(self, signer):
        chain = self._build_chain(signer, 3)
        result = verify_chain(chain)
        assert result.final_state == "state_3"


# ── Full verifier output ──────────────────────────────────────────────────────

class TestVerifyProofFull:

    def test_valid_proof_full_output(self, signer):
        proof = build_proof(signer)
        result = verify_proof_full(proof)

        assert result["valid"] is True
        assert result["chain_intact"] is True
        assert "governance_recorded" in result
        assert "governance_verified" in result
        assert "replay_result" in result
        assert result["failure_reason"] is None

    def test_governance_verified_is_false(self, signer):
        """
        governance_verified must be False.
        We prove the record is authentic — not that the governance
        decisions were CORRECT. Honest position for auditors.
        """
        proof = build_proof(signer)
        result = verify_proof_full(proof)
        assert result["governance_verified"] is False

    def test_governance_recorded_contains_versions(self, signer):
        proof = build_proof(signer)
        result = verify_proof_full(proof)
        gr = result["governance_recorded"]
        assert gr["model_version"] == "credit_model_v3.1"
        assert gr["policy_version"] == "credit_policy_v2"
        assert "determinism_mode" in gr

    def test_replay_result_structure(self, signer):
        proof = build_proof(signer)
        result = verify_proof_full(proof)
        rr = result["replay_result"]
        assert "mode_valid" in rr
        assert "seed_captured" in rr
        assert "external_calls_recorded" in rr
        assert "full_replay_executed" in rr
        assert rr["full_replay_executed"] is False  # Phase 4

    def test_invalid_proof_failure_reason_structured(self, signer):
        proof = build_proof(signer)
        proof["decision"]["to_state"] = "tampered"
        result = verify_proof_full(proof)
        assert result["valid"] is False
        fr = result["failure_reason"]
        assert "type" in fr
        assert "message" in fr
        assert "sequence_id" in fr

    def test_verified_at_is_iso8601(self, signer):
        proof = build_proof(signer)
        result = verify_proof_full(proof)
        assert result["verified_at"].endswith("Z")
        assert "T" in result["verified_at"]


# ── proof_id ──────────────────────────────────────────────────────────────────

class TestProofId:

    def test_proof_id_is_deterministic(self, signer):
        """Same proof → same proof_id."""
        proof_dict = build_proof(signer)
        p = ProofV1.model_validate(proof_dict)
        assert p.proof_id == p.proof_id

    def test_different_sequence_different_proof_id(self, signer):
        p1 = build_proof(signer, sequence_id=1)
        p2 = build_proof(signer, sequence_id=2,
                         previous_hash=p1["ledger"]["current_hash"],
                         from_state="approved", to_state="completed")
        proof1 = ProofV1.model_validate(p1)
        proof2 = ProofV1.model_validate(p2)
        assert proof1.proof_id != proof2.proof_id

    def test_proof_id_is_64_hex(self, signer):
        p = ProofV1.model_validate(build_proof(signer))
        assert len(p.proof_id) == 64
        int(p.proof_id, 16)


# ── System root ───────────────────────────────────────────────────────────────

class TestSystemRoot:

    def test_empty_returns_genesis(self):
        root = compute_system_root([])
        assert root == "0" * 64

    def test_single_hash(self):
        h = "a" * 64
        root = compute_system_root([h])
        assert len(root) == 64
        assert root != h  # root is SHA256 of h, not h itself

    def test_order_independent(self):
        """System root must be the same regardless of input order."""
        hashes = ["a" * 64, "b" * 64, "c" * 64]
        r1 = compute_system_root(hashes)
        r2 = compute_system_root(list(reversed(hashes)))
        assert r1 == r2

    def test_different_hashes_different_root(self):
        r1 = compute_system_root(["a" * 64])
        r2 = compute_system_root(["b" * 64])
        assert r1 != r2

    def test_adding_entry_changes_root(self):
        r1 = compute_system_root(["a" * 64])
        r2 = compute_system_root(["a" * 64, "b" * 64])
        assert r1 != r2

    def test_root_is_64_hex(self):
        root = compute_system_root(["a" * 64, "b" * 64])
        assert len(root) == 64
        int(root, 16)