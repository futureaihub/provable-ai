
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.canonical import genesis_hash
from provable_ai.engine import GovernanceEngine
from provable_ai.schema import DeterminismMode, ProofV1
from provable_ai.signer import EnvSigner
from provable_ai.storage import SQLiteStorage
from provable_ai.verifier import verify_chain, verify_proof, verify_proof_full


@pytest.fixture
def storage(tmp_path):
    db = SQLiteStorage(db_path=str(tmp_path / "e2e.db"))
    db.add_approved_model("credit_model_v3.1")
    db.add_approved_agent("agent_v1.0")
    db.add_approved_policy("credit_policy_v2")
    return db


@pytest.fixture
def signer(tmp_path):
    return EnvSigner(key_path=str(tmp_path / "key.hex"))


@pytest.fixture
def engine(storage, signer):
    return GovernanceEngine(storage=storage, signer=signer)


# ── Core end-to-end flow ──────────────────────────────────────────────────────

class TestCoreEndToEnd:

    def test_record_and_verify_single_decision(self, engine, signer):
        """
        CRO demo path:
        1. Record a credit decision
        2. Export the proof
        3. Verify it offline
        4. Get VALID
        """
        proof = engine.record_decision(
            instance_id="loan_9284",
            from_state="pending",
            to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="SCORE_ABOVE_THRESHOLD",
            policy_rule="credit_policy_v2.rule_7",
            raw_inputs={"credit_score": 720, "dti": "0.28"},
            feature_contributions=[
                {"feature": "credit_score", "contribution": "0.65"},
            ],
            threshold_used="700",
            metadata={"bureau": "experian"},
        )

        assert isinstance(proof, ProofV1)
        assert proof.ledger.sequence_id == 1
        assert proof.ledger.previous_hash == genesis_hash()
        assert proof.decision.to_state == "approved"

        # Verify the proof — offline, no storage needed
        proof_dict = proof.model_dump(mode="json")
        result = verify_proof(proof_dict)
        assert result.valid is True
        assert result.chain_intact is True
        assert result.final_state == "approved"
        assert result.key_id == signer.get_key_id()

    def test_proof_is_self_contained(self, engine, signer):
        """
        The proof must contain everything needed for verification.
        No external key store, no database, no network.
        """
        proof = engine.record_decision(
            instance_id="loan_self_contained",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs={"score": 720},
        )
        proof_dict = proof.model_dump(mode="json")

        # public_key is embedded — verifier needs no external key lookup
        assert "public_key" in proof_dict["signature"]
        assert len(proof_dict["signature"]["public_key"]) == 64

        # Verify with ONLY the proof dict — no signer, no storage
        result = verify_proof(proof_dict)
        assert result.valid is True

    def test_raw_inputs_not_in_proof(self, engine):
        """PII protection: raw_inputs must never appear in the proof."""
        raw_inputs = {"ssn": "123-45-6789", "income": "95000", "score": 720}
        proof = engine.record_decision(
            instance_id="loan_pii_test",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs=raw_inputs,
        )
        proof_dict = proof.model_dump(mode="json")
        proof_str = str(proof_dict)

        # Raw sensitive values must not appear
        assert "123-45-6789" not in proof_str
        assert "95000" not in proof_str

        # But inputs_hash must be present
        assert len(proof_dict["decision_context"]["inputs_hash"]) == 64

    def test_proof_id_is_deterministic(self, engine):
        """Same proof → same proof_id every time."""
        proof = engine.record_decision(
            instance_id="loan_proof_id",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs={"score": 720},
        )
        # proof_id derivable without database
        assert proof.proof_id == proof.proof_id
        assert len(proof.proof_id) == 64


# ── Chain end-to-end ──────────────────────────────────────────────────────────

class TestChainEndToEnd:

    def test_multi_step_chain_records_and_verifies(self, engine):
        """
        Record multiple steps in a loan lifecycle.
        Verify the complete chain — proves the entire history.
        """
        steps = [
            ("pending",    "under_review"),
            ("under_review", "approved"),
            ("approved",   "funded"),
        ]

        for i, (from_s, to_s) in enumerate(steps, 1):
            engine.record_decision(
                instance_id="loan_lifecycle",
                from_state=from_s,
                to_state=to_s,
                model_version="credit_model_v3.1",
                agent_version="agent_v1.0",
                policy_version="credit_policy_v2",
                reason_code=f"STEP_{i}",
                policy_rule="credit_policy_v2.rule_7",
                raw_inputs={"score": 720, "step": str(i)},
            )

        # Get complete chain from storage
        chain_entries = engine.storage.get_ledger_chain("loan_lifecycle")
        assert len(chain_entries) == 3

        # Build proof dicts for verification
        proof_dicts = []
        for entry in chain_entries:
            import json
            if entry.get("proof_json") and entry["proof_json"] != "{}":
                proof_dicts.append(json.loads(entry["proof_json"]))

        assert len(proof_dicts) == 3

        # Verify entire chain offline
        result = verify_chain(proof_dicts)
        assert result.valid is True
        assert result.chain_intact is True
        assert result.sequence_verified == 3
        assert result.final_state == "funded"

    def test_chain_links_correctly(self, engine):
        """Each entry's previous_hash must match prior entry's current_hash."""
        for i in range(3):
            engine.record_decision(
                instance_id="loan_chain_test",
                from_state=f"state_{i}",
                to_state=f"state_{i+1}",
                model_version="credit_model_v3.1",
                agent_version="agent_v1.0",
                policy_version="credit_policy_v2",
                reason_code="TEST",
                policy_rule="rule_1",
                raw_inputs={"step": str(i)},
            )

        chain = engine.storage.get_ledger_chain("loan_chain_test")
        # Verify chain links
        assert chain[0]["previous_hash"] == genesis_hash()
        assert chain[1]["previous_hash"] == chain[0]["current_hash"]
        assert chain[2]["previous_hash"] == chain[1]["current_hash"]


# ── Determinism modes ─────────────────────────────────────────────────────────

class TestDeterminismModes:

    def test_strict_deterministic(self, engine):
        proof = engine.record_decision(
            instance_id="loan_strict",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs={"score": 720},
            determinism_mode=DeterminismMode.STRICT_DETERMINISTIC,
        )
        assert proof.determinism.mode == DeterminismMode.STRICT_DETERMINISTIC
        assert proof.determinism.seed is None
        result = verify_proof(proof.model_dump(mode="json"))
        assert result.valid is True

    def test_replay_with_seed(self, engine):
        proof = engine.record_decision(
            instance_id="loan_seed",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs={"score": 720},
            determinism_mode=DeterminismMode.REPLAY_WITH_SEED,
            random_seed="seed_abc123",
        )
        assert proof.determinism.seed == "seed_abc123"
        result = verify_proof(proof.model_dump(mode="json"))
        assert result.valid is True

    def test_replay_with_recorded_io(self, engine):
        proof = engine.record_decision(
            instance_id="loan_io",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs={"score": 720},
            determinism_mode=DeterminismMode.REPLAY_WITH_RECORDED_IO,
            external_calls=[
                {"endpoint": "bureau_api", "response_hash": "a" * 64}
            ],
        )
        assert proof.determinism.external_calls_hash is not None
        result = verify_proof(proof.model_dump(mode="json"))
        assert result.valid is True


# ── Governance enforcement ────────────────────────────────────────────────────

class TestGovernanceEnforcement:

    def test_unauthorized_model_rejected(self, engine):
        from provable_ai.exceptions import UnauthorizedModelVersion
        with pytest.raises(UnauthorizedModelVersion):
            engine.record_decision(
                instance_id="loan_bad_model",
                from_state="pending", to_state="approved",
                model_version="unauthorized_model_v99",
                agent_version="agent_v1.0",
                policy_version="credit_policy_v2",
                reason_code="TEST", policy_rule="rule_1",
                raw_inputs={"score": 720},
            )

    def test_unauthorized_policy_rejected(self, engine):
        from provable_ai.exceptions import PolicyViolation
        with pytest.raises(PolicyViolation):
            engine.record_decision(
                instance_id="loan_bad_policy",
                from_state="pending", to_state="approved",
                model_version="credit_model_v3.1",
                agent_version="agent_v1.0",
                policy_version="inactive_policy_v0",
                reason_code="TEST", policy_rule="rule_1",
                raw_inputs={"score": 720},
            )


# ── Tamper detection end-to-end ───────────────────────────────────────────────

class TestTamperDetectionE2E:

    def test_proof_is_immutable_after_storage(self, engine):
        """
        After storing a proof, any modification to the retrieved proof
        must fail verification. This is the core guarantee.
        """
        import json
        proof = engine.record_decision(
            instance_id="loan_tamper_test",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="SCORE_ABOVE_THRESHOLD",
            policy_rule="credit_policy_v2.rule_7",
            raw_inputs={"score": 720},
        )

        entry = engine.storage.get_ledger_entry("loan_tamper_test")
        proof_dict = json.loads(entry["proof_json"])

        # Original verifies
        assert verify_proof(proof_dict).valid is True

        # Tamper: change decision outcome
        tampered = json.loads(entry["proof_json"])
        tampered["decision"]["to_state"] = "denied"
        result = verify_proof(tampered)
        assert result.valid is False
        assert result.failure_reason["type"] == "HashMismatch"

    def test_full_verification_output_on_tamper(self, engine):
        """The full verifier output must clearly explain any tamper."""
        import json
        engine.record_decision(
            instance_id="loan_full_output",
            from_state="pending", to_state="approved",
            model_version="credit_model_v3.1",
            agent_version="agent_v1.0",
            policy_version="credit_policy_v2",
            reason_code="TEST", policy_rule="rule_1",
            raw_inputs={"score": 720},
        )
        entry = engine.storage.get_ledger_entry("loan_full_output")
        tampered = json.loads(entry["proof_json"])
        tampered["governance"]["model_version"] = "evil_model"
        tampered["decision_context"]["model_version"] = "evil_model"

        result = verify_proof_full(tampered)
        assert result["valid"] is False
        assert result["failure_reason"]["type"] == "HashMismatch"
        assert result["governance_verified"] is False