
import json
import pytest
from provable_ai.engine import Engine


# ============================================================
# HELPERS
# ============================================================

LOAN_PROTOCOL = {
    "states": ["submitted", "under_review", "approved", "rejected"],
    "initial_state": "submitted",
    "transitions": [
        {"from_state": "submitted",    "to_state": "under_review"},
        {"from_state": "under_review", "to_state": "approved"},
        {"from_state": "under_review", "to_state": "rejected"},
    ]
}


def make_engine(tmp_path):
    e = Engine(db_path=str(tmp_path / "test.db"))
    e.storage.approve_model("credit_model_v1")
    e.storage.approve_agent("loan_agent_v1")
    e.storage.approve_policy("policy_v1")
    return e


def make_transition(engine, instance_id, to_state, actor="system"):
    return engine.transition(
        instance_id=instance_id,
        to_state=to_state,
        actor=actor,
        input_hash="a" * 64,
        output_hash="b" * 64,
        model_version="credit_model_v1",
        agent_version="loan_agent_v1",
        policy_version="policy_v1",
        metadata_json=json.dumps({"score": 720})
    )


# ============================================================
# PROTOCOL COMPILE
# ============================================================

class TestCompile:

    def test_compile_returns_protocol_hash(self, tmp_path):
        e = make_engine(tmp_path)
        result = e.compile(LOAN_PROTOCOL)
        assert "protocol_hash" in result
        assert len(result["protocol_hash"]) == 64

    def test_compile_is_deterministic(self, tmp_path):
        e = make_engine(tmp_path)
        r1 = e.compile(LOAN_PROTOCOL)
        r2 = e.compile(LOAN_PROTOCOL)
        assert r1["protocol_hash"] == r2["protocol_hash"]

    def test_different_spec_gives_different_hash(self, tmp_path):
        e = make_engine(tmp_path)
        spec_b = {**LOAN_PROTOCOL, "states": ["submitted", "approved"]}
        r_a = e.compile(LOAN_PROTOCOL)
        r_b = e.compile(spec_b)
        assert r_a["protocol_hash"] != r_b["protocol_hash"]

    def test_compile_stores_protocol(self, tmp_path):
        e = make_engine(tmp_path)
        result = e.compile(LOAN_PROTOCOL)
        stored = e.storage.get_protocol_by_hash(result["protocol_hash"])
        assert stored is not None
        assert stored["protocol_hash"] == result["protocol_hash"]


# ============================================================
# INSTANCE
# ============================================================

class TestInstance:

    def test_create_instance(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        result = e.create_instance("loan-001")
        assert result["instance_id"] == "loan-001"
        assert result["state"] == "submitted"

    def test_duplicate_instance_raises(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        with pytest.raises(Exception, match="already exists"):
            e.create_instance("loan-001")

    def test_create_instance_without_protocol_raises(self, tmp_path):
        e = make_engine(tmp_path)
        with pytest.raises(Exception, match="No protocol"):
            e.create_instance("loan-001")


# ============================================================
# GOVERNANCE ENFORCEMENT
# ============================================================

class TestGovernance:

    def test_unapproved_model_blocks_transition(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        with pytest.raises(Exception, match="Model version not approved"):
            e.transition(
                instance_id="loan-001",
                to_state="under_review",
                actor="system",
                input_hash="a" * 64,
                output_hash="b" * 64,
                model_version="bad_model_v99",
                agent_version="loan_agent_v1",
                policy_version="policy_v1",
                metadata_json="{}"
            )

    def test_unapproved_agent_blocks_transition(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        with pytest.raises(Exception, match="Agent version not approved"):
            e.transition(
                instance_id="loan-001",
                to_state="under_review",
                actor="system",
                input_hash="a" * 64,
                output_hash="b" * 64,
                model_version="credit_model_v1",
                agent_version="bad_agent_v99",
                policy_version="policy_v1",
                metadata_json="{}"
            )

    def test_inactive_policy_blocks_transition(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        with pytest.raises(Exception, match="Policy version not active"):
            e.transition(
                instance_id="loan-001",
                to_state="under_review",
                actor="system",
                input_hash="a" * 64,
                output_hash="b" * 64,
                model_version="credit_model_v1",
                agent_version="loan_agent_v1",
                policy_version="bad_policy_v99",
                metadata_json="{}"
            )

    def test_empty_field_raises(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        with pytest.raises(Exception, match="incomplete"):
            e.transition(
                instance_id="loan-001",
                to_state="under_review",
                actor="system",
                input_hash="",
                output_hash="b" * 64,
                model_version="credit_model_v1",
                agent_version="loan_agent_v1",
                policy_version="policy_v1",
                metadata_json="{}"
            )


# ============================================================
# TRANSITIONS
# ============================================================

class TestTransition:

    def test_valid_transition(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        result = make_transition(e, "loan-001", "under_review")
        assert result["new_state"] == "under_review"
        assert result["version"] == 1

    def test_invalid_transition_raises(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        with pytest.raises(Exception, match="Invalid transition"):
            make_transition(e, "loan-001", "approved")

    def test_multi_step_transitions(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        result = make_transition(e, "loan-001", "approved")
        assert result["new_state"] == "approved"
        assert result["version"] == 2

    def test_version_increments(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        r1 = make_transition(e, "loan-001", "under_review")
        r2 = make_transition(e, "loan-001", "rejected")
        assert r1["version"] == 1
        assert r2["version"] == 2

    def test_frozen_instance_blocks_transition(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        e.storage.freeze_instance("loan-001")
        with pytest.raises(Exception, match="frozen"):
            make_transition(e, "loan-001", "approved")


# ============================================================
# LEDGER INTEGRITY
# ============================================================

class TestLedger:

    def test_ledger_hash_chain(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        make_transition(e, "loan-001", "approved")
        ledger = e.storage.get_ledger("loan-001")
        assert len(ledger) == 2
        assert ledger[0]["previous_hash"] is None
        assert ledger[1]["previous_hash"] == ledger[0]["current_hash"]

    def test_ledger_signatures_present(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        ledger = e.storage.get_ledger("loan-001")
        assert ledger[0]["signature"] != ""
        assert len(ledger[0]["signature"]) == 128

    def test_ledger_captures_model_version(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        ledger = e.storage.get_ledger("loan-001")
        assert ledger[0]["model_version"] == "credit_model_v1"


# ============================================================
# REPLAY
# ============================================================

class TestReplay:

    def test_replay_valid(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        make_transition(e, "loan-001", "approved")
        result = e.replay("loan-001")
        assert result["valid"] is True
        assert result["final_state"] == "approved"

    def test_replay_detects_hash_tamper(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        e.storage.conn.execute(
            "UPDATE ledger SET current_hash='deadbeef' * 8 WHERE instance_id='loan-001'"
        )
        e.storage.conn.commit()
        result = e.replay("loan-001")
        assert result["valid"] is False

    def test_replay_empty_ledger(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        result = e.replay("loan-001")
        assert result["valid"] is True
        assert result["final_state"] == "submitted"


# ============================================================
# PROOF EXPORT
# ============================================================

class TestExport:

    def test_export_proof_structure(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        make_transition(e, "loan-001", "approved")
        proof = e.export_proof("loan-001")
        assert proof["valid"] is True
        assert proof["type"] == "provable-ai-proof-package"
        assert "public_key" in proof
        assert "signature" in proof
        assert "instance_root" in proof["proof"]

    def test_export_freezes_instance(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        e.export_proof("loan-001")
        inst = e.storage.get_instance("loan-001")
        assert inst["frozen"] == 1

    def test_export_twice_still_valid(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        e.export_proof("loan-001")
        proof2 = e.export_proof("loan-001")
        assert proof2["valid"] is True


# ============================================================
# OFFLINE VERIFY INTEGRATION
# ============================================================

class TestOfflineVerify:

    def test_verify_exported_proof(self, tmp_path):
        from tools.offline_verify import verify_proof
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        make_transition(e, "loan-001", "approved")
        proof_package = e.export_proof("loan-001")
        proof_file = str(tmp_path / "proof.json")
        with open(proof_file, "w") as f:
            json.dump(proof_package, f)
        valid, message, final_state = verify_proof(proof_file)
        assert valid is True
        assert final_state == "approved"

    def test_verify_rejects_tampered_proof(self, tmp_path):
        from tools.offline_verify import verify_proof
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        proof_package = e.export_proof("loan-001")
        proof_package["proof"]["ledger"][0]["to_state"] = "approved"
        proof_file = str(tmp_path / "tampered.json")
        with open(proof_file, "w") as f:
            json.dump(proof_package, f)
        valid, message, _ = verify_proof(proof_file)
        assert valid is False


# ============================================================
# DRIFT DETECTION
# ============================================================

class TestDrift:

    def test_system_root_matches_itself(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        root = e.compute_system_root()
        result = e.compare_system_root(root)
        assert result["match"] is True

    def test_system_root_detects_mismatch(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        result = e.compare_system_root("000" * 21 + "0")
        assert result["match"] is False

    def test_instance_root_matches_itself(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        root = e._compute_instance_root("loan-001")
        result = e.compare_instance_root("loan-001", root)
        assert result["match"] is True
        assert result["instance_id"] == "loan-001"

    def test_instance_root_mismatch(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        result = e.compare_instance_root("loan-001", "badhash" * 9)
        assert result["match"] is False

    def test_unknown_instance_raises(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        with pytest.raises(Exception, match="not found"):
            e.compare_instance_root("does-not-exist", "abc")


# ============================================================
# MULTIPLE INSTANCES
# ============================================================

class TestMultipleInstances:

    def test_two_instances_independent(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        e.create_instance("loan-002")
        make_transition(e, "loan-001", "under_review")
        make_transition(e, "loan-002", "under_review")
        make_transition(e, "loan-002", "approved")
        r1 = e.replay("loan-001")
        r2 = e.replay("loan-002")
        assert r1["final_state"] == "under_review"
        assert r2["final_state"] == "approved"

    def test_system_root_changes_after_transition(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(LOAN_PROTOCOL)
        e.create_instance("loan-001")
        make_transition(e, "loan-001", "under_review")
        root_before = e.compute_system_root()
        make_transition(e, "loan-001", "approved")
        root_after = e.compute_system_root()
        assert root_before != root_after
