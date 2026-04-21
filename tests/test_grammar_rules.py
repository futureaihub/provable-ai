
import pytest
from provable_ai.engine import Engine


VALID_SPEC = {
    "states": ["submitted", "review", "approved", "rejected"],
    "initial_state": "submitted",
    "transitions": [
        {"from_state": "submitted", "to_state": "review"},
        {"from_state": "review",    "to_state": "approved"},
        {"from_state": "review",    "to_state": "rejected"},
    ]
}


def make_engine(tmp_path):
    e = Engine(db_path=str(tmp_path / "test.db"))
    e.storage.approve_model("m1")
    e.storage.approve_agent("a1")
    e.storage.approve_policy("p1")
    return e


# ============================================================
# VALID SPEC COMPILATION
# ============================================================

class TestValidSpec:

    def test_valid_spec_compiles(self, tmp_path):
        e = make_engine(tmp_path)
        result = e.compile(VALID_SPEC)
        assert "protocol_hash" in result
        assert len(result["protocol_hash"]) == 64

    def test_minimal_spec_compiles(self, tmp_path):
        e = make_engine(tmp_path)
        spec = {
            "states": ["a", "b"],
            "initial_state": "a",
            "transitions": [{"from_state": "a", "to_state": "b"}]
        }
        result = e.compile(spec)
        assert result["protocol_hash"]

    def test_spec_hash_is_deterministic(self, tmp_path):
        e = make_engine(tmp_path)
        r1 = e.compile(VALID_SPEC)
        r2 = e.compile(VALID_SPEC)
        assert r1["protocol_hash"] == r2["protocol_hash"]

    def test_key_order_does_not_affect_hash(self, tmp_path):
        """Canonical JSON must be order-independent."""
        e = make_engine(tmp_path)
        spec_a = {
            "initial_state": "submitted",
            "states": ["submitted", "approved"],
            "transitions": [{"from_state": "submitted", "to_state": "approved"}]
        }
        spec_b = {
            "transitions": [{"from_state": "submitted", "to_state": "approved"}],
            "states": ["submitted", "approved"],
            "initial_state": "submitted",
        }
        r_a = e.compile(spec_a)
        r_b = e.compile(spec_b)
        assert r_a["protocol_hash"] == r_b["protocol_hash"]


# ============================================================
# TRANSITION RULES
# ============================================================

class TestTransitionRules:

    def test_transition_from_initial_state_works(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(VALID_SPEC)
        e.create_instance("i1")
        result = e.transition(
            "i1", "review", "system",
            "a" * 64, "b" * 64, "m1", "a1", "p1", "{}"
        )
        assert result["new_state"] == "review"

    def test_undefined_transition_is_rejected(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(VALID_SPEC)
        e.create_instance("i1")
        with pytest.raises(Exception, match="Invalid transition"):
            e.transition(
                "i1", "approved", "system",
                "a" * 64, "b" * 64, "m1", "a1", "p1", "{}"
            )

    def test_reverse_transition_is_rejected(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(VALID_SPEC)
        e.create_instance("i1")
        e.transition("i1", "review", "system", "a"*64, "b"*64, "m1", "a1", "p1", "{}")
        with pytest.raises(Exception, match="Invalid transition"):
            e.transition("i1", "submitted", "system", "a"*64, "b"*64, "m1", "a1", "p1", "{}")

    def test_branching_transitions(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(VALID_SPEC)
        e.create_instance("loan-a")
        e.transition("loan-a", "review", "system", "a"*64, "b"*64, "m1", "a1", "p1", "{}")
        r = e.transition("loan-a", "approved", "system", "a"*64, "b"*64, "m1", "a1", "p1", "{}")
        assert r["new_state"] == "approved"

        e.create_instance("loan-b")
        e.transition("loan-b", "review", "system", "a"*64, "b"*64, "m1", "a1", "p1", "{}")
        r = e.transition("loan-b", "rejected", "system", "a"*64, "b"*64, "m1", "a1", "p1", "{}")
        assert r["new_state"] == "rejected"


# ============================================================
# SPEC STRUCTURE
# ============================================================

class TestSpecStructure:

    def test_different_protocol_hashes(self, tmp_path):
        e = make_engine(tmp_path)
        spec_loan = {
            "states": ["submitted", "approved"],
            "initial_state": "submitted",
            "transitions": [{"from_state": "submitted", "to_state": "approved"}]
        }
        spec_kyc = {
            "states": ["pending", "verified"],
            "initial_state": "pending",
            "transitions": [{"from_state": "pending", "to_state": "verified"}]
        }
        r_loan = e.compile(spec_loan)
        r_kyc = e.compile(spec_kyc)
        assert r_loan["protocol_hash"] != r_kyc["protocol_hash"]

    def test_adding_state_changes_hash(self, tmp_path):
        e = make_engine(tmp_path)
        spec_v1 = {
            "states": ["a", "b"],
            "initial_state": "a",
            "transitions": [{"from_state": "a", "to_state": "b"}]
        }
        spec_v2 = {
            "states": ["a", "b", "c"],
            "initial_state": "a",
            "transitions": [
                {"from_state": "a", "to_state": "b"},
                {"from_state": "b", "to_state": "c"}
            ]
        }
        r1 = e.compile(spec_v1)
        r2 = e.compile(spec_v2)
        assert r1["protocol_hash"] != r2["protocol_hash"]

    def test_protocol_stored_after_compile(self, tmp_path):
        e = make_engine(tmp_path)
        result = e.compile(VALID_SPEC)
        stored = e.storage.get_protocol_by_hash(result["protocol_hash"])
        assert stored is not None

    def test_latest_protocol_is_active(self, tmp_path):
        e = make_engine(tmp_path)
        e.compile(VALID_SPEC)
        spec_v2 = {
            "states": ["new", "done"],
            "initial_state": "new",
            "transitions": [{"from_state": "new", "to_state": "done"}]
        }
        e.compile(spec_v2)
        latest = e.storage.get_latest_protocol()
        assert latest["initial_state"] == "new"


# ============================================================
# GOVERNANCE RULES
# ============================================================

class TestGovernanceRules:

    def test_governance_status_readable(self, tmp_path):
        e = make_engine(tmp_path)
        status = e.storage.get_governance_status()
        assert "approved_models" in status
        assert "approved_agents" in status
        assert "approved_policies" in status
        assert any(m["model_version"] == "m1" for m in status["approved_models"])

    def test_approve_then_query(self, tmp_path):
        e = make_engine(tmp_path)
        e.storage.approve_model("new_model_v2")
        status = e.storage.get_governance_status()
        versions = [m["model_version"] for m in status["approved_models"]]
        assert "new_model_v2" in versions

    def test_policy_can_be_deactivated(self, tmp_path):
        e = make_engine(tmp_path)
        e.storage.approve_policy("p1", active=True)
        assert e.storage.is_policy_active("p1") is True
        e.storage.approve_policy("p1", active=False)
        assert e.storage.is_policy_active("p1") is False
