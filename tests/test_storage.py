"""
Tests for provable_ai.storage — security-grade test suite
Run: pytest tests/test_storage.py -v

"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.canonical import canonical_hash, genesis_hash
from provable_ai.exceptions import ChainBroken, DuplicateSequenceId, SequenceGap
from provable_ai.storage import SQLiteStorage


@pytest.fixture
def db(tmp_path):
    return SQLiteStorage(db_path=str(tmp_path / "test.db"))


def make_proof(
    instance_id="loan_001",
    from_state="pending",
    to_state="approved",
    sequence_id=1,
    previous_hash=None,
    model_version="credit_model_v3.1",
    agent_version="agent_v1.0",
    policy_version="credit_policy_v2",
    key_id="env-abc1234567890123",
    metadata=None,
) -> dict:
    if previous_hash is None:
        previous_hash = genesis_hash()

    hp = {
        "decision": {"from_state": from_state, "to_state": to_state},
        "decision_context": {
            "reason_code": "SCORE_ABOVE_THRESHOLD",
            "policy_rule": "credit_policy_v2.rule_7",
            "model_version": model_version,
            "inputs_hash": "a" * 64,
            "feature_contributions": [],
            "threshold_used": "700",
            "metadata": metadata or {},
        },
        "governance": {
            "model_version": model_version,
            "agent_version": agent_version,
            "policy_version": policy_version,
        },
        "determinism": {
            "mode": "strict_deterministic",
            "seed": None,
            "external_calls_hash": None,
        },
        "previous_hash": previous_hash,
        "sequence_id": sequence_id,
    }
    current_hash = canonical_hash(hp)

    return {
        "type": "zorynex-proof-v1",
        "instance_id": instance_id,
        "decision": {"from_state": from_state, "to_state": to_state},
        "decision_context": {
            "reason_code": "SCORE_ABOVE_THRESHOLD",
            "policy_rule": "credit_policy_v2.rule_7",
            "model_version": model_version,
            "inputs_hash": "a" * 64,
            "feature_contributions": [],
            "threshold_used": "700",
            "metadata": metadata or {},
        },
        "governance": {
            "model_version": model_version,
            "agent_version": agent_version,
            "policy_version": policy_version,
        },
        "determinism": {
            "mode": "strict_deterministic",
            "seed": None,
            "external_calls_hash": None,
        },
        "ledger": {
            "sequence_id": sequence_id,
            "previous_hash": previous_hash,
            "current_hash": current_hash,
            "timestamp": "2026-04-28T14:33:01Z",
        },
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "public_key": "c" * 64,
            "value": "b" * 128,
        },
    }


# ── Initialization ────────────────────────────────────────────────────────────

class TestInitialization:

    def test_tables_created(self, db):
        cur = db.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        for t in ["ledger", "instances", "protocols",
                  "approved_models", "approved_agents", "approved_policies"]:
            assert t in tables

    def test_sequence_id_column_exists(self, db):
        cur = db.conn.cursor()
        cur.execute("PRAGMA table_info(ledger)")
        cols = {r["name"] for r in cur.fetchall()}
        assert "sequence_id" in cols
        assert "key_id" in cols
        assert "proof_json" in cols
        assert "previous_hash" in cols

    def test_unique_index_exists(self, db):
        cur = db.conn.cursor()
        # Index renamed to include tenant_id scope
        cur.execute("SELECT name FROM sqlite_master WHERE type='index' "
                    "AND name='idx_ledger_tenant_instance_seq'")
        assert cur.fetchone() is not None

    def test_triggers_installed(self, db):
        cur = db.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        triggers = {r[0] for r in cur.fetchall()}
        assert "ledger_no_update" in triggers
        assert "ledger_no_delete" in triggers

    def test_idempotent(self, tmp_path):
        db_path = str(tmp_path / "idem.db")
        db1 = SQLiteStorage(db_path=db_path)
        db1.close()
        db2 = SQLiteStorage(db_path=db_path)
        db2.close()


# ── DB-level tamper resistance ────────────────────────────────────────────────

class TestDBLevelTamperResistance:
    """
    These tests verify tamper resistance at the DATABASE level,
    not just the Python API level.
    Direct SQL UPDATE/DELETE on ledger must fail.
    """

    def test_direct_sql_update_blocked_by_trigger(self, db):
        """UPDATE on ledger must fail with ABORT — trigger fires."""
        p = make_proof()
        db.append_ledger_entry(p)
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)) as e:
            db.conn.execute(
                "UPDATE ledger SET to_state='tampered' WHERE instance_id='loan_001'"
            )
        assert "append-only" in str(e.value).lower() or "integrity" in str(e.value).lower()

    def test_direct_sql_delete_blocked_by_trigger(self, db):
        """DELETE on ledger must fail with ABORT — trigger fires."""
        p = make_proof()
        db.append_ledger_entry(p)
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)) as e:
            db.conn.execute(
                "DELETE FROM ledger WHERE instance_id='loan_001'"
            )
        assert "append-only" in str(e.value).lower() or "integrity" in str(e.value).lower()

    def test_no_update_method_on_class(self, db):
        assert not hasattr(db, "update_ledger_entry")

    def test_no_delete_method_on_class(self, db):
        assert not hasattr(db, "delete_ledger_entry")

    def test_trigger_fires_after_insert(self, db):
        """Verify trigger is still active on a non-empty table."""
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        p2 = make_proof(sequence_id=2,
                        previous_hash=p1["ledger"]["current_hash"],
                        from_state="approved", to_state="completed")
        db.append_ledger_entry(p2)
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)):
            db.conn.execute("UPDATE ledger SET to_state='hacked' WHERE sequence_id=1")


# ── Sequence continuity enforcement ──────────────────────────────────────────

class TestSequenceContinuity:

    def test_first_entry_must_be_seq_1(self, db):
        p = make_proof(sequence_id=2)  # wrong — first must be 1
        with pytest.raises((SequenceGap, DuplicateSequenceId)):
            db.append_ledger_entry(p)

    def test_sequential_inserts_work(self, db):
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        p2 = make_proof(sequence_id=2,
                        previous_hash=p1["ledger"]["current_hash"],
                        from_state="approved", to_state="completed")
        assert db.append_ledger_entry(p2) == 2

    def test_duplicate_sequence_id_rejected(self, db):
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        p1_dup = make_proof(sequence_id=1)  # same sequence_id
        with pytest.raises(DuplicateSequenceId):
            db.append_ledger_entry(p1_dup)

    def test_sequence_gap_rejected(self, db):
        """1 → 3 must fail — gap detected."""
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        p3 = make_proof(sequence_id=3,  # gap! expected 2
                        previous_hash=p1["ledger"]["current_hash"])
        with pytest.raises(SequenceGap):
            db.append_ledger_entry(p3)

    def test_out_of_order_insert_rejected(self, db):
        """sequence_id < current max must fail."""
        p1 = make_proof(sequence_id=1)
        p2 = make_proof(sequence_id=2,
                        previous_hash=p1["ledger"]["current_hash"],
                        from_state="approved", to_state="completed")
        db.append_ledger_entry(p1)
        db.append_ledger_entry(p2)
        # Try to insert seq=1 again
        p1_again = make_proof(sequence_id=1)
        with pytest.raises((DuplicateSequenceId, sqlite3.IntegrityError)):
            db.append_ledger_entry(p1_again)


# ── Hash chain enforcement ────────────────────────────────────────────────────

class TestHashChainEnforcement:

    def test_wrong_previous_hash_rejected(self, db):
        """Wrong previous_hash must be rejected before insert."""
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        # Use wrong previous_hash for sequence_id=2
        p2 = make_proof(
            sequence_id=2,
            previous_hash="wrong_hash" + "0" * 54,  # 64 chars but wrong value
        )
        with pytest.raises(ChainBroken):
            db.append_ledger_entry(p2)

    def test_correct_previous_hash_accepted(self, db):
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        p2 = make_proof(
            sequence_id=2,
            previous_hash=p1["ledger"]["current_hash"],  # correct
            from_state="approved", to_state="completed",
        )
        assert db.append_ledger_entry(p2) == 2

    def test_first_entry_must_use_genesis_hash(self, db):
        """First entry previous_hash must be genesis ("0" * 64)."""
        p_bad = make_proof(sequence_id=1, previous_hash="a" * 64)
        with pytest.raises(ChainBroken):
            db.append_ledger_entry(p_bad)

    def test_chain_links_verified_in_query(self, db):
        """Stored previous_hash must match prior entry's current_hash."""
        p1 = make_proof(sequence_id=1)
        db.append_ledger_entry(p1)
        p2 = make_proof(
            sequence_id=2,
            previous_hash=p1["ledger"]["current_hash"],
            from_state="approved", to_state="completed",
        )
        db.append_ledger_entry(p2)
        chain = db.get_ledger_chain("loan_001")
        assert chain[1]["previous_hash"] == chain[0]["current_hash"]


# ── Canonical JSON storage ────────────────────────────────────────────────────

class TestCanonicalJsonStorage:

    def test_proof_json_stored_canonically(self, db):
        """proof_json in DB must be compact + sorted keys."""
        p = make_proof()
        db.append_ledger_entry(p)
        entry = db.get_latest_ledger_entry("loan_001")
        stored = entry["proof_json"]
        # Must not have spaces after : or ,
        assert ": " not in stored
        assert ", " not in stored
        # Must be valid JSON
        parsed = json.loads(stored)
        assert parsed["instance_id"] == "loan_001"

    def test_metadata_json_stored_canonically(self, db):
        """metadata_json must be compact + sorted."""
        p = make_proof(metadata={"z_key": "last", "a_key": "first"})
        db.append_ledger_entry(p)
        entry = db.get_latest_ledger_entry("loan_001")
        stored = entry["metadata_json"]
        assert ": " not in stored
        assert ", " not in stored
        parsed = json.loads(stored)
        assert parsed["a_key"] == "first"

    def test_proof_json_key_order_sorted(self, db):
        """Keys in stored proof_json must be alphabetically sorted."""
        p = make_proof()
        db.append_ledger_entry(p)
        entry = db.get_latest_ledger_entry("loan_001")
        stored = entry["proof_json"]
        # Re-serializing with sort_keys should give identical output
        parsed = json.loads(stored)
        re_serialized = json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False)
        assert stored == re_serialized


# ── key_id persistence ────────────────────────────────────────────────────────

class TestKeyIdPersistence:

    def test_key_id_stored_in_ledger_row(self, db):
        """key_id from signature must be stored in the ledger row."""
        p = make_proof(key_id="env-abc1234567890123")
        db.append_ledger_entry(p)
        entry = db.get_latest_ledger_entry("loan_001")
        assert entry["key_id"] == "env-abc1234567890123"

    def test_different_key_ids_stored_correctly(self, db):
        p1 = make_proof(sequence_id=1, key_id="env-key_one_1234abcd")
        db.append_ledger_entry(p1)
        p2 = make_proof(
            sequence_id=2,
            previous_hash=p1["ledger"]["current_hash"],
            key_id="env-key_two_5678efgh",
            from_state="approved", to_state="completed",
        )
        db.append_ledger_entry(p2)
        chain = db.get_ledger_chain("loan_001")
        assert chain[0]["key_id"] == "env-key_one_1234abcd"
        assert chain[1]["key_id"] == "env-key_two_5678efgh"

    def test_legacy_key_id_default(self, db):
        """record_transition() uses 'legacy' key_id."""
        db.register_protocol("proto_1", {"name": "test"})
        db.record_transition(
            instance_id="legacy_001", from_state="pending", to_state="approved",
            actor="system", input_hash="a"*64, output_hash="b"*64,
            model_version="m_v1", agent_version="a_v1", policy_version="p_v1",
            previous_hash=genesis_hash(), current_hash="c"*64,
            signature="d"*128, protocol_hash="proto_1",
        )
        entry = db.get_latest_ledger_entry("legacy_001")
        assert entry["key_id"] == "legacy"


# ── Multi-instance isolation ──────────────────────────────────────────────────

class TestMultiInstanceIsolation:
    """Chains for different instance_ids must be completely independent."""

    def test_two_instances_independent_chains(self, db):
        """Each instance starts its own chain from genesis."""
        p_a1 = make_proof(instance_id="loan_A", sequence_id=1)
        p_b1 = make_proof(instance_id="loan_B", sequence_id=1)
        db.append_ledger_entry(p_a1)
        db.append_ledger_entry(p_b1)
        assert db.get_ledger_count("loan_A") == 1
        assert db.get_ledger_count("loan_B") == 1

    def test_instance_a_sequence_does_not_affect_instance_b(self, db):
        p_a1 = make_proof(instance_id="loan_A", sequence_id=1)
        p_a2 = make_proof(
            instance_id="loan_A", sequence_id=2,
            previous_hash=p_a1["ledger"]["current_hash"],
            from_state="approved", to_state="completed",
        )
        p_b1 = make_proof(instance_id="loan_B", sequence_id=1)
        db.append_ledger_entry(p_a1)
        db.append_ledger_entry(p_a2)
        db.append_ledger_entry(p_b1)
        assert db.get_max_sequence_id("loan_A") == 2
        assert db.get_max_sequence_id("loan_B") == 1

    def test_instance_b_chain_cannot_use_instance_a_hash(self, db):
        """previous_hash from loan_A's chain must be rejected for loan_B."""
        p_a1 = make_proof(instance_id="loan_A", sequence_id=1)
        db.append_ledger_entry(p_a1)
        # loan_B starts fresh — genesis hash required, not loan_A's hash
        p_b_wrong = make_proof(
            instance_id="loan_B",
            sequence_id=1,
            previous_hash=p_a1["ledger"]["current_hash"],  # wrong for B
        )
        with pytest.raises(ChainBroken):
            db.append_ledger_entry(p_b_wrong)

    def test_separate_instance_chains_retrieved_independently(self, db):
        p_a1 = make_proof(instance_id="loan_A", sequence_id=1, to_state="approved")
        p_b1 = make_proof(instance_id="loan_B", sequence_id=1, to_state="denied")
        db.append_ledger_entry(p_a1)
        db.append_ledger_entry(p_b1)
        chain_a = db.get_ledger_chain("loan_A")
        chain_b = db.get_ledger_chain("loan_B")
        assert len(chain_a) == 1
        assert len(chain_b) == 1
        # Different decisions → different hashes (even same instance structure)
        assert chain_a[0]["to_state"] == "approved"
        assert chain_b[0]["to_state"] == "denied"


# ── Cross-tenant isolation ────────────────────────────────────────────────────

class TestCrossTenantIsolation:
    """
    instance_id is scoped to tenant_id.
    Same instance_id under different tenants must be rejected.
    """

    def test_same_instance_id_different_tenant_rejected(self, db):
        """Cross-tenant instance reuse must be blocked."""
        from provable_ai.exceptions import LedgerError
        p_t1 = make_proof(instance_id="loan_001")
        # Override tenant_id for second insert
        p_t1["tenant_id"] = "bank_A"
        db.append_ledger_entry(p_t1)

        # Same instance_id, different tenant — must be rejected
        p_t2 = make_proof(instance_id="loan_001")
        p_t2["tenant_id"] = "bank_B"
        with pytest.raises(LedgerError) as e:
            db.append_ledger_entry(p_t2)
        assert "bank_A" in str(e.value) or "tenant" in str(e.value).lower()

    def test_same_instance_id_same_tenant_allowed(self, db):
        """Sequential entries for same (tenant, instance) must work."""
        p1 = make_proof(instance_id="loan_same_tenant", sequence_id=1)
        p1["tenant_id"] = "bank_A"
        db.append_ledger_entry(p1)

        p2 = make_proof(
            instance_id="loan_same_tenant",
            sequence_id=2,
            previous_hash=p1["ledger"]["current_hash"],
            from_state="approved", to_state="completed",
        )
        p2["tenant_id"] = "bank_A"
        assert db.append_ledger_entry(p2) == 2

    def test_different_instance_ids_different_tenants_independent(self, db):
        """Different instance_ids on different tenants are fully independent."""
        p_a = make_proof(instance_id="loan_a")
        p_a["tenant_id"] = "bank_A"
        p_b = make_proof(instance_id="loan_b")
        p_b["tenant_id"] = "bank_B"
        db.append_ledger_entry(p_a)
        db.append_ledger_entry(p_b)
        assert db.get_ledger_count() == 2


# ── Governance ────────────────────────────────────────────────────────────────

class TestGovernance:

    def test_add_and_get_models(self, db):
        db.add_approved_model("credit_model_v3.1")
        models = db.get_approved_models()
        assert any(m["version"] == "credit_model_v3.1" for m in models)

    def test_duplicate_model_idempotent(self, db):
        db.add_approved_model("model_v1")
        db.add_approved_model("model_v1")
        models = db.get_approved_models()
        assert sum(1 for m in models if m["version"] == "model_v1") == 1

    def test_deactivate_policy(self, db):
        db.add_approved_policy("policy_v1")
        policies = db.get_approved_policies()
        assert any(p["version"] == "policy_v1" for p in policies)
        db.deactivate_policy("policy_v1")
        policies_after = db.get_approved_policies()
        assert not any(p["version"] == "policy_v1" for p in policies_after)

    def test_empty_lists(self, db):
        assert db.get_approved_models() == []
        assert db.get_approved_agents() == []
        assert db.get_approved_policies() == []


# ── Migration ─────────────────────────────────────────────────────────────────

class TestSchemaMigration:

    def test_migration_adds_sequence_id_to_legacy_db(self, tmp_path):
        db_path = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(db_path)
        # Create legacy ledger without sequence_id
        conn.execute("""
            CREATE TABLE ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT NOT NULL, previous_hash TEXT,
                current_hash TEXT NOT NULL, signature TEXT NOT NULL,
                protocol_hash TEXT NOT NULL, from_state TEXT NOT NULL,
                to_state TEXT NOT NULL, actor TEXT NOT NULL,
                input_hash TEXT NOT NULL, output_hash TEXT NOT NULL,
                model_version TEXT NOT NULL, agent_version TEXT NOT NULL,
                policy_version TEXT NOT NULL, metadata_json TEXT NOT NULL,
                schema_version TEXT NOT NULL, version INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT UNIQUE NOT NULL, protocol_hash TEXT NOT NULL,
                current_state TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
                frozen INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE protocols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol_hash TEXT UNIQUE NOT NULL, spec_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            INSERT INTO ledger
            (instance_id, previous_hash, current_hash, signature,
             protocol_hash, from_state, to_state, actor, input_hash, output_hash,
             model_version, agent_version, policy_version,
             metadata_json, schema_version, version, timestamp)
            VALUES ('leg_001','{}','{}','sig','proto',
                    'pending','approved','system','','','m','a','p','{}','1.0',1,'2026-01-01T00:00:00Z')
        """.replace("{}","0"*64,2))
        conn.commit()
        conn.close()

        db = SQLiteStorage(db_path=db_path)
        cur = db.conn.cursor()
        cur.execute("PRAGMA table_info(ledger)")
        cols = {r["name"] for r in cur.fetchall()}
        assert "sequence_id" in cols
        cur.execute("SELECT COUNT(*) FROM ledger")
        assert cur.fetchone()[0] == 1
        db.close()


# ── Signature validation ─────────────────────────────────────────────────────

class TestSignatureValidation:
    """Signature must be validated before DB insert (Gap 9)."""

    def test_correct_signature_accepted(self, db):
        p = make_proof()
        assert db.append_ledger_entry(p) == 1

    def test_empty_signature_rejected(self, db):
        from provable_ai.exceptions import SigningFailed
        p = make_proof()
        p["signature"]["value"] = ""
        with pytest.raises(SigningFailed):
            db.append_ledger_entry(p)

    def test_short_signature_rejected(self, db):
        from provable_ai.exceptions import SigningFailed
        p = make_proof()
        p["signature"]["value"] = "a" * 64  # 64 chars not 128
        with pytest.raises(SigningFailed):
            db.append_ledger_entry(p)


# ── Deprecated record_transition ──────────────────────────────────────────────

class TestDeprecatedRecordTransition:

    def test_still_works(self, db):
        result = db.record_transition(
            instance_id="legacy_001", from_state="pending", to_state="approved",
            actor="system", input_hash="a"*64, output_hash="b"*64,
            model_version="m_v1", agent_version="a_v1", policy_version="p_v1",
            previous_hash=genesis_hash(), current_hash="c"*64,
            signature="d"*128, protocol_hash="proto_abc",
        )
        assert result["sequence_id"] == 1

    def test_increments_sequence(self, db):
        db.record_transition(
            instance_id="seq_test", from_state="pending", to_state="approved",
            actor="system", input_hash="a"*64, output_hash="b"*64,
            model_version="m", agent_version="a", policy_version="p",
            previous_hash=genesis_hash(), current_hash="c"*64,
            signature="d"*128, protocol_hash="proto",
        )
        r2 = db.record_transition(
            instance_id="seq_test", from_state="approved", to_state="completed",
            actor="system", input_hash="a"*64, output_hash="b"*64,
            model_version="m", agent_version="a", policy_version="p",
            previous_hash="c"*64, current_hash="e"*64,
            signature="d"*128, protocol_hash="proto",
        )
        assert r2["sequence_id"] == 2

    def test_wrong_previous_hash_rejected(self, db):
        """Deprecated method must also enforce chain integrity."""
        db.record_transition(
            instance_id="chain_test", from_state="pending", to_state="approved",
            actor="system", input_hash="a"*64, output_hash="b"*64,
            model_version="m", agent_version="a", policy_version="p",
            previous_hash=genesis_hash(), current_hash="c"*64,
            signature="d"*128, protocol_hash="proto",
        )
        with pytest.raises(ChainBroken):
            db.record_transition(
                instance_id="chain_test", from_state="approved", to_state="done",
                actor="system", input_hash="a"*64, output_hash="b"*64,
                model_version="m", agent_version="a", policy_version="p",
                previous_hash="wrong_hash" + "0" * 54,  # wrong
                current_hash="f"*64, signature="d"*128, protocol_hash="proto",
            )