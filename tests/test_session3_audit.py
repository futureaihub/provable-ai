"""
Zorynex Session 3 Audit Infrastructure — Final Tests
Run: pytest tests/test_session3_audit.py -v
"""
import hashlib
import json
import uuid
import pytest

from provable_ai.audit_log import (
    GENESIS_HASH, QUERY_MAX_LIMIT,
    VerificationAuditEntry, VerificationAuditLog,
    _compute_chain_hash, _compute_row_hash, compute_audit_leaf,
)
from provable_ai.audit_batch import (
    build_merkle_tree, merkle_root, merkle_root_from_entries,
    build_batch_export, verify_batch_signature,
    compute_inclusion_proof, verify_inclusion_proof,
)
from provable_ai.audit_compliance import build_compliance_pack
from provable_ai.audit_report import generate_audit_report
from provable_ai.audit_anchor import (
    AuditAnchorStore, _build_ts_request, verify_rfc3161_token,
)
from provable_ai.audit_keyregistry import KeyRegistry, auto_register_signer, KEY_REGISTRY_GENESIS


@pytest.fixture
def tmp_audit_log(tmp_path):
    return VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

@pytest.fixture
def tmp_anchor(tmp_path):
    return AuditAnchorStore(db_path=str(tmp_path / "anchors.db"))

@pytest.fixture
def tmp_reg(tmp_path):
    return KeyRegistry(db_path=str(tmp_path / "keys.db"))


def _make_proof(instance_id="loan_001", sequence_id=1):
    h = "a" * 64
    return {
        "type": "zorynex-proof-v1", "instance_id": instance_id,
        "proof_id": hashlib.sha256(f"{h}:{sequence_id}".encode()).hexdigest(),
        "tenant_id": "test_tenant",
        "ledger": {"sequence_id": sequence_id, "current_hash": h,
                   "previous_hash": "0"*64, "timestamp": "2026-04-30T10:00:00Z"},
        "decision": {"from_state": "applied", "to_state": "approved"},
        "decision_context": {"reason_code": "RC001", "policy_rule": "PR001",
                             "model_version": "v1.0", "inputs_hash": "c"*64},
        "governance": {"model_version": "v1.0", "agent_version": "a1.0",
                       "policy_version": "p1.0"},
        "signature": {"value": "d"*128, "key_id": "test-key", "algorithm": "Ed25519"},
    }


def _make_result(valid=True):
    return {
        "valid": valid, "chain_intact": valid, "sequence_verified": valid,
        "final_state": "approved" if valid else None, "key_id": "test-key",
        "verified_at": "2026-04-30T10:00:00Z",
        "governance_recorded": {
            "model_version": "v1.0", "agent_version": "a1.0",
            "policy_version": "p1.0", "determinism_mode": "strict_deterministic",
        } if valid else None,
        "governance_verified": False, "replay_result": None,
        "failure_reason": None if valid else {
            "type": "HashMismatch", "message": "Hash mismatch"
        },
    }


def _make_entry(result="valid", tenant_id="test_tenant", instance_id="loan_001"):
    return VerificationAuditEntry(
        tenant_id=tenant_id, trace_id=str(uuid.uuid4()),
        instance_id=instance_id, sequence_id=1,
        proof_id=hashlib.sha256(f"{instance_id}:1".encode()).hexdigest(),
        verified_at="2026-04-30T10:00:00Z", result=result,
        failure_code="HashMismatch" if result == "invalid" else None,
        failure_msg="Hash mismatch" if result == "invalid" else None,
        key_id="test-key",
        governance_json=json.dumps({
            "model_version": "v1.0", "agent_version": "a1.0",
            "policy_version": "p1.0", "determinism_mode": "strict_deterministic",
        }),
        recorded_at="2026-04-30T10:00:01Z",
        row_hash="", prev_chain_hash=GENESIS_HASH, chain_hash="",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PART 1 — AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditLog:

    def test_record_valid(self, tmp_audit_log):
        e = tmp_audit_log.record("t1", "tr", _make_proof(), _make_result(True))
        assert e.result == "valid" and e.instance_id == "loan_001"

    def test_record_invalid_always_stored(self, tmp_audit_log):
        e = tmp_audit_log.record("t1", "tr", _make_proof(), _make_result(False))
        assert e.result == "invalid" and e.failure_code == "HashMismatch"

    def test_both_results_present(self, tmp_audit_log):
        tmp_audit_log.record("t1", "t1", _make_proof("a"), _make_result(True))
        tmp_audit_log.record("t1", "t2", _make_proof("b"), _make_result(False))
        results = {e.result for e in tmp_audit_log.query("t1").entries}
        assert results == {"valid", "invalid"}

    def test_append_only_no_update(self, tmp_audit_log):
        import sqlite3
        tmp_audit_log.record("t1", "t1", _make_proof(), _make_result())
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)):
            tmp_audit_log._conn().execute(
                "UPDATE verification_audit SET result='invalid' WHERE id=1"
            )

    def test_append_only_no_delete(self, tmp_audit_log):
        import sqlite3
        tmp_audit_log.record("t1", "t1", _make_proof(), _make_result())
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)):
            tmp_audit_log._conn().execute(
                "DELETE FROM verification_audit WHERE id=1"
            )

    def test_tenant_isolation(self, tmp_audit_log):
        tmp_audit_log.record("ta", "t1", _make_proof(), _make_result())
        tmp_audit_log.record("tb", "t2", _make_proof(), _make_result())
        assert tmp_audit_log.count("ta") == 1
        assert all(e.tenant_id == "ta" for e in tmp_audit_log.query("ta").entries)

    def test_pagination_hard_cap(self, tmp_audit_log):
        qr = tmp_audit_log.query("t1", limit=QUERY_MAX_LIMIT + 9999)
        assert len(qr.entries) <= QUERY_MAX_LIMIT

    def test_stats_includes_chain_hash(self, tmp_audit_log):
        tmp_audit_log.record("t1", "t1", _make_proof(), _make_result())
        stats = tmp_audit_log.stats("t1")
        assert "chain_hash" in stats and stats["chain_hash"] != GENESIS_HASH

    def test_sequence_num_monotonic(self, tmp_audit_log):
        e1 = tmp_audit_log.record("t1", "t1", _make_proof("a"), _make_result())
        e2 = tmp_audit_log.record("t1", "t2", _make_proof("b"), _make_result())
        e3 = tmp_audit_log.record("t1", "t3", _make_proof("c"), _make_result())
        assert e1.sequence_num == 1 and e2.sequence_num == 2 and e3.sequence_num == 3

    def test_sequence_num_per_tenant(self, tmp_audit_log):
        ea = tmp_audit_log.record("ta", "ta1", _make_proof(), _make_result())
        eb = tmp_audit_log.record("tb", "tb1", _make_proof(), _make_result())
        assert ea.sequence_num == 1 and eb.sequence_num == 1


# ═══════════════════════════════════════════════════════════════════════════════
# PART 2 — HASH CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestHashChain:

    def test_first_row_genesis(self, tmp_audit_log):
        e = tmp_audit_log.record("t1", "t1", _make_proof(), _make_result())
        assert e.prev_chain_hash == GENESIS_HASH

    def test_chain_links(self, tmp_audit_log):
        e1 = tmp_audit_log.record("t1", "t1", _make_proof("a"), _make_result())
        e2 = tmp_audit_log.record("t1", "t2", _make_proof("b"), _make_result())
        assert e2.prev_chain_hash == e1.chain_hash

    def test_verify_chain_intact(self, tmp_audit_log):
        for i in range(5):
            tmp_audit_log.record("t1", f"t{i}", _make_proof(f"l{i}"), _make_result())
        r = tmp_audit_log.verify_chain("t1")
        assert r.valid is True and r.total_rows == 5

    def test_verify_chain_detects_tampering(self, tmp_audit_log):
        import sqlite3
        for i in range(3):
            tmp_audit_log.record("t1", f"t{i}", _make_proof(f"l{i}"), _make_result())
        conn = sqlite3.connect(tmp_audit_log.db_path)
        conn.execute("DROP TRIGGER IF EXISTS no_update_verification_audit")
        conn.execute("UPDATE verification_audit SET result='invalid' WHERE id=1")
        conn.commit()
        conn.close()
        r = tmp_audit_log.verify_chain("t1")
        assert r.valid is False and r.broken_at_id == 1

    def test_verify_chain_at_block(self, tmp_audit_log):
        e1 = tmp_audit_log.record("t1", "t1", _make_proof("a"), _make_result())
        tmp_audit_log.record("t1", "t2", _make_proof("b"), _make_result())
        r = tmp_audit_log.verify_chain_at_block("t1", sequence_num=1)
        assert r["valid"] is True and r["chain_hash"] == e1.chain_hash

    def test_verify_chain_at_block_partial(self, tmp_audit_log):
        for i in range(5):
            tmp_audit_log.record("t1", f"t{i}", _make_proof(f"l{i}"), _make_result())
        r = tmp_audit_log.verify_chain_at_block("t1", sequence_num=3)
        assert r["valid"] is True and r["total_rows"] == 3

    def test_tenant_chains_independent(self, tmp_audit_log):
        tmp_audit_log.record("ta", "ta1", _make_proof(), _make_result())
        tmp_audit_log.record("tb", "tb1", _make_proof(), _make_result())
        assert tmp_audit_log.verify_chain("ta").valid
        assert tmp_audit_log.verify_chain("tb").valid


# ═══════════════════════════════════════════════════════════════════════════════
# PART 3 — RICH MERKLE
# ═══════════════════════════════════════════════════════════════════════════════

class TestRichMerkle:

    def test_leaf_length(self):
        assert len(compute_audit_leaf(_make_entry("valid"))) == 64

    def test_different_results_different_leaves(self):
        assert (compute_audit_leaf(_make_entry("valid")) !=
                compute_audit_leaf(_make_entry("invalid")))

    def test_different_tenants_different_leaves(self):
        assert (compute_audit_leaf(_make_entry("valid", tenant_id="a")) !=
                compute_audit_leaf(_make_entry("valid", tenant_id="b")))

    def test_empty(self):
        assert merkle_root_from_entries([]) == "0" * 64

    def test_two_states_different_roots(self):
        a = [_make_entry("valid", instance_id="x"), _make_entry("invalid", instance_id="y")]
        b = [_make_entry("invalid", instance_id="x"), _make_entry("valid", instance_id="y")]
        assert merkle_root_from_entries(a) != merkle_root_from_entries(b)

    def test_deterministic(self):
        import random
        entries = [_make_entry("valid", instance_id=f"l{i}") for i in range(8)]
        shuffled = entries[:]
        random.shuffle(shuffled)
        assert merkle_root_from_entries(entries) == merkle_root_from_entries(shuffled)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 4 — BATCH EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestBatchExport:

    def test_merkle_single(self):
        pid  = "a" * 64
        root = merkle_root([pid])
        leaf = hashlib.sha256(pid.encode()).hexdigest()
        assert root == hashlib.sha256(
            bytes.fromhex(leaf) + bytes.fromhex(leaf)
        ).hexdigest()

    def test_merkle_deterministic(self):
        import random
        pids = [f"p{i}"*4 for i in range(8)]
        s = pids[:]
        random.shuffle(s)
        assert merkle_root(pids) == merkle_root(s)

    def test_tree_levels(self):
        pids = [f"p{i}"*16 for i in range(4)]
        root, levels = build_merkle_tree(pids)
        assert len(levels) == 3 and levels[2][0] == root

    def test_batch_structure(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        db    = SQLiteStorage(db_path=str(tmp_path / "t.db"))
        batch = build_batch_export(storage=db, tenant_id="t1", signer=get_signer())
        d     = batch.batch_dict
        assert d["type"] == "zorynex-batch-v1"
        assert "merkle_root" in d and "merkle_signature" in d

    def test_verification_info(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        db    = SQLiteStorage(db_path=str(tmp_path / "t.db"))
        batch = build_batch_export(storage=db, tenant_id="t1", signer=get_signer())
        info  = batch.batch_dict["verification_info"]
        assert info["algorithm"] == "Ed25519" and "public_key" in info

    def test_signature_verifiable(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        db    = SQLiteStorage(db_path=str(tmp_path / "t.db"))
        batch = build_batch_export(storage=db, tenant_id="t1", signer=get_signer())
        r     = verify_batch_signature(batch.batch_dict)
        assert r["valid"] and r["signature_valid"]

    def test_json_serializable(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        db    = SQLiteStorage(db_path=str(tmp_path / "t.db"))
        batch = build_batch_export(storage=db, tenant_id="t1", signer=get_signer())
        json.dumps(batch.batch_dict)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 5 — INCLUSION PROOFS (signature-bound)
# ═══════════════════════════════════════════════════════════════════════════════

class TestInclusionProofs:

    def test_basic_valid(self):
        pids = ["a"*64, "b"*64, "c"*64, "d"*64]
        assert verify_inclusion_proof(compute_inclusion_proof(pids, "b"*64))

    def test_eight_leaves(self):
        pids = [f"leaf_{i:02d}"*4 for i in range(8)]
        for target in pids:
            assert verify_inclusion_proof(compute_inclusion_proof(pids, target))

    def test_path_length_log2(self):
        pids = [f"l{i}"*16 for i in range(8)]
        assert len(compute_inclusion_proof(pids, pids[0]).path) == 3

    def test_bound_to_signature(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        db    = SQLiteStorage(db_path=str(tmp_path / "t.db"))
        batch = build_batch_export(storage=db, tenant_id="t1", signer=get_signer())
        pids  = [p.get("proof_id") for p in batch.batch_dict["proofs"]
                 if p.get("proof_id")]
        if not pids:
            return
        proof = compute_inclusion_proof(pids, pids[0], batch_dict=batch.batch_dict)
        assert proof.signed_root == proof.root
        assert proof.signature != "" and proof.public_key != ""
        assert verify_inclusion_proof(proof)

    def test_wrong_signed_root_fails(self):
        pids = ["a"*64, "b"*64]
        p    = compute_inclusion_proof(pids, "a"*64)
        d    = {"leaf_hash": p.leaf_hash, "path": p.path,
                "root": p.root, "signed_root": "z"*64,
                "signature": "", "public_key": ""}
        assert not verify_inclusion_proof(d)

    def test_tampered_path_fails(self):
        pids = ["a"*64, "b"*64, "c"*64, "d"*64]
        p    = compute_inclusion_proof(pids, "a"*64)
        d    = {"leaf_hash": p.leaf_hash, "path": list(p.path),
                "root": p.root, "signed_root": p.root,
                "signature": "", "public_key": ""}
        d["path"][0] = {"hash": "f"*64, "position": d["path"][0]["position"]}
        assert not verify_inclusion_proof(d)

    def test_not_in_batch_raises(self):
        with pytest.raises(ValueError, match="not found"):
            compute_inclusion_proof(["a"*64], "z"*64)

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            compute_inclusion_proof([], "a"*64)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 6 — EXTERNAL ANCHORING (RFC 3161 + self-chained store)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExternalAnchoring:

    def test_anchor_writes(self, tmp_anchor):
        r = tmp_anchor.anchor("t1", "a"*64, request_rfc3161=False)
        assert r.tenant_id == "t1" and r.anchor_seq == 1

    def test_anchor_seq_monotonic(self, tmp_anchor):
        r1 = tmp_anchor.anchor("t1", "a"*64, request_rfc3161=False)
        r2 = tmp_anchor.anchor("t1", "b"*64, request_rfc3161=False)
        assert r1.anchor_seq == 1 and r2.anchor_seq == 2

    def test_anchor_self_chained(self, tmp_anchor):
        for i in range(3):
            tmp_anchor.anchor("t1", f"{i}"*64, request_rfc3161=False)
        assert tmp_anchor.verify_anchor_chain("t1")["valid"] is True

    def test_anchor_chain_detects_tampering(self, tmp_anchor):
        import sqlite3
        tmp_anchor.anchor("t1", "a"*64, request_rfc3161=False)
        tmp_anchor.anchor("t1", "b"*64, request_rfc3161=False)
        conn = sqlite3.connect(tmp_anchor.db_path)
        conn.execute("DROP TRIGGER IF EXISTS no_update_anchors")
        zeroes = "0" * 64
        conn.execute(f"UPDATE chain_anchors SET chain_hash='{zeroes}' WHERE id=1")
        conn.commit()
        conn.close()
        assert tmp_anchor.verify_anchor_chain("t1")["valid"] is False

    def test_find_by_hash(self, tmp_anchor):
        tmp_anchor.anchor("t1", "a"*64, request_rfc3161=False)
        r = tmp_anchor.verify_against_anchor("t1", "a"*64)
        assert r["anchored"] is True

    def test_unknown_hash(self, tmp_anchor):
        assert tmp_anchor.verify_against_anchor("t1", "z"*64)["anchored"] is False

    def test_tenant_isolation(self, tmp_anchor):
        tmp_anchor.anchor("ta", "a"*64, request_rfc3161=False)
        assert tmp_anchor.verify_against_anchor("tb", "a"*64)["anchored"] is False

    def test_append_only(self, tmp_anchor):
        import sqlite3
        tmp_anchor.anchor("t1", "a"*64, request_rfc3161=False)
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)):
            tmp_anchor._conn().execute("DELETE FROM chain_anchors WHERE id=1")

    def test_rfc3161_ts_request_is_der(self):
        req = _build_ts_request(b"test")
        assert isinstance(req, bytes) and req[0] == 0x30  # SEQUENCE tag

    def test_rfc3161_verify_bad_hex(self):
        r = verify_rfc3161_token("not_valid_hex", "abc")
        assert r["valid"] is False

    def test_full_flow(self, tmp_path):
        audit = VerificationAuditLog(db_path=str(tmp_path / "a.db"))
        anch  = AuditAnchorStore(db_path=str(tmp_path / "anch.db"))
        audit.record("t1", "tr1", _make_proof("a"), _make_result(True))
        audit.record("t1", "tr2", _make_proof("b"), _make_result(False))
        ch = audit.get_latest_chain_hash("t1")
        anch.anchor("t1", ch, request_rfc3161=False)
        assert audit.verify_chain("t1").valid
        assert anch.verify_against_anchor("t1", ch)["anchored"]
        assert anch.verify_anchor_chain("t1")["valid"]


# ═══════════════════════════════════════════════════════════════════════════════
# PART 7 — KEY REGISTRY (append-only, chained, tenant-scoped)
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeyRegistry:

    def test_register_key(self, tmp_reg):
        r = tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        assert r.key_id == "k1" and r.status == "active" and r.tenant_id == "bank"

    def test_tenant_scoped(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank_a")
        r = tmp_reg.register_key("k1", "b"*64, tenant_id="bank_b")
        assert r.tenant_id == "bank_b"

    def test_one_active_per_tenant(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        with pytest.raises(ValueError, match="already has active key"):
            tmp_reg.register_key("k2", "b"*64, tenant_id="bank")

    def test_rotate_append_only(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        new_key, old_key = tmp_reg.rotate_key("k2", "b"*64, tenant_id="bank")
        assert new_key.status == "active" and old_key.status == "retired"
        rows = tmp_reg._conn().execute(
            "SELECT status FROM key_registry WHERE key_id='k1' AND tenant_id='bank'"
        ).fetchall()
        statuses = {r["status"] for r in rows}
        assert "active" in statuses and "retired" in statuses

    def test_no_update_trigger(self, tmp_reg):
        import sqlite3
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)):
            tmp_reg._conn().execute(
                "UPDATE key_registry SET status='retired' WHERE id=1"
            )

    def test_no_delete_trigger(self, tmp_reg):
        import sqlite3
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError)):
            tmp_reg._conn().execute("DELETE FROM key_registry WHERE id=1")

    def test_key_registry_chain_valid(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        tmp_reg.rotate_key("k2", "b"*64, tenant_id="bank")
        assert tmp_reg.verify_chain("bank")["valid"] is True

    def test_chain_detects_tampering(self, tmp_reg):
        import sqlite3
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        conn = sqlite3.connect(tmp_reg.db_path)
        conn.execute("DROP TRIGGER IF EXISTS no_update_key_registry")
        bbbb = "b" * 64
        conn.execute(f"UPDATE key_registry SET public_key='{bbbb}' WHERE id=1")
        conn.commit()
        conn.close()
        assert tmp_reg.verify_chain("bank")["valid"] is False

    def test_was_active_at(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        assert tmp_reg.was_active_at("k1", "bank", "2000-01-01T00:00:00Z") is False
        assert tmp_reg.was_active_at("k1", "bank", "2099-12-31T00:00:00Z") is True

    def test_was_active_after_retirement(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        tmp_reg.rotate_key("k2", "b"*64, tenant_id="bank")
        assert tmp_reg.was_active_at("k1", "bank", "2099-12-31T00:00:00Z") is False

    def test_retired_key_preserved(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        tmp_reg.rotate_key("k2", "b"*64, tenant_id="bank")
        assert tmp_reg.get("k1", "bank") is not None

    def test_rotation_policy(self, tmp_reg):
        tmp_reg.register_key("k1", "a"*64, tenant_id="bank")
        p = tmp_reg.rotation_policy("bank")
        assert p["algorithm"] == "Ed25519"
        assert "immutability" in p and "tenant_scoping" in p

    def test_auto_register_signer(self, tmp_path):
        from provable_ai.signer import get_signer
        import provable_ai.audit_keyregistry as kr_mod
        orig = kr_mod._registry
        kr_mod._registry = KeyRegistry(db_path=str(tmp_path / "k.db"))
        try:
            signer = get_signer()
            rec    = auto_register_signer(signer, tenant_id="system")
            assert rec.key_id == signer.get_key_id()
        finally:
            kr_mod._registry = orig


# ═══════════════════════════════════════════════════════════════════════════════
# PART 8 — COMPLIANCE (evidence-first + provenance)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCompliancePack:

    def _entries(self, n_valid=5, n_invalid=1):
        return ([_make_entry("valid",   instance_id=f"v{i}") for i in range(n_valid)] +
                [_make_entry("invalid", instance_id=f"i{i}") for i in range(n_invalid)])

    def test_all_frameworks(self):
        pack = build_compliance_pack(
            entries=self._entries(), tenant_id="bank", merkle_root="a"*64)
        assert {"SR_11_7", "EU_AI_ACT", "CFPB"} <= set(pack)

    def test_sr_11_7_structure(self):
        pack = build_compliance_pack(
            entries=self._entries(), tenant_id="bank", merkle_root="a"*64)
        assert "requirements" in pack["SR_11_7"] and "attestation" in pack["SR_11_7"]

    def test_raw_metrics(self):
        pack = build_compliance_pack(
            entries=self._entries(5, 2), tenant_id="bank", merkle_root="a"*64)
        rm = pack["SR_11_7"]["attestation"]["raw_metrics"]
        assert rm["total"] == 7 and rm["valid"] == 5 and rm["invalid"] == 2

    def test_provenance_links(self):
        entries = self._entries(5, 1)
        pack    = build_compliance_pack(
            entries=entries, tenant_id="bank", merkle_root="a"*64,
            from_date="2026-01-01T00:00:00Z")
        prov = pack["SR_11_7"]["attestation"]["raw_metrics"]["provenance"]
        assert "query_parameters" in prov
        assert prov["query_parameters"]["from_date"] == "2026-01-01T00:00:00Z"
        assert "sample_valid_trace_ids" in prov
        assert "sample_instance_ids" in prov
        assert prov["total_referenced"] == 6

    def test_provenance_in_cfpb(self):
        pack = build_compliance_pack(
            entries=self._entries(), tenant_id="bank", merkle_root="a"*64)
        assert "provenance" in pack["CFPB"]["attestation"]["raw_metrics"]

    def test_interpretive_note(self):
        pack = build_compliance_pack(
            entries=self._entries(), tenant_id="bank", merkle_root="a"*64)
        note = pack["SR_11_7"]["attestation"]["raw_metrics"]["note"]
        assert "interpretive" in note.lower() or "independent" in note.lower()

    def test_empty_no_crash(self):
        pack = build_compliance_pack(entries=[], tenant_id="bank", merkle_root="0"*64)
        assert "NO_DATA" in pack["SR_11_7"]["status"]

    def test_merkle_leaf_method_documented(self):
        pack = build_compliance_pack(
            entries=self._entries(), tenant_id="bank", merkle_root="a"*64)
        assert "merkle_leaf_method" in pack["SR_11_7"]["requirements"]["non_repudiation"]

    def test_json_serializable(self):
        pack = build_compliance_pack(
            entries=self._entries(), tenant_id="bank", merkle_root="a"*64)
        json.dumps(pack)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 9 — PDF REPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditReport:

    def test_pdf_generated(self):
        entries = [_make_entry("valid", instance_id=f"l{i}") for i in range(5)]
        m_root  = merkle_root_from_entries(entries)
        pack    = build_compliance_pack(
            entries=entries, tenant_id="bank", merkle_root=m_root)
        pdf     = generate_audit_report(
            tenant_id="bank", entries=entries,
            merkle_root=m_root, compliance_pack=pack)
        assert isinstance(pdf, bytes) and 5_000 < len(pdf) < 5_000_000

    def test_pdf_empty_entries(self):
        pack = build_compliance_pack(entries=[], tenant_id="bank", merkle_root="0"*64)
        pdf  = generate_audit_report(
            tenant_id="bank", entries=[],
            merkle_root="0"*64, compliance_pack=pack)
        assert isinstance(pdf, bytes) and len(pdf) > 1000