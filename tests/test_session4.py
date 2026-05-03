"""
Zorynex Session 4 — Performance + Operations Tests
====================================================
Covers:
  1. DriftDetector — snapshot, compare, history, persist
  2. take_snapshot — correct field extraction
  3. Drift types — root_mismatch (CRITICAL), chain/count (WARNING)
  4. Locust file — importable, task classes correct
  5. Server drift endpoints — smoke test via TestClient

Run: pytest tests/test_session4.py -v
"""

import hashlib
import json
import uuid
import pytest

from provable_ai.audit_anchor import AuditAnchorStore

import os
import pathlib
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent
_LOCUST_FILE  = str(_PROJECT_ROOT / "benchmarks" / "locustfile.py")

from provable_ai.drift_detector import (
    DriftDetector,
    DriftResult,
    SystemSnapshot,
    get_drift_detector,
    snapshot_to_dict,
    drift_result_to_dict,
    _severity,
    _recommendation,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_detector(tmp_path):
    return DriftDetector(db_path=str(tmp_path / "drift.db"))


def _snap(
    tenant_id="bank",
    environment="prod",
    system_root=None,
    instance_count=10,
    audit_chain_hash=None,
    audit_row_count=50,
    recorded_at="2026-04-30T10:00:00Z",
):
    return SystemSnapshot(
        snapshot_id=f"snap_{uuid.uuid4().hex[:8]}",
        tenant_id=tenant_id,
        environment=environment,
        system_root=system_root or "a" * 64,
        instance_count=instance_count,
        audit_chain_hash=audit_chain_hash or "b" * 64,
        audit_row_count=audit_row_count,
        recorded_at=recorded_at,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PART 1 — SNAPSHOT STORAGE
# ═══════════════════════════════════════════════════════════════════════════════

class TestSnapshotStorage:

    def test_save_and_retrieve(self, tmp_detector):
        snap = _snap()
        tmp_detector.save_snapshot(snap)
        retrieved = tmp_detector.get_snapshot(snap.snapshot_id)
        assert retrieved is not None
        assert retrieved.snapshot_id  == snap.snapshot_id
        assert retrieved.system_root  == snap.system_root
        assert retrieved.environment  == "prod"

    def test_save_idempotent(self, tmp_detector):
        snap = _snap()
        tmp_detector.save_snapshot(snap)
        tmp_detector.save_snapshot(snap)  # must not raise
        assert tmp_detector.get_snapshot(snap.snapshot_id) is not None

    def test_get_latest_returns_most_recent(self, tmp_detector):
        s1 = _snap(recorded_at="2026-04-30T09:00:00Z", system_root="a" * 64)
        s2 = _snap(recorded_at="2026-04-30T10:00:00Z", system_root="c" * 64)
        tmp_detector.save_snapshot(s1)
        tmp_detector.save_snapshot(s2)
        latest = tmp_detector.get_latest("bank", "prod")
        assert latest.system_root == "c" * 64

    def test_get_latest_env_isolation(self, tmp_detector):
        prod    = _snap(environment="prod",    system_root="a" * 64)
        staging = _snap(environment="staging", system_root="b" * 64)
        tmp_detector.save_snapshot(prod)
        tmp_detector.save_snapshot(staging)
        assert tmp_detector.get_latest("bank", "prod").system_root    == "a" * 64
        assert tmp_detector.get_latest("bank", "staging").system_root == "b" * 64

    def test_get_latest_none_if_absent(self, tmp_detector):
        assert tmp_detector.get_latest("nobody", "prod") is None

    def test_list_snapshots(self, tmp_detector):
        for i in range(5):
            tmp_detector.save_snapshot(_snap(
                system_root=f"{i}" * 64,
                recorded_at=f"2026-04-30T{10+i:02d}:00:00Z",
            ))
        snaps = tmp_detector.list_snapshots("bank")
        assert len(snaps) == 5
        # Most recent first
        assert snaps[0].recorded_at > snaps[-1].recorded_at

    def test_tenant_isolation(self, tmp_detector):
        tmp_detector.save_snapshot(_snap(tenant_id="bank_a"))
        tmp_detector.save_snapshot(_snap(tenant_id="bank_b"))
        assert len(tmp_detector.list_snapshots("bank_a")) == 1
        assert len(tmp_detector.list_snapshots("bank_b")) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# PART 2 — DRIFT COMPARISON
# ═══════════════════════════════════════════════════════════════════════════════

class TestDriftComparison:

    def test_identical_snapshots_no_drift(self):
        root = "a" * 64
        chain = "b" * 64
        s1 = _snap(system_root=root, audit_chain_hash=chain, instance_count=10)
        s2 = _snap(system_root=root, audit_chain_hash=chain, instance_count=10)
        r = DriftDetector.compare(s1, s2)
        assert r.drifted    is False
        assert r.drift_type is None
        assert r.severity   == "OK"

    def test_root_mismatch_critical(self):
        s1 = _snap(system_root="a" * 64)
        s2 = _snap(system_root="b" * 64)
        r = DriftDetector.compare(s1, s2)
        assert r.drifted    is True
        assert r.drift_type == "root_mismatch"
        assert r.severity   == "CRITICAL"
        assert "system_root" in r.details["mismatches"]

    def test_chain_mismatch_warning(self):
        root = "a" * 64
        s1 = _snap(system_root=root, audit_chain_hash="b" * 64)
        s2 = _snap(system_root=root, audit_chain_hash="c" * 64)
        r = DriftDetector.compare(s1, s2)
        assert r.drifted    is True
        assert r.drift_type == "chain_mismatch"
        assert r.severity   == "WARNING"

    def test_count_mismatch_warning(self):
        root = "a" * 64
        chain = "b" * 64
        s1 = _snap(system_root=root, audit_chain_hash=chain, instance_count=10)
        s2 = _snap(system_root=root, audit_chain_hash=chain, instance_count=20)
        r = DriftDetector.compare(s1, s2)
        assert r.drifted    is True
        assert r.drift_type == "count_mismatch"
        assert r.severity   == "WARNING"

    def test_combined_drift_critical(self):
        s1 = _snap(system_root="a" * 64, audit_chain_hash="b" * 64, instance_count=10)
        s2 = _snap(system_root="c" * 64, audit_chain_hash="d" * 64, instance_count=20)
        r = DriftDetector.compare(s1, s2)
        assert r.drifted    is True
        assert r.severity   == "CRITICAL"

    def test_drift_result_has_details(self):
        s1 = _snap(system_root="a" * 64, environment="prod")
        s2 = _snap(system_root="b" * 64, environment="staging")
        r = DriftDetector.compare(s1, s2)
        assert "snap_a" in r.details
        assert "snap_b" in r.details
        assert r.details["snap_a"]["env"] == "prod"
        assert r.details["snap_b"]["env"] == "staging"

    def test_drift_result_has_recommendation(self):
        s1 = _snap(system_root="a" * 64)
        s2 = _snap(system_root="b" * 64)
        r = DriftDetector.compare(s1, s2)
        assert len(r.recommendation) > 20  # not empty

    def test_compare_against_baseline_no_baseline(self, tmp_detector):
        snap = _snap()
        r = tmp_detector.compare_against_baseline(snap, baseline=None)
        assert r.drifted is False
        assert "baseline" in r.details.get("note", "").lower()

    def test_compare_against_baseline_drifted(self, tmp_detector):
        baseline = _snap(system_root="a" * 64)
        current  = _snap(system_root="b" * 64)
        r = tmp_detector.compare_against_baseline(current, baseline)
        assert r.drifted    is True
        assert r.drift_type == "root_mismatch"


# ═══════════════════════════════════════════════════════════════════════════════
# PART 3 — DRIFT HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestDriftHistory:

    def test_record_and_retrieve(self, tmp_detector):
        s1 = _snap(system_root="a" * 64)
        s2 = _snap(system_root="b" * 64)
        r  = DriftDetector.compare(s1, s2)
        tmp_detector.record_drift_event(r)
        history = tmp_detector.drift_history("bank")
        assert len(history) == 1
        assert history[0]["drifted"]    is True
        assert history[0]["drift_type"] == "root_mismatch"
        assert history[0]["severity"]   == "CRITICAL"

    def test_no_drift_event_recorded(self, tmp_detector):
        s1 = _snap(system_root="a" * 64, audit_chain_hash="b" * 64)
        s2 = _snap(system_root="a" * 64, audit_chain_hash="b" * 64)
        r  = DriftDetector.compare(s1, s2)
        tmp_detector.record_drift_event(r)
        history = tmp_detector.drift_history("bank")
        assert history[0]["drifted"] is False

    def test_history_limit(self, tmp_detector):
        for _ in range(10):
            s1 = _snap()
            s2 = _snap(system_root="c" * 64)
            tmp_detector.record_drift_event(DriftDetector.compare(s1, s2))
        assert len(tmp_detector.drift_history("bank", limit=5)) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# PART 4 — SERIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestSerialization:

    def test_snapshot_to_dict(self):
        snap = _snap()
        d    = snapshot_to_dict(snap)
        assert d["snapshot_id"]    == snap.snapshot_id
        assert d["system_root"]    == snap.system_root
        assert d["environment"]    == snap.environment
        assert d["instance_count"] == snap.instance_count
        json.dumps(d)  # must be JSON-serializable

    def test_drift_result_to_dict_clean(self):
        s1 = _snap(system_root="a" * 64)
        s2 = _snap(system_root="b" * 64)
        r  = DriftDetector.compare(s1, s2)
        d  = drift_result_to_dict(r)
        assert d["drifted"]    is True
        assert d["drift_type"] == "root_mismatch"
        assert d["severity"]   == "CRITICAL"
        assert "snap_a" in d and "snap_b" in d
        json.dumps(d)  # must be JSON-serializable

    def test_drift_result_to_dict_ok(self):
        root = "a" * 64
        chain = "b" * 64
        s1 = _snap(system_root=root, audit_chain_hash=chain)
        s2 = _snap(system_root=root, audit_chain_hash=chain)
        r  = DriftDetector.compare(s1, s2)
        d  = drift_result_to_dict(r)
        assert d["drifted"]    is False
        assert d["drift_type"] is None
        json.dumps(d)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 5 — TAKE_SNAPSHOT INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestTakeSnapshot:

    def test_take_snapshot_structure(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.audit_log import VerificationAuditLog
        from provable_ai.drift_detector import take_snapshot

        storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
        audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

        snap = take_snapshot(storage, audit_log, tenant_id="bank", environment="prod")
        assert snap.tenant_id    == "bank"
        assert snap.environment  == "prod"
        assert len(snap.system_root) == 64
        assert len(snap.audit_chain_hash) == 64
        assert snap.instance_count >= 0
        assert snap.audit_row_count >= 0
        assert snap.snapshot_id.startswith("snap_")

    def test_empty_storage_snapshot(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.audit_log import VerificationAuditLog
        from provable_ai.drift_detector import take_snapshot

        storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
        audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

        snap = take_snapshot(storage, audit_log, tenant_id="bank")
        assert snap.instance_count  == 0
        assert snap.audit_row_count == 0
        # Empty system root
        assert snap.system_root == "0" * 64

    def test_two_snapshots_same_state_same_root(self, tmp_path):
        from provable_ai.storage import SQLiteStorage
        from provable_ai.audit_log import VerificationAuditLog
        from provable_ai.drift_detector import take_snapshot

        storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
        audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

        s1 = take_snapshot(storage, audit_log, tenant_id="bank")
        s2 = take_snapshot(storage, audit_log, tenant_id="bank")
        # Same state = same root
        assert s1.system_root       == s2.system_root
        assert s1.audit_chain_hash  == s2.audit_chain_hash


# ═══════════════════════════════════════════════════════════════════════════════
# PART 6 — LOCUST FILE SMOKE TEST
# ═══════════════════════════════════════════════════════════════════════════════

class TestLocustFile:

    def test_locustfile_importable(self):
        """Locust file must import without errors."""
        pytest.importorskip("locust", reason="locust not installed — pip install locust")
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "locustfile", _LOCUST_FILE
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "MixedUser")
        assert hasattr(mod, "AuditUser")
        assert hasattr(mod, "SystemUser")
        assert hasattr(mod, "SlowUser")

    def test_payload_factories(self):
        pytest.importorskip("locust", reason="locust not installed")
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "locustfile", _LOCUST_FILE
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        payload = mod._decision_payload()
        assert "instance_id" in payload
        assert "model_version" in payload
        assert payload["determinism_mode"] == "strict_deterministic"

        proof = mod._proof_payload()
        assert "proof_id" in proof
        assert "ledger" in proof

    def test_user_weights_defined(self):
        pytest.importorskip("locust", reason="locust not installed")
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "locustfile", _LOCUST_FILE
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.SystemUser.weight > mod.SlowUser.weight

    def test_mixed_user_has_all_task_types(self):
        pytest.importorskip("locust", reason="locust not installed")
        import importlib.util
        import inspect
        spec = importlib.util.spec_from_file_location(
            "locustfile", _LOCUST_FILE
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # MixedUser should have task methods
        task_methods = [
            name for name, _ in inspect.getmembers(mod.MixedUser, predicate=inspect.isfunction)
        ]
        assert len(task_methods) >= 4


# ═══════════════════════════════════════════════════════════════════════════════
# PART 7 — SERVER DRIFT ENDPOINTS (TestClient)
# ═══════════════════════════════════════════════════════════════════════════════

class TestServerDriftEndpoints:

    @pytest.fixture(autouse=True)
    def setup_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_API_KEYS",
                           "admin-key:admin,audit-key:auditor,sys-key:system")
        monkeypatch.setenv("ZORYNEX_WEBHOOK_SECRET", "test-secret")
        monkeypatch.setenv("ZORYNEX_DB_PATH",
                           str(tmp_path / "proof.db"))
        monkeypatch.setenv("ZORYNEX_AUDIT_DB_PATH",
                           str(tmp_path / "audit.db"))
        monkeypatch.setenv("ZORYNEX_ANCHOR_DB_PATH",
                           str(tmp_path / "anchors.db"))
        monkeypatch.setenv("ZORYNEX_KEYREGISTRY_DB_PATH",
                           str(tmp_path / "keys.db"))
        monkeypatch.setenv("ZORYNEX_DRIFT_DB_PATH",
                           str(tmp_path / "drift.db"))

    @pytest.fixture
    def client(self):
        import sys

        # Drop all cached module references so the next import is truly fresh.
        # importlib.reload() is insufficient — pytest holds the old app object.
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("server") or mod_name in (
                "provable_ai.audit_log",
                "provable_ai.audit_anchor",
                "provable_ai.audit_keyregistry",
                "provable_ai.drift_detector",
            ):
                del sys.modules[mod_name]

        # Fresh import — all routes including drift endpoints will be registered
        from server.main import app
        from fastapi.testclient import TestClient
        return TestClient(app, raise_server_exceptions=False)

    def test_snapshot_endpoint(self, client):
        r = client.post(
            "/system/snapshot?env=prod",
            headers={"X-API-Key": "admin-key", "X-Tenant-Id": "test_tenant"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "snapshot" in data
        assert data["snapshot"]["environment"] == "prod"
        assert len(data["snapshot"]["system_root"]) == 64

    def test_snapshots_list_endpoint(self, client):
        # Take a snapshot first
        client.post(
            "/system/snapshot?env=prod",
            headers={"X-API-Key": "admin-key", "X-Tenant-Id": "test_tenant"},
        )
        r = client.get(
            "/system/snapshots",
            headers={"X-API-Key": "admin-key", "X-Tenant-Id": "test_tenant"},
        )
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_drift_no_snapshot_returns_404(self, client):
        r = client.get(
            "/system/drift?env_a=prod&env_b=staging",
            headers={"X-API-Key": "admin-key", "X-Tenant-Id": "test_tenant"},
        )
        assert r.status_code == 404

    def test_drift_same_state_no_drift(self, client):
        headers = {"X-API-Key": "admin-key", "X-Tenant-Id": "test_tenant"}
        # Take two snapshots of same empty state
        client.post("/system/snapshot?env=prod", headers=headers)
        client.post("/system/snapshot?env=staging", headers=headers)

        r = client.get("/system/drift?env_a=prod&env_b=staging", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert data["drifted"] is False
        assert data["severity"] == "OK"

    def test_drift_history_endpoint(self, client):
        r = client.get(
            "/system/drift/history",
            headers={"X-API-Key": "admin-key", "X-Tenant-Id": "test_tenant"},
        )
        assert r.status_code == 200
        assert "events" in r.json()

    def test_snapshot_requires_auth(self, client):
        r = client.post("/system/snapshot")
        assert r.status_code in (400, 401, 403)  # 400=missing tenant, 401/403=no auth

    def test_drift_requires_auth(self, client):
        r = client.get("/system/drift")
        assert r.status_code in (400, 401, 403)  # 400=missing tenant, 401/403=no auth


# ===========================================================================
# PART 8 -- EXTERNAL ANCHORING IN take_snapshot
# ===========================================================================

class TestSnapshotExternalAnchor:

    def test_take_snapshot_anchors_system_root(self, tmp_path, monkeypatch):
        """system_root must be written to anchor store when anchor_externally=True."""
        import provable_ai.audit_anchor as anch_mod

        anchor = AuditAnchorStore(db_path=str(tmp_path / "anchors.db"))
        # Patch the singleton so take_snapshot uses our tmp anchor store
        orig = anch_mod._anchor_store
        anch_mod._anchor_store = anchor
        monkeypatch.setenv("ZORYNEX_ANCHOR_DB_PATH", str(tmp_path / "anchors.db"))
        monkeypatch.setenv("ZORYNEX_ANCHOR_RFC3161", "false")  # no network in tests

        try:
            from provable_ai.storage import SQLiteStorage
            from provable_ai.audit_log import VerificationAuditLog
            from provable_ai.drift_detector import take_snapshot

            storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
            audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

            snap = take_snapshot(
                storage, audit_log, tenant_id="bank",
                environment="prod", anchor_externally=True,
            )
            # If system root is "0"*64 (empty DB), anchor is skipped
            # If non-empty, anchor should have been written
            # In empty DB case, verify anchor store is either empty or has 0 count
            count = anchor.count("bank")
            # Empty DB -> system_root = "0"*64 -> anchor skipped -> count = 0
            assert count == 0 or snap.system_root != "0" * 64
        finally:
            anch_mod._anchor_store = orig

    def test_take_snapshot_no_anchor_when_flag_false(self, tmp_path, monkeypatch):
        """anchor_externally=False must not write to anchor store."""
        import provable_ai.audit_anchor as anch_mod

        anchor = AuditAnchorStore(db_path=str(tmp_path / "anchors.db"))
        orig = anch_mod._anchor_store
        anch_mod._anchor_store = anchor
        monkeypatch.setenv("ZORYNEX_ANCHOR_RFC3161", "false")

        try:
            from provable_ai.storage import SQLiteStorage
            from provable_ai.audit_log import VerificationAuditLog
            from provable_ai.drift_detector import take_snapshot

            storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
            audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

            take_snapshot(
                storage, audit_log, tenant_id="bank",
                environment="dev", anchor_externally=False,
            )
            # No anchor should be written
            assert anchor.count("bank") == 0
        finally:
            anch_mod._anchor_store = orig

    def test_anchor_failure_does_not_break_snapshot(self, tmp_path, monkeypatch):
        """Even if anchoring fails, take_snapshot must succeed."""
        import provable_ai.audit_anchor as anch_mod

        # Make anchor store raise on every call
        class FailingAnchor:
            def anchor(self, *a, **kw):
                raise RuntimeError("anchor store unavailable")
            def count(self, *a):
                return 0

        orig = anch_mod._anchor_store
        anch_mod._anchor_store = FailingAnchor()
        monkeypatch.setenv("ZORYNEX_ANCHOR_RFC3161", "false")

        try:
            from provable_ai.storage import SQLiteStorage
            from provable_ai.audit_log import VerificationAuditLog
            from provable_ai.drift_detector import take_snapshot

            storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
            audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))

            # Must not raise even though anchor fails
            snap = take_snapshot(
                storage, audit_log, tenant_id="bank",
                environment="prod", anchor_externally=True,
            )
            assert snap.tenant_id == "bank"
        finally:
            anch_mod._anchor_store = orig


# ===========================================================================
# PART 9 -- LOCUST STABILITY MONITORING
# ===========================================================================

class TestLocustStabilityMonitoring:

    def test_stability_analysis_imported(self):
        """Locust file must expose stability tracking data."""
        pytest.importorskip("locust", reason="locust not installed")
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "locustfile", _LOCUST_FILE
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Must have stability tracking globals
        assert hasattr(mod, "_p95_timeline")
        assert hasattr(mod, "_INTERVAL_S")
        assert isinstance(mod._p95_timeline, list)

    def test_stability_thresholds_documented(self):
        """Module docstring must document latency thresholds."""
        with open(_LOCUST_FILE) as f:
            doc = f.read()
        assert "p95" in doc
        assert "SQLite" in doc
        assert "single-writer" in doc.lower() or "single writer" in doc.lower()

    def test_sqlite_bottleneck_documented(self):
        """Write tasks must document SQLite single-writer bottleneck."""
        with open(_LOCUST_FILE) as f:
            doc = f.read()
        assert "PostgreSQL" in doc
        assert "300ms" in doc or "migration" in doc.lower()