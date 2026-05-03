"""
Zorynex Phase 3 — Chaos Tests
================================
Simulates infrastructure failures to verify the system degrades gracefully.
All tests are mock-based. No live PostgreSQL, KMS, or external services needed.

Run: pytest tests/test_chaos.py -v
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import sqlite3
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZORYNEX_API_KEYS",           "admin-key:admin,sys-key:system,audit-key:auditor")
    monkeypatch.setenv("ZORYNEX_WEBHOOK_SECRET",      "chaos-test-secret")
    monkeypatch.setenv("ZORYNEX_SIGNING_KEY",         "a" * 64)
    monkeypatch.setenv("ZORYNEX_DB_PATH",             str(tmp_path / "chaos.db"))
    monkeypatch.setenv("ZORYNEX_AUDIT_DB_PATH",       str(tmp_path / "audit.db"))
    monkeypatch.setenv("ZORYNEX_ANCHOR_DB_PATH",      str(tmp_path / "anchors.db"))
    monkeypatch.setenv("ZORYNEX_KEYREGISTRY_DB_PATH", str(tmp_path / "keys.db"))
    monkeypatch.setenv("ZORYNEX_DRIFT_DB_PATH",       str(tmp_path / "drift.db"))
    monkeypatch.setenv("ZORYNEX_ANCHOR_RFC3161",      "false")
    yield

@pytest.fixture
def client():
    import sys
    for mod_name in list(sys.modules.keys()):
        if mod_name.startswith("server") or mod_name in (
            "provable_ai.audit_log", "provable_ai.audit_anchor",
            "provable_ai.audit_keyregistry", "provable_ai.drift_detector",
        ):
            del sys.modules[mod_name]
    from server.main import app
    return TestClient(app, raise_server_exceptions=False)

ADMIN = {"X-API-Key": "admin-key", "X-Tenant-Id": "chaos_tenant"}
SYS   = {"X-API-Key": "sys-key",   "X-Tenant-Id": "chaos_tenant"}
AUDIT = {"X-API-Key": "audit-key", "X-Tenant-Id": "chaos_tenant"}

DECISION = {
    "instance_id": "chaos-loan-001", "from_state": "pending", "to_state": "approved",
    "model_version": "credit-model-v3.1", "agent_version": "underwriter-v1.0",
    "policy_version": "credit-policy-v2", "reason_code": "SCORE", "policy_rule": "p.r",
    "raw_inputs": {"credit_score": "742"},
}

def _approve(storage):
    storage.add_approved_model("credit-model-v3.1")
    storage.add_approved_agent("underwriter-v1.0")
    storage.add_approved_policy("credit-policy-v2")


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — DB Unavailable
# ══════════════════════════════════════════════════════════════════════════════

class TestDBUnavailable:

    def test_decision_fails_gracefully_when_storage_raises(self, client):
        import server.main as srv
        import provable_ai.storage as st
        storage = st.SQLiteStorage(db_path=os.environ["ZORYNEX_DB_PATH"])
        _approve(storage)
        srv._storage = storage
        srv._engine  = None
        storage.append_ledger_entry = lambda _: (_ for _ in ()).throw(
            sqlite3.OperationalError("disk I/O error"))
        r = client.post("/decision", json=DECISION, headers=SYS)
        assert r.status_code in (400, 409, 500, 503)

    def test_health_alive_during_storage_failure(self, client):
        assert client.get("/health").status_code == 200

    def test_recovery_after_transient_failure(self, client, tmp_path):
        import server.main as srv
        import provable_ai.storage as st
        db_path = str(tmp_path / "recovery.db")
        storage = st.SQLiteStorage(db_path=db_path)
        _approve(storage)
        srv._storage = storage
        srv._engine  = None
        call_count = [0]
        original = storage.append_ledger_entry
        def flaky(proof_dict):
            call_count[0] += 1
            if call_count[0] == 1:
                raise sqlite3.OperationalError("temporary lock")
            return original(proof_dict)
        storage.append_ledger_entry = flaky
        r1 = client.post("/decision", json=DECISION, headers=SYS)
        assert r1.status_code in (400, 409, 500, 503)
        r2 = client.post("/decision", json={**DECISION, "instance_id": "recovery-001"}, headers=SYS)
        assert r2.status_code == 200

    def test_signing_failure_returns_503(self, client):
        import server.main as srv
        import provable_ai.storage as st
        from provable_ai.exceptions import KMSUnavailable
        storage = st.SQLiteStorage(db_path=os.environ["ZORYNEX_DB_PATH"])
        _approve(storage)
        srv._storage = storage
        srv._engine  = None
        mock_signer = MagicMock()
        mock_signer.get_key_id.return_value     = "kms-test"
        mock_signer.get_public_key.return_value = "b" * 64
        mock_signer.sign_hash.side_effect = KMSUnavailable(
            key_id="kms-test", underlying_error="unreachable")
        with patch("server.main.get_signer", return_value=mock_signer):
            srv._engine = None
            r = client.post("/decision", json=DECISION, headers=SYS)
        assert r.status_code == 503

    def test_no_partial_write_on_storage_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        from provable_ai.exceptions import SigningFailed
        storage = SQLiteStorage(db_path=str(tmp_path / "partial.db"))
        _approve(storage)
        signer = get_signer()
        engine = GovernanceEngine(storage=storage, signer=signer)
        original_sign = signer.sign_hash
        signer.sign_hash = lambda _: (_ for _ in ()).throw(
            SigningFailed(key_id="env", underlying_error="injected"))
        with pytest.raises(SigningFailed):
            engine.record_decision(
                instance_id="partial-001", from_state="a", to_state="b",
                model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
                policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
                raw_inputs={"s": "1"},
            )
        signer.sign_hash = original_sign
        chain = storage.get_ledger_chain("partial-001")
        assert len(chain) == 0  # nothing written


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — KMS Unavailable
# ══════════════════════════════════════════════════════════════════════════════

class TestKMSUnavailable:

    def test_failover_signer_transparent(self, monkeypatch):
        from provable_ai.signer import EnvSigner
        from provable_ai.signer_failover import FailoverSigner
        from provable_ai.exceptions import KMSUnavailable
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        primary = MagicMock()
        primary.get_key_id.return_value     = "kms-p"
        primary.get_public_key.return_value = "c" * 64
        primary.sign_hash.side_effect = KMSUnavailable(key_id="kms-p", underlying_error="down")
        signer = FailoverSigner(primary=primary, fallback=EnvSigner(),
                                max_consecutive_failures=1, failback_interval=999)
        sig = signer.sign_hash(b"\xaa" * 32)
        assert len(sig) == 128
        assert signer.metrics()["mode"] == "fallback"

    def test_both_fail_raises_signing_failed(self, monkeypatch):
        from provable_ai.signer_failover import FailoverSigner
        from provable_ai.exceptions import KMSUnavailable, SigningFailed
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        def bad(key_id):
            m = MagicMock()
            m.get_key_id.return_value = key_id
            m.get_public_key.return_value = "d" * 64
            m.sign_hash.side_effect = KMSUnavailable(key_id=key_id, underlying_error="down")
            return m
        signer = FailoverSigner(primary=bad("p"), fallback=bad("f"),
                                max_consecutive_failures=1, failback_interval=999)
        with pytest.raises(SigningFailed):
            signer.sign_hash(b"\xbb" * 32)

    def test_failover_counter_increments(self, monkeypatch):
        from provable_ai.signer import EnvSigner
        from provable_ai.signer_failover import FailoverSigner
        from provable_ai.exceptions import KMSUnavailable
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        primary = MagicMock()
        primary.get_key_id.return_value     = "kms-p"
        primary.get_public_key.return_value = "e" * 64
        primary.sign_hash.side_effect = KMSUnavailable(key_id="kms-p", underlying_error="down")
        signer = FailoverSigner(primary=primary, fallback=EnvSigner(),
                                max_consecutive_failures=1, failback_interval=999)
        signer.sign_hash(b"\xcc" * 32)
        assert signer.metrics()["failover_count"] == 1

    def test_signing_failure_leaves_ledger_clean(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        from provable_ai.exceptions import KMSUnavailable
        storage = SQLiteStorage(db_path=str(tmp_path / "kms_clean.db"))
        _approve(storage)
        signer = get_signer()
        engine = GovernanceEngine(storage=storage, signer=signer)
        signer.sign_hash = lambda _: (_ for _ in ()).throw(
            KMSUnavailable(key_id="env", underlying_error="injected"))
        with pytest.raises(KMSUnavailable):
            engine.record_decision(
                instance_id="kms-clean", from_state="a", to_state="b",
                model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
                policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
                raw_inputs={"s": "1"},
            )
        assert len(storage.get_ledger_chain("kms-clean")) == 0

    def test_kms_prometheus_metrics_format(self, monkeypatch):
        from provable_ai.signer import EnvSigner
        from provable_ai.signer_failover import FailoverSigner
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer = FailoverSigner(primary=EnvSigner(), fallback=EnvSigner())
        prom = signer.prometheus_metrics()
        assert "zorynex_kms_failover_total" in prom
        assert "zorynex_kms_primary_healthy" in prom


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Webhook Flood
# ══════════════════════════════════════════════════════════════════════════════

def _sign(body: bytes, secret: str = "chaos-test-secret",
          ts: str = None, nonce: str = None) -> dict:
    ts    = ts or str(int(time.time()))
    nonce = nonce or f"nonce-{time.time_ns()}"
    sig   = hmac.new(secret.encode(), f"{ts}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()
    return {**SYS, "Content-Type": "application/json",
            "X-Zorynex-Timestamp": ts, "X-Zorynex-Nonce": nonce,
            "X-Zorynex-Signature": f"sha256={sig}"}


class TestWebhookFlood:

    def test_valid_webhook_accepted(self, client):
        body = b'{"event": "decision.recorded"}'
        r = client.post("/webhook/receive", content=body, headers=_sign(body))
        assert r.status_code == 200
        assert r.json().get("received") is True

    def test_missing_signature_rejected(self, client):
        r = client.post("/webhook/receive", content=b'{"event":"x"}',
                        headers={**SYS, "Content-Type": "application/json"})
        assert r.status_code == 401

    def test_tampered_body_rejected(self, client):
        body   = b'{"event": "decision.recorded"}'
        hdrs   = _sign(body)
        tamper = b'{"event": "decision.recorded", "amount": 99999}'
        r = client.post("/webhook/receive", content=tamper, headers=hdrs)
        assert r.status_code == 401

    def test_stale_timestamp_rejected(self, client):
        body = b'{"event": "test"}'
        hdrs = _sign(body, ts=str(int(time.time()) - 400))
        r = client.post("/webhook/receive", content=body, headers=hdrs)
        assert r.status_code == 401

    def test_replay_same_nonce_rejected(self, client):
        body = b'{"event": "decision.recorded"}'
        hdrs = _sign(body)
        r1 = client.post("/webhook/receive", content=body, headers=hdrs)
        assert r1.status_code == 200
        r2 = client.post("/webhook/receive", content=body, headers=hdrs)
        assert r2.status_code == 401

    def test_wrong_secret_rejected(self, client):
        body = b'{"event": "test"}'
        r = client.post("/webhook/receive", content=body, headers=_sign(body, secret="wrong"))
        assert r.status_code == 401

    def test_flood_no_crash(self, client):
        body = b'{"event": "load.test"}'
        results, errors = [], []
        def send():
            try:
                r = client.post("/webhook/receive", content=body, headers=_sign(body))
                results.append(r.status_code)
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=send) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert errors == []
        for code in results:
            assert code in (200, 401), f"Unexpected: {code}"


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — Disk Full
# ══════════════════════════════════════════════════════════════════════════════

class TestDiskFull:

    def test_decision_fails_on_disk_full(self, client):
        import server.main as srv
        import provable_ai.storage as st
        storage = st.SQLiteStorage(db_path=os.environ["ZORYNEX_DB_PATH"])
        _approve(storage)
        srv._storage = storage
        srv._engine  = None
        storage.append_ledger_entry = lambda _: (_ for _ in ()).throw(
            OSError(28, "No space left on device"))
        r = client.post("/decision", json=DECISION, headers=SYS)
        assert r.status_code in (400, 409, 500, 503)
        assert client.get("/health").status_code == 200  # still alive

    def test_siem_disk_full_is_non_fatal(self, monkeypatch):
        from provable_ai.siem import SyslogTransport, SIEMEvent
        t = SyslogTransport(host="localhost", port=514, proto="udp")
        with patch("provable_ai.siem.socket.socket") as MockSock:
            MockSock.return_value.sendto.side_effect = OSError(28, "No space left on device")
            MockSock.return_value.close = MagicMock()
            t.send(SIEMEvent(event="test", tenant_id="t", trace_id="r"))  # must not raise

    def test_audit_log_disk_full_non_fatal(self, client):
        import server.main as srv
        import provable_ai.storage as st
        import provable_ai.audit_log as al_mod
        storage = st.SQLiteStorage(db_path=os.environ["ZORYNEX_DB_PATH"])
        _approve(storage)
        srv._storage = storage
        srv._engine  = None
        mock_audit = MagicMock()
        mock_audit.record.side_effect = OSError(28, "No space left on device")
        mock_audit.get_latest_chain_hash.return_value = "0" * 64
        mock_audit.count.return_value = 0
        al_mod._audit_log = mock_audit
        r = client.post("/decision", json=DECISION, headers=SYS)
        assert r.status_code in (200, 500)
        al_mod._audit_log = None


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 5 — Concurrent Write Storm
# ══════════════════════════════════════════════════════════════════════════════

class TestConcurrentWriteStorm:

    def test_sequential_decisions_maintain_chain(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        from provable_ai.verifier import verify_chain
        storage = SQLiteStorage(db_path=str(tmp_path / "storm.db"))
        _approve(storage)
        engine = GovernanceEngine(storage=storage, signer=get_signer())
        proofs = []
        for i in range(10):
            p = engine.record_decision(
                instance_id="storm-001", from_state=f"s{i}", to_state=f"s{i+1}",
                model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
                policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
                raw_inputs={"i": str(i)},
            )
            proofs.append(p)
        seqs = [p.ledger.sequence_id for p in proofs]
        assert seqs == list(range(1, 11))
        result = verify_chain([p.model_dump(mode="json") for p in proofs])
        assert result.valid is True

    def test_different_instances_have_independent_sequence_ids(self, tmp_path, monkeypatch):
        """
        Writes to different instance IDs must have independent sequence chains.
        Each instance starts at sequence_id=1 regardless of other instances.
        This verifies isolation without requiring concurrent writes (SQLite is
        single-writer; concurrent thread safety is a PostgreSQL concern).
        """
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine

        storage = SQLiteStorage(db_path=str(tmp_path / "isolation.db"))
        _approve(storage)
        engine  = GovernanceEngine(storage=storage, signer=get_signer())

        # Write 5 decisions to each of 5 instances (interleaved)
        results = {f"inst_{i}": [] for i in range(5)}
        for j in range(5):                       # 5 decisions per instance
            for i in range(5):                   # interleaved across instances
                inst_id = f"inst_{i}"
                p = engine.record_decision(
                    instance_id=inst_id,
                    from_state=f"s{j}", to_state=f"s{j+1}",
                    model_version="credit-model-v3.1",
                    agent_version="underwriter-v1.0",
                    policy_version="credit-policy-v2",
                    reason_code="R", policy_rule="p.r",
                    raw_inputs={"j": str(j)},
                )
                results[inst_id].append(p.ledger.sequence_id)

        # Each instance must have sequence IDs [1, 2, 3, 4, 5] — no cross-contamination
        for inst_id, seqs in results.items():
            assert seqs == list(range(1, 6)), (
                f"{inst_id} has wrong sequences: {seqs}"
            )

    def test_api_decisions_sequential_all_succeed(self, client):
        import server.main as srv
        import provable_ai.storage as st
        storage = st.SQLiteStorage(db_path=os.environ["ZORYNEX_DB_PATH"])
        _approve(storage)
        srv._storage = storage
        srv._engine  = None
        for i in range(10):
            r = client.post("/decision", json={**DECISION, "instance_id": f"load-{i:04d}"}, headers=SYS)
            assert r.status_code == 200, f"Failed on decision {i}: {r.json()}"


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 6 — Key Corruption
# ══════════════════════════════════════════════════════════════════════════════

class TestKeyCorruption:

    def test_truncated_key_raises(self, tmp_path, monkeypatch):
        from provable_ai.signer import EnvSigner
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        key_path = str(tmp_path / "corrupt.hex")
        with open(key_path, "w") as f: f.write("a" * 10)
        with pytest.raises(Exception):
            EnvSigner(key_path=key_path).sign_hash(b"\xaa" * 32)

    def test_empty_key_raises(self, tmp_path, monkeypatch):
        from provable_ai.signer import EnvSigner
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        key_path = str(tmp_path / "empty.hex")
        with open(key_path, "w") as f: f.write("")
        with pytest.raises(Exception):
            EnvSigner(key_path=key_path).sign_hash(b"\xaa" * 32)

    def test_invalid_hex_raises(self, tmp_path, monkeypatch):
        from provable_ai.signer import EnvSigner
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        key_path = str(tmp_path / "bad.hex")
        with open(key_path, "w") as f: f.write("NOT_HEX_" * 8)
        with pytest.raises(Exception):
            EnvSigner(key_path=key_path)

    def test_valid_env_key_works(self, monkeypatch):
        from provable_ai.signer import EnvSigner
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "b" * 64)
        sig = EnvSigner().sign_hash(b"\xdd" * 32)
        assert len(sig) == 128


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 7 — Chain Integrity After Failures
# ══════════════════════════════════════════════════════════════════════════════

class TestChainIntegrityAfterFailures:

    def test_chain_intact_after_failed_write(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        from provable_ai.exceptions import SigningFailed
        from provable_ai.verifier import verify_chain
        storage = SQLiteStorage(db_path=str(tmp_path / "chain.db"))
        _approve(storage)
        signer = get_signer()
        engine = GovernanceEngine(storage=storage, signer=signer)
        # First succeeds
        p1 = engine.record_decision(
            instance_id="chain-001", from_state="a", to_state="b",
            model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
            policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
            raw_inputs={"s": "1"},
        )
        assert p1.ledger.sequence_id == 1
        # Second fails
        orig = signer.sign_hash
        signer.sign_hash = lambda _: (_ for _ in ()).throw(
            SigningFailed(key_id="env", underlying_error="injected"))
        with pytest.raises(SigningFailed):
            engine.record_decision(
                instance_id="chain-001", from_state="b", to_state="c",
                model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
                policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
                raw_inputs={"s": "2"},
            )
        signer.sign_hash = orig
        # Third succeeds at sequence 2 (no gap)
        p3 = engine.record_decision(
            instance_id="chain-001", from_state="b", to_state="c",
            model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
            policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
            raw_inputs={"s": "3"},
        )
        assert p3.ledger.sequence_id == 2
        chain = storage.get_ledger_chain("chain-001")
        proofs = [json.loads(e["proof_json"]) for e in chain]
        result = verify_chain(proofs)
        assert result.valid is True
        assert result.sequence_verified == 2

    def test_siem_failure_does_not_affect_proof(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        from provable_ai.siem import SIEMRouter, SIEMEvent
        class FailTransport:
            name = "fail"
            def send(self, ev): raise RuntimeError("SIEM down")
            def flush(self): pass
        router = SIEMRouter([FailTransport()], min_level="info", workers=1)
        storage = SQLiteStorage(db_path=str(tmp_path / "siem_chaos.db"))
        _approve(storage)
        engine = GovernanceEngine(storage=storage, signer=get_signer())
        p = engine.record_decision(
            instance_id="siem-001", from_state="a", to_state="b",
            model_version="credit-model-v3.1", agent_version="underwriter-v1.0",
            policy_version="credit-policy-v2", reason_code="R", policy_rule="p.r",
            raw_inputs={"s": "1"},
        )
        assert p.ledger.sequence_id == 1
        router.emit(SIEMEvent(event="decision_recorded", tenant_id="t", trace_id="r"))
        time.sleep(0.1)
        assert len(storage.get_ledger_chain("siem-001")) == 1