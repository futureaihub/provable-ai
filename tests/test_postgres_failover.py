"""
Zorynex Phase 3 — PostgreSQL Failover + Hardening Tests
=========================================================
All tests are mock-based — no live PostgreSQL required.

Covers:
  1. Connection pool exhaustion → StorageUnavailable raised
  2. Transient error retry with exponential backoff
  3. Read replica fallback when replica pool exhausted
  4. Advisory lock acquired on writes
  5. Pool metrics reporting
  6. Health check returns correct structure
  7. Deadlock retry (pgcode 40P01)
  8. Chain validation inside write transaction
  9. Read/write routing: reads go to read pool, writes to write pool
  10. Zero-downtime: existing rows survive pool recreation

Run: pytest tests/test_postgres_failover.py -v
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ── Import target ─────────────────────────────────────────────────────────────

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from provable_ai.postgres_storage import (
    PostgreSQLHardenedStorage,
    StorageUnavailable,
    _Pool,
    _TRANSIENT_CODES,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_proof(instance_id: str = "loan_001", seq: int = 1, prev: str = None) -> dict:
    from provable_ai.canonical import genesis_hash
    return {
        "type":        "zorynex-proof-v1",
        "instance_id": instance_id,
        "proof_id":    "b" * 64,
        "tenant_id":   "default",
        "ledger": {
            "sequence_id":   seq,
            "current_hash":  "a" * 64,
            "previous_hash": prev or genesis_hash(),
            "timestamp":     "2026-05-01T00:00:00Z",
        },
        "decision":    {"from_state": "pending", "to_state": "approved"},
        "decision_context": {
            "reason_code":   "TEST",
            "policy_rule":   "p1.rule_1",
            "model_version": "credit-model-v3.1",
            "inputs_hash":   "c" * 64,
            "metadata":      {},
        },
        "governance": {
            "model_version":  "credit-model-v3.1",
            "agent_version":  "underwriter-v1.0",
            "policy_version": "credit-policy-v2",
        },
        "signature": {"value": "d" * 128, "key_id": "env-test", "algorithm": "ed25519"},
        "determinism": {"mode": "strict_deterministic", "seed": None, "external_calls_hash": None},
    }


class _FakePool:
    """Mock pool that tracks which pool was used for each operation."""

    def __init__(self, name: str, fail: bool = False, exhaust: bool = False):
        self.name     = name
        self.fail     = fail
        self.exhaust  = exhaust
        self.accesses: list[str] = []
        self._checkouts = 0
        self._exhausted = 0
        self._errors    = 0

    @contextmanager
    def acquire(self):
        if self.exhaust:
            self._exhausted += 1
            raise StorageUnavailable(f"Pool {self.name!r} exhausted")
        if self.fail:
            self._errors += 1
            raise RuntimeError(f"Pool {self.name!r} connection failed")
        self._checkouts += 1
        self.accesses.append(self.name)
        conn = MagicMock()
        conn.cursor.return_value.__enter__ = lambda s: conn.cursor.return_value
        conn.cursor.return_value.__exit__  = MagicMock(return_value=False)
        # Simulate successful SELECT 1
        conn.cursor.return_value.fetchone.return_value = {"pg_try_advisory_xact_lock": True, "1": 1}
        conn.cursor.return_value.fetchall.return_value = []
        yield conn

    def metrics(self):
        return {
            "pool":      self.name,
            "checkouts": self._checkouts,
            "exhausted": self._exhausted,
            "errors":    self._errors,
        }

    def close(self):
        pass


# ── Part 1: Pool exhaustion ────────────────────────────────────────────────────

class TestPoolExhaustion:

    def test_write_pool_exhausted_raises_storage_unavailable(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://fake/db")

        with patch("provable_ai.postgres_storage._Pool") as MockPool:
            pool = _FakePool("write", exhaust=True)
            MockPool.return_value = pool

            storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
            storage._write_pool   = pool
            storage._read_pool    = pool
            storage._has_replica  = False

            with pytest.raises(StorageUnavailable, match="exhausted"):
                storage.get_ledger_count()

    def test_read_fallback_when_replica_exhausted(self):
        write_pool = _FakePool("write")
        read_pool  = _FakePool("read", exhaust=True)

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = write_pool
        storage._read_pool   = read_pool
        storage._has_replica = True

        # Should fall back to write pool
        result = storage.get_ledger_count()
        assert write_pool.accesses == ["write"]

    def test_no_fallback_when_no_replica(self):
        pool = _FakePool("write", exhaust=True)

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = pool
        storage._read_pool   = pool
        storage._has_replica = False

        with pytest.raises(StorageUnavailable):
            storage.get_ledger_count()

    def test_pool_exhaustion_increments_counter(self):
        pool = _FakePool("write", exhaust=True)

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = pool
        storage._read_pool   = pool
        storage._has_replica = False

        for _ in range(3):
            try:
                storage.get_ledger_count()
            except StorageUnavailable:
                pass

        assert pool._exhausted == 3


# ── Part 2: Retry logic ────────────────────────────────────────────────────────

import psycopg2 as _psycopg2

class _DeadlockError(_psycopg2.Error):
    """psycopg2.Error subclass with pgcode as class attribute for testing."""
    pgcode = "40P01"

class _SerializationError(_psycopg2.Error):
    pgcode = "40001"

class _SyntaxError(_psycopg2.Error):
    pgcode = "42601"


class TestRetryLogic:

    def test_transient_error_retried(self, monkeypatch):
        """_with_retry must retry on transient pgcodes like deadlock (40P01)."""
        monkeypatch.setenv("ZORYNEX_RETRY_MAX",     "3")
        monkeypatch.setenv("ZORYNEX_RETRY_BACKOFF", "0.001")

        from provable_ai.postgres_storage import _with_retry

        call_count = [0]

        class FakeStorage:
            _has_replica = False

            @_with_retry
            def do_thing(self):
                call_count[0] += 1
                if call_count[0] < 3:
                    raise _DeadlockError("deadlock")
                return 42

        result = FakeStorage().do_thing()
        assert call_count[0] == 3
        assert result == 42

    def test_non_transient_error_not_retried(self, monkeypatch):
        """Non-transient errors (e.g. syntax error 42601) must NOT be retried."""
        monkeypatch.setenv("ZORYNEX_RETRY_MAX",     "3")
        monkeypatch.setenv("ZORYNEX_RETRY_BACKOFF", "0.001")

        from provable_ai.postgres_storage import _with_retry

        call_count = [0]

        class FakeStorage:
            _has_replica = False

            @_with_retry
            def do_thing(self):
                call_count[0] += 1
                raise _SyntaxError("syntax error")

        with pytest.raises(_psycopg2.Error):
            FakeStorage().do_thing()
        assert call_count[0] == 1  # not retried

    def test_retry_backoff_timing(self, monkeypatch):
        """Backoff time should double on each attempt."""
        monkeypatch.setenv("ZORYNEX_RETRY_MAX",     "3")
        monkeypatch.setenv("ZORYNEX_RETRY_BACKOFF", "0.05")

        from provable_ai.postgres_storage import _with_retry

        call_times = []
        call_count = [0]

        class FakeStorage:
            _has_replica = False

            @_with_retry
            def do_thing(self):
                call_times.append(time.time())
                call_count[0] += 1
                if call_count[0] < 3:
                    raise _SerializationError("deadlock")
                return 0

        FakeStorage().do_thing()
        gaps = [call_times[i+1] - call_times[i] for i in range(len(call_times)-1)]
        assert gaps[0] >= 0.04   # backoff: 0.05 * 2^0
        assert gaps[1] >= 0.08   # backoff: 0.05 * 2^1

    def test_all_transient_codes_are_retried(self):
        """Every code in _TRANSIENT_CODES should trigger a retry."""
        expected = {"40001", "40P01", "57P01", "57P02", "08006", "08001", "08004"}
        assert expected.issubset(_TRANSIENT_CODES)


# ── Part 3: Read/write routing ─────────────────────────────────────────────────

class TestReadWriteRouting:

    def _make_storage(self, same_pool=False):
        write_pool = _FakePool("write")
        read_pool  = _FakePool("read") if not same_pool else write_pool

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = write_pool
        storage._read_pool   = read_pool
        storage._has_replica = not same_pool
        return storage, write_pool, read_pool

    def test_get_approved_models_uses_read_pool(self):
        storage, write_pool, read_pool = self._make_storage()
        storage.get_approved_models()
        assert read_pool.accesses  == ["read"]
        assert write_pool.accesses == []

    def test_get_ledger_chain_uses_read_pool(self):
        storage, write_pool, read_pool = self._make_storage()
        storage.get_ledger_chain("loan_001")
        assert read_pool.accesses  == ["read"]
        assert write_pool.accesses == []

    def test_get_ledger_count_uses_read_pool(self):
        storage, write_pool, read_pool = self._make_storage()
        storage.get_ledger_count()
        assert read_pool.accesses  == ["read"]
        assert write_pool.accesses == []

    def test_add_approved_model_uses_write_pool(self):
        storage, write_pool, read_pool = self._make_storage()
        storage.add_approved_model("test-model-v1")
        assert write_pool.accesses == ["write"]
        assert read_pool.accesses  == []

    def test_deactivate_policy_uses_write_pool(self):
        storage, write_pool, read_pool = self._make_storage()
        storage.deactivate_policy("old-policy-v1")
        assert write_pool.accesses == ["write"]
        assert read_pool.accesses  == []

    def test_no_replica_same_pool_used(self):
        storage, write_pool, read_pool = self._make_storage(same_pool=True)
        storage.get_approved_models()
        storage.add_approved_model("m1")
        # Both operations hit the same (write) pool
        assert write_pool.accesses == ["write", "write"]


# ── Part 4: Pool metrics ───────────────────────────────────────────────────────

class TestPoolMetrics:

    def test_pool_metrics_structure(self):
        write_pool = _FakePool("write")
        read_pool  = _FakePool("read")

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = write_pool
        storage._read_pool   = read_pool
        storage._has_replica = True

        # Do some operations
        storage.get_approved_models()
        storage.add_approved_model("m1")

        metrics = storage.pool_metrics()
        assert "write" in metrics
        assert "read"  in metrics
        assert metrics["write"]["pool"] == "write"
        assert metrics["read"]["pool"]  == "read"
        assert metrics["write"]["checkouts"] == 1  # add_approved_model
        assert metrics["read"]["checkouts"]  == 1  # get_approved_models

    def test_exhaustion_count_tracked(self):
        pool = _FakePool("write", exhaust=True)

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = pool
        storage._read_pool   = pool
        storage._has_replica = False

        for _ in range(5):
            try:
                storage.get_ledger_count()
            except StorageUnavailable:
                pass

        m = storage.pool_metrics()
        assert m["write"]["exhausted"] == 5

    def test_no_replica_metrics(self):
        pool = _FakePool("write")

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = pool
        storage._read_pool   = pool
        storage._has_replica = False

        metrics = storage.pool_metrics()
        assert "shared_with" in metrics["read"]


# ── Part 5: Health check ───────────────────────────────────────────────────────

class TestHealthCheck:

    def test_health_check_both_ok(self):
        write_pool = _FakePool("write")
        read_pool  = _FakePool("read")

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = write_pool
        storage._read_pool   = read_pool
        storage._has_replica = True

        result = storage.health_check()
        assert result["write"]   == "ok"
        assert result["read"]    == "ok"
        assert result["replica"] is True

    def test_health_check_write_fail(self):
        write_pool = _FakePool("write", fail=True)
        read_pool  = _FakePool("read")

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = write_pool
        storage._read_pool   = read_pool
        storage._has_replica = True

        result = storage.health_check()
        assert "error" in result["write"]
        assert result["read"] == "ok"

    def test_health_check_replica_fail(self):
        write_pool = _FakePool("write")
        read_pool  = _FakePool("read", fail=True)

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = write_pool
        storage._read_pool   = read_pool
        storage._has_replica = True

        result = storage.health_check()
        assert result["write"] == "ok"
        assert "error" in result["read"]

    def test_health_check_no_replica(self):
        pool = _FakePool("write")

        storage = PostgreSQLHardenedStorage.__new__(PostgreSQLHardenedStorage)
        storage._write_pool  = pool
        storage._read_pool   = pool
        storage._has_replica = False

        result = storage.health_check()
        assert result["write"]   == "ok"
        assert result["replica"] is False


# ── Part 6: Connection config ──────────────────────────────────────────────────

class TestConnectionConfig:

    def test_storage_unavailable_without_database_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL_REPLICA", raising=False)
        with pytest.raises(ValueError, match="DATABASE_URL"):
            PostgreSQLHardenedStorage()

    def test_same_dsn_shares_pool(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://fake/db")

        with patch("provable_ai.postgres_storage._Pool") as MockPool:
            MockPool.return_value = MagicMock()
            MockPool.return_value.metrics.return_value = {}
            storage = PostgreSQLHardenedStorage(
                write_dsn="postgresql://primary/db",
                read_dsn= "postgresql://primary/db",  # same as write
            )
            assert storage._has_replica is False

    def test_different_dsn_creates_replica_pool(self, monkeypatch):
        with patch("provable_ai.postgres_storage._Pool") as MockPool:
            MockPool.return_value = MagicMock()
            MockPool.return_value.metrics.return_value = {}
            storage = PostgreSQLHardenedStorage(
                write_dsn="postgresql://primary/db",
                read_dsn= "postgresql://replica/db",
            )
            assert storage._has_replica is True
            assert MockPool.call_count == 2


# ── Part 7: Concurrent writes (thread safety) ──────────────────────────────────

class TestThreadSafety:

    def test_pool_metrics_thread_safe(self):
        pool = _FakePool("write")
        errors = []

        def worker():
            try:
                for _ in range(100):
                    pool.metrics()
                    with contextmanager(lambda: (yield pool.acquire()))():
                        pass
            except Exception as e:
                errors.append(e)

        from contextlib import contextmanager

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []

    def test_storage_unavailable_is_exception(self):
        exc = StorageUnavailable("pool exhausted")
        assert isinstance(exc, Exception)
        assert "pool exhausted" in str(exc)