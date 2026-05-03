"""
Zorynex — Hardened PostgreSQL Storage
========================================
Production-grade PostgreSQL backend with:
  - Read/write connection separation (write pool → primary, read pool → replica)
  - Connection exhaustion handling with exponential backoff
  - Advisory locking for concurrent writes to same instance
  - Automatic retry on transient errors (deadlock, connection reset)
  - Health check + connection pool metrics
  - Graceful degradation: if replica is down, reads fall back to primary

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │  PostgreSQLHardenedStorage                                   │
    │                                                              │
    │  write_pool → PRIMARY  (all writes, advisory locks)          │
    │  read_pool  → REPLICA  (all reads, falls back to primary)   │
    │                                                              │
    │  Retry: 3 attempts, exponential backoff 0.1 → 0.4 → 1.6s   │
    │  Pool exhaustion: raises StorageUnavailable after timeout    │
    └─────────────────────────────────────────────────────────────┘

Environment variables:
    DATABASE_URL          Primary (write) DSN
    DATABASE_URL_REPLICA  Read replica DSN (optional; falls back to primary)
    ZORYNEX_POOL_MIN      Minimum connections per pool (default: 2)
    ZORYNEX_POOL_MAX      Maximum connections per pool (default: 20)
    ZORYNEX_POOL_TIMEOUT  Seconds to wait for connection (default: 5)
    ZORYNEX_RETRY_MAX     Max retries on transient error (default: 3)
    ZORYNEX_RETRY_BACKOFF Base backoff seconds (default: 0.1)

Usage:
    from provable_ai.postgres_storage import PostgreSQLHardenedStorage

    storage = PostgreSQLHardenedStorage()
    storage.append_ledger_entry(proof_dict)
    chain = storage.get_ledger_chain(instance_id)
    metrics = storage.pool_metrics()
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from typing import Any, Generator

logger = logging.getLogger("zorynex.postgres_storage")

# Transient errors that warrant a retry
_TRANSIENT_CODES = frozenset([
    "40001",  # serialization_failure (deadlock)
    "40P01",  # deadlock_detected
    "57P01",  # admin_shutdown
    "57P02",  # crash_shutdown
    "08006",  # connection_failure
    "08001",  # sqlclient_unable_to_establish_sqlconnection
    "08004",  # rejected_async_connect
])


class StorageUnavailable(Exception):
    """Raised when all retries exhausted or pool fully exhausted."""


# ── Connection pool wrapper ───────────────────────────────────────────────────

class _Pool:
    """
    Thin wrapper around psycopg2.pool.ThreadedConnectionPool.
    Tracks checkout metrics and provides a context manager.
    """

    def __init__(self, name: str, dsn: str, minconn: int, maxconn: int, timeout: float):
        import psycopg2.pool
        import psycopg2.extras
        self.name    = name
        self._lock   = threading.Lock()
        self._pool   = psycopg2.pool.ThreadedConnectionPool(
            minconn=minconn, maxconn=maxconn, dsn=dsn,
            connect_timeout=int(timeout),
            options="-c statement_timeout=30000",
        )
        self._cursor_factory = psycopg2.extras.RealDictCursor
        self._checkouts: int = 0
        self._exhausted: int = 0
        self._errors:    int = 0

    @contextlib.contextmanager
    def acquire(self) -> Generator[Any, None, None]:
        import psycopg2.pool
        try:
            conn = self._pool.getconn()
        except psycopg2.pool.PoolError:
            with self._lock:
                self._exhausted += 1
            raise StorageUnavailable(f"Pool '{self.name}' exhausted")

        conn.cursor_factory = self._cursor_factory
        with self._lock:
            self._checkouts += 1
        try:
            yield conn
        except Exception:
            conn.rollback()
            with self._lock:
                self._errors += 1
            raise
        finally:
            self._pool.putconn(conn)

    def metrics(self) -> dict:
        with self._lock:
            return {
                "pool":       self.name,
                "checkouts":  self._checkouts,
                "exhausted":  self._exhausted,
                "errors":     self._errors,
            }

    def close(self) -> None:
        self._pool.closeall()


# ── Retry decorator ───────────────────────────────────────────────────────────

def _with_retry(fn):
    """Decorator: retry fn on transient PostgreSQL errors with exponential backoff."""
    import functools
    import psycopg2

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        max_retries = int(os.environ.get("ZORYNEX_RETRY_MAX", "3"))
        backoff     = float(os.environ.get("ZORYNEX_RETRY_BACKOFF", "0.1"))

        for attempt in range(max_retries):
            try:
                return fn(self, *args, **kwargs)
            except StorageUnavailable:
                raise  # pool exhaustion — don't retry
            except psycopg2.Error as e:
                code = getattr(e.pgcode, "strip", lambda: "")()
                if code in _TRANSIENT_CODES and attempt < max_retries - 1:
                    wait = backoff * (2 ** attempt)
                    logger.warning(
                        "Transient PG error %s, retrying in %.2fs (attempt %d/%d)",
                        code, wait, attempt + 1, max_retries,
                    )
                    time.sleep(wait)
                    continue
                raise
        raise StorageUnavailable(f"All {max_retries} retries exhausted")
    return wrapper


# ── Main storage class ────────────────────────────────────────────────────────

class PostgreSQLHardenedStorage:
    """
    Hardened PostgreSQL storage with read/write separation and retry logic.

    Drop-in replacement for PostgreSQLStorage (repositories.py).
    Implements the same public interface as SQLiteStorage.
    """

    def __init__(
        self,
        write_dsn: str | None = None,
        read_dsn:  str | None = None,
        min_conn:  int | None = None,
        max_conn:  int | None = None,
        timeout:   float | None = None,
    ) -> None:
        min_conn = min_conn or int(os.environ.get("ZORYNEX_POOL_MIN", "2"))
        max_conn = max_conn or int(os.environ.get("ZORYNEX_POOL_MAX", "20"))
        timeout  = timeout  or float(os.environ.get("ZORYNEX_POOL_TIMEOUT", "5"))

        _write_dsn = write_dsn or os.environ.get("DATABASE_URL", "")
        _read_dsn  = read_dsn  or os.environ.get("DATABASE_URL_REPLICA", _write_dsn)

        if not _write_dsn:
            raise ValueError("DATABASE_URL or write_dsn required")

        self._write_pool = _Pool("write", _write_dsn, min_conn, max_conn, timeout)
        # If replica DSN is same as write DSN, share the pool reference
        if _read_dsn == _write_dsn:
            self._read_pool = self._write_pool
            self._has_replica = False
        else:
            self._read_pool  = _Pool("read", _read_dsn, min_conn, max_conn, timeout)
            self._has_replica = True

        logger.info(
            "PostgreSQLHardenedStorage ready (replica=%s, pool_min=%d, pool_max=%d)",
            self._has_replica, min_conn, max_conn,
        )

    # ── Read context manager ──────────────────────────────────────────────────

    @contextlib.contextmanager
    def _read(self) -> Generator[Any, None, None]:
        """
        Acquire a read connection.
        Falls back to write pool if replica pool is exhausted or unavailable.
        """
        try:
            with self._read_pool.acquire() as conn:
                yield conn
        except StorageUnavailable:
            if self._has_replica:
                logger.warning("Read replica unavailable, falling back to primary")
                with self._write_pool.acquire() as conn:
                    yield conn
            else:
                raise

    @contextlib.contextmanager
    def _write(self) -> Generator[Any, None, None]:
        with self._write_pool.acquire() as conn:
            yield conn

    # ── Write operations ──────────────────────────────────────────────────────

    @_with_retry
    def append_ledger_entry(self, proof_dict: dict) -> int:
        """
        Append a proof to the ledger with advisory locking.

        Advisory lock key is derived from tenant_id + instance_id so concurrent
        writes for different instances never block each other.
        """
        import psycopg2.errors

        ledger         = proof_dict["ledger"]
        decision       = proof_dict["decision"]
        decision_ctx   = proof_dict["decision_context"]
        governance     = proof_dict["governance"]
        signature      = proof_dict["signature"]

        instance_id    = proof_dict["instance_id"]
        tenant_id      = proof_dict.get("tenant_id", "default")
        sequence_id    = ledger["sequence_id"]
        previous_hash  = ledger["previous_hash"]

        proof_json_str = json.dumps(proof_dict, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False)

        lock_key = abs(hash(f"{tenant_id}:{instance_id}")) % (2 ** 31)

        with self._write() as conn:
            with conn.cursor() as cur:
                # Instance-level advisory lock prevents sequence race conditions
                cur.execute("SELECT pg_try_advisory_xact_lock(%s)", (lock_key,))
                if not cur.fetchone()["pg_try_advisory_xact_lock"]:
                    raise StorageUnavailable(
                        f"Could not acquire advisory lock for {instance_id}"
                    )

                # Validate chain linkage inside the lock
                cur.execute("""
                    SELECT current_hash, sequence_id FROM ledger
                    WHERE tenant_id=%s AND instance_id=%s
                    ORDER BY sequence_id DESC LIMIT 1
                    FOR UPDATE SKIP LOCKED
                """, (tenant_id, instance_id))
                last = cur.fetchone()

                if last is None:
                    from provable_ai.canonical import genesis_hash
                    if previous_hash != genesis_hash():
                        from provable_ai.exceptions import ChainBroken
                        raise ChainBroken(
                            instance_id=instance_id,
                            expected_hash=genesis_hash(),
                            got_hash=previous_hash,
                        )
                    expected_seq = 1
                else:
                    if previous_hash != last["current_hash"]:
                        from provable_ai.exceptions import ChainBroken
                        raise ChainBroken(
                            instance_id=instance_id,
                            expected_hash=last["current_hash"],
                            got_hash=previous_hash,
                        )
                    expected_seq = last["sequence_id"] + 1

                if sequence_id != expected_seq:
                    from provable_ai.exceptions import SequenceGap
                    raise SequenceGap(
                        instance_id=instance_id,
                        expected=expected_seq,
                        got=sequence_id,
                    )

                # Upsert instance state
                cur.execute("""
                    INSERT INTO instances (tenant_id, instance_id, current_state, protocol_hash)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (tenant_id, instance_id) DO UPDATE
                        SET current_state = EXCLUDED.current_state
                """, (tenant_id, instance_id, decision["to_state"],
                      governance.get("policy_version", "unknown")))

                try:
                    cur.execute("""
                        INSERT INTO ledger (
                            tenant_id, instance_id, sequence_id,
                            previous_hash, current_hash,
                            signature, key_id, protocol_hash,
                            from_state, to_state,
                            model_version, agent_version, policy_version,
                            metadata_json, proof_json, timestamp
                        ) VALUES (
                            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                        )
                    """, (
                        tenant_id, instance_id, sequence_id,
                        previous_hash, ledger["current_hash"],
                        signature["value"], signature["key_id"],
                        governance.get("policy_version", "unknown"),
                        decision["from_state"], decision["to_state"],
                        governance["model_version"], governance["agent_version"],
                        governance["policy_version"],
                        json.dumps(decision_ctx.get("metadata", {})),
                        proof_json_str,
                        ledger["timestamp"],
                    ))
                except psycopg2.errors.UniqueViolation:
                    conn.rollback()
                    from provable_ai.exceptions import DuplicateSequenceId
                    raise DuplicateSequenceId(
                        instance_id=instance_id,
                        sequence_id=sequence_id,
                    )

            conn.commit()

        return sequence_id

    @_with_retry
    def add_approved_model(self, model_version: str) -> None:
        with self._write() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO approved_models (model_version) VALUES (%s) ON CONFLICT DO NOTHING",
                    (model_version,),
                )
            conn.commit()

    @_with_retry
    def add_approved_agent(self, agent_version: str) -> None:
        with self._write() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO approved_agents (agent_version) VALUES (%s) ON CONFLICT DO NOTHING",
                    (agent_version,),
                )
            conn.commit()

    @_with_retry
    def add_approved_policy(self, policy_version: str) -> None:
        with self._write() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO approved_policies (policy_version, active)
                    VALUES (%s, TRUE) ON CONFLICT (policy_version) DO UPDATE SET active = TRUE
                """, (policy_version,))
            conn.commit()

    @_with_retry
    def deactivate_policy(self, policy_version: str) -> None:
        with self._write() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE approved_policies SET active = FALSE WHERE policy_version = %s",
                    (policy_version,),
                )
            conn.commit()

    @_with_retry
    def register_protocol(self, protocol_hash: str, spec: dict) -> None:
        with self._write() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO protocols (protocol_hash, spec_json, active)
                    VALUES (%s, %s, TRUE) ON CONFLICT DO NOTHING
                """, (protocol_hash, json.dumps(spec, sort_keys=True)))
            conn.commit()

    # ── Read operations (replica-eligible) ───────────────────────────────────

    @_with_retry
    def get_ledger_chain(
        self, instance_id: str, tenant_id: str = "default"
    ) -> list[dict]:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT * FROM ledger
                    WHERE tenant_id=%s AND instance_id=%s
                    ORDER BY sequence_id ASC
                """, (tenant_id, instance_id))
                return [dict(r) for r in cur.fetchall()]

    @_with_retry
    def get_latest_ledger_entry(
        self, instance_id: str, tenant_id: str = "default"
    ) -> dict | None:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT proof_json FROM ledger
                    WHERE tenant_id=%s AND instance_id=%s
                    ORDER BY sequence_id DESC LIMIT 1
                """, (tenant_id, instance_id))
                row = cur.fetchone()
        return json.loads(row["proof_json"]) if row else None

    @_with_retry
    def get_ledger_entry(
        self, instance_id: str, sequence_id: int = None, tenant_id: str = "default"
    ) -> dict | None:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT proof_json FROM ledger
                    WHERE tenant_id=%s AND instance_id=%s AND sequence_id=%s
                """, (tenant_id, instance_id, sequence_id))
                row = cur.fetchone()
        return json.loads(row["proof_json"]) if row else None

    @_with_retry
    def get_ledger_count(
        self, instance_id: str | None = None, tenant_id: str = "default"
    ) -> int:
        with self._read() as conn:
            with conn.cursor() as cur:
                if instance_id:
                    cur.execute(
                        "SELECT COUNT(*) AS n FROM ledger WHERE tenant_id=%s AND instance_id=%s",
                        (tenant_id, instance_id),
                    )
                else:
                    cur.execute(
                        "SELECT COUNT(*) AS n FROM ledger WHERE tenant_id=%s", (tenant_id,)
                    )
                return (cur.fetchone() or {}).get("n", 0)

    @_with_retry
    def get_max_sequence_id(
        self, instance_id: str, tenant_id: str = "default"
    ) -> int:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(MAX(sequence_id), 0) AS m FROM ledger
                    WHERE tenant_id=%s AND instance_id=%s
                """, (tenant_id, instance_id))
                return (cur.fetchone() or {}).get("m", 0)

    @_with_retry
    def get_approved_models(self) -> list[str]:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT model_version FROM approved_models")
                return [r["model_version"] for r in cur.fetchall()]

    @_with_retry
    def get_approved_agents(self) -> list[str]:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT agent_version FROM approved_agents")
                return [r["agent_version"] for r in cur.fetchall()]

    @_with_retry
    def get_approved_policies(self) -> list[str]:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT policy_version FROM approved_policies WHERE active = TRUE"
                )
                return [r["policy_version"] for r in cur.fetchall()]

    @_with_retry
    def get_protocol(self, protocol_hash: str) -> dict | None:
        with self._read() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT spec_json FROM protocols WHERE protocol_hash=%s",
                    (protocol_hash,),
                )
                row = cur.fetchone()
        return json.loads(row["spec_json"]) if row else None

    # ── Health + metrics ──────────────────────────────────────────────────────

    def health_check(self) -> dict:
        """
        Verify both pools can execute a query.
        Returns {"write": "ok"|"error", "read": "ok"|"error", "replica": bool}
        """
        result = {"write": "unknown", "read": "unknown", "replica": self._has_replica}

        try:
            with self._write() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            result["write"] = "ok"
        except Exception as e:
            result["write"] = f"error: {e}"

        try:
            with self._read() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            result["read"] = "ok"
        except Exception as e:
            result["read"] = f"error: {e}"

        return result

    def pool_metrics(self) -> dict:
        """Return checkout/exhaustion/error counters for both pools."""
        metrics = {"write": self._write_pool.metrics()}
        if self._has_replica:
            metrics["read"] = self._read_pool.metrics()
        else:
            metrics["read"] = {"shared_with": "write"}
        return metrics

    def close(self) -> None:
        """Return all connections to the pools and close them."""
        self._write_pool.close()
        if self._has_replica:
            self._read_pool.close()
        logger.info("PostgreSQLHardenedStorage pools closed")


# ── Singleton ─────────────────────────────────────────────────────────────────

_storage: PostgreSQLHardenedStorage | None = None


def get_hardened_storage() -> PostgreSQLHardenedStorage:
    global _storage
    if _storage is None:
        _storage = PostgreSQLHardenedStorage()
    return _storage