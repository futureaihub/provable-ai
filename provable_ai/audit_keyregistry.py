"""
Zorynex — Key Registry (Append-Only, Hash-Chained)
====================================================
Maps key_id → public_key + full lifecycle, with immutability guarantees.

Design principles fixed vs v1:
  - NO UPDATE ever — rotation is a NEW row with status='retired_predecessor'
    and a NEW row with status='active'. The old row is immutable.
  - Hash chain across key_registry rows — any modification detectable
  - tenant_id scoped — a key registered for tenant A cannot be used for tenant B
  - was_active_at() is purely read-based — cannot be manipulated by modifying rows

Key lifecycle (append-only model):
    Row 1: key-001, status=active,   registered_at=T1, superseded_by=NULL
    Row 2: key-001, status=retired,  registered_at=T1, superseded_by=key-002,
           retired_at=T2             ← NEW row, key-001 original row UNTOUCHED
    Row 3: key-002, status=active,   registered_at=T2, superseded_by=NULL

This means:
    - Any historical key state is provable (rows are never modified)
    - Chain hash detects insertion/deletion of key records
    - Auditor can reconstruct exact key state at any point in time

Tenant-key binding:
    Every key is registered with a tenant_id.
    Keys are not shared across tenants.
    was_active_at() always includes tenant_id in the check.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

KEY_REGISTRY_GENESIS = "0" * 64


@dataclass
class KeyRecord:
    key_id:        str
    tenant_id:     str           # which tenant this key is scoped to
    public_key:    str           # 64-char hex (Ed25519)
    algorithm:     str           # "Ed25519"
    source:        str           # "env" | "kms" | "hsm"
    status:        str           # "active" | "retired"
    registered_at: str           # ISO-8601 UTC
    retired_at:    str | None    # ISO-8601 UTC, None if still active
    superseded_by: str | None    # key_id of replacement key
    notes:         str | None
    row_hash:      str = ""
    chain_hash:    str = ""


class KeyRegistry:
    """
    Append-only, hash-chained key registry.

    Immutability guarantee: key records are NEVER modified after insert.
    Rotation writes a RETIREMENT ROW (old key marked retired) and a
    NEW ACTIVE ROW — the original active row is untouched.

    This means any auditor can independently verify the full key history
    by walking the chain from GENESIS.
    """

    def __init__(self, db_path: str = "zorynex_keyregistry.db") -> None:
        self.db_path = db_path
        self._local  = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS key_registry (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id         TEXT NOT NULL,
                tenant_id      TEXT NOT NULL,
                public_key     TEXT NOT NULL,
                algorithm      TEXT NOT NULL DEFAULT 'Ed25519',
                source         TEXT NOT NULL DEFAULT 'env',
                status         TEXT NOT NULL DEFAULT 'active'
                               CHECK(status IN ('active','retired')),
                registered_at  TEXT NOT NULL,
                retired_at     TEXT,
                superseded_by  TEXT,
                notes          TEXT,
                row_hash       TEXT NOT NULL DEFAULT '',
                chain_hash     TEXT NOT NULL DEFAULT ''
            )
        """)
        # NEVER allow modification — rotation is done by inserting new rows
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS no_update_key_registry
            BEFORE UPDATE ON key_registry
            BEGIN
                SELECT RAISE(ABORT, 'key_registry is append-only: use rotate_key() for rotation');
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS no_delete_key_registry
            BEFORE DELETE ON key_registry
            BEGIN
                SELECT RAISE(ABORT, 'key_registry is append-only');
            END
        """)
        # One-active-per-tenant enforced in Python (register_key checks before insert).
        # A partial unique index on (tenant_id, status WHERE status='active') cannot
        # coexist with append-only rotation: old active row stays immutably in the table
        # alongside the new active row insert. Python-level check is the correct approach.
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_kr_tenant_status
            ON key_registry(tenant_id, status)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_kr_key_tenant
            ON key_registry(key_id, tenant_id)
        """)
        conn.commit()

    def _row_hash(
        self, key_id: str, tenant_id: str, public_key: str,
        algorithm: str, source: str, status: str,
        registered_at: str, retired_at: str | None,
        superseded_by: str | None, notes: str | None,
    ) -> str:
        content = json.dumps({
            "key_id": key_id, "tenant_id": tenant_id, "public_key": public_key,
            "algorithm": algorithm, "source": source, "status": status,
            "registered_at": registered_at, "retired_at": retired_at,
            "superseded_by": superseded_by, "notes": notes,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _prev_chain_hash(self, tenant_id: str) -> str:
        """
        Return the chain_hash of the last-inserted row for this tenant.
        Every inserted row (active or retired) participates in the chain —
        the chain is a log of all key events, not just active states.
        """
        row = self._conn().execute(
            "SELECT chain_hash FROM key_registry WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        return row["chain_hash"] if row else KEY_REGISTRY_GENESIS

    def _insert_row(
        self, key_id: str, tenant_id: str, public_key: str,
        algorithm: str, source: str, status: str,
        registered_at: str, retired_at: str | None = None,
        superseded_by: str | None = None, notes: str | None = None,
    ) -> KeyRecord:
        rh  = self._row_hash(
            key_id, tenant_id, public_key, algorithm, source,
            status, registered_at, retired_at, superseded_by, notes,
        )
        prev = self._prev_chain_hash(tenant_id)
        ch   = hashlib.sha256(bytes.fromhex(prev) + bytes.fromhex(rh)).hexdigest()

        self._conn().execute("""
            INSERT INTO key_registry
                (key_id, tenant_id, public_key, algorithm, source, status,
                 registered_at, retired_at, superseded_by, notes, row_hash, chain_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (key_id, tenant_id, public_key, algorithm, source, status,
              registered_at, retired_at, superseded_by, notes, rh, ch))
        self._conn().commit()

        return KeyRecord(
            key_id=key_id, tenant_id=tenant_id, public_key=public_key,
            algorithm=algorithm, source=source, status=status,
            registered_at=registered_at, retired_at=retired_at,
            superseded_by=superseded_by, notes=notes,
            row_hash=rh, chain_hash=ch,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def register_key(
        self,
        key_id:     str,
        public_key: str,
        tenant_id:  str,
        algorithm:  str = "Ed25519",
        source:     str = "env",
        notes:      str | None = None,
    ) -> KeyRecord:
        """
        Register a new key as active for this tenant.
        Raises ValueError if another active key already exists for this tenant.
        Idempotent: if this exact key_id + tenant_id is already active, returns it.
        """
        now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = self._conn()

        # Already registered and active for this tenant?
        existing = conn.execute(
            """SELECT * FROM key_registry WHERE key_id=? AND tenant_id=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (key_id, tenant_id),
        ).fetchone()
        if existing:
            return _row_to_record(existing)

        # Another active key for this tenant? (check most recent active row)
        active = conn.execute(
            """SELECT key_id FROM key_registry WHERE tenant_id=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (tenant_id,),
        ).fetchone()
        if active:
            raise ValueError(
                f"Tenant '{tenant_id}' already has active key '{active['key_id']}'. "
                f"Call rotate_key() to switch to a new key."
            )

        return self._insert_row(key_id, tenant_id, public_key, algorithm, source,
                                "active", now, notes=notes)

    def register_or_update(
        self,
        key_id:     str,
        public_key: str,
        tenant_id:  str,
        algorithm:  str = "Ed25519",
        source:     str = "env",
    ) -> KeyRecord:
        """
        Register if not exists; if another active key for this tenant exists, rotate to this one.
        Used at server startup — idempotent.
        """
        now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = self._conn()

        existing = conn.execute(
            """SELECT * FROM key_registry WHERE key_id=? AND tenant_id=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (key_id, tenant_id),
        ).fetchone()
        if existing:
            return _row_to_record(existing)

        # Another active key? Rotate.
        active = conn.execute(
            """SELECT * FROM key_registry WHERE tenant_id=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (tenant_id,),
        ).fetchone()
        if active and active["key_id"] != key_id:
            # Append a retirement row for the old key
            self._insert_row(
                active["key_id"], tenant_id, active["public_key"],
                active["algorithm"], active["source"],
                "retired", active["registered_at"],
                retired_at=now, superseded_by=key_id,
                notes="Auto-retired during startup key registration",
            )

        return self._insert_row(key_id, tenant_id, public_key, algorithm, source,
                                "active", now)

    def rotate_key(
        self,
        new_key_id:     str,
        new_public_key: str,
        tenant_id:      str,
        algorithm:      str = "Ed25519",
        source:         str = "env",
        notes:          str | None = None,
    ) -> tuple[KeyRecord, KeyRecord | None]:
        """
        Rotate to a new signing key for this tenant.

        Append-only: writes TWO new rows:
            1. Retirement row for the current active key
            2. New active row for the new key

        The original active row is NEVER modified.

        Returns (new_key_record, retired_key_record | None)
        """
        now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = self._conn()

        old_row    = conn.execute(
            """SELECT * FROM key_registry WHERE tenant_id=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (tenant_id,),
        ).fetchone()
        old_record = None

        if old_row:
            # Insert retirement record (old key, status=retired, superseded_by=new)
            old_record = self._insert_row(
                old_row["key_id"], tenant_id, old_row["public_key"],
                old_row["algorithm"], old_row["source"],
                "retired", old_row["registered_at"],
                retired_at=now, superseded_by=new_key_id, notes=notes,
            )

        new_record = self._insert_row(
            new_key_id, tenant_id, new_public_key, algorithm, source,
            "active", now, notes=notes,
        )
        return new_record, old_record

    def get_active(self, tenant_id: str) -> KeyRecord | None:
        """Get current active key for tenant — the most recently inserted active row."""
        row = self._conn().execute(
            """SELECT * FROM key_registry WHERE tenant_id=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (tenant_id,),
        ).fetchone()
        return _row_to_record(row) if row else None

    def get(self, key_id: str, tenant_id: str) -> KeyRecord | None:
        row = self._conn().execute(
            "SELECT * FROM key_registry WHERE key_id=? AND tenant_id=? ORDER BY id DESC LIMIT 1",
            (key_id, tenant_id),
        ).fetchone()
        return _row_to_record(row) if row else None

    def was_active_at(self, key_id: str, tenant_id: str, timestamp: str) -> bool:
        """
        Was key_id active for tenant_id at the given timestamp?

        Append-only model:
          - Original active row: registered_at = when key was first registered
          - Retirement row: retired_at = when key was rotated out
          A key was active at T if registered_at <= T AND
          (no retirement row exists OR retirement row's retired_at > T).
        """
        # Find earliest active registration for this key+tenant
        active_row = self._conn().execute(
            """SELECT * FROM key_registry
               WHERE key_id=? AND tenant_id=? AND status='active'
               ORDER BY id ASC LIMIT 1""",
            (key_id, tenant_id),
        ).fetchone()
        if not active_row:
            return False
        if active_row["registered_at"] > timestamp:
            return False

        # Check if a retirement row exists at or before the timestamp
        retired_row = self._conn().execute(
            """SELECT retired_at FROM key_registry
               WHERE key_id=? AND tenant_id=? AND status='retired'
               ORDER BY id ASC LIMIT 1""",
            (key_id, tenant_id),
        ).fetchone()
        if retired_row and retired_row["retired_at"] and retired_row["retired_at"] <= timestamp:
            return False

        return True

    def verify_chain(self, tenant_id: str) -> dict[str, Any]:
        """
        Walk every key_registry row for this tenant and recompute the hash chain.
        Any modification to any row is detectable.
        """
        rows = self._conn().execute(
            "SELECT * FROM key_registry WHERE tenant_id=? ORDER BY id ASC",
            (tenant_id,),
        ).fetchall()

        if not rows:
            return {"valid": True, "total": 0, "broken_at": None}

        prev = KEY_REGISTRY_GENESIS
        for row in rows:
            expected_rh = self._row_hash(
                row["key_id"], row["tenant_id"], row["public_key"],
                row["algorithm"], row["source"], row["status"],
                row["registered_at"], row["retired_at"],
                row["superseded_by"], row["notes"],
            )
            expected_ch = hashlib.sha256(
                bytes.fromhex(prev) + bytes.fromhex(expected_rh)
            ).hexdigest()
            if row["row_hash"] != expected_rh or row["chain_hash"] != expected_ch:
                return {"valid": False, "total": len(rows),
                        "broken_at": row["id"],
                        "message": f"Key registry chain broken at id={row['id']}"}
            prev = row["chain_hash"]

        return {"valid": True, "total": len(rows), "broken_at": None}

    def list_all(self, tenant_id: str) -> list[KeyRecord]:
        rows = self._conn().execute(
            "SELECT * FROM key_registry WHERE tenant_id=? ORDER BY id ASC",
            (tenant_id,),
        ).fetchall()
        return [_row_to_record(r) for r in rows]

    def rotation_policy(self, tenant_id: str) -> dict[str, Any]:
        active   = self.get_active(tenant_id)
        all_keys = self.list_all(tenant_id)
        return {
            "algorithm":          "Ed25519",
            "immutability":       "Key registry is append-only and hash-chained",
            "rotation_mechanism": "rotate_key() appends retirement + new active rows (no UPDATE ever)",
            "historical_verify":  "was_active_at(key_id, tenant_id, timestamp) reads immutable rows",
            "tenant_scoping":     "Every key is scoped to a tenant_id — no cross-tenant use",
            "current_active_key": active.key_id if active else None,
            "total_rows":         len(all_keys),
            "retired_keys":       sum(1 for k in all_keys if k.status == "retired"),
        }

    def to_dict(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            {
                "key_id": k.key_id, "tenant_id": k.tenant_id,
                "public_key": k.public_key, "algorithm": k.algorithm,
                "source": k.source, "status": k.status,
                "registered_at": k.registered_at, "retired_at": k.retired_at,
                "superseded_by": k.superseded_by, "notes": k.notes,
            }
            for k in self.list_all(tenant_id)
        ]


def _row_to_record(row: sqlite3.Row) -> KeyRecord:
    return KeyRecord(
        key_id=row["key_id"],               tenant_id=row["tenant_id"],
        public_key=row["public_key"],       algorithm=row["algorithm"],
        source=row["source"],               status=row["status"],
        registered_at=row["registered_at"], retired_at=row["retired_at"],
        superseded_by=row["superseded_by"], notes=row["notes"],
        row_hash=row["row_hash"],           chain_hash=row["chain_hash"],
    )


_registry: KeyRegistry | None = None


def get_key_registry() -> KeyRegistry:
    global _registry
    if _registry is None:
        path = os.environ.get("ZORYNEX_KEYREGISTRY_DB_PATH", "zorynex_keyregistry.db")
        _registry = KeyRegistry(db_path=path)
    return _registry


def auto_register_signer(signer: Any, tenant_id: str = "system") -> KeyRecord:
    """Register the active signer key in the registry. Idempotent."""
    return get_key_registry().register_or_update(
        key_id=signer.get_key_id(), public_key=signer.get_public_key(),
        tenant_id=tenant_id, algorithm="Ed25519", source="env",
    )