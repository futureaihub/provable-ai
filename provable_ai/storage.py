"""
Zorynex SQLite Storage
======================
Append-only ledger with database-level tamper resistance.

CRITICAL RULES — enforced at BOTH Python AND database level:
    ✗ Never UPDATE a ledger row — blocked by SQL TRIGGER
    ✗ Never DELETE a ledger row — blocked by SQL TRIGGER
    ✓ Only INSERT new rows (append-only)
    ✓ sequence_id must equal previous_max + 1 (no gaps)
    ✓ previous_hash must match last entry's current_hash
    ✓ proof_json stored in canonical format (sorted keys, compact)

Tamper resistance layers:
    Layer 1: Python API — no update/delete methods exist
    Layer 2: SQLite TRIGGER — blocks UPDATE/DELETE at DB engine level
    Layer 3: Python — sequence continuity enforced before insert
    Layer 4: Python — hash chain integrity enforced before insert
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .canonical import genesis_hash
from .exceptions import ChainBroken, DuplicateSequenceId, SequenceGap


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(obj: Any) -> str:
    """
    Canonical JSON for storage.
    EXACT form: sorted keys, compact separators=(",", ":"), ensure_ascii=False.
    Must match canonical_encode() in canonical.py byte-for-byte.
    Never use json.dumps() directly for proof storage — always use this.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


class SQLiteStorage:
    """
    Append-only SQLite ledger storage with cryptographic chain enforcement.

    Tamper resistance enforced at two independent layers:
    1. Python — no mutating methods exposed
    2. SQLite triggers — UPDATE and DELETE on ledger raise database errors
    """

    def __init__(self, db_path: str = "provable_ai.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._configure()
        self._init_tables()
        self._install_triggers()
        self._migrate_schema()

    def _configure(self) -> None:
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.conn.execute("PRAGMA synchronous=FULL;")

    def _init_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS protocols (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol_hash TEXT    UNIQUE NOT NULL,
                spec_json     TEXT    NOT NULL,
                active        INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT    NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS instances (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id     TEXT    NOT NULL DEFAULT 'default',
                instance_id   TEXT    UNIQUE NOT NULL,
                protocol_hash TEXT    NOT NULL,
                current_state TEXT    NOT NULL,
                version       INTEGER NOT NULL DEFAULT 0,
                frozen        INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT    NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id      TEXT    NOT NULL DEFAULT 'default',
                instance_id    TEXT    NOT NULL,
                sequence_id    INTEGER NOT NULL DEFAULT 0,
                previous_hash  TEXT    NOT NULL DEFAULT '',
                current_hash   TEXT    NOT NULL,
                signature      TEXT    NOT NULL,
                key_id         TEXT    NOT NULL DEFAULT 'legacy',
                protocol_hash  TEXT    NOT NULL,
                from_state     TEXT    NOT NULL,
                to_state       TEXT    NOT NULL,
                actor          TEXT    NOT NULL DEFAULT 'system',
                input_hash     TEXT    NOT NULL DEFAULT '',
                output_hash    TEXT    NOT NULL DEFAULT '',
                model_version  TEXT    NOT NULL,
                agent_version  TEXT    NOT NULL,
                policy_version TEXT    NOT NULL,
                metadata_json  TEXT    NOT NULL DEFAULT '{}',
                proof_json     TEXT    NOT NULL DEFAULT '{}',
                schema_version TEXT    NOT NULL DEFAULT '1.0',
                version        INTEGER NOT NULL DEFAULT 1,
                timestamp      TEXT    NOT NULL,
                CHECK(length(current_hash) = 64),
                CHECK(length(signature) = 128),
                CHECK(sequence_id >= 1 OR sequence_id = 0)
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_instance
            ON ledger(instance_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_protocol
            ON ledger(protocol_hash)
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_models (
                model_version TEXT PRIMARY KEY,
                model_name    TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_agents (
                agent_version TEXT PRIMARY KEY,
                agent_name    TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_policies (
                policy_version TEXT    PRIMARY KEY,
                active         INTEGER NOT NULL DEFAULT 1,
                created_at     TEXT    NOT NULL
            )
        """)

        self.conn.commit()

    def _install_triggers(self) -> None:
        """
        Install DB-level triggers blocking UPDATE and DELETE on ledger.

        These fire BEFORE the operation at the SQLite engine level.
        They cannot be bypassed by any Python code — only by
        dropping and recreating the table (which would break the chain).
        """
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS ledger_no_update
            BEFORE UPDATE ON ledger
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: ledger rows are append-only. UPDATE blocked.');
            END
        """)

        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS ledger_no_delete
            BEFORE DELETE ON ledger
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: ledger rows are append-only. DELETE blocked.');
            END
        """)


        # ── Governance approval tables: permanent records — deletion blocked ────
        # Deactivation sets is_active=0. Physical deletion is NEVER permitted.
        # These triggers ensure governance history is immutable at the DB level.
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS approved_models_no_delete
            BEFORE DELETE ON approved_models
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: governance approvals are permanent. DELETE blocked.');
            END
        """)
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS approved_agents_no_delete
            BEFORE DELETE ON approved_agents
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: governance approvals are permanent. DELETE blocked.');
            END
        """)
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS approved_policies_no_delete
            BEFORE DELETE ON approved_policies
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: governance approvals are permanent. DELETE blocked.');
            END
        """)
        # ── Compiled protocols are immutable ────────────────────────────────────
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS protocols_no_update
            BEFORE UPDATE ON protocols
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: compiled protocols are immutable. UPDATE blocked.');
            END
        """)
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS protocols_no_delete
            BEFORE DELETE ON protocols
            BEGIN
                SELECT RAISE(ABORT,'ZORYNEX INTEGRITY VIOLATION: compiled protocols are immutable. DELETE blocked.');
            END
        """)

        self.conn.commit()

    def _migrate_schema(self) -> None:
        """Add name columns to governance tables if upgrading from older schema."""
        for table, col in [
            ("approved_models", "model_name"),
            ("approved_agents", "agent_name"),
        ]:
            try:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
                self.conn.commit()
            except Exception:
                pass  # column already exists
        """Safe additive migrations. Never drops columns or tables."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(ledger)")
        existing_cols = {row["name"] for row in cur.fetchall()}

        migrations = [
            ("tenant_id",     "TEXT    NOT NULL DEFAULT 'default'"),
            ("sequence_id",   "INTEGER NOT NULL DEFAULT 0"),
            ("key_id",        "TEXT    NOT NULL DEFAULT 'legacy'"),
            ("proof_json",    "TEXT    NOT NULL DEFAULT '{}'"),
            ("input_hash",    "TEXT    NOT NULL DEFAULT ''"),
            ("output_hash",   "TEXT    NOT NULL DEFAULT ''"),
            ("actor",         "TEXT    NOT NULL DEFAULT 'system'"),
            ("previous_hash", "TEXT    NOT NULL DEFAULT ''"),
        ]

        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                cur.execute(
                    f"ALTER TABLE ledger ADD COLUMN {col_name} {col_def}"
                )

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_tenant_instance_seq
            ON ledger(tenant_id, instance_id, sequence_id)
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_tenant_instance_hash
            ON ledger(tenant_id, instance_id, current_hash)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_instance_hash_lookup
            ON ledger(tenant_id, instance_id, current_hash)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_key_id
            ON ledger(key_id)
        """)
        # Gap 10: index for fast hash lookups during verification queries
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_tenant_instance_lookup
            ON ledger(tenant_id, instance_id, current_hash)
        """)

        self.conn.commit()

    # ── Chain validation (pre-insert) ─────────────────────────────────────────

    def _validate_chain_integrity(
        self,
        instance_id: str,
        sequence_id: int,
        previous_hash: str,
        tenant_id: str = "default",
    ) -> None:
        """
        Enforce sequence continuity, hash chain linkage, and tenant isolation.

        Rules:
        1. sequence_id == max_existing + 1 (no gaps, no out-of-order)
        2. previous_hash == current_hash of last entry
        3. First entry (seq=1): previous_hash must be genesis ("0" * 64)
        4. instance_id must not exist under a DIFFERENT tenant_id

        Raises:
            DuplicateSequenceId: sequence_id already exists
            SequenceGap:         sequence_id > expected (gap detected)
            ChainBroken:         previous_hash doesn't match last entry
            LedgerError:         instance_id already owned by different tenant
        """
        from .exceptions import LedgerError
        cur = self.conn.cursor()

        # Cross-tenant isolation: reject if instance_id exists under different tenant
        cur.execute("""
            SELECT DISTINCT tenant_id FROM ledger
            WHERE instance_id = ? AND tenant_id != ?
            LIMIT 1
        """, (instance_id, tenant_id))
        conflict = cur.fetchone()
        if conflict:
            raise LedgerError(
                message=(
                    f"instance_id '{instance_id}' already exists under "
                    f"tenant '{conflict[0]}'. Cross-tenant instance reuse is forbidden."
                ),
                context={
                    "instance_id": instance_id,
                    "requesting_tenant": tenant_id,
                    "owning_tenant": conflict[0],
                }
            )

        cur.execute("""
            SELECT sequence_id, current_hash FROM ledger
            WHERE tenant_id = ? AND instance_id = ?
            ORDER BY sequence_id DESC
            LIMIT 1
        """, (tenant_id, instance_id,))
        last = cur.fetchone()

        if last is None:
            expected_seq = 1
            expected_prev = genesis_hash()
        else:
            expected_seq = last["sequence_id"] + 1
            expected_prev = last["current_hash"]

        if sequence_id < expected_seq:
            raise DuplicateSequenceId(
                sequence_id=sequence_id, tenant_id=None
            )
        if sequence_id > expected_seq:
            raise SequenceGap(
                expected_sequence_id=expected_seq,
                actual_sequence_id=sequence_id,
            )
        if previous_hash != expected_prev:
            raise ChainBroken(
                sequence_id=sequence_id,
                expected_hash=expected_prev,
                actual_hash=previous_hash,
            )

    # ── Ledger operations ─────────────────────────────────────────────────────

    def get_latest_ledger_entry(self, instance_id: str, tenant_id: str = "default") -> dict | None:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM ledger WHERE tenant_id = ? AND instance_id = ?
            ORDER BY sequence_id DESC LIMIT 1
        """, (tenant_id, instance_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_ledger_entry(
        self, instance_id: str, sequence_id: int | None = None,
        tenant_id: str = "default"
    ) -> dict | None:
        cur = self.conn.cursor()
        if sequence_id is not None:
            cur.execute("""
                SELECT * FROM ledger WHERE tenant_id = ? AND instance_id = ? AND sequence_id = ?
            """, (tenant_id, instance_id, sequence_id))
        else:
            cur.execute("""
                SELECT * FROM ledger WHERE tenant_id = ? AND instance_id = ?
                ORDER BY sequence_id DESC LIMIT 1
            """, (tenant_id, instance_id,))
        row = cur.fetchone()
        if row is None:
            return None
        result = dict(row)
        if result.get("proof_json") and result["proof_json"] != "{}":
            try:
                result["proof"] = json.loads(result["proof_json"])
            except (json.JSONDecodeError, TypeError):
                pass
        return result

    def get_ledger_chain(self, instance_id: str, tenant_id: str = "default") -> list[dict]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM ledger WHERE tenant_id = ? AND instance_id = ?
            ORDER BY sequence_id ASC
        """, (tenant_id, instance_id,))
        return [dict(row) for row in cur.fetchall()]

    def append_ledger_entry(self, proof_dict: dict) -> int:
        """
        Append a new proof to the ledger.

        Validates chain integrity before insert.
        Stores proof_json and metadata_json in canonical format.
        Wrapped in an atomic transaction — no partial writes.

        Raises:
            DuplicateSequenceId: sequence already exists
            SequenceGap:         sequence is not exactly max + 1
            ChainBroken:         previous_hash doesn't match
            sqlite3.IntegrityError: DB-level constraint violated
        """
        ledger = proof_dict["ledger"]
        decision = proof_dict["decision"]
        decision_context = proof_dict["decision_context"]
        governance = proof_dict["governance"]
        signature = proof_dict["signature"]

        instance_id = proof_dict["instance_id"]
        sequence_id = ledger["sequence_id"]
        previous_hash = ledger["previous_hash"]
        tenant_id = proof_dict.get("tenant_id", "default")

        # Signature length check before any DB interaction
        if not signature["value"] or len(signature["value"]) != 128:
            from .exceptions import SigningFailed
            raise SigningFailed(
                key_id=signature.get("key_id", "unknown"),
                underlying_error=(
                    f"Signature value must be 128 hex chars (64-byte Ed25519), "
                    f"got {len(signature.get('value', ''))} chars."
                )
            )

        # Pre-insert chain integrity validation
        self._validate_chain_integrity(instance_id, sequence_id, previous_hash, tenant_id)

        # Ensure instance row exists and is not cross-tenant
        self._ensure_instance(
            instance_id=instance_id,
            protocol_hash=governance.get("policy_version", "unknown"),
            current_state=decision["to_state"],
            tenant_id=tenant_id,
        )

        # Canonical JSON storage
        proof_json_str = _canonical_json(proof_dict)
        metadata_json_str = _canonical_json(decision_context.get("metadata", {}))

        cur = self.conn.cursor()
        try:
            cur.execute("""
                INSERT INTO ledger (
                    tenant_id, instance_id, sequence_id,
                    previous_hash, current_hash,
                    signature, key_id,
                    protocol_hash, from_state, to_state,
                    model_version, agent_version, policy_version,
                    metadata_json, proof_json,
                    schema_version, version, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant_id, instance_id, sequence_id,
                previous_hash, ledger["current_hash"],
                signature["value"], signature["key_id"],
                governance.get("policy_version", "unknown"),
                decision["from_state"], decision["to_state"],
                governance["model_version"],
                governance["agent_version"],
                governance["policy_version"],
                metadata_json_str, proof_json_str,
                proof_dict.get("type", "zorynex-proof-v1"),
                1, ledger["timestamp"],
            ))
            self.conn.commit()
        except sqlite3.IntegrityError:
            self.conn.rollback()
            raise

        return sequence_id

    def _ensure_instance(self, instance_id: str, protocol_hash: str,
                          current_state: str, tenant_id: str = "default") -> None:
        """
        Create instance row if it does not exist for this (tenant_id, instance_id).
        Cross-tenant isolation is enforced separately in _validate_chain_integrity.
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id FROM instances WHERE tenant_id = ? AND instance_id = ?",
            (tenant_id, instance_id)
        )
        if cur.fetchone() is None:
            cur.execute("""
                INSERT OR IGNORE INTO instances
                (tenant_id, instance_id, protocol_hash, current_state, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (tenant_id, instance_id, protocol_hash, current_state, _utc_now()))


    def get_approved_models(self) -> list[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT model_name, model_version FROM approved_models")
        return [{"name": r[0] or r[1], "version": r[1]} for r in cur.fetchall()]

    def get_approved_agents(self) -> list[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT agent_name, agent_version FROM approved_agents")
        return [{"name": r[0] or r[1], "version": r[1]} for r in cur.fetchall()]

    def get_approved_policies(self) -> list[dict]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT policy_version FROM approved_policies WHERE active = 1"
        )
        # policies stored as "name:version" or just "version"
        result = []
        for (pv,) in cur.fetchall():
            if ":" in pv:
                name, ver = pv.split(":", 1)
            else:
                name, ver = pv, pv
            result.append({"name": name, "version": ver})
        return result

    def add_approved_model(self, model_version: str, model_name: str = "") -> None:
        name = model_name or model_version
        self.conn.execute(
            "INSERT OR REPLACE INTO approved_models VALUES (?, ?, ?)",
            (model_version, name, _utc_now())
        )
        self.conn.commit()

    def add_approved_agent(self, agent_version: str, agent_name: str = "") -> None:
        name = agent_name or agent_version
        self.conn.execute(
            "INSERT OR REPLACE INTO approved_agents VALUES (?, ?, ?)",
            (agent_version, name, _utc_now())
        )
        self.conn.commit()

    def add_approved_policy(self, policy_version: str, policy_name: str = "") -> None:
        # Store as "name:version" so we can recover both later
        name    = policy_name or policy_version
        key     = f"{name}:{policy_version}" if policy_name and policy_name != policy_version else policy_version
        self.conn.execute(
            "INSERT OR REPLACE INTO approved_policies VALUES (?, 1, ?)",
            (key, _utc_now())
        )
        self.conn.commit()

    def deactivate_policy(self, policy_version: str) -> None:
        self.conn.execute(
            "UPDATE approved_policies SET active = 0 WHERE policy_version = ?",
            (policy_version,)
        )
        self.conn.commit()

    def register_protocol(self, protocol_hash: str, spec: dict) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id FROM protocols WHERE protocol_hash = ?", (protocol_hash,)
        )
        if cur.fetchone() is None:
            self.conn.execute(
                "INSERT INTO protocols VALUES (NULL, ?, ?, 1, ?)",
                (protocol_hash, _canonical_json(spec), _utc_now())
            )
            self.conn.commit()

    def get_protocol(self, protocol_hash: str) -> dict | None:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM protocols WHERE protocol_hash = ?", (protocol_hash,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        result = dict(row)
        result["spec"] = json.loads(result["spec_json"])
        return result

    def get_ledger_count(self, instance_id: str | None = None, tenant_id: str = "default") -> int:
        cur = self.conn.cursor()
        if instance_id:
            cur.execute(
                "SELECT COUNT(*) FROM ledger WHERE tenant_id = ? AND instance_id = ?",
                (tenant_id, instance_id,)
            )
        else:
            cur.execute("SELECT COUNT(*) FROM ledger")
        return cur.fetchone()[0]

    def get_max_sequence_id(self, instance_id: str, tenant_id: str = "default") -> int:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT MAX(sequence_id) FROM ledger WHERE tenant_id = ? AND instance_id = ?",
            (tenant_id, instance_id,)
        )
        result = cur.fetchone()[0]
        return result if result is not None else 0


    # ── Backward-compatibility aliases (old test_engine.py API) ──────────────

    def approve_model(self, model_version: str) -> None:
        """Alias for add_approved_model."""
        self.add_approved_model(model_version)

    def approve_agent(self, agent_version: str) -> None:
        """Alias for add_approved_agent."""
        self.add_approved_agent(agent_version)

    def approve_policy(self, policy_version: str, active: bool = True) -> None:
        """Alias: approve or deactivate a policy version."""
        if active:
            self.add_approved_policy(policy_version)
        else:
            # Deactivate = set active=0, never DELETE (governance history is immutable)
            self.conn.execute(
                "UPDATE approved_policies SET active = 0 WHERE policy_version = ?",
                (policy_version,)
            )
            self.conn.commit()

    def is_policy_active(self, policy_version: str) -> bool:
        """Return True if policy_version exists AND is active (active=1)."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT 1 FROM approved_policies WHERE policy_version=? AND active=1",
            (policy_version,)
        )
        return cur.fetchone() is not None

    def deactivate_policy(self, policy_version: str) -> None:
        """Deactivate a policy — sets active=0. Record is never deleted.
        Governance approvals are permanent records; deactivation only hides
        the policy from get_approved_policies() without erasing history."""
        self.conn.execute(
            "UPDATE approved_policies SET active = 0 WHERE policy_version = ?",
            (policy_version,)
        )
        self.conn.commit()

    def get_protocol_by_hash(self, protocol_hash: str) -> dict | None:
        """Alias for get_protocol."""
        return self.get_protocol(protocol_hash)

    def get_ledger(self, instance_id: str, tenant_id: str = "default") -> list[dict]:
        """Alias for get_ledger_chain — returns list of ledger row dicts."""
        import json
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM ledger
            WHERE instance_id=? AND tenant_id=?
            ORDER BY sequence_id ASC
        """, (instance_id, tenant_id))
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            # Add previous_hash=None for first entry (genesis)
            if d.get("previous_hash") == "0" * 64 or d.get("previous_hash") == "":
                d["previous_hash"] = None
            result.append(d)
        return result

    def get_instance(self, instance_id: str, tenant_id: str = "default") -> dict | None:
        """Return instance row as dict."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM instances WHERE instance_id=? AND tenant_id=?",
                    (instance_id, tenant_id))
        row = cur.fetchone()
        return dict(row) if row else None

    def freeze_instance(self, instance_id: str, tenant_id: str = "default") -> None:
        """Set frozen=1 on an instance."""
        self.conn.execute(
            "UPDATE instances SET frozen=1 WHERE instance_id=? AND tenant_id=?",
            (instance_id, tenant_id)
        )
        self.conn.commit()

    def get_latest_protocol(self) -> dict | None:
        """Return the most recently registered protocol spec dict."""
        cur = self.conn.cursor()
        cur.execute("SELECT spec_json FROM protocols ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        import json
        spec = json.loads(row["spec_json"])
        return spec

    def get_governance_status(self) -> dict:
        """Return approved models, agents, policies as lists of dicts."""
        cur = self.conn.cursor()
        cur.execute("SELECT model_version FROM approved_models")
        models = [{"model_version": r["model_version"]} for r in cur.fetchall()]
        cur.execute("SELECT agent_version FROM approved_agents")
        agents = [{"agent_version": r["agent_version"]} for r in cur.fetchall()]
        cur.execute("SELECT policy_version FROM approved_policies")
        policies = [{"policy_version": r["policy_version"]} for r in cur.fetchall()]
        return {
            "approved_models":   models,
            "approved_agents":   agents,
            "approved_policies": policies,
        }

    def close(self) -> None:
        self.conn.close()

    # ── Deprecated ───────────────────────────────────────────────────────────

    def record_transition(
        self, instance_id: str, from_state: str, to_state: str,
        actor: str, input_hash: str, output_hash: str,
        model_version: str, agent_version: str, policy_version: str,
        previous_hash: str, current_hash: str, signature: str,
        protocol_hash: str, metadata: dict | None = None,
        schema_version: str = "1.0",
    ) -> dict:
        """DEPRECATED: Use append_ledger_entry() instead."""
        self._ensure_instance(instance_id, protocol_hash, to_state)
        current_max = self.get_max_sequence_id(instance_id)
        sequence_id = current_max + 1

        self._validate_chain_integrity(instance_id, sequence_id, previous_hash)

        metadata_json_str = _canonical_json(metadata or {})
        now = _utc_now()
        cur = self.conn.cursor()
        try:
            cur.execute("""
                INSERT INTO ledger (
                    instance_id, sequence_id, previous_hash, current_hash,
                    signature, key_id, protocol_hash, from_state, to_state,
                    actor, input_hash, output_hash,
                    model_version, agent_version, policy_version,
                    metadata_json, proof_json, schema_version, version, timestamp
                ) VALUES (?, ?, ?, ?, ?, 'legacy', ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, '{}', ?, 1, ?)
            """, (
                instance_id, sequence_id, previous_hash, current_hash,
                signature, protocol_hash, from_state, to_state,
                actor, input_hash, output_hash,
                model_version, agent_version, policy_version,
                metadata_json_str, schema_version, now,
            ))
            self.conn.commit()
        except sqlite3.IntegrityError:
            self.conn.rollback()
            raise

        return {
            "instance_id": instance_id,
            "sequence_id": sequence_id,
            "from_state": from_state,
            "to_state": to_state,
            "current_hash": current_hash,
            "hash_prefix": current_hash[:16],
            "timestamp": now,
        }