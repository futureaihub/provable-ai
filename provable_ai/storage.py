"""
provable_ai/storage.py
======================
"""

import os
import json
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


DATABASE_URL = os.environ.get("ZORYNEX_DATABASE_URL", "").strip()
_USE_POSTGRES = DATABASE_URL.startswith("postgresql://") or \
                DATABASE_URL.startswith("postgres://")


# ============================================================
# SQLITE STORAGE
# ============================================================

class SQLiteStorage:

    def __init__(self, db_path: str = "zorynex.db"):
        import sqlite3
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._configure()
        self._init_tables()
        self._migrate_schema()

    def _configure(self):
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")

    def _init_tables(self):
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS protocols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol_hash TEXT UNIQUE NOT NULL,
                spec_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT UNIQUE NOT NULL,
                protocol_hash TEXT NOT NULL,
                current_state TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 0,
                frozen INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(protocol_hash) REFERENCES protocols(protocol_hash)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT NOT NULL,
                previous_hash TEXT,
                current_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                protocol_hash TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                model_version TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                schema_version TEXT NOT NULL DEFAULT '1.0',
                version INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(instance_id) REFERENCES instances(instance_id)
            )
        """)

        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_instance ON ledger(instance_id)"
        )

        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_models (
                model_version TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_agents (
                agent_version TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_policies (
                policy_version TEXT PRIMARY KEY,
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                api_key TEXT NOT NULL,
                ip TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                result TEXT,
                method TEXT,
                path TEXT
            )
        """)

        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)"
        )

        self.conn.commit()

    def _migrate_schema(self):
        columns = [
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(ledger)")
        ]
        if "schema_version" not in columns:
            self.conn.execute(
                "ALTER TABLE ledger ADD COLUMN schema_version TEXT NOT NULL DEFAULT '1.0'"
            )
            self.conn.commit()

    # ============================================================
    # GOVERNANCE — READ
    # ============================================================

    def is_model_approved(self, model_version: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM approved_models WHERE model_version=?",
            (model_version,)
        ).fetchone()
        return row is not None

    def is_agent_approved(self, agent_version: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM approved_agents WHERE agent_version=?",
            (agent_version,)
        ).fetchone()
        return row is not None

    def is_policy_active(self, policy_version: str) -> bool:
        row = self.conn.execute(
            "SELECT active FROM approved_policies WHERE policy_version=?",
            (policy_version,)
        ).fetchone()
        return row is not None and row["active"] == 1

    # ============================================================
    # GOVERNANCE — WRITE
    # ============================================================

    def approve_model(self, model_version: str):
        self.conn.execute(
            "INSERT OR IGNORE INTO approved_models (model_version, created_at) VALUES (?,?)",
            (model_version, _utcnow())
        )
        self.conn.commit()

    def approve_agent(self, agent_version: str):
        self.conn.execute(
            "INSERT OR IGNORE INTO approved_agents (agent_version, created_at) VALUES (?,?)",
            (agent_version, _utcnow())
        )
        self.conn.commit()

    def approve_policy(self, policy_version: str, active: bool = True):
        self.conn.execute(
            """INSERT INTO approved_policies (policy_version, active, created_at)
               VALUES (?,?,?)
               ON CONFLICT(policy_version) DO UPDATE SET active=excluded.active""",
            (policy_version, 1 if active else 0, _utcnow())
        )
        self.conn.commit()

    def get_governance_status(self) -> dict:
        return {
            "approved_models": [
                dict(r) for r in self.conn.execute(
                    "SELECT * FROM approved_models ORDER BY created_at DESC"
                ).fetchall()
            ],
            "approved_agents": [
                dict(r) for r in self.conn.execute(
                    "SELECT * FROM approved_agents ORDER BY created_at DESC"
                ).fetchall()
            ],
            "approved_policies": [
                dict(r) for r in self.conn.execute(
                    "SELECT * FROM approved_policies ORDER BY created_at DESC"
                ).fetchall()
            ],
        }

    # ============================================================
    # AUDIT LOG
    # ============================================================

    def insert_audit_log(self, entry: dict):
        self.conn.execute(
            """INSERT INTO audit_log
               (timestamp, api_key, ip, action, resource, result, method, path)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                entry.get("timestamp"), entry.get("api_key"), entry.get("ip"),
                entry.get("action"), entry.get("resource"), entry.get("result"),
                entry.get("method"), entry.get("path")
            )
        )
        self.conn.commit()

    def get_audit_logs(self, limit: int = 100) -> list:
        rows = self.conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ============================================================
    # PROTOCOLS
    # ============================================================

    def get_protocol_by_hash(self, protocol_hash):
        row = self.conn.execute(
            "SELECT * FROM protocols WHERE protocol_hash=?",
            (protocol_hash,)
        ).fetchone()
        return dict(row) if row else None

    def register_protocol(self, protocol_hash, spec_dict):
        self.conn.execute("UPDATE protocols SET active=0")
        self.conn.execute(
            "INSERT INTO protocols (protocol_hash, spec_json, active, created_at) VALUES (?,?,1,?)",
            (protocol_hash, json.dumps(spec_dict), _utcnow())
        )
        self.conn.commit()

    def get_latest_protocol(self):
        row = self.conn.execute(
            "SELECT * FROM protocols WHERE active=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        spec = json.loads(row["spec_json"])
        return {
            "protocol_hash": row["protocol_hash"],
            "states": spec["states"],
            "initial_state": spec["initial_state"],
            "transitions": spec["transitions"]
        }

    # ============================================================
    # INSTANCES
    # ============================================================

    def create_instance(self, instance_id, protocol_hash, initial_state):
        self.conn.execute(
            "INSERT INTO instances (instance_id, protocol_hash, current_state, version, frozen, created_at) VALUES (?,?,?,0,0,?)",
            (instance_id, protocol_hash, initial_state, _utcnow())
        )
        self.conn.commit()

    def get_instance(self, instance_id):
        row = self.conn.execute(
            "SELECT * FROM instances WHERE instance_id=?", (instance_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_instances(self):
        rows = self.conn.execute("SELECT * FROM instances").fetchall()
        return [dict(r) for r in rows]

    def update_instance_state(self, instance_id, new_state, new_version):
        self.conn.execute(
            "UPDATE instances SET current_state=?, version=? WHERE instance_id=?",
            (new_state, new_version, instance_id)
        )
        self.conn.commit()

    def freeze_instance(self, instance_id):
        self.conn.execute(
            "UPDATE instances SET frozen=1 WHERE instance_id=?", (instance_id,)
        )
        self.conn.commit()

    # ============================================================
    # LEDGER
    # ============================================================

    def insert_ledger_entry(self, record):
        self.conn.execute(
            """INSERT INTO ledger
               (instance_id, previous_hash, current_hash, signature, protocol_hash,
                from_state, to_state, actor, input_hash, output_hash,
                model_version, agent_version, policy_version,
                metadata_json, schema_version, version, timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record["instance_id"], record["previous_hash"], record["current_hash"],
                record["signature"], record["protocol_hash"],
                record["from_state"], record["to_state"], record["actor"],
                record["input_hash"], record["output_hash"],
                record["model_version"], record["agent_version"], record["policy_version"],
                record["metadata_json"], record["schema_version"],
                record["version"], record["timestamp"]
            )
        )
        self.conn.commit()

    def get_ledger(self, instance_id):
        rows = self.conn.execute(
            "SELECT * FROM ledger WHERE instance_id=? ORDER BY id ASC",
            (instance_id,)
        ).fetchall()
        return [dict(r) for r in rows]


# ============================================================
# POSTGRESQL STORAGE
# ============================================================

class PostgresStorage:
    """
    Production backend. Drop-in replacement for SQLiteStorage.
    Requires: pip install psycopg2-binary
    Set: ZORYNEX_DATABASE_URL=postgresql://user:pass@host:5432/zorynex
    """

    def __init__(self, db_path: str = None):
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            raise RuntimeError(
                "psycopg2 is required for PostgreSQL. "
                "Install it: pip install psycopg2-binary"
            )
        self._psycopg2 = psycopg2
        self._extras = psycopg2.extras
        self.conn = psycopg2.connect(DATABASE_URL)
        self.conn.autocommit = False
        self._init_tables()

    def _cursor(self):
        return self.conn.cursor(cursor_factory=self._extras.RealDictCursor)

    def _commit(self):
        self.conn.commit()

    def _init_tables(self):
        cur = self._cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS protocols (
                id SERIAL PRIMARY KEY,
                protocol_hash TEXT UNIQUE NOT NULL,
                spec_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS instances (
                id SERIAL PRIMARY KEY,
                instance_id TEXT UNIQUE NOT NULL,
                protocol_hash TEXT NOT NULL,
                current_state TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 0,
                frozen INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id SERIAL PRIMARY KEY,
                instance_id TEXT NOT NULL,
                previous_hash TEXT,
                current_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                protocol_hash TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                model_version TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                schema_version TEXT NOT NULL DEFAULT '1.0',
                version INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ledger_instance ON ledger(instance_id)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_models (
                model_version TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_agents (
                agent_version TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS approved_policies (
                policy_version TEXT PRIMARY KEY,
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                api_key TEXT NOT NULL,
                ip TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                result TEXT,
                method TEXT,
                path TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        self._commit()

    # ============================================================
    # GOVERNANCE
    # ============================================================

    def is_model_approved(self, v):
        cur = self._cursor()
        cur.execute("SELECT 1 FROM approved_models WHERE model_version=%s", (v,))
        return cur.fetchone() is not None

    def is_agent_approved(self, v):
        cur = self._cursor()
        cur.execute("SELECT 1 FROM approved_agents WHERE agent_version=%s", (v,))
        return cur.fetchone() is not None

    def is_policy_active(self, v):
        cur = self._cursor()
        cur.execute("SELECT active FROM approved_policies WHERE policy_version=%s", (v,))
        row = cur.fetchone()
        return row is not None and row["active"] == 1

    def approve_model(self, v):
        cur = self._cursor()
        cur.execute(
            "INSERT INTO approved_models (model_version, created_at) VALUES (%s,%s) ON CONFLICT DO NOTHING",
            (v, _utcnow())
        )
        self._commit()

    def approve_agent(self, v):
        cur = self._cursor()
        cur.execute(
            "INSERT INTO approved_agents (agent_version, created_at) VALUES (%s,%s) ON CONFLICT DO NOTHING",
            (v, _utcnow())
        )
        self._commit()

    def approve_policy(self, v, active=True):
        cur = self._cursor()
        cur.execute(
            """INSERT INTO approved_policies (policy_version, active, created_at)
               VALUES (%s,%s,%s)
               ON CONFLICT (policy_version) DO UPDATE SET active=EXCLUDED.active""",
            (v, 1 if active else 0, _utcnow())
        )
        self._commit()

    def get_governance_status(self):
        cur = self._cursor()
        cur.execute("SELECT * FROM approved_models ORDER BY created_at DESC")
        models = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM approved_agents ORDER BY created_at DESC")
        agents = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM approved_policies ORDER BY created_at DESC")
        policies = [dict(r) for r in cur.fetchall()]
        return {"approved_models": models, "approved_agents": agents, "approved_policies": policies}

    # ============================================================
    # AUDIT LOG
    # ============================================================

    def insert_audit_log(self, entry: dict):
        cur = self._cursor()
        cur.execute(
            """INSERT INTO audit_log
               (timestamp, api_key, ip, action, resource, result, method, path)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                entry.get("timestamp"), entry.get("api_key"), entry.get("ip"),
                entry.get("action"), entry.get("resource"), entry.get("result"),
                entry.get("method"), entry.get("path")
            )
        )
        self._commit()

    def get_audit_logs(self, limit: int = 100) -> list:
        cur = self._cursor()
        cur.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT %s", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ============================================================
    # PROTOCOLS
    # ============================================================

    def get_protocol_by_hash(self, h):
        cur = self._cursor()
        cur.execute("SELECT * FROM protocols WHERE protocol_hash=%s", (h,))
        row = cur.fetchone()
        return dict(row) if row else None

    def register_protocol(self, protocol_hash, spec_dict):
        cur = self._cursor()
        cur.execute("UPDATE protocols SET active=0")
        cur.execute(
            "INSERT INTO protocols (protocol_hash, spec_json, active, created_at) VALUES (%s,%s,1,%s)",
            (protocol_hash, json.dumps(spec_dict), _utcnow())
        )
        self._commit()

    def get_latest_protocol(self):
        cur = self._cursor()
        cur.execute("SELECT * FROM protocols WHERE active=1 ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        spec = json.loads(row["spec_json"])
        return {
            "protocol_hash": row["protocol_hash"],
            "states": spec["states"],
            "initial_state": spec["initial_state"],
            "transitions": spec["transitions"]
        }

    # ============================================================
    # INSTANCES
    # ============================================================

    def create_instance(self, instance_id, protocol_hash, initial_state):
        cur = self._cursor()
        cur.execute(
            "INSERT INTO instances (instance_id, protocol_hash, current_state, version, frozen, created_at) VALUES (%s,%s,%s,0,0,%s)",
            (instance_id, protocol_hash, initial_state, _utcnow())
        )
        self._commit()

    def get_instance(self, instance_id):
        cur = self._cursor()
        cur.execute("SELECT * FROM instances WHERE instance_id=%s", (instance_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_instances(self):
        cur = self._cursor()
        cur.execute("SELECT * FROM instances")
        return [dict(r) for r in cur.fetchall()]

    def update_instance_state(self, instance_id, new_state, new_version):
        cur = self._cursor()
        cur.execute(
            "UPDATE instances SET current_state=%s, version=%s WHERE instance_id=%s",
            (new_state, new_version, instance_id)
        )
        self._commit()

    def freeze_instance(self, instance_id):
        cur = self._cursor()
        cur.execute("UPDATE instances SET frozen=1 WHERE instance_id=%s", (instance_id,))
        self._commit()

    # ============================================================
    # LEDGER
    # ============================================================

    def insert_ledger_entry(self, record):
        cur = self._cursor()
        cur.execute(
            """INSERT INTO ledger
               (instance_id, previous_hash, current_hash, signature, protocol_hash,
                from_state, to_state, actor, input_hash, output_hash,
                model_version, agent_version, policy_version,
                metadata_json, schema_version, version, timestamp)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                record["instance_id"], record["previous_hash"], record["current_hash"],
                record["signature"], record["protocol_hash"],
                record["from_state"], record["to_state"], record["actor"],
                record["input_hash"], record["output_hash"],
                record["model_version"], record["agent_version"], record["policy_version"],
                record["metadata_json"], record["schema_version"],
                record["version"], record["timestamp"]
            )
        )
        self._commit()

    def get_ledger(self, instance_id):
        cur = self._cursor()
        cur.execute(
            "SELECT * FROM ledger WHERE instance_id=%s ORDER BY id ASC", (instance_id,)
        )
        return [dict(r) for r in cur.fetchall()]


# ============================================================
# FACTORY
# ============================================================

def get_storage(db_path: str = "zorynex.db"):
    """
    Returns correct backend based on ZORYNEX_DATABASE_URL env var.
    SQLite if not set. PostgreSQL if set.
    """
    if _USE_POSTGRES:
        return PostgresStorage()
    return SQLiteStorage(db_path)
