import sqlite3
import json
from datetime import datetime


class SQLiteStorage:

    def __init__(self, db_path="provable_ai.db"):
        self.conn = sqlite3.connect(
            db_path,
            check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row

        self._configure()
        self._init_tables()
        self._migrate_schema()

    # ============================================================
    # SQLITE CONFIG
    # ============================================================

    def _configure(self):
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")

    # ============================================================
    # INIT TABLES
    # ============================================================

    def _init_tables(self):
        cur = self.conn.cursor()

        # ---------------- PROTOCOLS ----------------
        cur.execute("""
        CREATE TABLE IF NOT EXISTS protocols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol_hash TEXT UNIQUE NOT NULL,
            spec_json TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """)

        # ---------------- INSTANCES ----------------
        cur.execute("""
        CREATE TABLE IF NOT EXISTS instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instance_id TEXT UNIQUE NOT NULL,
            protocol_hash TEXT NOT NULL,
            current_state TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0,
            frozen INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(protocol_hash)
                REFERENCES protocols(protocol_hash)
        )
        """)

        # ---------------- LEDGER ----------------
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
            FOREIGN KEY(instance_id)
                REFERENCES instances(instance_id)
        )
        """)

        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_instance ON ledger(instance_id)"
        )

        # ---------------- GOVERNANCE TABLES ----------------
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

        self.conn.commit()

    # ============================================================
    # SAFE SCHEMA MIGRATION
    # ============================================================

    def _migrate_schema(self):

        # ensure schema_version column exists
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
    # GOVERNANCE ENFORCEMENT
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
            """
            INSERT INTO protocols
            (protocol_hash, spec_json, active, created_at)
            VALUES (?,?,1,?)
            """,
            (
                protocol_hash,
                json.dumps(spec_dict),
                datetime.utcnow().isoformat()
            )
        )
        self.conn.commit()

    def get_latest_protocol(self):
        row = self.conn.execute(
            """
            SELECT * FROM protocols
            WHERE active=1
            ORDER BY id DESC
            LIMIT 1
            """
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
            """
            INSERT INTO instances
            (instance_id, protocol_hash, current_state, version, frozen, created_at)
            VALUES (?,?,?,?,0,?)
            """,
            (
                instance_id,
                protocol_hash,
                initial_state,
                0,
                datetime.utcnow().isoformat()
            )
        )
        self.conn.commit()

    def get_instance(self, instance_id):
        row = self.conn.execute(
            "SELECT * FROM instances WHERE instance_id=?",
            (instance_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_instances(self):
        rows = self.conn.execute("SELECT * FROM instances").fetchall()
        return [dict(r) for r in rows]

    def update_instance_state(self, instance_id, new_state, new_version):
        self.conn.execute(
            """
            UPDATE instances
            SET current_state=?, version=?
            WHERE instance_id=?
            """,
            (new_state, new_version, instance_id)
        )
        self.conn.commit()

    def freeze_instance(self, instance_id):
        self.conn.execute(
            "UPDATE instances SET frozen=1 WHERE instance_id=?",
            (instance_id,)
        )
        self.conn.commit()

    # ============================================================
    # LEDGER
    # ============================================================

    def insert_ledger_entry(self, record):
        self.conn.execute(
            """
            INSERT INTO ledger
            (
                instance_id,
                previous_hash,
                current_hash,
                signature,
                protocol_hash,
                from_state,
                to_state,
                actor,
                input_hash,
                output_hash,
                model_version,
                agent_version,
                policy_version,
                metadata_json,
                schema_version,
                version,
                timestamp
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                record["instance_id"],
                record["previous_hash"],
                record["current_hash"],
                record["signature"],
                record["protocol_hash"],
                record["from_state"],
                record["to_state"],
                record["actor"],
                record["input_hash"],
                record["output_hash"],
                record["model_version"],
                record["agent_version"],
                record["policy_version"],
                record["metadata_json"],
                record["schema_version"],
                record["version"],
                record["timestamp"]
            )
        )
        self.conn.commit()

    def get_ledger(self, instance_id):
        rows = self.conn.execute(
            "SELECT * FROM ledger WHERE instance_id=? ORDER BY id ASC",
            (instance_id,)
        ).fetchall()
        return [dict(r) for r in rows]