"""Initial PostgreSQL schema — all tables from SQLite storage.

Revision: 0001
Revises:  —
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Ledger (append-only proof chain) ─────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            id              BIGSERIAL PRIMARY KEY,
            tenant_id       TEXT    NOT NULL DEFAULT 'default',
            instance_id     TEXT    NOT NULL,
            sequence_id     INTEGER NOT NULL,
            previous_hash   TEXT    NOT NULL DEFAULT '',
            current_hash    TEXT    NOT NULL CHECK(length(current_hash) = 64),
            signature       TEXT    NOT NULL CHECK(length(signature) = 128),
            key_id          TEXT    NOT NULL DEFAULT 'legacy',
            protocol_hash   TEXT    NOT NULL,
            from_state      TEXT    NOT NULL,
            to_state        TEXT    NOT NULL,
            actor           TEXT    NOT NULL DEFAULT 'system',
            input_hash      TEXT    NOT NULL DEFAULT '',
            output_hash     TEXT    NOT NULL DEFAULT '',
            model_version   TEXT    NOT NULL,
            agent_version   TEXT    NOT NULL,
            policy_version  TEXT    NOT NULL,
            metadata_json   TEXT    NOT NULL DEFAULT '{}',
            proof_json      TEXT    NOT NULL DEFAULT '{}',
            schema_version  TEXT    NOT NULL DEFAULT '1.0',
            version         INTEGER NOT NULL DEFAULT 1,
            timestamp       TEXT    NOT NULL,
            UNIQUE(tenant_id, instance_id, sequence_id),
            UNIQUE(tenant_id, instance_id, current_hash)
        )
    """)

    # Prevent UPDATE and DELETE at DB level (append-only guarantee)
    op.execute("""
        CREATE OR REPLACE RULE ledger_no_update AS
            ON UPDATE TO ledger DO INSTEAD NOTHING
    """)
    op.execute("""
        CREATE OR REPLACE RULE ledger_no_delete AS
            ON DELETE TO ledger DO INSTEAD NOTHING
    """)

    # Indexes for common query patterns
    op.execute("CREATE INDEX IF NOT EXISTS idx_ledger_tenant_instance ON ledger(tenant_id, instance_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_ledger_tenant_ts ON ledger(tenant_id, timestamp DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_ledger_current_hash ON ledger(current_hash)")

    # ── Instances ─────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS instances (
            tenant_id       TEXT NOT NULL,
            instance_id     TEXT NOT NULL,
            current_state   TEXT NOT NULL,
            protocol_hash   TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT NOW()::TEXT,
            PRIMARY KEY (tenant_id, instance_id)
        )
    """)

    # ── Governance ────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS approved_models (
            model_version TEXT PRIMARY KEY,
            added_at      TEXT NOT NULL DEFAULT NOW()::TEXT
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS approved_agents (
            agent_version TEXT PRIMARY KEY,
            added_at      TEXT NOT NULL DEFAULT NOW()::TEXT
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS approved_policies (
            policy_version TEXT PRIMARY KEY,
            active         BOOLEAN NOT NULL DEFAULT TRUE,
            added_at       TEXT NOT NULL DEFAULT NOW()::TEXT
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS protocols (
            id            BIGSERIAL PRIMARY KEY,
            protocol_hash TEXT UNIQUE NOT NULL,
            spec_json     TEXT NOT NULL,
            active        BOOLEAN NOT NULL DEFAULT TRUE,
            created_at    TEXT NOT NULL DEFAULT NOW()::TEXT
        )
    """)

    # ── Audit log ─────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS verification_audit (
            id              BIGSERIAL PRIMARY KEY,
            tenant_id       TEXT    NOT NULL,
            trace_id        TEXT    NOT NULL,
            instance_id     TEXT,
            sequence_id     INTEGER,
            proof_id        TEXT,
            verified_at     TEXT    NOT NULL,
            result          TEXT    NOT NULL CHECK(result IN ('valid','invalid')),
            failure_code    TEXT,
            failure_msg     TEXT,
            key_id          TEXT,
            governance_json TEXT,
            recorded_at     TEXT    NOT NULL,
            sequence_num    INTEGER NOT NULL DEFAULT 0,
            row_hash        TEXT    NOT NULL DEFAULT '',
            prev_chain_hash TEXT    NOT NULL DEFAULT '',
            chain_hash      TEXT    NOT NULL DEFAULT '',
            UNIQUE(tenant_id, sequence_num)
        )
    """)

    # Append-only: block UPDATE/DELETE via rules
    op.execute("""
        CREATE OR REPLACE RULE audit_no_update AS
            ON UPDATE TO verification_audit DO INSTEAD NOTHING
    """)
    op.execute("""
        CREATE OR REPLACE RULE audit_no_delete AS
            ON DELETE TO verification_audit DO INSTEAD NOTHING
    """)

    op.execute("CREATE INDEX IF NOT EXISTS idx_va_tenant_verified ON verification_audit(tenant_id, verified_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_va_trace ON verification_audit(trace_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_va_tenant_instance ON verification_audit(tenant_id, instance_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_va_tenant_seq ON verification_audit(tenant_id, sequence_num)")


def downgrade() -> None:
    for t in [
        "verification_audit", "protocols", "approved_policies",
        "approved_agents", "approved_models", "instances", "ledger",
    ]:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")