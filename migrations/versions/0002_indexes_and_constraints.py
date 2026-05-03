
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def _exec_autocommit(sql: str) -> None:
    """
    Execute SQL outside the current transaction block.

    CREATE INDEX CONCURRENTLY requires autocommit mode because PostgreSQL
    does not allow it inside a transaction. We get the raw DBAPI connection,
    set autocommit=True, execute, then restore the previous state.

    This is the correct Alembic pattern for CONCURRENTLY statements.
    Reference: https://alembic.sqlalchemy.org/en/latest/cookbook.html
               #building-an-up-to-date-database-from-scratch
    """
    conn = op.get_bind()
    # Get the raw psycopg2 connection
    raw_conn = conn.connection
    old_autocommit = raw_conn.autocommit
    raw_conn.autocommit = True
    try:
        raw_conn.execute(raw_conn.cursor().__class__.__mro__[0].__init__.__doc__ or "")
    except Exception:
        pass
    try:
        with raw_conn.cursor() as cur:
            cur.execute(sql)
    finally:
        raw_conn.autocommit = old_autocommit


def _concurrent_index(sql: str) -> None:
    """Run a CREATE INDEX CONCURRENTLY outside any transaction."""
    bind = op.get_bind()
    # Alembic 1.x: use execution_options to step outside the transaction
    bind.execute(sa.text("COMMIT"))  # commit the alembic version row transaction
    # Now run index creation with autocommit via raw connection
    raw = bind.connection.connection      # psycopg2 connection
    prev = raw.autocommit
    raw.autocommit = True
    try:
        with raw.cursor() as cur:
            cur.execute(sql)
    finally:
        raw.autocommit = prev
    # Alembic needs a transaction open again for its bookkeeping
    bind.execute(sa.text("BEGIN"))


def upgrade() -> None:
    # Each CONCURRENTLY index runs outside the transaction block.
    # Regular DDL (CHECK constraint, extension) stays inside.

    _concurrent_index("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_approved_policies_active
        ON approved_policies (policy_version)
        WHERE active = TRUE
    """)

    _concurrent_index("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ledger_tenant_seq_desc
        ON ledger (tenant_id, sequence_id DESC)
    """)

    _concurrent_index("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ledger_current_hash
        ON ledger (current_hash)
        WHERE current_hash IS NOT NULL
    """)

    _concurrent_index("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_instances_tenant
        ON instances (tenant_id, instance_id)
    """)

    # These run inside the transaction — no CONCURRENTLY needed
    op.execute("""
        DO $$
        BEGIN
            CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'pg_stat_statements not available: %', SQLERRM;
        END;
        $$
    """)

    op.execute("""
        DO $$
        BEGIN
            ALTER TABLE ledger ADD CONSTRAINT chk_sequence_positive
                CHECK (sequence_id > 0);
        EXCEPTION WHEN duplicate_object THEN
            NULL;
        END;
        $$
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE ledger DROP CONSTRAINT IF EXISTS chk_sequence_positive")

    # These don't require CONCURRENTLY for drops (DROP INDEX takes a brief lock)
    for idx in [
        "idx_approved_policies_active",
        "idx_ledger_tenant_seq_desc",
        "idx_ledger_current_hash",
        "idx_instances_tenant",
    ]:
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {idx}")