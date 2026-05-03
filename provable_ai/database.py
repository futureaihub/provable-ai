"""
Zorynex — PostgreSQL Connection Pool
======================================
Thread-safe psycopg2 connection pool with configurable min/max.

Design decisions:
    - psycopg2 (sync) not asyncpg — the server is sync FastAPI + uvicorn,
      not async. asyncpg requires an event loop; psycopg2 does not.
    - ThreadedConnectionPool — one connection per thread, safe under uvicorn
      workers. With 4 workers and pool max=20, each worker gets up to 5 conns.
    - Pool is initialised once at import time via get_pool(). Subsequent calls
      return the same instance (singleton).
    - Connection timeout: 5s acquire, 30s statement.

Environment variables:
    DATABASE_URL          postgres://user:pass@host:5432/dbname   (preferred)
    PGHOST / PGPORT / PGDATABASE / PGUSER / PGPASSWORD            (fallback)
    ZORYNEX_POOL_MIN      minimum idle connections  (default: 2)
    ZORYNEX_POOL_MAX      maximum total connections (default: 20)

Usage:
    from provable_ai.database import get_pool, get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Generator

import psycopg2
import psycopg2.extras
import psycopg2.pool

logger = logging.getLogger("zorynex.database")

_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _dsn() -> str:
    """Build DSN from DATABASE_URL or individual PG* env vars."""
    url = os.environ.get("DATABASE_URL", "")
    if url:
        return url
    return " ".join(filter(None, [
        f"host={v}"     if (v := os.environ.get("PGHOST",     "localhost")) else "",
        f"port={v}"     if (v := os.environ.get("PGPORT",     "5432"))     else "",
        f"dbname={v}"   if (v := os.environ.get("PGDATABASE", "zorynex"))  else "",
        f"user={v}"     if (v := os.environ.get("PGUSER",     "zorynex"))  else "",
        f"password={v}" if (v := os.environ.get("PGPASSWORD", ""))         else "",
    ]))


def get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        min_conn = int(os.environ.get("ZORYNEX_POOL_MIN", "2"))
        max_conn = int(os.environ.get("ZORYNEX_POOL_MAX", "20"))
        dsn = _dsn()
        logger.info("Initialising PostgreSQL pool min=%d max=%d", min_conn, max_conn)
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            dsn=dsn,
            connect_timeout=5,
            options="-c statement_timeout=30000",  # 30s per statement
        )
    return _pool


@contextlib.contextmanager
def get_conn() -> Generator[psycopg2.extensions.connection, None, None]:
    """
    Context manager: acquire a connection from the pool, return it on exit.

    Automatically rolls back uncommitted work on exception, then returns
    the connection to the pool in a clean state.

    Usage:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(...)
            conn.commit()
    """
    pool = get_pool()
    conn = pool.getconn()
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def close_pool() -> None:
    """Gracefully close all pool connections. Call on server shutdown."""
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None
        logger.info("PostgreSQL pool closed")


# ---------------------------------------------------------------------------
# SQLAlchemy compatibility shim
# test_phase2.py was written against an earlier SQLAlchemy-based database.py
# that exposed a declarative `Base`. Our current database.py uses a raw
# psycopg2 pool. This stub keeps the old import working without changing
# any behavior. Tests that actually USE Base will still fail (they test a
# different architecture), but the collection error is eliminated.
# ---------------------------------------------------------------------------
try:
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):
        pass

except ImportError:
    # SQLAlchemy not installed — provide a minimal placeholder so the import
    # succeeds even without SQLAlchemy in the environment.
    class Base:  # type: ignore[no-redef]
        """Placeholder Base for environments without SQLAlchemy."""
        metadata = None