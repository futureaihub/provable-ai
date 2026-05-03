
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# ── Constants ─────────────────────────────────────────────────────────────────

QUERY_MAX_LIMIT: int = 1000   # hard cap on any single query result set
GENESIS_HASH:    str = "0" * 64   # chain starts here (no predecessor)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class VerificationAuditEntry:
    """
    One verification event.

    New fields vs v1:
        row_hash        — integrity hash of this row's content
        prev_chain_hash — chain link to previous row (GENESIS_HASH for first row)
        chain_hash      — SHA-256(prev_chain_hash + row_hash)
    """
    tenant_id:       str
    trace_id:        str
    instance_id:     str | None
    sequence_id:     int | None
    proof_id:        str | None
    verified_at:     str
    result:          str            # "valid" | "invalid"
    failure_code:    str | None
    failure_msg:     str | None
    key_id:          str | None
    governance_json: str | None
    recorded_at:     str
    sequence_num:    int = 0        # explicit monotonic per-tenant sequence (portable)
    # Hash chain fields
    row_hash:        str = ""       # set on insert
    prev_chain_hash: str = ""       # GENESIS_HASH for first row per tenant
    chain_hash:      str = ""       # SHA-256(prev_chain_hash + row_hash)


@dataclass
class AuditQueryResult:
    entries:   list[VerificationAuditEntry]
    total:     int
    tenant_id: str
    from_date: str | None
    to_date:   str | None


@dataclass
class ChainVerificationResult:
    valid:        bool
    total_rows:   int
    broken_at_id: int | None        # DB id of first broken row (None if valid)
    failure_msg:  str | None


# ── Hash chain helpers ────────────────────────────────────────────────────────

def _compute_row_hash(entry: VerificationAuditEntry) -> str:
    """
    SHA-256 of canonical row content.

    sequence_num is included — any reordering of rows changes this hash,
    making ordering tampering detectable by chain verification.
    governance_json is included verbatim (already canonical JSON).
    """
    content = {
        "tenant_id":       entry.tenant_id,
        "trace_id":        entry.trace_id,
        "instance_id":     entry.instance_id,
        "sequence_id":     entry.sequence_id,
        "sequence_num":    entry.sequence_num,   # ordering tamper detection
        "proof_id":        entry.proof_id,
        "verified_at":     entry.verified_at,
        "result":          entry.result,
        "failure_code":    entry.failure_code,
        "failure_msg":     entry.failure_msg,
        "key_id":          entry.key_id,
        "governance_json": entry.governance_json,
        "recorded_at":     entry.recorded_at,
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_chain_hash(prev_chain_hash: str, row_hash: str) -> str:
    """SHA-256(prev_chain_hash_bytes + row_hash_bytes)."""
    data = bytes.fromhex(prev_chain_hash) + bytes.fromhex(row_hash)
    return hashlib.sha256(data).hexdigest()


def compute_audit_leaf(entry: VerificationAuditEntry) -> str:
    """
    Compute the Merkle leaf for this audit entry.

    Leaf content includes full audit context — two different audit states
    cannot produce the same leaf, and therefore cannot produce the same root.

    Fields included:
        tenant_id, instance_id, sequence_id, result, verified_at, failure_code
    """
    leaf_content = "|".join([
        entry.tenant_id or "",
        entry.instance_id or "",
        str(entry.sequence_id) if entry.sequence_id is not None else "",
        entry.result,
        entry.verified_at,
        entry.failure_code or "",
    ])
    return hashlib.sha256(leaf_content.encode("utf-8")).hexdigest()


# ── Audit log ─────────────────────────────────────────────────────────────────

class VerificationAuditLog:
    """
    Tamper-evident, append-only verification audit log.

    Tamper evidence mechanism:
        - row_hash:        SHA-256 of row content → detects field modification
        - chain_hash:      SHA-256(prev_chain_hash + row_hash) → detects insertion/deletion
        - verify_chain():  walks all rows in order, recomputes every link → proves integrity

    Any modification (change a field, delete a row, insert a row, restore old DB)
    will break the chain from that point forward.

    Thread safety: connection-per-thread via threading.local.
    Tenant isolation: every query has WHERE tenant_id = ?
    Pagination: hard cap of QUERY_MAX_LIMIT (1000) rows per query.
    """

    def __init__(self, db_path: str = "provable_ai_audit.db") -> None:
        self.db_path = db_path
        self._local  = threading.local()
        self._init_db()

    # ── Connection ────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verification_audit (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
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
                UNIQUE(tenant_id, sequence_num)  -- strictly one row per sequence per tenant
            )
        """)

        # Append-only: triggers block UPDATE and DELETE at DB engine level
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS no_update_verification_audit
            BEFORE UPDATE ON verification_audit
            BEGIN
                SELECT RAISE(ABORT, 'verification_audit is append-only: UPDATE not permitted');
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS no_delete_verification_audit
            BEFORE DELETE ON verification_audit
            BEGIN
                SELECT RAISE(ABORT, 'verification_audit is append-only: DELETE not permitted');
            END
        """)

        # Indexes — (tenant_id, verified_at) is the primary query pattern
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_va_tenant_verified_at
            ON verification_audit(tenant_id, verified_at)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_va_trace_id
            ON verification_audit(trace_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_va_instance_id
            ON verification_audit(tenant_id, instance_id)
        """)
        # Chain verification walks by (tenant_id, id ASC)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_va_tenant_id_asc
            ON verification_audit(tenant_id, id ASC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_va_tenant_seq
            ON verification_audit(tenant_id, sequence_num)
        """)
        conn.commit()

    # ── Write ─────────────────────────────────────────────────────────────────

    def record(
        self,
        tenant_id:     str,
        trace_id:      str,
        proof_dict:    dict[str, Any],
        verify_result: dict[str, Any],
    ) -> VerificationAuditEntry:
        """
        Record a verification event — both successes and failures.

        Args:
            tenant_id:     from X-Tenant-Id header
            trace_id:      from X-Trace-Id header
            proof_dict:    the submitted proof.json (may be malformed)
            verify_result: output of verify_proof_full()

        Chain maintenance:
            Fetches the previous row's chain_hash for this tenant,
            computes row_hash from content, computes chain_hash, inserts.
            All three steps happen inside a single connection — atomic.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Extract proof identity (best-effort — proof may be malformed)
        instance_id = _safe_get(proof_dict, "instance_id")
        sequence_id = _safe_get_int(proof_dict, "ledger", "sequence_id")
        proof_id    = _safe_get(proof_dict, "proof_id")
        verified_at = verify_result.get("verified_at") or now

        # ALWAYS record failures — incomplete audit trail fails compliance
        result       = "valid" if verify_result.get("valid") else "invalid"
        failure      = verify_result.get("failure_reason") or {}
        failure_code = failure.get("type")    if failure else None
        failure_msg  = failure.get("message") if failure else None
        key_id       = verify_result.get("key_id")

        gov      = verify_result.get("governance_recorded")
        gov_json = (
            json.dumps(gov, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if gov else None
        )

        entry = VerificationAuditEntry(
            tenant_id=tenant_id, trace_id=trace_id,
            instance_id=instance_id, sequence_id=sequence_id,
            proof_id=proof_id, verified_at=verified_at,
            result=result, failure_code=failure_code, failure_msg=failure_msg,
            key_id=key_id, governance_json=gov_json, recorded_at=now,
        )

        # ── Hash chain ────────────────────────────────────────────────────────
        conn = self._conn()

        # Get previous chain_hash + sequence_num for this tenant
        prev_row = conn.execute(
            "SELECT chain_hash FROM verification_audit WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        prev_chain_hash = prev_row["chain_hash"] if prev_row else GENESIS_HASH

        # Explicit monotonic sequence — portable across DB engines
        seq_row = conn.execute(
            "SELECT COALESCE(MAX(sequence_num), 0) FROM verification_audit WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        sequence_num = (seq_row[0] or 0) + 1
        entry.sequence_num = sequence_num

        row_hash   = _compute_row_hash(entry)
        chain_hash = _compute_chain_hash(prev_chain_hash, row_hash)

        entry.row_hash        = row_hash
        entry.prev_chain_hash = prev_chain_hash
        entry.chain_hash      = chain_hash

        conn.execute("""
            INSERT INTO verification_audit (
                tenant_id, trace_id, instance_id, sequence_id, proof_id,
                verified_at, result, failure_code, failure_msg,
                key_id, governance_json, recorded_at,
                sequence_num, row_hash, prev_chain_hash, chain_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.tenant_id, entry.trace_id, entry.instance_id,
            entry.sequence_id, entry.proof_id, entry.verified_at,
            entry.result, entry.failure_code, entry.failure_msg,
            entry.key_id, entry.governance_json, entry.recorded_at,
            entry.sequence_num, entry.row_hash, entry.prev_chain_hash, entry.chain_hash,
        ))
        conn.commit()
        return entry

    # ── Chain verification ────────────────────────────────────────────────────

    def verify_chain(self, tenant_id: str) -> ChainVerificationResult:
        """
        Walk every row for this tenant in insertion order and recompute the chain.

        Returns ChainVerificationResult:
            valid=True  → chain is intact, no tampering detected
            valid=False → chain broken at broken_at_id

        Algorithm:
            1. Fetch all rows ORDER BY id ASC
            2. For each row: recompute row_hash from stored fields
            3. Recompute chain_hash = SHA-256(prev_chain_hash + row_hash)
            4. Compare against stored chain_hash
            5. Fail immediately on first mismatch
        """
        rows = self._conn().execute(
            """SELECT * FROM verification_audit
               WHERE tenant_id=? ORDER BY id ASC""",
            (tenant_id,),
        ).fetchall()

        if not rows:
            return ChainVerificationResult(
                valid=True, total_rows=0,
                broken_at_id=None, failure_msg=None,
            )

        prev_chain_hash = GENESIS_HASH
        for row in rows:
            entry = _row_to_entry(row)

            # Recompute row_hash from stored content
            expected_row_hash   = _compute_row_hash(entry)
            expected_chain_hash = _compute_chain_hash(prev_chain_hash, expected_row_hash)

            if row["row_hash"] != expected_row_hash:
                return ChainVerificationResult(
                    valid=False, total_rows=len(rows),
                    broken_at_id=row["id"],
                    failure_msg=(
                        f"Row id={row['id']}: row_hash mismatch. "
                        f"Stored={row['row_hash'][:16]}... "
                        f"Expected={expected_row_hash[:16]}..."
                    ),
                )

            if row["chain_hash"] != expected_chain_hash:
                return ChainVerificationResult(
                    valid=False, total_rows=len(rows),
                    broken_at_id=row["id"],
                    failure_msg=(
                        f"Row id={row['id']}: chain_hash mismatch. "
                        f"Chain is broken at this point — data was modified."
                    ),
                )

            prev_chain_hash = row["chain_hash"]

        return ChainVerificationResult(
            valid=True, total_rows=len(rows),
            broken_at_id=None, failure_msg=None,
        )

    def verify_chain_at_block(
        self,
        tenant_id:      str,
        sequence_num:   int,
    ) -> dict[str, Any]:
        """
        Verify chain state at a specific sequence_num (block).

        Returns the chain_hash at that block and whether the chain was
        intact from genesis up to that point.

        Use case: prove chain state at time of audit export.
        """
        rows = self._conn().execute(
            """SELECT * FROM verification_audit
               WHERE tenant_id=? AND sequence_num<=?
               ORDER BY sequence_num ASC""",
            (tenant_id, sequence_num),
        ).fetchall()

        if not rows:
            return {
                "valid": True, "sequence_num": sequence_num,
                "chain_hash": GENESIS_HASH, "total_rows": 0,
            }

        prev_chain_hash = GENESIS_HASH
        for row in rows:
            entry = _row_to_entry(row)
            expected_rh = _compute_row_hash(entry)
            expected_ch = _compute_chain_hash(prev_chain_hash, expected_rh)
            if row["row_hash"] != expected_rh or row["chain_hash"] != expected_ch:
                return {
                    "valid": False,
                    "sequence_num": sequence_num,
                    "chain_hash": None,
                    "total_rows": len(rows),
                    "broken_at_sequence": row["sequence_num"],
                }
            prev_chain_hash = row["chain_hash"]

        return {
            "valid": True,
            "sequence_num": sequence_num,
            "chain_hash": prev_chain_hash,
            "total_rows": len(rows),
        }

    # ── Read ──────────────────────────────────────────────────────────────────

    def query(
        self,
        tenant_id:   str,
        from_date:   str | None = None,
        to_date:     str | None = None,
        result:      str | None = None,   # "valid" | "invalid" | None = both
        instance_id: str | None = None,
        limit:       int        = 100,
        offset:      int        = 0,
    ) -> AuditQueryResult:
        """
        Query the audit log with optional filters.

        Hard cap: max QUERY_MAX_LIMIT (1000) rows regardless of requested limit.
        Tenant isolation: all queries scoped to tenant_id.
        """
        # Enforce pagination hard cap
        limit = min(limit, QUERY_MAX_LIMIT)

        params: list[Any] = [tenant_id]
        where  = ["tenant_id = ?"]

        if from_date:
            where.append("verified_at >= ?")
            params.append(from_date)
        if to_date:
            where.append("verified_at <= ?")
            params.append(to_date)
        if result in ("valid", "invalid"):
            where.append("result = ?")
            params.append(result)
        if instance_id:
            where.append("instance_id = ?")
            params.append(instance_id)

        where_sql = " AND ".join(where)

        total_row = self._conn().execute(
            f"SELECT COUNT(*) FROM verification_audit WHERE {where_sql}", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        rows = self._conn().execute(
            f"""SELECT * FROM verification_audit
                WHERE {where_sql}
                ORDER BY verified_at DESC, id DESC
                LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()

        return AuditQueryResult(
            entries=[_row_to_entry(r) for r in rows],
            total=total, tenant_id=tenant_id,
            from_date=from_date, to_date=to_date,
        )

    def get_by_trace(self, tenant_id: str, trace_id: str) -> list[VerificationAuditEntry]:
        """Fetch all audit entries for a specific trace_id. Tenant-scoped."""
        rows = self._conn().execute(
            "SELECT * FROM verification_audit WHERE tenant_id=? AND trace_id=? ORDER BY id",
            (tenant_id, trace_id),
        ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def count(self, tenant_id: str) -> int:
        """Total verification count for a tenant."""
        row = self._conn().execute(
            "SELECT COUNT(*) FROM verification_audit WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        return row[0] if row else 0

    def get_latest_chain_hash(self, tenant_id: str) -> str:
        """Latest chain_hash for a tenant. GENESIS_HASH if no rows yet."""
        row = self._conn().execute(
            "SELECT chain_hash FROM verification_audit WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        return row["chain_hash"] if row else GENESIS_HASH

    def stats(self, tenant_id: str) -> dict[str, Any]:
        """Summary statistics for a tenant's verification activity."""
        row = self._conn().execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN result='valid'   THEN 1 ELSE 0 END) as valid_count,
                SUM(CASE WHEN result='invalid' THEN 1 ELSE 0 END) as invalid_count,
                MIN(verified_at) as first_verified,
                MAX(verified_at) as last_verified
            FROM verification_audit WHERE tenant_id=?
        """, (tenant_id,)).fetchone()

        if not row or row["total"] == 0:
            return {
                "total": 0, "valid": 0, "invalid": 0,
                "valid_rate": 0.0,
                "first_verified": None, "last_verified": None,
                "chain_hash": GENESIS_HASH,
            }

        return {
            "total":          row["total"],
            "valid":          row["valid_count"]   or 0,
            "invalid":        row["invalid_count"] or 0,
            "valid_rate":     round((row["valid_count"] or 0) / row["total"] * 100, 1),
            "first_verified": row["first_verified"],
            "last_verified":  row["last_verified"],
            "chain_hash":     self.get_latest_chain_hash(tenant_id),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_get(d: dict, *keys: str) -> str | None:
    try:
        val = d
        for k in keys:
            val = val[k]
        return str(val) if val is not None else None
    except (KeyError, TypeError):
        return None


def _safe_get_int(d: dict, *keys: str) -> int | None:
    try:
        val = d
        for k in keys:
            val = val[k]
        return int(val) if val is not None else None
    except (KeyError, TypeError, ValueError):
        return None


def _row_to_entry(row: sqlite3.Row) -> VerificationAuditEntry:
    return VerificationAuditEntry(
        tenant_id=row["tenant_id"],           trace_id=row["trace_id"],
        instance_id=row["instance_id"],       sequence_id=row["sequence_id"],
        proof_id=row["proof_id"],             verified_at=row["verified_at"],
        result=row["result"],                 failure_code=row["failure_code"],
        failure_msg=row["failure_msg"],       key_id=row["key_id"],
        governance_json=row["governance_json"], recorded_at=row["recorded_at"],
        sequence_num=row["sequence_num"] if "sequence_num" in row.keys() else 0,
        row_hash=row["row_hash"],             prev_chain_hash=row["prev_chain_hash"],
        chain_hash=row["chain_hash"],
    )


# ── Singleton ─────────────────────────────────────────────────────────────────

_audit_log: VerificationAuditLog | None = None


def get_audit_log() -> VerificationAuditLog:
    global _audit_log
    if _audit_log is None:
        path = os.environ.get("ZORYNEX_AUDIT_DB_PATH", "zorynex_audit.db")
        _audit_log = VerificationAuditLog(db_path=path)
    return _audit_log