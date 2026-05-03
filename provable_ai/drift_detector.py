"""
Zorynex — System Root + Drift Detection
=========================================
Detects state drift across environments (dev, staging, prod) and over time.

What is drift?
    The system root hash is SHA-256 of all latest proof hashes for a tenant.
    If the same instance_id set has the same latest proofs in two environments,
    their system roots should match. If they differ, data diverged.

Use cases:
    1. Cross-environment consistency: prod vs staging have the same data?
    2. Temporal drift: system root changed unexpectedly between two time points?
    3. Replication check: replica DB agrees with primary?
    4. Post-migration verification: data intact after DB migration?

Drift record:
    {
      "snapshot_id":   "snap_<uuid>",
      "tenant_id":     "bank_abc",
      "environment":   "prod",
      "system_root":   "a3f8...",
      "instance_count": 142,
      "chain_hash":    "b9c2...",
      "proof_count":   1440,
      "recorded_at":   "2026-04-30T12:00:00Z",
    }

Drift result:
    {
      "drifted":       True/False,
      "drift_type":    "root_mismatch" | "chain_mismatch" | "count_mismatch" | None,
      "details":       {...},
      "severity":      "CRITICAL" | "WARNING" | "OK",
    }

Usage:
    from provable_ai.drift_detector import DriftDetector, take_snapshot

    # Take a snapshot of current state
    snap = take_snapshot(storage, audit_log, tenant_id="bank_abc", env="prod")

    # Compare two snapshots (e.g. prod vs staging)
    result = DriftDetector.compare(snap_prod, snap_staging)

    # Compare against a baseline (stored snapshot)
    detector = DriftDetector(db_path="zorynex_drift.db")
    baseline = detector.get_latest(tenant_id, "prod")
    result   = detector.compare_against_baseline(snap_now, baseline)
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# ── Snapshot ──────────────────────────────────────────────────────────────────

@dataclass
class SystemSnapshot:
    """
    Point-in-time snapshot of the system state for a tenant in an environment.
    All fields are deterministic — same state always produces same values.
    """
    snapshot_id:    str
    tenant_id:      str
    environment:    str        # "dev" | "staging" | "prod" | custom
    system_root:    str        # SHA-256 root from compute_system_root()
    instance_count: int        # number of unique instances in ledger
    audit_chain_hash: str      # latest chain_hash of audit log
    audit_row_count: int       # total audit log rows
    recorded_at:    str        # ISO-8601 UTC


@dataclass
class DriftResult:
    """Result of comparing two snapshots or a snapshot against a baseline."""
    drifted:       bool
    drift_type:    str | None       # "root_mismatch" | "chain_mismatch" | "count_mismatch" | "combined"
    severity:      str              # "OK" | "WARNING" | "CRITICAL"
    snap_a:        SystemSnapshot
    snap_b:        SystemSnapshot
    details:       dict[str, Any]
    recommendation: str


# ── Detector ──────────────────────────────────────────────────────────────────

class DriftDetector:
    """
    Stores snapshots and compares them for drift.

    Storage: append-only SQLite (separate from audit + anchor DBs).
    Snapshots are never deleted — they form a historical record.
    """

    def __init__(self, db_path: str = "zorynex_drift.db") -> None:
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
            CREATE TABLE IF NOT EXISTS snapshots (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id     TEXT NOT NULL UNIQUE,
                tenant_id       TEXT NOT NULL,
                environment     TEXT NOT NULL,
                system_root     TEXT NOT NULL,
                instance_count  INTEGER NOT NULL,
                audit_chain_hash TEXT NOT NULL,
                audit_row_count  INTEGER NOT NULL,
                recorded_at     TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS drift_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   TEXT NOT NULL,
                env_a       TEXT NOT NULL,
                env_b       TEXT NOT NULL,
                snap_a_id   TEXT NOT NULL,
                snap_b_id   TEXT NOT NULL,
                drifted     INTEGER NOT NULL,
                drift_type  TEXT,
                severity    TEXT NOT NULL,
                details_json TEXT NOT NULL,
                detected_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_snap_tenant_env ON snapshots(tenant_id, environment)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_snap_recorded ON snapshots(tenant_id, recorded_at)")
        conn.commit()

    # ── Snapshot management ───────────────────────────────────────────────────

    def save_snapshot(self, snap: SystemSnapshot) -> SystemSnapshot:
        """Persist a snapshot. Idempotent by snapshot_id."""
        conn = self._conn()
        conn.execute("""
            INSERT OR IGNORE INTO snapshots
                (snapshot_id, tenant_id, environment, system_root, instance_count,
                 audit_chain_hash, audit_row_count, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snap.snapshot_id, snap.tenant_id, snap.environment,
            snap.system_root, snap.instance_count,
            snap.audit_chain_hash, snap.audit_row_count, snap.recorded_at,
        ))
        conn.commit()
        return snap

    def get_latest(self, tenant_id: str, environment: str) -> SystemSnapshot | None:
        """Get the most recent snapshot for a tenant+environment."""
        row = self._conn().execute(
            """SELECT * FROM snapshots WHERE tenant_id=? AND environment=?
               ORDER BY recorded_at DESC LIMIT 1""",
            (tenant_id, environment),
        ).fetchone()
        return _row_to_snapshot(row) if row else None

    def get_snapshot(self, snapshot_id: str) -> SystemSnapshot | None:
        row = self._conn().execute(
            "SELECT * FROM snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()
        return _row_to_snapshot(row) if row else None

    def list_snapshots(self, tenant_id: str, limit: int = 20) -> list[SystemSnapshot]:
        rows = self._conn().execute(
            """SELECT * FROM snapshots WHERE tenant_id=?
               ORDER BY recorded_at DESC LIMIT ?""",
            (tenant_id, min(limit, 100)),
        ).fetchall()
        return [_row_to_snapshot(r) for r in rows]

    # ── Comparison ────────────────────────────────────────────────────────────

    @staticmethod
    def compare(snap_a: SystemSnapshot, snap_b: SystemSnapshot) -> DriftResult:
        """
        Compare two snapshots. Returns DriftResult describing any drift.

        Drift types:
            root_mismatch  — system roots differ (proof data diverged)
            chain_mismatch — audit chains differ (audit history diverged)
            count_mismatch — instance or row counts differ
            combined       — multiple drift indicators
        """
        issues: list[str] = []
        details: dict[str, Any] = {
            "snap_a": {
                "id": snap_a.snapshot_id, "env": snap_a.environment,
                "recorded_at": snap_a.recorded_at,
                "system_root": snap_a.system_root,
                "instance_count": snap_a.instance_count,
                "audit_chain_hash": snap_a.audit_chain_hash,
                "audit_row_count": snap_a.audit_row_count,
            },
            "snap_b": {
                "id": snap_b.snapshot_id, "env": snap_b.environment,
                "recorded_at": snap_b.recorded_at,
                "system_root": snap_b.system_root,
                "instance_count": snap_b.instance_count,
                "audit_chain_hash": snap_b.audit_chain_hash,
                "audit_row_count": snap_b.audit_row_count,
            },
            "mismatches": {},
        }

        if snap_a.system_root != snap_b.system_root:
            issues.append("root_mismatch")
            details["mismatches"]["system_root"] = {
                snap_a.environment: snap_a.system_root,
                snap_b.environment: snap_b.system_root,
            }

        if snap_a.audit_chain_hash != snap_b.audit_chain_hash:
            issues.append("chain_mismatch")
            details["mismatches"]["audit_chain_hash"] = {
                snap_a.environment: snap_a.audit_chain_hash,
                snap_b.environment: snap_b.audit_chain_hash,
            }

        if snap_a.instance_count != snap_b.instance_count:
            issues.append("count_mismatch")
            details["mismatches"]["instance_count"] = {
                snap_a.environment: snap_a.instance_count,
                snap_b.environment: snap_b.instance_count,
            }
        elif snap_a.audit_row_count != snap_b.audit_row_count:
            # Same instances but different audit counts — partial drift
            issues.append("count_mismatch")
            details["mismatches"]["audit_row_count"] = {
                snap_a.environment: snap_a.audit_row_count,
                snap_b.environment: snap_b.audit_row_count,
            }

        if not issues:
            return DriftResult(
                drifted=False, drift_type=None, severity="OK",
                snap_a=snap_a, snap_b=snap_b, details=details,
                recommendation="No drift detected. Environments are consistent.",
            )

        drift_type  = "combined" if len(issues) > 1 else issues[0]
        severity    = _severity(issues)
        recommendation = _recommendation(drift_type, snap_a.environment, snap_b.environment)

        return DriftResult(
            drifted=True, drift_type=drift_type, severity=severity,
            snap_a=snap_a, snap_b=snap_b, details=details,
            recommendation=recommendation,
        )

    def compare_against_baseline(
        self,
        snap_now:  SystemSnapshot,
        baseline:  SystemSnapshot | None,
    ) -> DriftResult:
        """
        Compare current snapshot against a stored baseline.
        If no baseline exists, saves snap_now as the baseline and returns OK.
        """
        if baseline is None:
            self.save_snapshot(snap_now)
            return DriftResult(
                drifted=False, drift_type=None, severity="OK",
                snap_a=snap_now, snap_b=snap_now,
                details={"note": "No baseline found — snap_now saved as first baseline."},
                recommendation="Baseline established. Run again to detect drift.",
            )
        return self.compare(baseline, snap_now)

    def record_drift_event(self, result: DriftResult) -> None:
        """Persist a drift result for audit trail."""
        now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = self._conn()
        conn.execute("""
            INSERT INTO drift_events
                (tenant_id, env_a, env_b, snap_a_id, snap_b_id,
                 drifted, drift_type, severity, details_json, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.snap_a.tenant_id,
            result.snap_a.environment, result.snap_b.environment,
            result.snap_a.snapshot_id, result.snap_b.snapshot_id,
            1 if result.drifted else 0,
            result.drift_type, result.severity,
            json.dumps(result.details, sort_keys=True),
            now,
        ))
        conn.commit()

    def drift_history(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
        """Recent drift events for a tenant."""
        rows = self._conn().execute(
            """SELECT * FROM drift_events WHERE tenant_id=?
               ORDER BY detected_at DESC LIMIT ?""",
            (tenant_id, min(limit, 100)),
        ).fetchall()
        return [
            {
                "env_a": r["env_a"], "env_b": r["env_b"],
                "snap_a_id": r["snap_a_id"], "snap_b_id": r["snap_b_id"],
                "drifted":  bool(r["drifted"]),
                "drift_type": r["drift_type"], "severity": r["severity"],
                "detected_at": r["detected_at"],
            }
            for r in rows
        ]


# ── Snapshot factory ──────────────────────────────────────────────────────────

def take_snapshot(
    storage:    Any,    # SQLiteStorage
    audit_log:  Any,    # VerificationAuditLog
    tenant_id:  str,
    environment: str = "prod",
    anchor_externally: bool = True,
) -> SystemSnapshot:
    """
    Capture the current system state for drift detection.

    External anchoring:
        When anchor_externally=True (default in prod), the system_root is
        written to the anchor store. This means:
          - If someone rewrites the entire proof DB consistently, the system
            root changes — and the anchor store (separate file, separate volume)
            holds the old root. Drift is detectable cross-system, not just
            internally.
          - anchor_externally=False is correct for dev/test environments
            where network TSA calls are unwanted.

    Args:
        storage:           SQLiteStorage instance (proof ledger)
        audit_log:         VerificationAuditLog instance
        tenant_id:         which tenant to snapshot
        environment:       "dev" | "staging" | "prod" | custom label
        anchor_externally: write system_root to anchor store (default True)

    Returns:
        SystemSnapshot with all current state values.
    """
    from provable_ai.verifier import compute_system_root

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # System root from proof ledger — fetch latest hashes per instance
    try:
        cur = storage.conn.cursor()
        cur.execute("""
            SELECT instance_id, current_hash FROM ledger
            WHERE tenant_id=? AND sequence_id = (
                SELECT MAX(l2.sequence_id) FROM ledger l2
                WHERE l2.instance_id = ledger.instance_id
                  AND l2.tenant_id   = ledger.tenant_id
            )
            ORDER BY instance_id
        """, (tenant_id,))
        rows           = cur.fetchall()
        latest_hashes  = [r["current_hash"] for r in rows]
        instance_count = len(rows)
        system_root    = compute_system_root(latest_hashes)
    except Exception:
        system_root    = "0" * 64
        instance_count = 0

    # Audit log state
    audit_chain_hash = audit_log.get_latest_chain_hash(tenant_id)
    audit_row_count  = audit_log.count(tenant_id)

    snap = SystemSnapshot(
        snapshot_id=f"snap_{uuid.uuid4().hex[:16]}",
        tenant_id=tenant_id,
        environment=environment,
        system_root=system_root,
        instance_count=instance_count,
        audit_chain_hash=audit_chain_hash,
        audit_row_count=audit_row_count,
        recorded_at=now,
    )

    # ── External anchoring ────────────────────────────────────────────────────
    # Anchoring the system_root outside the proof DB closes the "full DB
    # rewrite" attack vector. An attacker who rewrites the DB to produce a
    # consistent internal hash chain still cannot forge the anchor store entry
    # (separate file, separate volume, RFC 3161 timestamp from a third party).
    #
    # The anchor key used: f"system_root:{tenant_id}:{environment}"
    # This ties the root to a specific tenant + environment so cross-env
    # comparisons remain meaningful.
    if anchor_externally and system_root != "0" * 64:
        try:
            from provable_ai.audit_anchor import get_anchor_store
            # We anchor the system_root as the chain_hash for this snapshot.
            # The anchor store records: root value + timestamp + RFC 3161 token.
            # request_rfc3161 follows ZORYNEX_ANCHOR_RFC3161 env var.
            import os
            use_rfc3161 = os.environ.get("ZORYNEX_ANCHOR_RFC3161", "true").lower() == "true"
            get_anchor_store().anchor(
                tenant_id=tenant_id,
                chain_hash=system_root,   # anchor the system_root hash
                request_rfc3161=use_rfc3161,
            )
        except Exception as e:
            # Anchor failure must never break snapshot — log and continue
            import logging
            logging.getLogger("zorynex.drift").warning(
                "system_root anchor failed (snapshot still saved): %s", e
            )

    return snap


def snapshot_to_dict(snap: SystemSnapshot) -> dict[str, Any]:
    """Serialize snapshot to a JSON-safe dict for API responses."""
    return {
        "snapshot_id":     snap.snapshot_id,
        "tenant_id":       snap.tenant_id,
        "environment":     snap.environment,
        "system_root":     snap.system_root,
        "instance_count":  snap.instance_count,
        "audit_chain_hash": snap.audit_chain_hash,
        "audit_row_count": snap.audit_row_count,
        "recorded_at":     snap.recorded_at,
    }


def drift_result_to_dict(result: DriftResult) -> dict[str, Any]:
    """Serialize drift result for API responses."""
    return {
        "drifted":         result.drifted,
        "drift_type":      result.drift_type,
        "severity":        result.severity,
        "recommendation":  result.recommendation,
        "snap_a":          snapshot_to_dict(result.snap_a),
        "snap_b":          snapshot_to_dict(result.snap_b),
        "details":         result.details,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity(issues: list[str]) -> str:
    """
    CRITICAL: proof data diverged (root_mismatch) — data integrity at risk
    WARNING:  audit or count mismatch — investigate but not yet critical
    """
    if "root_mismatch" in issues:
        return "CRITICAL"
    if "combined" in issues or len(issues) > 1:
        return "CRITICAL"
    return "WARNING"


def _recommendation(drift_type: str, env_a: str, env_b: str) -> str:
    recs = {
        "root_mismatch": (
            f"CRITICAL: Proof ledger has diverged between {env_a} and {env_b}. "
            f"Do not trust either environment until the cause is identified. "
            f"Compare ledger entries manually and check for unauthorized DB writes."
        ),
        "chain_mismatch": (
            f"Audit log chains differ between {env_a} and {env_b}. "
            f"Verify chain integrity on both: GET /audit/chain-verify. "
            f"This may indicate different verification activity, not data corruption."
        ),
        "count_mismatch": (
            f"Instance or audit counts differ between {env_a} and {env_b}. "
            f"This is expected if environments are not fully synced. "
            f"If they should be identical, check for missing sync."
        ),
        "combined": (
            f"Multiple drift indicators between {env_a} and {env_b}. "
            f"This is CRITICAL — treat as potential data integrity incident. "
            f"Isolate both environments and compare ledger entries."
        ),
    }
    return recs.get(drift_type, "Investigate drift before proceeding.")


def _row_to_snapshot(row: sqlite3.Row) -> SystemSnapshot:
    return SystemSnapshot(
        snapshot_id=row["snapshot_id"], tenant_id=row["tenant_id"],
        environment=row["environment"], system_root=row["system_root"],
        instance_count=row["instance_count"],
        audit_chain_hash=row["audit_chain_hash"],
        audit_row_count=row["audit_row_count"],
        recorded_at=row["recorded_at"],
    )


# ── Singleton ─────────────────────────────────────────────────────────────────

_detector: DriftDetector | None = None


def get_drift_detector() -> DriftDetector:
    global _detector
    if _detector is None:
        path = os.environ.get("ZORYNEX_DRIFT_DB_PATH", "zorynex_drift.db")
        _detector = DriftDetector(db_path=path)
    return _detector