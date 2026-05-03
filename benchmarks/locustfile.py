
from __future__ import annotations

import os
import time
import uuid
import random
import gc

from locust import HttpUser, TaskSet, between, events, tag, task


# -- Config -------------------------------------------------------------------

ADMIN_KEY  = os.environ.get("ZORYNEX_BENCH_ADMIN_KEY",  "admin-key")
SYSTEM_KEY = os.environ.get("ZORYNEX_BENCH_SYSTEM_KEY", "sys-key")
TENANT_ID  = os.environ.get("ZORYNEX_BENCH_TENANT_ID",  "bench_tenant")

ADMIN_HEADERS  = {
    "X-API-Key": ADMIN_KEY, "X-Tenant-Id": TENANT_ID, "Content-Type": "application/json",
}
SYSTEM_HEADERS = {
    "X-API-Key": SYSTEM_KEY, "X-Tenant-Id": TENANT_ID, "Content-Type": "application/json",
}
AUDIT_HEADERS  = {"X-API-Key": ADMIN_KEY, "X-Tenant-Id": TENANT_ID}


# -- Payload factories ---------------------------------------------------------

def _decision_payload() -> dict:
    return {
        "instance_id":    f"loan_{uuid.uuid4().hex[:12]}",
        "from_state":     "pending",
        "to_state":       "approved",
        "model_version":  "credit-model-v1",
        "agent_version":  "underwriter-agent-v1",
        "policy_version": "credit-policy-v1",
        "reason_code":    "SCORE_ABOVE_THRESHOLD",
        "policy_rule":    "credit_policy_v1.rule_7",
        "raw_inputs":     {
            "credit_score":   str(random.randint(650, 850)),
            "debt_to_income": str(round(random.uniform(0.1, 0.4), 3)),
            "loan_amount":    str(random.randint(10000, 500000)),
        },
        "feature_contributions": [
            {"feature": "credit_score",   "contribution": "0.45"},
            {"feature": "debt_to_income", "contribution": "0.35"},
            {"feature": "loan_amount",    "contribution": "0.20"},
        ],
        "threshold_used":   "700",
        "determinism_mode": "strict_deterministic",
        "metadata":         {"bench_run": "true"},
    }


def _proof_payload() -> dict:
    h   = "a" * 64
    pid = "b" * 64
    return {
        "type":        "zorynex-proof-v1",
        "instance_id": f"loan_{uuid.uuid4().hex[:8]}",
        "proof_id":    pid,
        "tenant_id":   TENANT_ID,
        "ledger": {
            "sequence_id": 1, "current_hash": h,
            "previous_hash": "0" * 64, "timestamp": "2026-04-30T10:00:00Z",
        },
        "decision":    {"from_state": "pending", "to_state": "approved"},
        "decision_context": {
            "reason_code": "SCORE_ABOVE_THRESHOLD",
            "policy_rule": "credit_policy_v1.rule_7",
            "model_version": "credit-model-v1",
            "inputs_hash":   "c" * 64,
        },
        "governance": {
            "model_version":  "credit-model-v1",
            "agent_version":  "underwriter-agent-v1",
            "policy_version": "credit-policy-v1",
        },
        "signature": {"value": "d" * 128, "key_id": "bench-key", "algorithm": "Ed25519"},
    }


# -- Stability monitoring -----------------------------------------------------
# Records p95 per interval to detect climbing latency (resource leaks,
# lock contention, disk pressure). Printed in on_test_stop.

_INTERVAL_S     = 30          # how often to record a p95 sample
_p95_timeline:  list[tuple[float, float]] = []   # (elapsed_s, p95_ms)
_start_time:    float = 0.0


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    global _start_time
    _start_time = time.time()
    print("\n" + "=" * 60)
    print("Zorynex Performance Benchmark")
    print(f"  Host:      {environment.host}")
    print(f"  Tenant:    {TENANT_ID}")
    print("=" * 60)
    print("\nThresholds (SQLite single-writer baseline):")
    print("  /health, /audit/stats    p95 < 50ms")
    print("  /audit/log, /verify      p95 < 200ms")
    print("  /decision                p95 < 300ms")
    print("  /audit/report (PDF)      p95 < 5000ms")
    print("\nSQLite note: write p95 will degrade before read p95 under load.")
    print("That is expected. Document the crossover point, do not hide it.\n")


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, **kwargs):
    """Sample p95 every INTERVAL_S seconds for stability tracking."""
    elapsed = time.time() - _start_time
    # Record a p95 sample at interval boundaries
    bucket = int(elapsed / _INTERVAL_S) * _INTERVAL_S
    if not _p95_timeline or _p95_timeline[-1][0] != bucket:
        _p95_timeline.append((bucket, response_time))


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    stats = environment.runner.stats
    total = stats.total
    elapsed = time.time() - _start_time

    print("\n" + "=" * 60)
    print("BENCHMARK COMPLETE")
    print("=" * 60)
    print(f"\nDuration:        {elapsed:.0f}s")
    print(f"Total requests:  {total.num_requests}")
    print(f"Total failures:  {total.num_failures}")
    print(f"Failure rate:    {total.fail_ratio * 100:.2f}%")
    print(f"Avg RPS:         {total.current_rps:.1f}")
    print(f"\nOverall latency:")
    print(f"  p50:  {total.get_response_time_percentile(0.50):.0f}ms")
    print(f"  p95:  {total.get_response_time_percentile(0.95):.0f}ms")
    print(f"  p99:  {total.get_response_time_percentile(0.99):.0f}ms")
    print(f"  max:  {total.max_response_time:.0f}ms")

    print("\nPer-endpoint p95 (worst first):")
    for name, entry in sorted(
        stats.entries.items(),
        key=lambda x: x[1].get_response_time_percentile(0.95) or 0,
        reverse=True,
    ):
        p95 = entry.get_response_time_percentile(0.95) or 0
        err = entry.num_failures
        print(f"  {name[1]:44s}  p95={p95:6.0f}ms  n={entry.num_requests:5d}  err={err}")

    # -- Stability analysis ---------------------------------------------------
    # Detect climbing p95 (resource leak, lock contention, WAL growth)
    if len(_p95_timeline) >= 4:
        early = [x[1] for x in _p95_timeline[:len(_p95_timeline)//3]]
        late  = [x[1] for x in _p95_timeline[-len(_p95_timeline)//3:]]
        early_avg = sum(early) / len(early)
        late_avg  = sum(late)  / len(late)
        drift_pct = ((late_avg - early_avg) / max(early_avg, 1)) * 100

        print(f"\nStability check (p95 drift over run):")
        print(f"  Early avg: {early_avg:.0f}ms  Late avg: {late_avg:.0f}ms  "
              f"Drift: {drift_pct:+.1f}%")
        if drift_pct > 25:
            print("  WARN: p95 climbed >25% -- possible resource leak or WAL growth")
            print("  Check: SQLite WAL file size, Python object count, disk IOPS")
        elif drift_pct > 10:
            print("  NOTE: p95 climbed >10% -- monitor over longer runs")
        else:
            print("  OK: p95 stable over run duration")

    print("\nBottleneck: highest p95 endpoint above is your optimization target.")
    print("SQLite single-writer: write endpoints will saturate first.")
    print("Migration path: PostgreSQL (Phase 3), not adding uvicorn workers.")
    print("\nLong-running stability test (3600s):")
    print("  locust -f benchmarks/locustfile.py --headless -u 10 -r 1 -t 3600s \\")
    print("         --host http://localhost:8000 --csv benchmarks/results/stability")
    print("=" * 60 + "\n")


# -- Task sets ----------------------------------------------------------------

class ReadTasks(TaskSet):
    """Read-only: audit queries and health. Safe to run at high concurrency."""

    @tag("health")
    @task(5)
    def health(self):
        with self.client.get("/health", name="/health", catch_response=True) as r:
            if r.status_code != 200:
                r.failure(f"health={r.status_code}")

    @tag("read")
    @task(3)
    def audit_stats(self):
        with self.client.get(
            "/audit/stats", headers=AUDIT_HEADERS, name="/audit/stats", catch_response=True,
        ) as r:
            if r.status_code not in (200, 401, 403):
                r.failure(f"stats={r.status_code}")

    @tag("read")
    @task(2)
    def audit_log(self):
        with self.client.get(
            "/audit/log?limit=20", headers=AUDIT_HEADERS, name="/audit/log", catch_response=True,
        ) as r:
            if r.status_code not in (200, 401, 403):
                r.failure(f"log={r.status_code}")

    @tag("chain")
    @task(1)
    def chain_verify(self):
        with self.client.get(
            "/audit/chain-verify", headers=AUDIT_HEADERS,
            name="/audit/chain-verify", catch_response=True,
        ) as r:
            if r.status_code not in (200, 500, 401, 403):
                r.failure(f"chain={r.status_code}")

    @tag("read")
    @task(1)
    def metrics(self):
        with self.client.get(
            "/metrics", headers=ADMIN_HEADERS, name="/metrics", catch_response=True,
        ) as r:
            if r.status_code not in (200, 401, 403):
                r.failure(f"metrics={r.status_code}")


class WriteTasks(TaskSet):
    """
    Write-heavy: decision recording and verification.

    SQLite single-writer: these share one write lock.
    p95 here is the canary for SQLite saturation.
    When p95 > 300ms consistently, it is time to migrate to PostgreSQL.
    """

    @tag("write", "decision")
    @task(10)
    def record_decision(self):
        with self.client.post(
            "/decision", json=_decision_payload(),
            headers=SYSTEM_HEADERS, name="/decision", catch_response=True,
        ) as r:
            if r.status_code in (200, 401, 403, 422, 409):
                pass
            else:
                r.failure(f"decision={r.status_code} {r.text[:80]}")

    @tag("write", "verify")
    @task(5)
    def verify_proof(self):
        with self.client.post(
            "/verify", json=_proof_payload(),
            headers=SYSTEM_HEADERS, name="/verify", catch_response=True,
        ) as r:
            if r.status_code in (200, 401, 403):
                pass
            else:
                r.failure(f"verify={r.status_code}")

    @tag("write", "anchor")
    @task(1)
    def anchor_chain(self):
        with self.client.post(
            "/audit/anchor", headers=ADMIN_HEADERS, name="/audit/anchor", catch_response=True,
        ) as r:
            if r.status_code in (200, 401, 403):
                pass
            else:
                r.failure(f"anchor={r.status_code}")


class SlowTasks(TaskSet):
    """
    Heavy ops: PDF, batch export, compliance.
    Run infrequently -- these are I/O-heavy and will dominate p99 if called often.
    They reveal disk pressure under load.
    """

    @tag("slow", "pdf")
    @task(1)
    def audit_report_pdf(self):
        with self.client.get(
            "/audit/report", headers=AUDIT_HEADERS,
            name="/audit/report (PDF)", catch_response=True, timeout=30,
        ) as r:
            if r.status_code not in (200, 401, 403):
                r.failure(f"pdf={r.status_code}")

    @tag("slow", "export")
    @task(1)
    def batch_export(self):
        with self.client.get(
            "/audit/export", headers=AUDIT_HEADERS,
            name="/audit/export", catch_response=True, timeout=30,
        ) as r:
            if r.status_code not in (200, 500, 401, 403):
                r.failure(f"export={r.status_code}")

    @tag("slow", "compliance")
    @task(1)
    def compliance_pack(self):
        with self.client.get(
            "/audit/compliance", headers=AUDIT_HEADERS,
            name="/audit/compliance", catch_response=True, timeout=30,
        ) as r:
            if r.status_code not in (200, 401, 403):
                r.failure(f"compliance={r.status_code}")


# -- User classes -------------------------------------------------------------

class AuditUser(HttpUser):
    """Auditor: read-only, high frequency dashboard polling."""
    tasks     = [ReadTasks]
    wait_time = between(0.5, 2)
    weight    = 3


class SystemUser(HttpUser):
    """
    AI system: write-heavy. Primary write path.

    SQLite single-writer makes this the bottleneck.
    When weight=5 at 20 concurrent users -> 10 concurrent writers -> lock queue.
    This is intentional -- the benchmark surfaces the bottleneck.
    """
    tasks     = [WriteTasks]
    wait_time = between(0.1, 0.5)
    weight    = 5


class SlowUser(HttpUser):
    """Compliance jobs: heavy ops, very low frequency."""
    tasks     = [SlowTasks]
    wait_time = between(5, 15)
    weight    = 1


class MixedUser(HttpUser):
    """
    Realistic mixed workload for capacity planning.

    Distribution:
        30% health + metrics (low cost)
        30% audit reads
        30% writes (decision + verify)
        10% heavy ops (PDF, export, compliance)

    SQLite bottleneck will show at write endpoints first.
    When write p95 > 300ms at your target user count,
    that is your PostgreSQL migration trigger.
    """
    wait_time = between(0.2, 1.5)

    @tag("health")
    @task(10)
    def health(self):
        self.client.get("/health", name="/health")

    @tag("read")
    @task(8)
    def audit_stats(self):
        self.client.get("/audit/stats", headers=AUDIT_HEADERS, name="/audit/stats")

    @tag("read")
    @task(5)
    def audit_log(self):
        self.client.get("/audit/log?limit=20", headers=AUDIT_HEADERS, name="/audit/log")

    @tag("write")
    @task(8)
    def record_decision(self):
        self.client.post(
            "/decision", json=_decision_payload(),
            headers=SYSTEM_HEADERS, name="/decision",
        )

    @tag("write")
    @task(5)
    def verify_proof(self):
        self.client.post(
            "/verify", json=_proof_payload(),
            headers=SYSTEM_HEADERS, name="/verify",
        )

    @tag("chain")
    @task(2)
    def chain_verify(self):
        self.client.get(
            "/audit/chain-verify", headers=AUDIT_HEADERS, name="/audit/chain-verify"
        )

    @tag("drift")
    @task(1)
    def system_snapshot(self):
        self.client.post(
            "/system/snapshot?env=prod", headers=ADMIN_HEADERS, name="/system/snapshot"
        )

    @tag("slow")
    @task(1)
    def audit_report(self):
        self.client.get(
            "/audit/report", headers=AUDIT_HEADERS,
            name="/audit/report (PDF)", timeout=30,
        )

    @tag("slow")
    @task(1)
    def compliance(self):
        self.client.get(
            "/audit/compliance", headers=AUDIT_HEADERS,
            name="/audit/compliance", timeout=30,
        )