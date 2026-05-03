
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Zorynex benchmark runner")
    p.add_argument("--host",     default="http://localhost:8000")
    p.add_argument("--users",    type=int, default=20, help="concurrent users")
    p.add_argument("--ramp",     type=int, default=2,  help="users spawned per second")
    p.add_argument("--duration", type=int, default=60, help="seconds")
    p.add_argument("--scenario", choices=["mixed", "read", "write", "slow"],
                   default="mixed")
    return p.parse_args()


def run_benchmark(args: argparse.Namespace) -> Path:
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir  = Path("benchmarks/results") / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    # Map scenario to locust user class
    user_class_map = {
        "mixed": "MixedUser",
        "read":  "AuditUser",
        "write": "SystemUser",
        "slow":  "SlowUser",
    }
    user_class = user_class_map[args.scenario]

    cmd = [
        sys.executable, "-m", "locust",
        "-f",           "benchmarks/locustfile.py",
        "--headless",
        "--host",       args.host,
        "--users",      str(args.users),
        "--spawn-rate", str(args.ramp),
        "--run-time",   f"{args.duration}s",
        "--csv",        str(out_dir / "stats"),
        "--class-picker",
        user_class,
    ]

    print(f"\nRunning: scenario={args.scenario} users={args.users} "
          f"ramp={args.ramp}/s duration={args.duration}s")
    print(f"Output: {out_dir}\n")

    start = time.time()
    result = subprocess.run(cmd, capture_output=False)
    elapsed = time.time() - start

    # Write summary
    summary = out_dir / "summary.txt"
    with open(summary, "w") as f:
        f.write(f"Zorynex Benchmark Summary\n")
        f.write(f"{'='*50}\n")
        f.write(f"Scenario:   {args.scenario} ({user_class})\n")
        f.write(f"Users:      {args.users}\n")
        f.write(f"Duration:   {args.duration}s\n")
        f.write(f"Host:       {args.host}\n")
        f.write(f"Elapsed:    {elapsed:.1f}s\n")
        f.write(f"Exit code:  {result.returncode}\n\n")
        f.write("Thresholds:\n")
        f.write("  /health, /audit/stats  p95 < 50ms   PASS if ✓\n")
        f.write("  /audit/log, /verify    p95 < 200ms  PASS if ✓\n")
        f.write("  /decision              p95 < 300ms  PASS if ✓\n")
        f.write("  /audit/report (PDF)    p95 < 5000ms PASS if ✓\n\n")
        f.write("See stats.csv for per-endpoint breakdown.\n")
        f.write("\nInterpretation:\n")
        f.write("  - Highest p95 = bottleneck. Profile that first.\n")
        f.write("  - Rising p95 over time = resource leak.\n")
        f.write("  - Error rate > 0% = bug or misconfiguration.\n")
        f.write("  - p99 >> p95 = occasional slow outliers, likely GC or I/O.\n")

    print(f"\nResults written to: {out_dir}")
    return out_dir


if __name__ == "__main__":
    args = parse_args()
    out_dir = run_benchmark(args)
    print(f"\nRun: cat {out_dir}/summary.txt")
    print(f"CSV: {out_dir}/stats_stats.csv")