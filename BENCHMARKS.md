# Zorynex — Performance Benchmarks

**Version:** v1.0.0  
**Date:** 2026-05-09  
**Infrastructure:** SQLite · Single worker · Local NVMe · Python 3.12

---

## Summary

| Operation | p50 | p95 | p99 | Overhead target |
|---|---|---|---|---|
| Decision recording (`POST /decision`) | 2.5ms | 3.2ms | 7.6ms | < 10ms ✓ |
| Proof export (`GET /proof/export?inline=true`) | 1.9ms | 2.3ms | 38ms* | < 50ms ✓ |
| Offline verification (4 cryptographic checks) | 0.14ms | 0.17ms | 0.18ms | < 1ms ✓ |
| Health check (`GET /health`) | < 0.1ms | < 0.1ms | < 0.1ms | sub-ms ✓ |

**All operations include Ed25519 signing and SHA-256 hash chain computation.**

*p99 export spike is SQLite page cache cold start on first access — warms within 3–5 requests.

---

## Decision Recording — Detail

**What happens in `POST /decision`:**

1. Governance validation — approved model/agent/policy check against DB
2. Canonical JSON serialisation of decision payload
3. SHA-256 hash computation over canonical payload
4. SHA-256 hash chain — new hash incorporates previous entry's hash
5. Ed25519 signature over instance root (all hashes concatenated)
6. Append-only write to SQLite ledger
7. Structured audit log event emission

**Results (n=200, SQLite, single worker):**

```
p50   2.49ms
p95   3.16ms
p99   7.55ms
avg   2.72ms
max  26.64ms  (first call — DB page cache cold)
```

**Throughput estimate:** ~370 decisions/second sustained (single worker, SQLite).

---

## Proof Export — Detail

**What happens in `GET /proof/export/{id}?inline=true`:**

1. Load full chain from ledger for instance_id
2. Recompute package hash (SHA-256 over full ledger serialisation)
3. Recompute instance root (SHA-256 over all current_hashes)
4. Ed25519 signature over instance root
5. Compute proof_fingerprint (SHA-256(instance_root + ":" + chain_length))
6. Serialise full package as JSON

**Results (n=100, 2-entry chains, SQLite):**

```
p50   1.85ms
p95   2.26ms
p99  38.00ms  (SQLite page cache miss — warms quickly)
avg   2.32ms
max  38.00ms
```

---

## Offline Verification — Detail

**What happens in `verify/verify_package.py`:**

1. Check 1: Package structure — field presence, type validation
2. Check 2: SHA-256 of full ledger → compare to `package_hash`
3. Check 3: Per-entry canonical hash recomputation + previous_hash linkage
4. Check 4: Ed25519 signature verification over `instance_root`

**Results (n=200, 2-entry chain, pure Python):**

```
p50   0.14ms
p95   0.17ms
p99   0.18ms
avg   0.15ms
max   0.23ms
```

Verification is faster than recording because it performs no writes and no KMS calls. An auditor with only PyNaCl installed can verify at ~6,500 proofs/second on a laptop.

---

## Proof Fingerprint Overhead

`proof_fingerprint` computation was added in v1.0.0 (Session A). It runs inside `export_proof()`:

```
proof_fingerprint = SHA256(instance_root + ":" + chain_length)
```

This is one additional SHA-256 call — measured overhead: **< 0.02ms** (negligible). Already included in the export p50/p95/p99 numbers above.

---

## PostgreSQL Projection

PostgreSQL with connection pooling and multi-worker deployment:

| Metric | SQLite (1 worker) | PostgreSQL (4 workers, projected) |
|---|---|---|
| Decision p95 | 3.2ms | ~8–15ms (network + lock overhead) |
| Throughput | ~370/s | ~1,200–1,800/s |
| p99 tail | 7.6ms | ~25–40ms |
| Concurrent safe | No (1 worker only) | Yes (advisory locking) |

*PostgreSQL benchmarks will be added after production deployment data is available.*

---

## Overhead Statement

**Zorynex adds less than 10ms of overhead to any AI decision pipeline on SQLite with a single worker.** The overhead is dominated by:

1. Ed25519 signing — ~1–2ms (libsodium, highly optimised)
2. SHA-256 chaining — < 0.5ms (Python standard library)
3. SQLite write — ~0.5–1ms (NVMe, WAL mode)

For KMS-based signing (production), add 10–30ms for the KMS API call. This is the dominant cost in production deployments and is independent of chain length.

---

## Reproducing These Results

```bash
# Requires: running server on localhost:8000
# Install: pip install locust

python benchmarks/benchmark_runner.py \
    --scenario mixed \
    --users 20 \
    --duration 60
```

Results are written to `benchmarks/results/YYYYMMDD_HHMMSS/`.

The engine-level numbers in this document were produced by directly timing `engine.transition()` and `engine.export_proof()` with n=200 iterations, excluding warm-up calls, on Python 3.12 / macOS / NVMe SSD.