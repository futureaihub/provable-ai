# Zorynex — Business Continuity

**Audience:** Operations teams, enterprise procurement, vendor risk reviewers.

---

## Recovery Objectives

| Scenario | RTO | RPO |
|---|---|---|
| Server crash (single instance) | < 2 minutes | 0 — append-only ledger, no data loss |
| KMS primary unavailable | Automatic failover < 30s | 0 |
| Database corruption | < 4 hours (restore from backup) | Last backup interval |
| Full infrastructure loss | < 24 hours | Last backup interval |

---

## Proof Durability

Proof artifacts are durable by design:

- **Exported packages are self-contained.** Once a `proof.json` is exported, it is permanently verifiable with no server access. Customers who export proofs before an outage are unaffected.
- **The ledger is append-only.** No proof entry can be modified or deleted. Recovery from backup restores the complete history.
- **Verification is offline.** Auditors can verify exported proofs during any outage — the verifier has zero server dependency.

---

## Backup Strategy

### SQLite (development / small production)

```bash
# Daily backup — copy DB files while server is running (SQLite WAL mode is safe)
cp provable_ai.db provable_ai.db.$(date +%Y%m%d)
cp zorynex_keyregistry.db zorynex_keyregistry.db.$(date +%Y%m%d)

# Off-site: sync to S3
aws s3 sync /var/zorynex/data/ s3://your-bucket/zorynex-backups/$(date +%Y%m%d)/
```

### PostgreSQL (production)

```bash
# Continuous WAL archiving for point-in-time recovery
# Configure in postgresql.conf:
# archive_mode = on
# archive_command = 'aws s3 cp %p s3://your-bucket/wal/%f'

# Daily logical backup
pg_dump zorynex_db | gzip > zorynex_$(date +%Y%m%d).sql.gz
```

### Key Registry

Back up the key registry separately from the proof ledger. The key registry maps key IDs to public keys — losing it does not invalidate proofs (public keys are embedded in each proof), but it impairs the ability to look up historical key metadata.

---

## High Availability

### Multi-worker PostgreSQL

```bash
# Production: multiple Uvicorn workers with PostgreSQL
ZORYNEX_BACKEND=postgres
ZORYNEX_WORKERS=4
DATABASE_URL=postgresql://user:pass@db-primary:5432/zorynex

# PostgreSQL advisory locking prevents concurrent chain writes
# Read/write split via PostgreSQLHardenedStorage
```

### KMS Failover

`FailoverSigner` provides automatic signing continuity:

```bash
ZORYNEX_KMS_KEY_ID=alias/zorynex-prod          # primary
ZORYNEX_KMS_FALLBACK_KEY_ID=alias/zorynex-dr   # fallback
ZORYNEX_KMS_REGION=us-east-1
```

Primary → fallback transition: automatic on KMS error.
Failback to primary: automatic when primary recovers.
Both keys tracked in key registry — all proofs remain verifiable.

---

## Deployment Checklist

Before declaring production-ready:

```
☐ ZORYNEX_BACKEND=postgres (not sqlite for multi-worker)
☐ Daily database backups configured and tested
☐ KMS primary + fallback keys both provisioned
☐ ZORYNEX_ANCHOR_RFC3161=true (external timestamps)
☐ SIEM transport configured and receiving events
☐ GET /ready returns 200 (DB + signer both healthy)
☐ Backup restore tested — verified proofs from restored DB
☐ Runbook for KMS failure available to on-call team
```

---

## Data Retention

- **Proof ledger:** Permanent. No automatic deletion. Append-only by design and database trigger enforcement.
- **Audit log:** Configurable. Default: retained indefinitely. Purge via `POST /audit/purge` (admin only) if required by data retention policy.
- **RFC 3161 anchors:** Permanent. Correspond to proof entries — deleting them removes independent timestamp evidence.
- **Raw inputs:** Never stored. Only `SHA-256(inputs)` is written to the ledger. GDPR deletion requests are addressed by noting that raw PII never entered the system.

---

## Vendor Dependencies

| Dependency | Purpose | Fallback |
|---|---|---|
| AWS KMS | Ed25519 signing (production) | `EnvSigner` (file-based key) |
| FreeTSA | RFC 3161 external timestamps | Proofs remain valid without timestamps |
| PyNaCl / libsodium | Ed25519 cryptography | No fallback — required for signing |
| PostgreSQL | Production ledger storage | SQLite (single-worker only) |