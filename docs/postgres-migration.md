# Zorynex — PostgreSQL Operations Guide

Covers: zero-downtime migration, read/write separation, backup/restore, connection exhaustion, failover procedures.

---

## Zero-downtime migration from SQLite to PostgreSQL

### Why it is safe to do live

The Zorynex ledger is **append-only**. There are no UPDATE or DELETE operations on proof data. This means:

1. You can copy existing rows to PostgreSQL while the SQLite instance is still serving traffic
2. Any new rows written to SQLite during the copy can be caught up afterward
3. Cutover is atomic: update `ZORYNEX_BACKEND=postgres` and restart

### Step-by-step runbook

```bash
# 1. Provision PostgreSQL (version 14+)
#    Recommended: RDS PostgreSQL, Cloud SQL, or self-managed with streaming replication

# 2. Create the database and user
psql -h $PG_HOST -U postgres << 'SQL'
CREATE DATABASE zorynex;
CREATE USER zorynex WITH PASSWORD 'strong-password-here';
GRANT ALL PRIVILEGES ON DATABASE zorynex TO zorynex;
SQL

# 3. Set environment
export DATABASE_URL=postgresql://zorynex:password@$PG_HOST:5432/zorynex

# 4. Run migrations (creates all tables with production constraints + indexes)
alembic upgrade head

# Verify tables exist
psql $DATABASE_URL -c "\dt"

# 5. Export existing SQLite data
python - << 'PYEOF'
import json, sqlite3

conn = sqlite3.connect("provable_ai.db")
conn.row_factory = sqlite3.Row

# Export ledger
rows = conn.execute("SELECT * FROM ledger ORDER BY id").fetchall()
with open("/tmp/ledger_export.jsonl", "w") as f:
    for row in rows:
        f.write(json.dumps(dict(row)) + "\n")

# Export governance
gov = {
    "models":   [r["model_version"] for r in conn.execute("SELECT * FROM approved_models")],
    "agents":   [r["agent_version"] for r in conn.execute("SELECT * FROM approved_agents")],
    "policies": [r["policy_version"] for r in conn.execute("SELECT * FROM approved_policies")],
}
with open("/tmp/governance_export.json", "w") as f:
    json.dump(gov, f)

print(f"Exported {len(rows)} ledger entries")
PYEOF

# 6. Import to PostgreSQL
python - << 'PYEOF'
import json, psycopg2

conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur  = conn.cursor()

# Import governance
with open("/tmp/governance_export.json") as f:
    gov = json.load(f)

for m in gov["models"]:
    cur.execute("INSERT INTO approved_models (model_version) VALUES (%s) ON CONFLICT DO NOTHING", (m,))
for a in gov["agents"]:
    cur.execute("INSERT INTO approved_agents (agent_version) VALUES (%s) ON CONFLICT DO NOTHING", (a,))
for p in gov["policies"]:
    cur.execute("INSERT INTO approved_policies (policy_version, active) VALUES (%s, TRUE) ON CONFLICT DO NOTHING", (p,))

# Import ledger
with open("/tmp/ledger_export.jsonl") as f:
    for line in f:
        row = json.loads(line)
        cur.execute("""
            INSERT INTO ledger (
                tenant_id, instance_id, sequence_id,
                previous_hash, current_hash, signature, key_id,
                protocol_hash, from_state, to_state,
                model_version, agent_version, policy_version,
                metadata_json, proof_json, timestamp
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT DO NOTHING
        """, (
            row.get("tenant_id","default"), row["instance_id"], row["sequence_id"],
            row["previous_hash"], row["current_hash"], row["signature"], row.get("key_id","legacy"),
            row.get("protocol_hash",""), row.get("from_state",""), row.get("to_state",""),
            row.get("model_version",""), row.get("agent_version",""), row.get("policy_version",""),
            row.get("metadata_json","{}"), row.get("proof_json","{}"), row.get("timestamp",""),
        ))

conn.commit()
print("Import complete")
PYEOF

# 7. Verify row counts match
sqlite3 provable_ai.db "SELECT COUNT(*) FROM ledger"
psql $DATABASE_URL -c "SELECT COUNT(*) FROM ledger"

# 8. Cutover (requires restart — typically < 30 seconds)
export ZORYNEX_BACKEND=postgres
export ZORYNEX_WORKERS=4
docker-compose restart zorynex   # or: systemctl restart zorynex

# 9. Verify health
curl http://localhost:8000/health
curl http://localhost:8000/ready
```

---

## Read/write separation

Use `PostgreSQLHardenedStorage` with a read replica to route read traffic off the primary.

```bash
# Environment variables
export DATABASE_URL=postgresql://zorynex:pass@primary:5432/zorynex
export DATABASE_URL_REPLICA=postgresql://zorynex:pass@replica:5432/zorynex
```

```python
from provable_ai.postgres_storage import PostgreSQLHardenedStorage

storage = PostgreSQLHardenedStorage(
    write_dsn="postgresql://zorynex:pass@primary/zorynex",
    read_dsn= "postgresql://zorynex:pass@replica/zorynex",
)

# Writes go to primary, reads go to replica
storage.append_ledger_entry(proof_dict)   # → primary
chain = storage.get_ledger_chain(id)      # → replica

# Replica failure: reads fall back to primary automatically
# Pool metrics
print(storage.pool_metrics())
```

**Replication lag:** In typical streaming replication, lag is < 100ms. For audit queries where consistency is critical, set `ZORYNEX_READ_CONSISTENCY=strong` to route all reads to the primary.

---

## Backup and restore

### Continuous backup with WAL archiving (recommended)

```bash
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'aws s3 cp %p s3://your-bucket/wal/%f'

# Take base backup
pg_basebackup -h $PG_HOST -U zorynex -D /backup/base \
    --wal-method=stream --checkpoint=fast --progress

# Restore to point in time
pg_restore -h $NEW_HOST -U postgres -d zorynex /backup/base
# Then replay WAL from S3 to desired timestamp
```

### Daily logical backup (simpler)

```bash
# Backup (runs in < 1 minute for typical Zorynex DB sizes)
pg_dump $DATABASE_URL \
    --format=custom \
    --compress=9 \
    --file=/backup/zorynex_$(date +%Y%m%d).dump

# Restore
pg_restore --clean --if-exists -d $DATABASE_URL \
    /backup/zorynex_20260501.dump
```

### Verify backup integrity

```bash
# Restore to a test instance and run chain verification
export DATABASE_URL=postgresql://zorynex:pass@test-host/zorynex_restored
pg_restore -d $DATABASE_URL /backup/zorynex_20260501.dump

# Verify all chains intact
curl -H "X-API-Key: admin-key" http://test-host:8000/audit/chain-verify
```

---

## Connection exhaustion

Zorynex uses pgBouncer in production (transaction pooling). Without it, each uvicorn worker holds connections open and you can exhaust PostgreSQL's `max_connections`.

```
Without pgBouncer: 4 workers × 20 pool_max = 80 connections (can hit PG limit)
With pgBouncer:    80 client connections → 20 actual server connections
```

### Signs of exhaustion

```
StorageUnavailable: Pool 'write' exhausted
FATAL: remaining connection slots are reserved for non-replication superuser connections
```

### Fix

```bash
# docker-compose.prod.yml already includes pgBouncer
# Tune PGBOUNCER_DEFAULT_POOL_SIZE to match your PG max_connections:
# PGBOUNCER_DEFAULT_POOL_SIZE = max_connections × 0.8 / number_of_services

# Monitor
psql $DATABASE_URL -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state"
```

---

## Failover procedures

### Primary failure

```bash
# 1. Detect: health check returns 500, /ready shows database=error
# 2. Promote replica (if streaming replication)
pg_ctl promote -D /var/lib/postgresql/data

# 3. Update DATABASE_URL to point to promoted replica
export DATABASE_URL=postgresql://zorynex:pass@replica:5432/zorynex

# 4. Restart app workers
docker-compose restart zorynex

# 5. Verify
curl http://localhost:8000/ready
```

### Connection pool saturation failover

```bash
# Increase max_connections temporarily
psql -c "ALTER SYSTEM SET max_connections = 300; SELECT pg_reload_conf();"

# Terminate idle connections older than 5 minutes
psql -c "
    SELECT pg_terminate_backend(pid)
    FROM pg_stat_activity
    WHERE state = 'idle'
      AND query_start < NOW() - INTERVAL '5 minutes'
      AND datname = 'zorynex'
"
```

### RDS Multi-AZ failover

RDS automatically promotes the standby. DNS endpoint is unchanged.

Expected behavior:
- Inflight transactions fail (psycopg2 connection error)
- `PostgreSQLHardenedStorage` retries 3 times with exponential backoff
- Reconnects automatically after DNS propagates (typically 30-60 seconds)
- No data loss (synchronous replication on Multi-AZ)

---

## Monitoring queries

```sql
-- Active connections by state
SELECT state, count(*) FROM pg_stat_activity
WHERE datname = 'zorynex' GROUP BY state;

-- Slowest queries (requires pg_stat_statements)
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
WHERE query ILIKE '%ledger%'
ORDER BY mean_exec_time DESC LIMIT 10;

-- Table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;

-- Replication lag
SELECT client_addr, state,
       pg_size_pretty(pg_wal_lsn_diff(sent_lsn, replay_lsn)) AS lag
FROM pg_stat_replication;

-- Index usage (identify unused indexes)
SELECT indexrelname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
WHERE idx_scan = 0 AND schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;
```