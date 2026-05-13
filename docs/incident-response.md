# Zorynex — Incident Response

**Audience:** Operations teams, security teams, compliance officers.

---

## Overview

This document defines incident response procedures for a Zorynex deployment. Because Zorynex is self-hosted, incident response is primarily the customer's responsibility. Zorynex provides guidance and support.

**Contact for security incidents:** security@zorynex.co

---

## Incident Classification

| Severity | Definition | Response Time |
|---|---|---|
| P1 — Critical | Signing key compromised, proof ledger inaccessible, all proofs unverifiable | Immediate |
| P2 — High | KMS unavailable, proof export failing, chain integrity violation detected | Within 1 hour |
| P3 — Medium | Single endpoint failing, rate limits exceeded, audit log gaps | Within 4 hours |
| P4 — Low | Non-critical feature degraded, documentation issue | Next business day |

---

## P1 — Signing Key Compromised

**Detection signals:**
- Proofs verifying with an unexpected public key
- Unauthorized access to `ZORYNEX_SIGNING_KEY` environment variable
- AWS KMS CloudTrail shows signing operations from unexpected IAM principals

**Immediate actions:**

1. **Revoke the compromised key immediately**
   - AWS KMS: disable the key via KMS console (do not delete — existing proofs still need the public key for verification)
   - Environment variable: change `ZORYNEX_SIGNING_KEY` to a new key immediately

2. **Block new proof generation**
   - Set `ZORYNEX_API_KEYS` to remove all `system` role keys
   - This prevents new decisions from being signed with the compromised key

3. **Assess the blast radius**
   - Identify the time window during which the key was compromised
   - All proofs signed during that window must be treated as potentially tampered
   - RFC 3161 timestamps (if enabled) provide independent evidence of when each proof was created

4. **Register a new key**
   - Generate new Ed25519 key or create new KMS key
   - Add to Zorynex key registry
   - Configure as new signing key

5. **Restore service**
   - Re-enable `system` role keys
   - All new proofs will use the new key

6. **Notify affected parties**
   - Inform auditors and regulators of the incident
   - Provide the time window and scope of potentially affected proofs

---

## P2 — KMS Unavailable

**Detection signals:**
- `POST /decision` returns `SIGNER_UNAVAILABLE`
- `GET /ready` shows `signer: unavailable`
- CloudWatch alarms on KMS API errors

**Actions:**

1. **Check KMS endpoint availability**
   - Verify AWS KMS is operational in your region (AWS Health Dashboard)
   - Check VPC endpoint configuration if using private endpoints

2. **Verify FailoverSigner is configured**
   - If `ZORYNEX_KMS_FALLBACK_KEY_ID` is set, the fallback key should activate automatically
   - Check logs for `signer_failover` events

3. **Temporary workaround (if no failover configured)**
   - Configure `EnvSigner` with a backup key as temporary measure
   - Document all decisions recorded under the temporary key
   - Re-sign with primary key when KMS is restored (contact Zorynex support for re-signing tooling)

4. **Queue decisions if possible**
   - If your AI system can queue decisions, do so rather than recording without a valid signer
   - Unverifiable proofs are not valid evidence

---

## P2 — Chain Integrity Violation

**Detection signals:**
- `GET /audit/chain-verify` returns `valid: false`
- `CHAIN_BROKEN` or `SEQUENCE_GAP` errors in logs
- Verification failures on exported proofs

**This is a potential security incident.** Treat as such.

**Actions:**

1. **Preserve current state immediately**
   - Do not restart the server
   - Do not run any maintenance jobs
   - Take a database backup immediately

2. **Identify the break point**
   ```bash
   curl http://localhost:8000/audit/chain-verify \
     -H "X-API-Key: admin-key"
   # Response shows which sequence_id has broken linkage
   ```

3. **Determine cause**
   - `SEQUENCE_GAP`: entries are missing — possible deletion or failed write
   - `HASH_MISMATCH`: entry content differs from expected — possible modification
   - Check if database triggers were bypassed (direct DB access?)

4. **Do not attempt to repair the chain**
   - Any modification invalidates the tamper-evidence property
   - Preserve the broken state as forensic evidence

5. **Notify**
   - Contact `security@zorynex.co` immediately
   - Notify your compliance team and legal counsel
   - Preserve all logs from the period surrounding the break

---

## P3 — Audit Log Gap

**Detection signals:**
- SIEM shows gap in Zorynex log events
- `GET /audit/log` shows missing entries

**Actions:**

1. Check if the server was restarted (logs to stdout — not persisted if container was killed)
2. Verify SIEM ingestion pipeline is healthy
3. Check disk space — full disk can prevent logging
4. If gap is in the proof ledger (not just logs), treat as P2

---

## Runbook: Complete Service Failure

```bash
# 1. Check server status
curl http://localhost:8000/health

# 2. Check readiness (DB + signer)
curl http://localhost:8000/ready

# 3. Check recent logs
journalctl -u zorynex --since "1 hour ago" | tail -100

# 4. Verify database integrity
python3 -c "
from provable_ai.storage import SQLiteStorage
s = SQLiteStorage()
cur = s.conn.cursor()
cur.execute('PRAGMA integrity_check')
print(cur.fetchone())
"

# 5. Verify chain integrity
curl http://localhost:8000/audit/chain-verify \
  -H "X-API-Key: $ADMIN_KEY"

# 6. Check system root
curl http://localhost:8000/system/root \
  -H "X-API-Key: $ADMIN_KEY"

# 7. Restart if safe to do so
systemctl restart zorynex
```

---

## Post-Incident

Within 5 business days of a P1 or P2 incident, produce a post-incident report including:

1. **Timeline** — when was the incident detected, what happened when
2. **Root cause** — why did it happen
3. **Blast radius** — what data or proofs are affected
4. **Remediation** — what was done to resolve it
5. **Prevention** — what changes prevent recurrence

Store the post-incident report with your compliance documentation. Regulators may ask for it.

---

## Contact

**Security incidents:** security@zorynex.co

**Operational support:** hanif@zorynex.co

**Response times:** 48-hour acknowledgement, 7-day resolution timeline for security reports.