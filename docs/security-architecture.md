# Zorynex — Security Architecture

**Audience:** Enterprise security teams, InfoSec, CISO offices, vendor security reviewers.

This document describes the security architecture of the Zorynex Provable AI infrastructure layer. It is designed to answer vendor questionnaires, support security reviews, and satisfy pre-pilot due diligence.

---

## System Overview

Zorynex is a self-hosted infrastructure layer. There is no Zorynex cloud. Customer data, proof artifacts, signing keys, and decision records never leave the customer's infrastructure boundary. Zorynex operates entirely within the customer's own environment.

```
Customer Infrastructure Boundary
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   AI System → Zorynex API → Proof Ledger → Exports      │
│                                                         │
│   Signing Key (KMS or local)                            │
│   Audit Logs (customer SIEM)                            │
│   Database (customer-managed SQLite or PostgreSQL)      │
│                                                         │
└─────────────────────────────────────────────────────────┘
         │
         │  Optional: RFC 3161 timestamp request only
         ▼
    FreeTSA (external — receives hash only, never proof content)
```

The only external network call is an optional RFC 3161 timestamp request to FreeTSA. This sends only a SHA-256 hash — never proof content, never customer data.

---

## Cryptographic Architecture

### Signing

| Property | Value |
|---|---|
| Algorithm | Ed25519 (via PyNaCl / libsodium) |
| Key size | 256-bit (32 bytes) |
| Key format | Hex-encoded for storage |
| Private key storage | Environment variable or AWS KMS — never on disk in production |
| Signature covers | SHA-256 hash of the instance root (32 raw bytes) |

### Hashing

| Property | Value |
|---|---|
| Algorithm | SHA-256 (Python standard library `hashlib`) |
| Canonical JSON | UTF-8, `sort_keys=True`, `separators=(",",":")`, no floats, no datetime |
| Hash chain | Each entry's `current_hash` becomes the next entry's `previous_hash` |
| Genesis hash | 64 zero characters — known, auditor-verifiable starting point |
| Package hash | SHA-256 over full ledger serialization — detects any modification |

### What Is Signed vs What Is Hashed

The Ed25519 signature covers the **instance root** — the SHA-256 of all `current_hash` values in sequence. This means the signature covers the entire chain, not individual entries.

Individual proof entries are protected by the **hash chain** — any modification to any field in any entry breaks every subsequent hash. The signature confirms the chain was valid at signing time.

### Proof Fingerprint

```
proof_fingerprint = SHA256(instance_root + ":" + chain_length)
```

Deterministic, auditor-derivable, does not require Zorynex infrastructure to verify.

---

## Key Management

### Development (`EnvSigner`)

- Private key stored as hex in `ZORYNEX_SIGNING_KEY` environment variable
- Key generated automatically by `bootstrap.py` on first run
- Key stored in `provable_key.hex` — excluded from version control via `.gitignore`
- **Not recommended for production**

### Production (`AWSKmsSigner`)

- Private key never leaves AWS KMS
- Signing operations performed inside KMS
- Zorynex only transmits: the 32-byte hash to be signed
- AWS KMS returns: the 64-byte Ed25519 signature
- Key ID configured via `ZORYNEX_KMS_KEY_ID` environment variable

### Failover (`FailoverSigner`)

- Primary KMS → Fallback KMS → automatic failback when primary recovers
- Configurable retry intervals and auto-failback thresholds
- Both keys must be valid Ed25519 keys registered in the key registry

### Key Rotation

1. Generate new key and register in key registry
2. Update `ZORYNEX_KMS_KEY_ID` to new key
3. All future proofs signed with new key
4. **Old proofs remain verifiable** — public key is embedded in every proof artifact
5. Auditors verify using the public key in the proof, not a central registry

---

## Database Security

### Append-Only Enforcement

The proof ledger is enforced append-only at the SQLite trigger level:

```sql
CREATE TRIGGER IF NOT EXISTS ledger_no_update
  BEFORE UPDATE ON ledger
  BEGIN
    SELECT RAISE(ABORT, 'ZORYNEX INTEGRITY VIOLATION: ...');
  END;

CREATE TRIGGER IF NOT EXISTS ledger_no_delete
  BEFORE DELETE ON ledger
  BEGIN
    SELECT RAISE(ABORT, 'ZORYNEX INTEGRITY VIOLATION: ...');
  END;
```

Additional triggers protect governance history:
- `approved_models_no_delete` — governance approvals are permanent records
- `approved_agents_no_delete`
- `approved_policies_no_delete`
- `protocols_no_update` — compiled protocols are immutable
- `protocols_no_delete`

**Even a compromised application layer cannot modify ledger history** — the database will reject the operation at the trigger level.

### PostgreSQL (Production)

- Read/write split with advisory locking prevents duplicate sequence_ids under concurrent writes
- Row-level locking on ledger writes
- Connection pooling with retry logic
- TLS required on all PostgreSQL connections in production

### Multi-Tenant Isolation

- Every database row is scoped by `tenant_id`
- `UNIQUE(tenant_id, instance_id, sequence_id)` — same instance_id cannot exist across tenants
- Tenant ID enforced at application layer and verified at query layer
- No cross-tenant data access is possible without bypassing both layers

---

## API Security

### Authentication

- All endpoints require `X-API-Key` header (except `/health`, `/ready`, `/verify-ui`, `/quickstart`)
- API keys are pre-configured environment variables — no database-backed auth in this version
- Keys are mapped to roles: `admin`, `auditor`, `system`

### RBAC

| Role | Permitted Operations |
|---|---|
| `admin` | Full access — governance, audit, export, verify, monitor, dashboard |
| `system` | Record decisions, create instances |
| `auditor` | Read-only — proofs, chain, compliance exports, dashboard. Cannot write. |

Role violations return HTTP 403 with structured error body. Every role denial is logged as an `auth.role_denied` audit event.

### Rate Limiting

- Per-tenant rate limiting via `slowapi`
- Global rate limiting as secondary layer
- Rate limit headers returned on all responses
- 429 responses include `retry_after` field

### Webhook Security

- HMAC-SHA256 verification on all incoming webhooks
- Nonce-based replay protection with configurable time window
- Webhook secret configured via `ZORYNEX_WEBHOOK_SECRET` environment variable

### TLS

- TLS terminated at nginx reverse proxy in production
- Application server (`uvicorn`) is internal-only, not exposed directly
- nginx configuration included at `nginx/nginx.conf`

---

## Audit Logging

### Structured JSON Logs

All events are emitted as structured JSON to stdout/stderr, capturable by any log aggregator:

```json
{
  "level": "info",
  "message": "decision_recorded",
  "timestamp": "2026-05-09T14:33:01Z",
  "trace_id": "a3f8c2d1-...",
  "tenant_id": "default",
  "instance_id": "loan-9284",
  "sequence_id": 1,
  "key_id": "env-a428fc62..."
}
```

### Admin Audit Trail

Platform admin actions are logged as `event_type: admin_audit`:

```json
{
  "level": "audit",
  "event_type": "admin_audit",
  "action": "governance.model_approved",
  "actor": "dev-key12...",
  "tenant_id": "default",
  "trace_id": "...",
  "ip": "10.0.0.1",
  "timestamp": "2026-05-09T14:33:01Z"
}
```

Events tracked: `governance.model_approved`, `governance.agent_approved`, `governance.policy_approved`, `proof.exported`, `dashboard.viewed`, `auth.role_denied`.

### SIEM Integration

Four transports supported:
- **Webhook** — HMAC-signed HTTP POST to your SIEM endpoint
- **Syslog** — RFC 5424 syslog, UDP or TCP
- **Splunk HEC** — Splunk HTTP Event Collector
- **Datadog** — Datadog Logs API

Configure via `ZORYNEX_SIEM_*` environment variables. See `docs/siem.md` for full configuration.

---

## Network Security

### Inbound

| Port | Protocol | Purpose |
|---|---|---|
| 443 | HTTPS | All API traffic (nginx terminates TLS) |
| 80 | HTTP | Redirect to HTTPS only |

### Outbound

| Destination | Purpose | Required |
|---|---|---|
| AWS KMS endpoint | Signing operations | Yes (if using KMS) |
| FreeTSA (freetsa.org) | RFC 3161 timestamps | No (optional) |
| SIEM endpoint | Audit log forwarding | No (optional) |

### Internal

The application server (`uvicorn`) listens on `127.0.0.1:8000` and is accessible only via nginx reverse proxy. It is not exposed to the network directly.

---

## Vulnerability Management

### Dependencies

Security-critical dependencies:

| Package | Purpose | Version policy |
|---|---|---|
| `pynacl` | Ed25519 signing (libsodium binding) | Pin to minor, update on CVE |
| `fastapi` | API framework | Pin to minor, update monthly |
| `uvicorn` | ASGI server | Pin to minor, update monthly |
| `psycopg2-binary` | PostgreSQL driver | Pin to minor, update on CVE |
| `cryptography` | RFC 3161 timestamp verification | Pin to minor, update on CVE |

Run `pip install --upgrade -r requirements.txt` and review changelogs before each deployment.

### Reporting Vulnerabilities

Email `security@zorynex.co` with description, reproduction steps, and impact assessment. Response within 48 hours. See `SECURITY.md` for full disclosure policy.

---

## Deployment Security Checklist

```
☐ ZORYNEX_SIGNING_KEY from KMS — never from environment variable in production
☐ ZORYNEX_API_KEYS — one key per role, unique per environment, rotated quarterly
☐ ZORYNEX_WEBHOOK_SECRET — rotated if exposed, min 32 chars
☐ ZORYNEX_REQUIRE_TENANT=true — enforced in production
☐ ZORYNEX_ANCHOR_RFC3161=true — external timestamp anchoring enabled
☐ TLS terminated at nginx — uvicorn not exposed directly
☐ Database backups — the ledger IS the evidence. Back it up daily.
☐ Network isolation — API not exposed without nginx
☐ Log aggregation — stdout captured and forwarded to SIEM
☐ Key registry backups — separate from ledger backups
```