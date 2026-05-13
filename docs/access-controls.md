# Zorynex — Access Controls

**Audience:** Security reviewers, IAM teams, compliance auditors.

---

## Authentication Model

Zorynex uses static API key authentication. Every request to a protected endpoint requires the `X-API-Key` header. Keys are mapped to roles in the `ZORYNEX_API_KEYS` environment variable.

```bash
# Format: key:role,key:role,...
export ZORYNEX_API_KEYS="prod-admin-key:admin,audit-key:auditor,svc-key:system"
```

Keys are compared using constant-time comparison to prevent timing attacks.

**Public endpoints** (no API key required):
- `GET /health` — liveness probe
- `GET /ready` — readiness probe
- `GET /verify-ui` — browser verifier (runs verification client-side, sends no data to server)
- `GET /quickstart` — documentation page

---

## Role-Based Access Control (RBAC)

Three roles with strict permission boundaries:

### `admin`
Full access to all endpoints. Intended for: integration engineers, DevOps, platform administrators.

### `system`
Write access for recording decisions and creating instances. Intended for: the AI system or service that produces decisions. Should not have read access to audit exports or compliance data.

### `auditor`
Read-only access. Intended for: compliance teams, internal audit, external auditors. Cannot write decisions, cannot modify governance, cannot access metrics.

### Permission Matrix

| Operation | admin | system | auditor |
|---|---|---|---|
| `POST /decision` | ✓ | ✓ | — |
| `POST /instance/create` | ✓ | ✓ | — |
| `POST /demo/bootstrap` | ✓ | — | — |
| `POST /protocol/compile` | ✓ | — | — |
| `POST /governance/model` | ✓ | — | — |
| `POST /governance/agent` | ✓ | — | — |
| `POST /governance/policy` | ✓ | — | — |
| `GET /governance/status` | ✓ | ✓ | ✓ |
| `GET /proof/{id}` | ✓ | ✓ | ✓ |
| `GET /chain/{id}` | ✓ | ✓ | ✓ |
| `GET /proof/export/{id}` | ✓ | ✓ | ✓ |
| `POST /verify-package` | ✓ | ✓ | ✓ |
| `GET /audit/log` | ✓ | — | ✓ |
| `GET /audit/compliance` | ✓ | — | ✓ |
| `GET /audit/report` | ✓ | — | ✓ |
| `GET /audit/export` | ✓ | — | ✓ |
| `GET /audit/chain-verify` | ✓ | — | ✓ |
| `GET /dashboard` | ✓ | — | ✓ |
| `GET /metrics` | ✓ | — | — |
| `GET /system/root` | ✓ | — | ✓ |
| `GET /system/drift` | ✓ | — | ✓ |
| `POST /system/snapshot` | ✓ | — | — |
| `POST /webhook/receive` | ✓ | — | — |

Role violations return HTTP 403 with structured error. Every denial is logged as `auth.role_denied` in the admin audit trail.

---

## Multi-Tenant Access Control

When `ZORYNEX_REQUIRE_TENANT=true`, every request must include `X-Tenant-Id`. Tenants are isolated at the database level:

```sql
UNIQUE(tenant_id, instance_id, sequence_id)
UNIQUE(tenant_id, instance_id, current_hash)
```

All queries are scoped by `tenant_id`. A valid API key for tenant A cannot access tenant B's data — the `tenant_id` is enforced at every query, not just at the authentication layer.

A single API key can serve multiple tenants by passing different `X-Tenant-Id` values, but only within the same deployment. Cross-deployment access requires separate credentials.

---

## API Key Management

### Rotation

1. Add new key to `ZORYNEX_API_KEYS` alongside the old key
2. Update all clients to use new key
3. Remove old key from `ZORYNEX_API_KEYS`
4. Restart server (key changes require restart in current version)

**Recommended rotation frequency:** Quarterly for service keys, immediately on suspected compromise.

### Key Format

API keys have no enforced format. Recommended: UUID v4 or 32+ character random hex string.

```bash
# Generate a secure key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Key Logging

API keys are **never logged in full**. The admin audit trail logs only the first 8 characters (`dev-key1...`) for correlation purposes. Full keys never appear in logs, metrics, or error responses.

### Emergency Revocation

To immediately revoke all access:
```bash
export ZORYNEX_API_KEYS="disabled:admin"
# Restart server
```

---

## Signing Key Access

The Ed25519 private key is the most sensitive credential in a Zorynex deployment. Access controls:

### AWS KMS (Production)

- Private key never leaves KMS
- Access controlled via AWS IAM roles
- KMS key policy restricts which IAM principals can use the key for signing
- CloudTrail logs every KMS API call
- Key rotation via KMS key rotation — new key registered in Zorynex key registry

**Recommended KMS key policy:** Grant `kms:Sign` only to the IAM role running the Zorynex server. Do not grant `kms:Decrypt` or `kms:GetKeyMaterial`.

### Environment Variable (Development Only)

- `ZORYNEX_SIGNING_KEY` contains the 64-char hex private key
- Access limited to users/processes that can read environment variables
- Never commit to version control (`.gitignore` includes `.env` and `*.hex`)

---

## Webhook Access Control

Incoming webhooks are authenticated via HMAC-SHA256:

```
expected = HMAC-SHA256(secret, payload)
received = X-Zorynex-Signature header
```

Replay protection: each webhook includes a nonce checked against a recent-nonce cache. Duplicate nonces within the configured time window are rejected.

Secret rotation: update `ZORYNEX_WEBHOOK_SECRET` and restart. Brief dual-validation window not supported — coordinate rotation with webhook senders.

---

## Network Access Controls

### Recommended Firewall Rules

| Source | Destination | Port | Protocol | Purpose |
|---|---|---|---|---|
| Load balancer / CDN | nginx | 443 | HTTPS | All API traffic |
| nginx | uvicorn | 8000 | HTTP | Internal only |
| uvicorn | AWS KMS | 443 | HTTPS | Signing |
| uvicorn | PostgreSQL | 5432 | TCP | Database |
| uvicorn | FreeTSA | 443 | HTTPS | Timestamps (optional) |
| uvicorn | SIEM endpoint | varies | HTTP/S | Audit logs (optional) |

Block all direct access to uvicorn port 8000 from outside the server.

### IP Allowlisting

For high-security environments, consider allowlisting:
- IP ranges of your AI system (the `system` role caller)
- IP ranges of your compliance team (the `auditor` role caller)
- IP ranges of your operations team (the `admin` role caller)

This is a network-layer control only — still require API key authentication.

---

## Access Review

Recommended quarterly access review:

```
☐ List all API keys in ZORYNEX_API_KEYS
☐ Confirm each key is associated with an active team member or service
☐ Confirm each key has the minimum role needed (principle of least privilege)
☐ Rotate any key not rotated in >90 days
☐ Remove keys for departed team members or decommissioned services
☐ Review admin audit trail for unexpected role denial events
☐ Confirm KMS key policy still restricts access to current server IAM role only
```