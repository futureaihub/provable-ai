# Zorynex Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@zorynex.co** with:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any proposed fix

You will receive acknowledgement within 48 hours and a resolution timeline within 7 days. We follow coordinated disclosure — reporter is credited unless anonymity is requested.

---

## Scope

This policy covers `provable_ai/`, `server/`, `tools/`, `verify/`, and `sdk/`.

---

## What Zorynex protects

| Property | Guarantee |
|---|---|
| **Decision integrity** | Any modification to a recorded decision is detectable via SHA-256 hash mismatch |
| **Sequence integrity** | Any insertion, deletion, or reordering of decisions is detectable via hash chain linkage |
| **Input privacy** | Raw inputs are SHA-256 hashed before storage — sensitive values never appear in the proof ledger |
| **External anchoring** | RFC 3161 timestamps from FreeTSA are outside your infrastructure's control boundary |
| **Governance enforcement** | Decisions from unapproved model, agent, or policy versions are blocked at the gate — not just logged |

---

## What Zorynex does NOT protect against

| Threat | Mitigation |
|---|---|
| Compromised signing key | Rotate immediately. All prior proofs remain verifiable with the old public key (embedded in each proof). |
| Database-level rewrite by a privileged attacker | RFC 3161 external timestamps + optional S3 anchoring provide independent evidence outside your infrastructure. |
| Infrastructure compromise | Standard operations security: network isolation, secrets management, access control, audit logs. |
| Side-channel attacks on signing key | Use `AWSKmsSigner` or `GCPKmsSigner` instead of `EnvSigner` — private key never leaves the KMS. |

---

## Trust boundary

```
FreeTSA (external)     ←  outside your control — independent timestamp authority
         ↓
Anchor store           ←  separate volume / separate DB file from proof ledger
         ↓
Proof ledger           ←  append-only, SHA-256 hash-chained, Ed25519 signed
         ↓
Your infrastructure    ←  your responsibility: key management, access control, backups
```

The key insight: verification works against the exported proof file, not against your infrastructure. An auditor's result does not depend on trusting anything you control.

---

## Key management

**Development**

```bash
# bootstrap.py generates this automatically
export ZORYNEX_SIGNING_KEY="64-char-hex-ed25519-private-key"
# provable_key.hex and .env are in .gitignore — never commit them
```

**Production**

```bash
# AWS KMS — private key never leaves the KMS
export ZORYNEX_KMS_KEY_ID="alias/zorynex-prod"
export ZORYNEX_KMS_REGION="us-east-1"
```

**Key rotation**

Register a new key. All future proofs use the new key. Old proofs remain permanently verifiable with the old public key — it is embedded in every proof at signing time.

**Key backup**

Store key material offline, encrypted, in at least two geographically separate locations. The signing key is the root of trust for all proofs. Losing it does not invalidate existing proofs (public key is embedded), but means you cannot issue new ones.

---

## API security

| Control | Detail |
|---|---|
| Authentication | `X-API-Key` header required on all non-public endpoints |
| RBAC | `admin` (full), `auditor` (read-only), `system` (write decisions) |
| Webhook integrity | HMAC-SHA256 + nonce-based replay protection |
| Rate limiting | Per-tenant and global limits via `slowapi` |
| TLS | Nginx terminates TLS in production — app is internal-only |
| Tenant isolation | `X-Tenant-Id` enforced at DB level — separate ledger per tenant |

---

## Cryptographic specification

| Property | Value |
|---|---|
| Signing algorithm | Ed25519 (PyNaCl / libsodium) |
| Hash algorithm | SHA-256 (Python standard library hashlib) |
| Canonical JSON | UTF-8, `sort_keys=True`, `separators=(",",":")`, no floats, no datetime objects |
| What is signed | 32 raw bytes of `current_hash` via Ed25519 |
| What is hashed | `decision`, `decision_context`, `governance`, `determinism`, `previous_hash`, `sequence_id` |
| Genesis hash | 64 zero characters — the known starting point of every chain |

---

## Known limitations

**SQLite in production**
SQLite has no row-level locking. Use PostgreSQL for multi-worker production deployments (`ZORYNEX_BACKEND=postgres`).

**FreeTSA availability**
RFC 3161 timestamps require network access to FreeTSA. Failures are non-fatal — proofs are still recorded and fully valid without the external timestamp. Anchoring simply provides additional independent evidence.

**Hash chain is not a blockchain**
The chain provides cryptographic tamper-evidence within your infrastructure. It does not provide decentralised consensus. An attacker with full database and key access could theoretically reconstruct a chain — external anchoring (RFC 3161, S3) is the defence against that.

**Proof records governance at signing time**
Zorynex records which model, agent, and policy versions were approved and used at the moment of signing. It does not independently validate that those model versions produced the correct output — it proves the record of what happened, not the correctness of the decision itself.

---

## Dependency security

Keep these up to date — they form the security-critical path:

| Package | Role |
|---|---|
| `pynacl` | Ed25519 signing and verification |
| `fastapi` / `uvicorn` | HTTP server layer |
| `psycopg2-binary` | PostgreSQL driver (production) |
| `cryptography` | RFC 3161 timestamp verification |

Run `pip install --upgrade -r requirements.txt` regularly and review release notes for security advisories.

---

## Disclosure timeline

1. Reporter submits privately to security@zorynex.co
2. Acknowledgement within 48 hours
3. Fix developed and tested internally
4. Fix released and advisory published simultaneously
5. Reporter credited in advisory (unless anonymity requested)