# Security Policy

## Overview

Provable AI is security-sensitive infrastructure. The system produces
cryptographic proof artifacts used by regulators and auditors to verify
AI decisions in financial services. We take security reports seriously
and respond promptly.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | ✅ Active |
| Tagged releases | ✅ Active |
| Forks / derivatives | ❌ Not supported |

---

## Cryptographic Components

The following cryptographic primitives are used in this system:

### SHA-256 Hash Chains (hashlib)
- Used in: `provable_ai/signer.py`, `provable_ai/storage.py`
- Purpose: Tamper-evident hash chain linking each decision record
- Every ledger entry includes `prev_hash` (SHA-256 of previous record)
- Altering any record breaks the chain — detectable via replay

### Ed25519 Digital Signatures (PyNaCl / libsodium)
- Used in: `provable_ai/signer.py`
- Purpose: Cryptographic signing of every proof artifact
- Key generation: `SigningKey.generate()` on first run
- Key storage: `provable_key.hex` — private key file
- Public key: Shareable for external verification

### Merkle Roots
- Used in: `provable_ai/engine.py`, `tools/verify_core.py`
- Purpose: Replay-verifiable state for tamper detection
- Enables reconstruction of any execution history

### Verification Chain
- `tools/verify_core.py` — 224-line core verification module
- `tools/verify_proof.py` — Proof artifact parser and validator
- `tools/offline_verify.py` — Standalone offline verifier
- `cli.py` — Root CLI entry point

---

## Private Key Security

**The file `provable_key.hex` contains your Ed25519 private signing key.**

Critical requirements:
- **Never commit `provable_key.hex` to version control**
- The `.gitignore` file excludes this file by default — do not remove this entry
- In production, manage the key path via the `SIGNING_KEY_PATH` environment variable
- Rotate the signing key if it is ever exposed
- Back up the key securely — losing it means previously signed proofs cannot be re-signed

In production Docker deployments, inject the key via Docker secrets or
AWS Secrets Manager rather than the filesystem.

---

## Production Security

The production FastAPI server (`server/main.py`) includes:

- **Authentication middleware** — API key or token-based auth
- **Rate limiting** — prevents abuse of the decision recording endpoint
- **Audit logging** — all API calls logged for internal review
- **Input validation** — request schema validation on all endpoints

**Environment variables for production:**

```bash
SECRET_KEY=your-secret-key          # API authentication
SIGNING_KEY_PATH=provable_key.hex   # Ed25519 key location
LEDGER_DB_PATH=ledger.db            # SQLite ledger path
LOG_LEVEL=INFO                      # Logging verbosity
```

**Docker production deployment:**

```bash
docker-compose -f docker-compose.prod.yml up -d
```

The production compose file enforces:
- Non-root container user
- Read-only filesystem where possible
- Health check on `/health` endpoint
- No exposed debug endpoints

---

## Reporting a Vulnerability

**Do not report security vulnerabilities in public GitHub issues.**

Report vulnerabilities privately to:

**Email:** hanif@zorynex.co  
**Subject:** `[SECURITY] Brief description`

### What to include

- Description of the vulnerability
- Steps to reproduce
- Which component is affected (engine.py, signer.py, verify_core.py, etc.)
- Potential impact — specifically whether proof artifact integrity could be compromised
- Your name / handle for attribution (optional)

### What happens next

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgement of report |
| Within 7 days | Initial assessment and severity rating |
| Within 30 days | Fix developed and tested |
| Within 45 days | Fix released and reporter notified |

We will credit security researchers in release notes unless anonymity is requested.

---

## Threat Model

**In scope — we want to know about:**

- Vulnerabilities that allow forging or altering proof artifacts without detection
- Weaknesses in the SHA-256 hash chain implementation that allow chain manipulation
- Ed25519 signing vulnerabilities that allow signature forgery
- Merkle root manipulation that defeats replay-based tamper detection
- Authentication bypass in the FastAPI server
- Private key exposure through the API or filesystem
- Replay attacks on the verification CLI
- SQLite ledger manipulation that bypasses tamper detection

**Out of scope:**

- Vulnerabilities in upstream dependencies (PyNaCl, FastAPI, SQLite) — report directly to those projects
- Social engineering attacks
- Physical access attacks
- Denial of service without cryptographic impact
- Missing security headers on non-production deployments

---

## Dependency Security

Key dependencies and their security posture:

| Package | Purpose | Security Notes |
|---------|---------|----------------|
| PyNaCl | Ed25519 signatures | Wrapper around libsodium — audited cryptography library |
| FastAPI | API server | Actively maintained — update regularly |
| SQLite | Ledger storage | Append-only access pattern — no remote connections |
| hashlib | SHA-256 chains | Python standard library — no external dependency |

Run `pip audit` against `requirements.txt` to check for known vulnerabilities in dependencies.

---

## Verification Security

The independent verification tools are designed to operate without trusting the originating system:

- `offline_verify.py` has no network calls — fully airgapped
- `verify_core.py` implements verification from first principles — no shortcuts
- Proof artifacts are self-contained — no external lookups required
- The public key for signature verification can be distributed separately from the proof

This means a regulator or auditor can verify proof artifacts without any access to your infrastructure, reducing the attack surface for evidence manipulation.

---

## Contact

**Hanif Shaik** — Founder, Zorynex  
[hanif@zorynex.co](mailto:hanif@zorynex.co)  
[zorynex.co](https://zorynex.co)
