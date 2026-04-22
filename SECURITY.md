# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main (v1.0) | ✅ Active |

---

## Reporting a Vulnerability

If you discover a security vulnerability in Provable AI, **please report it privately**.

**Do not open a public GitHub issue.** Public disclosure before a fix is available puts users at risk.

### How to report

Email: **hanif@zorynex.co**

Include as much of the following as possible:

- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected component (`provable_ai/`, `server/`, `tools/`, `cli.py`, or other)
- Suggested fix or mitigation if you have one

We will acknowledge your report within **48 hours** and aim to resolve confirmed vulnerabilities within **14 days**, depending on severity.

---

## Security Model

Provable AI is designed to protect the **integrity and verifiability** of AI decisions. The system's core security guarantees are:

### Cryptographic Integrity

- **SHA-256 hash chains** — every ledger entry links `prev_hash → curr_hash`, forming a tamper-evident chain. Altering any entry breaks every subsequent hash.
- **Ed25519 signatures (PyNaCl)** — every decision record is cryptographically signed at write time. Signatures are verified independently against the embedded public key.
- **Merkle roots** — computed across all `curr_hashes` in an instance, enabling replay-based tamper detection without server access.

### Governance Enforcement

- Model, agent, and policy versions are validated against approved registries **before** any proof is written.
- Unauthorized versions raise an Exception and are blocked — not merely logged.
- Protocol integrity is re-verified on every state transition; a tampered protocol spec will be detected.

### Proof Immutability

- Instances are **frozen** after export. Once a proof artifact is generated, the underlying instance cannot be modified.
- Proof packages include the `public_key` — auditors can verify independently with no server access, no registration, and no trust in any internal system.

### Independent Verification

- The verification CLI (`cli.py` / `tools/offline_verify.py`) is source-available and runs fully offline.
- Verification rebuilds every SHA-256 hash from raw payload data and re-verifies Ed25519 signatures. If any step fails, tamper is detected.

### What Provable AI does NOT claim

- Provable AI does not protect the **confidentiality** of decision inputs or outputs — it protects **integrity and verifiability**.
- Provable AI does not replace secure deployment practices (secrets management, access control, network hardening).
- Key management security depends on the operator's environment configuration.

---

## Scope

The following are **in scope** for security reports:

- Cryptographic bypass or weaknesses in hash chain / signature verification
- Governance gate bypass — unauthorized model/agent/policy versions executing without exception
- Proof export producing invalid or misleadingly passing verification
- Instance mutation after freeze
- Replay verification producing false-positive VALID results
- Server authentication or rate-limiting bypass (`server/main.py`)
- Injection vulnerabilities in API endpoints

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report directly to those maintainers)
- Social engineering attacks
- Issues requiring physical access to the host machine
- Theoretical attacks with no practical exploitation path

---

## Responsible Disclosure

We follow coordinated disclosure. We ask researchers to:

1. Report privately before any public disclosure
2. Allow reasonable time to investigate and ship a fix (target: 14 days for critical, 30 days for moderate)
3. Not exploit the vulnerability beyond what is necessary to demonstrate it

We commit to:

1. Acknowledging reports within 48 hours
2. Keeping reporters informed of investigation progress
3. Crediting researchers in release notes (if desired)
4. Not pursuing legal action against good-faith security researchers

We appreciate responsible disclosure and security research that helps strengthen the system.

---

## Contact

**Security reports:** hanif@zorynex.co  
**General enquiries:** zorynexfounder@gmail.com  
**Repository:** https://github.com/futureaihub/provable-ai
