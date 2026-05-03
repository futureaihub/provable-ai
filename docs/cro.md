# Zorynex — Executive & Risk Leadership Brief

**Audience:** Chief Risk Officers, General Counsels, Chief Compliance Officers, and senior risk leadership.

---

## The problem

Every time your AI model makes a credit, fraud, or underwriting decision, you need to prove:

1. **What decision was made** — and the exact reasoning
2. **Which model made it** — and whether it was approved at the time
3. **When it was made** — with an independent timestamp
4. **That the record hasn't been altered** — cryptographically

Without this you are exposed to regulatory action (SR 11-7, EU AI Act, CFPB), legal liability when adverse action notices cannot be reconstructed, and reputational risk when AI decisions appear inconsistent.

---

## What Zorynex provides

**Every AI decision becomes a cryptographic proof:**

```
Decision:  loan_9284 → APPROVED
Model:     credit-model-v3.1 (governance-approved)
Policy:    credit-policy-v2.rule_7 (credit score threshold)
Timestamp: 2026-03-15T14:23:01Z (RFC 3161 external anchor)
Signed:    env-58c9d4aa2634ed9a (Ed25519)
```

This proof is:
- **Tamper-evident** — any modification is immediately detectable
- **Chain-linked** — the full sequence of decisions is provable
- **Independently verifiable** — your auditors verify with zero access to your infrastructure

---

## How verification works for auditors

Your auditors receive a proof package (JSON file). They verify it in 30 seconds:

**Browser (no installation required):**
1. Open the verification link
2. Drag and drop the proof file
3. Four green checkmarks confirm authenticity

**What they see:**
```
✓ Package untampered
✓ Chain valid
✓ Signature valid
✓ Decision sequence intact

RESULT: VERIFIED ✓
Instance: loan-application-9284 · Final state: funded
```

They can download a PDF verification report for their records.

---

## Regulatory alignment

| Requirement | How Zorynex addresses it |
|---|---|
| **SR 11-7** (Fed model risk) | Model version, governance approval, and decision reasoning are cryptographically bound to every proof |
| **EU AI Act** | High-risk AI decisions are logged with immutable audit trails and human-readable reasoning |
| **CFPB adverse action** | Every decision and its reasoning can be reconstructed exactly as it occurred |
| **GDPR / data minimisation** | Raw inputs are SHA-256 hashed — no PII stored in proofs |

Export compliance documentation:
```
GET /audit/compliance   → structured JSON pack for regulators
GET /audit/report       → PDF audit report
```

---

## What Zorynex does not claim

- **Tamper-evident**, not tamper-proof — detects modification, cannot physically prevent it
- **Verifiable**, not trustless — the signing key is inside your control boundary
- **Audit infrastructure**, not a compliance guarantee — you are still responsible for model governance decisions

---

## Deployment options

| Option | Setup | Best for |
|---|---|---|
| **API** (hosted or self-hosted) | 3 commands | Teams with existing Python infrastructure |
| **Docker** | `docker compose up` | Rapid deployment, any cloud |
| **PostgreSQL + HA** | Configuration | Enterprise multi-region |

---

## Key contacts

- Technical integration: see [docs/dev.md](dev.md)
- Auditor verification: see [docs/auditor.md](auditor.md)
- Security policy: see [SECURITY.md](../SECURITY.md)
- Enterprise enquiries: enterprise@zorynex.co