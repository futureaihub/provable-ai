# Zorynex — Data Handling

**Audience:** Data protection officers, legal teams, compliance reviewers, enterprise security.

---

## Summary

Zorynex is a self-hosted infrastructure layer. **Zorynex never receives, stores, or processes customer data on Zorynex infrastructure.** Everything runs within the customer's own environment. There is no Zorynex cloud, no Zorynex-managed database, and no data transmission to Zorynex servers.

---

## What Zorynex Stores

### Proof Ledger

The proof ledger stores cryptographic records of AI decisions. It does **not** store raw customer data.

| Field | What Is Stored | What Is NOT Stored |
|---|---|---|
| `inputs_hash` | SHA-256 of raw inputs | The raw inputs themselves |
| `decision` | from_state, to_state | Customer PII |
| `governance` | model/agent/policy versions | Model weights or parameters |
| `decision_context` | reason_code, policy_rule, feature_contributions, threshold_used | Raw feature values |
| `signature` | Ed25519 signature | Private key |
| `timestamp` | UTC timestamp of execution | Customer identity |

### What "inputs_hash" Means for GDPR

Raw inputs are SHA-256 hashed before anything is written to the ledger. The original values never enter the ledger. SHA-256 is a one-way function — you cannot recover the original value from the hash.

**GDPR Art. 17 (Right to Erasure):** Because only the hash is stored, responding to an erasure request is straightforward — the original data was never stored in the proof ledger.

**Adverse Action Notices:** `feature_contributions` and `threshold_used` fields contain model-level explanations (e.g., `credit_score` with contribution `0.65`) — not raw values. These satisfy CFPB adverse action notice requirements without storing PII.

### Governance Tables

| Table | What Is Stored |
|---|---|
| `approved_models` | Model name and version strings |
| `approved_agents` | Agent name and version strings |
| `approved_policies` | Policy name and version strings |
| `protocols` | Workflow state/transition specifications |

No customer data in governance tables.

### Audit Log

Structured JSON logs contain: event type, timestamp, trace_id, tenant_id, API key prefix (first 8 chars), IP address. No customer data. No PII.

---

## What Zorynex Does NOT Store

- Raw customer inputs — only SHA-256 hash
- Personal identifiable information of any kind
- Model weights or training data
- Private signing keys (in production, keys stay in AWS KMS)
- Customer passwords or credentials
- Payment information

---

## Data Flow

```
Customer AI System
        │
        │  POST /decision
        │  { raw_inputs: { credit_score: 742, dti: 0.28 } }
        │
        ▼
Zorynex API Layer
        │
        │  SHA-256( raw_inputs )  →  stored as inputs_hash
        │  raw_inputs             →  DISCARDED, never written to disk
        │
        ▼
Proof Ledger (customer database)
        │
        │  { inputs_hash: "7f3a9c...", decision: {...}, governance: {...} }
        │
        ▼
Proof Export (proof.json)
        │
        │  Self-contained file — stays within customer environment
        │  Sent to auditors by customer, not by Zorynex
```

---

## Data Residency

All data resides in the customer's infrastructure. Zorynex does not operate or manage any data storage. The customer controls:

- Database location (SQLite file path or PostgreSQL server)
- Backup strategy and frequency
- Geographic location of all data
- Retention policy

---

## Retention

Zorynex does not impose any data retention policy — that is entirely the customer's responsibility. The proof ledger is append-only (deletions blocked at the database trigger level), which means records accumulate. The customer must plan for:

- Database size growth based on decision volume
- Backup and archival strategy
- Long-term storage for proofs that may be needed years after the decision

**Recommendation:** Retain proof ledger records for the same duration as required by applicable regulation (SR 11-7: 7 years; CFPB: 5 years; EU AI Act: duration of high-risk AI system lifecycle + 10 years).

---

## External Data Transmission

The only external transmission is the optional RFC 3161 timestamp request:

| What is sent | To whom | When |
|---|---|---|
| SHA-256 hash of the proof (32 bytes) | FreeTSA (freetsa.org) | Only when `ZORYNEX_ANCHOR_RFC3161=true` |
| Nothing else | Nobody | Never |

The RFC 3161 request contains only a hash. No proof content, no customer data, no identifiers are transmitted. FreeTSA returns a signed timestamp token that is stored alongside the proof.

To disable entirely: `ZORYNEX_ANCHOR_RFC3161=false` (default).

---

## Data Classification

| Data Type | Classification | Location | Encrypted at Rest |
|---|---|---|---|
| Proof ledger | Confidential | Customer DB | Customer responsibility |
| Signing key | Secret | AWS KMS or env var | Yes (KMS) / Customer responsibility (env) |
| Audit logs | Confidential | Customer log system | Customer responsibility |
| API keys | Secret | Environment variables | Customer responsibility |
| RFC 3161 tokens | Confidential | Customer DB (anchor table) | Customer responsibility |

---

## Sub-processors

Zorynex has **no sub-processors** that handle customer data. The optional FreeTSA timestamp service receives only a SHA-256 hash — not customer data. No data processing agreements are required with FreeTSA.

If the customer uses AWS KMS for signing, the AWS Data Processing Addendum (DPA) applies to that relationship between the customer and AWS — not to Zorynex.

---

## Data Breach Response

Because Zorynex does not store customer data on Zorynex infrastructure, a breach of Zorynex infrastructure does not expose customer proof records. Customer proof records are located in customer-managed databases within the customer's infrastructure boundary.

If a customer's Zorynex deployment is compromised:
1. Revoke all API keys immediately (`ZORYNEX_API_KEYS`)
2. Rotate the signing key (new key registered, old proofs remain verifiable)
3. Preserve the database — do not delete records (they may be evidence)
4. Contact `security@zorynex.co` for incident support

---

## Regulatory Alignment

| Regulation | Requirement | How Zorynex Addresses It |
|---|---|---|
| GDPR Art. 5(1)(c) | Data minimisation | Only hashes stored, not raw inputs |
| GDPR Art. 17 | Right to erasure | Only hash was stored — no erasure needed for original data |
| GDPR Art. 25 | Privacy by design | Hash-only architecture built in from day one |
| CCPA | No sale of personal information | No customer data on Zorynex infrastructure to sell |
| SR 11-7 | Evidence retention | Append-only ledger cannot be altered — records preserved |
| CFPB | Adverse action documentation | feature_contributions + reason_code in every proof |