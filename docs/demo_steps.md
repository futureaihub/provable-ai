# Zorynex — Live Demo Guide

**Who watches this:** Developers, compliance leads, investors, CROs, regulators.

**What they'll leave knowing:** AI decisions at your company are not just logged — they are cryptographically locked at the moment they happen, and any auditor can verify them forever, independently, with zero access to your systems.

**Total time:** 10 minutes start to finish.

---

## Before the demo — one command

```bash
python bootstrap.py --start
```

Server starts. Open **http://127.0.0.1:8000/docs** → click **Authorize** → `X-API-Key: dev-key`.

---

## Step 1 — Seed the environment (10 seconds)

Run `POST /demo/bootstrap` in Swagger, or:

```bash
curl -X POST http://127.0.0.1:8000/demo/bootstrap \
  -H "X-API-Key: dev-key"
```

This approves a model, agent, and policy, compiles a loan workflow, and creates a demo instance — all in one call. No manual setup.

**What to say:**
*"In production, your team defines which model versions, agent versions, and policy versions are authorised to write decisions. Nothing outside that list can touch the ledger."*

---

## Step 2 — Record a loan decision

```bash
curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": "loan-9284",
    "from_state": "received",
    "to_state": "approved",
    "model_version": "credit-model-v3.1",
    "agent_version": "underwriter-v1.0",
    "policy_version": "credit-policy-v2",
    "reason_code": "SCORE_ABOVE_THRESHOLD",
    "policy_rule": "credit-policy-v2.rule_7",
    "raw_inputs": {"credit_score": "742", "debt_to_income": "0.28"},
    "feature_contributions": [
      {"feature": "credit_score",   "contribution": "0.65"},
      {"feature": "debt_to_income", "contribution": "-0.12"}
    ],
    "threshold_used": "700"
  }'
```

Response:
```json
{
  "proof_id":     "cef509088ea8...",
  "sequence_id":  1,
  "instance_id":  "loan-9284",
  "current_hash": "b189dc8f0e01...",
  "proof_url":    "/proof/loan-9284"
}
```

**Invisible to the eye — six things happened at once:**
1. Governance enforced — `credit-model-v3.1` is approved ✓
2. Credit score `742` hashed — the raw number is never stored ✓
3. SHA-256 hash computed over the full decision payload ✓
4. Ed25519 signature applied with your private key ✓
5. Hash chain linked to all prior decisions for this instance ✓
6. Written to an append-only ledger — no UPDATE, no DELETE ✓

**What to say:**
*"Notice `sequence_id: 1`. Every decision gets a sequence number. If a record is ever deleted or reordered, the sequence breaks. The mathematics catches it — not an audit log."*

---

## Step 3 — Record the funding step

```bash
curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": "loan-9284",
    "from_state":  "approved",
    "to_state":    "funded",
    "model_version":  "credit-model-v3.1",
    "agent_version":  "underwriter-v1.0",
    "policy_version": "credit-policy-v2",
    "reason_code": "MANUAL_REVIEW_PASSED",
    "policy_rule": "credit-policy-v2.rule_12",
    "raw_inputs":  {"reviewer_id": "usr-991"}
  }'
```

Response shows `sequence_id: 2`. The hash of this proof depends on the hash of proof 1. Reorder them, insert anything between them, or delete either one — the chain breaks. Every time.

---

## Step 4 — Export the proof package

```bash
curl "http://127.0.0.1:8000/proof/export/loan-9284?inline=true" \
  -H "X-API-Key: dev-key" \
  -o proof.json
```

`proof.json` is a single self-contained file. It contains the full decision chain, the cryptographic hash chain, the Ed25519 signatures, and the public key needed to verify everything.

Hand it to anyone. They need no access to your server, database, or organisation — ever.

**What to say:**
*"This file is the proof. Not a log entry. Not a screenshot. A cryptographically sealed record that stands on its own, forever."*

---

## Step 5 — Verify offline

### Option A — Browser (best for compliance and auditor audiences)

```
open http://127.0.0.1:8000/verify-ui
```

Drag `proof.json` into the page. Four checks run in the browser — no data leaves the device.

```
✓ Package structure valid   (2 proofs in package)
✓ Package untampered        (SHA-256 of full ledger matches)
✓ Chain valid               (2 proofs, sequence 1→2)
✓ Signature valid           (Ed25519  key: env-7492b963...)

RESULT:  VERIFIED ✓
Instance:    loan-9284
Final state: funded
```

Download the PDF verification report for the auditor's records.

### Option B — CLI (best for developer audiences)

```bash
python verify/verify_package.py proof.json
```

### Option C — API (best for integration audiences)

```bash
curl -X POST http://127.0.0.1:8000/verify-package \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d @proof.json
```

**What to say:**
*"An auditor opens this link. Drops the file. That's their verification — no call to our API, no database query, no trust in us required. The cryptography is self-contained."*

---

## Step 6 — Demonstrate tamper detection

**This is the moment that lands.**

Open `proof.json` in any text editor. Find `"to_state": "approved"` and change it to `"to_state": "rejected"`. Save. Run the verifier.

```bash
python verify/verify_package.py proof.json
```

Output:
```
  ✓ Package structure valid
  ✗ Package untampered
       Hash mismatch — package was modified after export.
       stored:   b189dc8f0e01150b...
       computed: a72f3c91d84bb02e...

  RESULT:  VERIFICATION FAILED ✗
```

One character changed. Caught instantly.

**What to say:**
*"No audit log to check. No database to query. The mathematics detected it. This is what makes AI governance provable — not just documented. The moment any field changes, anywhere in the chain, verification fails. There is no way around it."*

---

## What each audience needs to hear

**Developers:**
- Simple mode: just `instance_id`, `from_state`, `to_state`, `raw_inputs` — governance auto-resolves
- Python SDK: `client.record_decision(...)` — one line
- Verification: same algorithm in Python, TypeScript, and the browser

**Compliance / Legal:**
- The proof is created at decision time — not reconstructed after the fact
- Raw inputs are hashed — no PII in the proof ledger
- The public key is embedded — no external key registry needed for verification
- RFC 3161 external timestamps available for independent time proof

**CRO / Risk Leadership:**
- SR 11-7, EU AI Act, CFPB adverse action — all addressed in the compliance export (`GET /audit/compliance`)
- Regulatory examination: hand the auditor a file, they verify in minutes, not weeks
- Governance is enforced — unapproved model versions are rejected before the decision is recorded

**Investors:**
- Every enterprise AI deployment has this problem — no provable audit trail
- The moat: the proof format is open, the verification is offline, the customer data stays with the customer
- Current alternatives: log everything and hope, or build it in-house

---

## Demo checklist

```
☐ python bootstrap.py --start runs cleanly
☐ /docs opens, Authorize works with dev-key
☐ POST /demo/bootstrap returns status: ready
☐ POST /decision (full mode) returns proof_id, sequence_id: 1
☐ Second POST /decision returns sequence_id: 2
☐ GET /proof/export returns proof.json with 2 entries
☐ /verify-ui: 4 green checkmarks, PDF downloads
☐ CLI: RESULT: VERIFIED ✓
☐ POST /verify-package: verified: true
☐ Tampered proof: VERIFICATION FAILED ✗ with hash mismatch shown
```

---

## Common questions and answers

**"Can someone alter the proof before it's written?"**
The proof is signed and hashed in-process at the moment the decision is recorded, before anything is written to the ledger. The signature covers the hash, and the hash covers the full payload.

**"What if your server goes down after we export?"**
`proof.json` is fully self-contained. Verification works with zero server access, permanently. The public key is embedded in the file.

**"What if someone replaces the entire database?"**
With RFC 3161 timestamps enabled, each proof is submitted to FreeTSA — an independent external timestamp authority. Even if your entire database is replaced, the external timestamps prove what existed and when.

**"Is this a blockchain?"**
No. A blockchain requires decentralised consensus across untrusted parties. This is a cryptographic hash chain — the same mathematical property (any change breaks the chain), without the complexity, latency, or cost.

**"What about GDPR? You're storing decision data."**
Raw inputs are SHA-256 hashed before storage. The hash is stored, not the value. You can respond to a GDPR deletion request by noting that only the hash of the input was ever stored — the original data never entered the proof ledger.