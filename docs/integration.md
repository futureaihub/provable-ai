# Zorynex — Integration Guide

**Audience:** Engineers integrating Zorynex into an AI decision pipeline.

Every AI decision your system makes becomes a cryptographically signed, hash-chained proof artifact — independently verifiable by regulators and auditors with zero server access, forever.

---

## How it fits into your stack

Zorynex sits between your AI model output and your decision delivery. Nothing in your existing pipeline changes.

```
Your Data  →  Your AI Model  →  Zorynex  →  Decision Delivered
                                    ↓
                             Proof Artifact (proof.json)
                                    ↓
                   Auditor verifies offline  →  VALID / INVALID
```

**What Zorynex captures at execution time:**
- Exact model version, agent version, and policy version in effect
- Decision outcome — the state transition
- Reason code and policy rule applied
- SHA-256 hash of inputs — raw inputs are never stored
- Feature contributions for adverse action notices
- Ed25519 cryptographic signature
- SHA-256 hash chain linking to every prior decision for this instance

---

## Requirements

```bash
Python 3.11+
pip install -r requirements.txt
```

---

## Quickstart — 3 commands

```bash
# First time
python bootstrap.py --start     # generates keys, writes .env, starts server

# After that
source .env && uvicorn server.main:app --reload
```

Open **http://127.0.0.1:8000/docs** → Authorize (`X-API-Key: dev-key`) → run `POST /demo/bootstrap`.

---

## Two modes for POST /decision

**Simple mode** — governance auto-resolves from approved lists (4 required fields):

```bash
curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": "loan-9284",
    "from_state":  "received",
    "to_state":    "approved",
    "raw_inputs":  {"credit_score": "742"}
  }'
```

**Full mode** — all fields explicit (required in production for complete audit trail):

```bash
curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id":    "loan-9284",
    "from_state":     "received",
    "to_state":       "approved",
    "model_version":  "credit-model-v3.1",
    "agent_version":  "underwriter-v1.0",
    "policy_version": "credit-policy-v2",
    "reason_code":    "SCORE_ABOVE_THRESHOLD",
    "policy_rule":    "credit-policy-v2.rule_7",
    "raw_inputs":     {"credit_score": "742", "debt_to_income": "0.28"},
    "feature_contributions": [
      {"feature": "credit_score",   "contribution": "0.65"},
      {"feature": "debt_to_income", "contribution": "-0.12"}
    ],
    "threshold_used": "700",
    "metadata": {"bureau": "experian", "pull_type": "hard"}
  }'
```

Response:
```json
{
  "proof_id":     "cef509088ea8...",
  "sequence_id":  1,
  "instance_id":  "loan-9284",
  "current_hash": "b189dc8f0e01...",
  "proof_url":    "/proof/loan-9284",
  "trace_id":     "a3f8c2d1-..."
}
```

---

## Python SDK

Zero dependencies — copy `sdk/zorynex.py` into your project:

```python
from sdk.zorynex import ZorynexClient

client = ZorynexClient(
    base_url  = "http://127.0.0.1:8000",
    api_key   = "your-api-key",
    tenant_id = "default",
)

# Bootstrap once
client.bootstrap()

# Simple mode
proof = client.record_decision(
    instance_id = "loan-9284",
    from_state  = "received",
    to_state    = "approved",
    raw_inputs  = {"credit_score": "742"},
)
print(proof["proof_id"])

# Export and verify
package = client.export_proof("loan-9284")
result  = client.verify_package(package)
assert result["verified"] is True
```

---

## Decision request fields

| Field | Type | Required | Description |
|---|---|---|---|
| `instance_id` | string | Yes | Unique ID for this decision entity (loan ID, claim ID, etc.) |
| `from_state` | string | Yes | State before this decision |
| `to_state` | string | Yes | State after this decision |
| `model_version` | string | Optional* | Must match an approved model. Auto-resolved if omitted. |
| `agent_version` | string | Optional* | Must match an approved agent. Auto-resolved if omitted. |
| `policy_version` | string | Optional* | Must match an approved policy. Auto-resolved if omitted. |
| `reason_code` | string | Optional* | Machine-readable reason (`SCORE_ABOVE_THRESHOLD`). Defaults to `DECISION`. |
| `policy_rule` | string | Optional* | Specific rule applied (`credit-policy-v2.rule_7`). Defaults to `policy.default`. |
| `raw_inputs` | dict | Optional | Hashed before storage — raw values never stored. Defaults to `{}`. |
| `feature_contributions` | list | No | `[{"feature": "credit_score", "contribution": "0.65"}]` — values must be strings |
| `threshold_used` | string | No | Threshold as string — not int or float |
| `metadata` | dict | No | Additional context. No raw PII. |
| `determinism_mode` | string | No | `strict_deterministic` (default), `replay_with_seed`, `replay_with_recorded_io` |
| `random_seed` | string | No | Required when `determinism_mode=replay_with_seed` |
| `external_calls` | list | No | Required when `determinism_mode=replay_with_recorded_io` |

*Optional in simple mode — auto-resolved from approved lists. Explicitly recommended in production.

---

## Authentication and roles

All endpoints require `X-API-Key`. Configure via environment:

```bash
# Format: "key:role,key:role,..."
export ZORYNEX_API_KEYS="admin-key:admin,audit-key:auditor,svc-key:system"
```

| Role | Access |
|---|---|
| `admin` | Full access — governance, audit, export, verify |
| `system` | Record decisions, create instances |
| `auditor` | Read-only — proofs, chain, compliance exports. Cannot write. |

Multi-tenant deployments: add `X-Tenant-Id` header. Tenants are completely isolated at the database level — same `instance_id` across tenants is allowed.

---

## Governance setup

Decisions from unapproved model, agent, or policy versions are **blocked**, not logged. This is enforcement, not auditing.

```bash
# Via API
curl -X POST http://127.0.0.1:8000/governance/model \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "credit_model", "version": "v3.1"}'

curl -X POST http://127.0.0.1:8000/governance/agent \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "underwriter", "version": "v1.0"}'

curl -X POST http://127.0.0.1:8000/governance/policy \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "credit_policy", "version": "v2"}'
```

Attempting to record a decision with an unapproved version:
```json
{
  "error": "UNAUTHORIZED_MODEL_VERSION",
  "message": "Model version 'v3.0' is not approved. Approved: ['v3.1']",
  "hint": "Approve this version via POST /governance/model first."
}
```

---

## Proof structure

Every exported proof package (`proof.json`) is self-contained:

```json
{
  "type":       "provable-ai-proof-package",
  "instance_id": "loan-9284",
  "package_hash": "sha256 of full ledger — tamper detection",
  "public_key":   "ed25519 public key — embedded for offline verification",
  "signature":    "ed25519 signature over instance root",
  "proof": {
    "instance_id":   "loan-9284",
    "instance_root": "sha256 over all current_hashes in chain",
    "ledger": [
      {
        "decision":     { "from_state": "received", "to_state": "approved" },
        "decision_context": {
          "reason_code":  "SCORE_ABOVE_THRESHOLD",
          "policy_rule":  "credit-policy-v2.rule_7",
          "inputs_hash":  "sha256 of raw_inputs — original never stored",
          "feature_contributions": [{"feature": "credit_score", "contribution": "0.65"}],
          "threshold_used": "700"
        },
        "governance": {
          "model_version":  "credit-model-v3.1",
          "agent_version":  "underwriter-v1.0",
          "policy_version": "credit-policy-v2"
        },
        "ledger": {
          "sequence_id":    1,
          "previous_hash":  "0000...0000",
          "current_hash":   "b189dc8f...",
          "timestamp":      "2026-04-28T14:33:01Z"
        }
      }
    ]
  }
}
```

**The `public_key` is embedded** — an auditor needs no external key registry, no server call, and no access to your organisation to verify this file.

---

## Hash chain specification

First decision in any chain:
```
previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"
```

Every subsequent decision:
```
previous_hash = current_hash of the immediately preceding decision
```

Altering any decision breaks every subsequent hash. There is no way to forge an undetected modification.

**What is hashed (canonical JSON — deterministic field order):**
```json
{
  "decision":         {...},
  "decision_context": {...},
  "governance":       {...},
  "determinism":      {...},
  "previous_hash":    "...",
  "sequence_id":      1
}
```

**Explicitly excluded from hash:** `timestamp`, `current_hash`, `signature`, `public_key`, `key_id`, `type`, `instance_id`, `proof_id`, `tenant_id`

**Cryptographic specification:**

| Property | Value |
|---|---|
| Signing algorithm | Ed25519 (PyNaCl / libsodium) |
| Hash algorithm | SHA-256 |
| Key format | 32-byte Ed25519 (64 hex chars) |
| Canonical JSON | UTF-8, `sort_keys=True`, `separators=(",", ":")`, no floats, no datetime objects |

---

## Verification

```bash
# Browser (for auditors — no install)
open http://127.0.0.1:8000/verify-ui

# CLI (for engineers)
python verify/verify_package.py proof.json
python verify/verify_package.py proof.json --verbose   # full chain table
python verify/verify_package.py proof.json --json       # machine-readable

# API (for integrations)
curl -X POST http://127.0.0.1:8000/verify-package \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d @proof.json
```

**What the 4 checks verify:**
1. **Package structure** — type is `provable-ai-proof-package`, ledger is non-empty
2. **Package untampered** — SHA-256 of full ledger matches `package_hash`
3. **Chain valid** — per-proof canonical hash recomputed, previous_hash linkage verified
4. **Signature valid** — Ed25519 over instance root verified against embedded public key

---

## Key management

**Development:**
```bash
# bootstrap.py generates this automatically
export ZORYNEX_SIGNING_KEY="64-char-hex-ed25519-private-key"
# Never commit provable_key.hex or .env
```

**Production (AWS KMS):**
```bash
export ZORYNEX_KMS_KEY_ID="alias/zorynex-prod"
export ZORYNEX_KMS_REGION="us-east-1"
# AWSKmsSigner activated — private key never leaves KMS
```

**Key rotation:**
New key is registered. All future proofs use the new key. Old proofs remain verifiable with the old public key — it is embedded in each proof.

---

## Endpoint reference

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/demo/bootstrap` | admin | Seed complete demo environment |
| `POST` | `/protocol/compile` | admin | Define workflow states + transitions |
| `POST` | `/governance/model` | admin | Approve a model version |
| `POST` | `/governance/agent` | admin | Approve an agent version |
| `POST` | `/governance/policy` | admin | Approve a policy version |
| `GET` | `/governance/status` | admin | List all approved governance |
| `POST` | `/instance/create` | admin, system | Create a workflow instance |
| `POST` | `/decision` | admin, system | Record an AI decision |
| `GET` | `/proof/{id}` | admin, auditor, system | Get latest proof (slim) |
| `GET` | `/proof/{id}?verbose=true` | admin, auditor, system | Get proof with full payload |
| `GET` | `/chain/{id}` | admin, auditor, system | Get chain summary |
| `GET` | `/chain/{id}?full=true` | admin, auditor, system | Get full chain |
| `GET` | `/proof/export/{id}?inline=true` | admin, auditor, system | Export verifiable proof package |
| `POST` | `/verify-package` | admin, auditor, system | Verify full proof package |
| `POST` | `/verify` | admin, auditor, system | Verify single proof dict |
| `GET` | `/audit/compliance` | admin, auditor | SR 11-7 / EU AI Act / CFPB pack |
| `GET` | `/audit/log` | admin, auditor | Audit event log |
| `GET` | `/audit/chain-verify` | admin, auditor | Verify full proof ledger integrity |
| `GET` | `/audit/export` | admin, auditor | Batch export with Merkle root |
| `GET` | `/audit/report` | admin, auditor | PDF audit report |
| `GET` | `/health` | public | Liveness probe |
| `GET` | `/ready` | public | Readiness probe (DB + signer) |
| `GET` | `/metrics` | admin | Prometheus metrics |
| `GET` | `/system/root` | admin, auditor | Global system root hash |

---

## Error format

All errors return structured JSON:

```json
{
  "error":   "UNAUTHORIZED_MODEL_VERSION",
  "message": "Model version 'v2.9' is not approved. Approved: ['v3.1']",
  "hint":    "Approve this version via POST /governance/model first.",
  "trace_id": "a3f8c2d1-..."
}
```

Validation errors:
```json
{
  "error":          "INVALID_REQUEST",
  "missing_fields": ["from_state", "to_state"],
  "trace_id":       "..."
}
```

---

## Production checklist

```
☐ ZORYNEX_SIGNING_KEY — from KMS or secrets manager, never in code
☐ ZORYNEX_API_KEYS — one key per role, rotate quarterly
☐ ZORYNEX_REQUIRE_TENANT=true — enforce tenant isolation
☐ ZORYNEX_ANCHOR_RFC3161=true — enable external timestamps
☐ ZORYNEX_BACKEND=postgres + DATABASE_URL — for multi-worker deployments
☐ ZORYNEX_WORKERS=4 — safe with PostgreSQL. Keep at 1 for SQLite.
☐ TLS terminated at nginx — app is internal only
☐ Database backups — the ledger IS the proof record. Back it up.
☐ Webhook HMAC secret — rotate if exposed
```

---

## Regulatory alignment

| Regulation | Requirement | How Zorynex addresses it |
|---|---|---|
| SR 11-7 | Model risk management with reproducible validation evidence | Version-locked execution captured at runtime, not reconstructed after the fact |
| EU AI Act Art. 9 | Active risk management system | Governance enforcement gate — unapproved versions are blocked |
| EU AI Act Art. 13 | Transparency and documentation | Signed proof artifact with full decision chain, verifiable offline |
| CFPB Adverse Action | Proof of AI decision reasoning | `reason_code`, `feature_contributions`, `threshold_used` embedded in every proof |
| GDPR Art. 17 | Right to erasure | Only input hashes are stored — raw PII never enters the proof ledger |