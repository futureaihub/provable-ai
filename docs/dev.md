# Zorynex — Developer Integration Guide

**Audience:** Engineers integrating Zorynex into an AI decision pipeline.

---

## Installation

```bash
git clone https://github.com/zorynex/provable-ai
cd provable-ai
pip install -r requirements.txt
```

## Quickstart (2 minutes)

```bash
# First time
python bootstrap.py --start     # generates keys + starts server automatically

# After that
source .env && uvicorn server.main:app --reload
```

Open **http://127.0.0.1:8000/docs** → Authorize (`X-API-Key: dev-key`) → run `POST /demo/bootstrap`.

---

## Two modes for POST /decision

**Simple mode** — governance auto-resolved from your approved lists:
```json
{
  "instance_id": "loan-001",
  "from_state":  "pending",
  "to_state":    "approved",
  "raw_inputs":  {"credit_score": "742"}
}
```

**Full mode** — explicit control:
```json
{
  "instance_id":   "loan-001",
  "from_state":    "pending",
  "to_state":      "approved",
  "model_version": "credit-model-v3.1",
  "agent_version": "underwriter-v1.0",
  "policy_version":"credit-policy-v2",
  "reason_code":   "SCORE_ABOVE_THRESHOLD",
  "policy_rule":   "credit-policy-v2.rule_7",
  "raw_inputs":    {"credit_score": "742", "dti": "0.28"}
}
```

---

## Quick integration

## Python SDK

```python
from sdk.zorynex import ZorynexClient

client = ZorynexClient(
    base_url  = "http://127.0.0.1:8000",
    api_key   = "dev-key",
    tenant_id = "default",
)

# Bootstrap demo environment
client.bootstrap()

# Record decision
proof = client.record_decision(
    instance_id="loan-001", from_state="pending", to_state="approved",
    raw_inputs={"credit_score": "742"},
)

# Export + verify
package = client.export_proof("loan-001")
result  = client.verify_package(package)
assert result["verified"] is True
```

---

## REST API

## Full workflow (production pattern)

```python
# 1. Compile a protocol
client.compile_protocol(
    states        = ["received", "under_review", "approved", "rejected"],
    initial_state = "received",
    transitions   = [
        {"from_state": "received",     "to_state": "under_review"},
        {"from_state": "under_review", "to_state": "approved"},
        {"from_state": "under_review", "to_state": "rejected"},
    ],
)

# 2. Approve governance
client.approve_model("credit_model", "v3.1")
client.approve_agent("underwriter",  "v1.0")
client.approve_policy("credit_policy", "v2")

# 3. Create instance
client.create_instance("loan-9284")

# 4. Record decisions
for transition in workflow_transitions:
    client.record_decision(
        instance_id   = "loan-9284",
        from_state    = transition.from_state,
        to_state      = transition.to_state,
        raw_inputs    = transition.inputs,
        model_version = "v3.1",
        agent_version = "v1.0",
        policy_version= "v2",
    )

# 5. Export proof
package = client.export_proof("loan-9284")  # full verifiable package

# 6. Verify before archiving
result = client.verify_package(package)
assert result["verified"], result["checks"]
```

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ZORYNEX_SIGNING_KEY` | Yes | — | 64-char hex Ed25519 private key |
| `ZORYNEX_API_KEYS` | Yes | `dev-key:admin` | `key:role,key:role` |
| `ZORYNEX_WEBHOOK_SECRET` | Yes | — | HMAC secret |
| `ZORYNEX_DB_PATH` | No | `provable_ai.db` | SQLite path |
| `DATABASE_URL` | Prod | — | PostgreSQL URL |
| `ZORYNEX_BACKEND` | No | `sqlite` | `sqlite` or `postgres` |
| `ZORYNEX_ENV` | No | `development` | Affects startup log verbosity |
| `ZORYNEX_REQUIRE_TENANT` | No | `false` | Enforce `X-Tenant-Id` in prod |
| `ZORYNEX_ANCHOR_RFC3161` | No | `false` | Enable FreeTSA timestamps |

Generate signing key:
```bash
python -c "from nacl.signing import SigningKey; print(SigningKey.generate().encode().hex())"
```

---

## Authentication

All endpoints require `X-API-Key` in the header. Roles:

| Role | Access |
|---|---|
| `admin` | Full access — governance, export, audit |
| `system` | Record decisions, create instances |
| `auditor` | Read-only — proofs, chain, compliance exports |

```bash
# Example
curl http://127.0.0.1:8000/governance/status \
  -H "X-API-Key: dev-key" \
  -H "X-Tenant-Id: default"
```

---

## Error format

All errors return structured JSON:
```json
{
  "error":   "UNAUTHORIZED_MODEL_VERSION",
  "message": "Model version 'v1' is not approved. Approved: ['v3.1']",
  "trace_id":"abc-123"
}
```

Validation errors:
```json
{
  "error":          "INVALID_REQUEST",
  "missing_fields": ["from_state", "to_state"],
  "trace_id":       "abc-123"
}
```

---

## Verification (offline)

```bash
# Browser (for auditors)
open http://127.0.0.1:8000/verify-ui

# CLI
python verify/verify_package.py proof.json
python verify/verify_package.py proof.json --verbose   # with decision chain
python verify/verify_package.py proof.json --json      # machine-readable

# API
curl -X POST http://127.0.0.1:8000/verify-package \
  -H "X-API-Key: dev-key" -d @proof.json
```

---

## Production checklist

- [ ] `ZORYNEX_SIGNING_KEY` — from a secrets manager, never in code
- [ ] `ZORYNEX_REQUIRE_TENANT=true` — enforce tenant isolation
- [ ] `ZORYNEX_ANCHOR_RFC3161=true` — enable external timestamps
- [ ] `ZORYNEX_BACKEND=postgres` + `DATABASE_URL` — for multi-worker deployments
- [ ] `ZORYNEX_WORKERS=4` — safe with PostgreSQL (keep at 1 for SQLite)
- [ ] HMAC webhook secret — rotate quarterly
- [ ] Backups — the SQLite/PG database IS the proof ledger

---

See also: [auditor.md](auditor.md) · [cro.md](cro.md) · [siem.md](siem.md)