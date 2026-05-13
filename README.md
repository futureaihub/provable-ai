# Zorynex — Provable AI Infrastructure

[![License](https://img.shields.io/badge/license-Zorynex%20Source--Available-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-576%20passing-brightgreen)](tests/)
[![Status](https://img.shields.io/badge/status-production--ready-green)]()

Every AI decision becomes a cryptographic proof artifact — tamper-evident, hash-chained, independently verifiable with zero server access.

**The core property:** An auditor receives a file. They verify it on their own machine. No call to your API. No database access. No trust in your organisation required. The mathematics proves it.

---

## Get started in 3 commands

```bash
git clone https://github.com/zorynex/provable-ai
cd provable-ai
pip install -r requirements.txt

python bootstrap.py --start   # generates keys, initialises DB, starts server
```

Open **http://127.0.0.1:8000/quickstart** for a copy-paste guide to your first proof, or go straight to **http://127.0.0.1:8000/docs** → Authorize (`X-API-Key: dev-key`) → run `POST /demo/bootstrap`.

---

## After first run

```bash
# One-line start
source .env && uvicorn server.main:app --reload
```

Startup banner:
```
==============================================================
  Zorynex Provable AI  ·  Cryptographic proof infrastructure
==============================================================
  Swagger UI →  http://127.0.0.1:8000/docs
  ReDoc      →  http://127.0.0.1:8000/redoc
  Quickstart →  http://127.0.0.1:8000/quickstart
  Verify UI  →  http://127.0.0.1:8000/verify-ui
==============================================================
```

---

## What it does

- **Signs every AI decision** with Ed25519 — any modification is immediately detectable
- **Hash-chains decisions** — the full sequence of events is cryptographically provable
- **Hashes sensitive inputs** — no PII stored in the proof, but inputs are auditable
- **Enforces governance** — only approved models, agents, and policies can write decisions
- **Verifiable offline** — auditors verify with zero access to your infrastructure
- **Anchors externally** — optional RFC 3161 timestamps from FreeTSA, outside your control boundary

---

## The 4-step proof lifecycle

```
POST /decision          →  decision recorded, signed, hash-chained
GET  /proof/export/{id} →  self-contained proof.json exported
POST /verify-package    →  4 cryptographic checks in 200ms
open /verify-ui         →  auditor drags file in, sees green or red
```

---


## Proof identity — `proof_fingerprint`

Every exported package includes a `proof_fingerprint` field — a cryptographically deterministic identity for the proof that any auditor can independently verify.

**Formula:**
```
proof_fingerprint = SHA256(instance_root + ":" + chain_length)
```

**Example:**
```json
{
  "proof_fingerprint": "b7ee4d91b9fcde28a3c4f9e1d0b2a7c6...(64 hex chars)...",
  "chain_length":      2,
  "instance_root":     "eed1202fd77c54085e9e024ddacaa554...",
  ...
}
```

To verify independently:
```python
import hashlib, json

pkg            = json.load(open("proof.json"))
instance_root  = pkg["proof"]["instance_root"]
chain_length   = pkg["chain_length"]
expected       = hashlib.sha256(f"{instance_root}:{chain_length}".encode()).hexdigest()

assert expected == pkg["proof_fingerprint"], "Fingerprint mismatch — proof identity cannot be confirmed"
print("✓ Fingerprint verified:", expected[:16], "...")
```

This check is independent of the cryptographic signature verification — it confirms proof identity, not proof integrity. Run it before submitting a proof to a regulator or auditor to confirm you have the correct package.

## API at a glance

| | Endpoint | What it does |
|---|---|---|
| 🚀 | `POST /demo/bootstrap` | Seed a complete demo environment in one call |
| 🚀 | `POST /decision` | Record an AI decision — simple or full mode |
| 🚀 | `GET /proof/export/{id}?inline=true` | Export a verifiable proof package |
| 🚀 | `POST /verify-package` | Verify a package — 4 cryptographic checks |
| ⚙️ | `POST /protocol/compile` | Define workflow states and transitions |
| ⚙️ | `POST /governance/model` | Approve a model version |
| ⚙️ | `POST /instance/create` | Create a workflow instance |
| 🔍 | `GET /proof/{id}` | Retrieve a single proof |
| 🔍 | `GET /chain/{id}` | Full decision chain |
| 🛡 | `GET /audit/compliance` | SR 11-7 / EU AI Act / CFPB compliance pack |
| 🩺 | `GET /health` | Liveness probe |

Full reference: [/docs](http://127.0.0.1:8000/docs) · [/redoc](http://127.0.0.1:8000/redoc)

---

## Simple mode — record a decision in 4 fields

Governance auto-resolves from your approved lists:

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

---

## Verification — three ways, same result

**Browser — for auditors (no code, no API key needed):**
```
open http://127.0.0.1:8000/verify-ui
```
Drag and drop a proof package. Four green checkmarks. Download a PDF report.

**CLI — for engineers:**
```bash
python verify/verify_package.py proof.json
# ✓ Package structure valid
# ✓ Package untampered
# ✓ Chain valid
# ✓ Signature valid
# RESULT: VERIFIED ✓
```

**API — for integrations:**
```bash
curl -X POST http://127.0.0.1:8000/verify-package \
  -H "X-API-Key: dev-key" -d @proof.json
```

---

## Python SDK — zero dependencies

```python
from sdk.zorynex import ZorynexClient

client = ZorynexClient(base_url="http://127.0.0.1:8000", api_key="dev-key")

client.bootstrap()  # seed demo environment

proof = client.record_decision(
    instance_id="loan-9284", from_state="received", to_state="approved",
    raw_inputs={"credit_score": "742"},
)

package = client.export_proof("loan-9284")
result  = client.verify_package(package)
print(result["verified"])  # True
```

**TypeScript:** `sdk/zorynex.ts` — Node 18+, Deno, browser, Bun.

**Postman:** Import `sdk/zorynex.postman_collection.json` — 38 requests, 7 folders, pre-configured variables.

---

## Deployment

## Docker

**Dev (SQLite, zero config):**
```bash
docker compose -f docker-compose.sqlite.yml up
# → http://127.0.0.1:8000/docs   X-API-Key: dev-key
```

**Full stack (PostgreSQL):**
```bash
docker compose up --build
```

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ZORYNEX_SIGNING_KEY` | Yes | auto-generated by bootstrap | 64-char hex Ed25519 private key |
| `ZORYNEX_API_KEYS` | Yes | `dev-key:admin` | `key:role,key:role` |
| `ZORYNEX_WEBHOOK_SECRET` | Yes | auto-generated by bootstrap | HMAC secret |
| `ZORYNEX_DB_PATH` | No | `provable_ai.db` | SQLite path |
| `DATABASE_URL` | Prod | — | PostgreSQL connection string |
| `ZORYNEX_BACKEND` | No | `sqlite` | `sqlite` or `postgres` |
| `ZORYNEX_REQUIRE_TENANT` | No | `false` | Enforce `X-Tenant-Id` in production |
| `ZORYNEX_ANCHOR_RFC3161` | No | `false` | Enable FreeTSA external timestamps |

`python bootstrap.py` generates all required values and writes `.env`.

---

## Architecture

```
GovernanceEngine
├── SQLiteStorage / PostgreSQLHardenedStorage  — append-only proof ledger
├── EnvSigner / KmsSigner / FailoverSigner     — Ed25519 signing
└── Verifier                                   — offline chain verification

FastAPI server  (admin / auditor / system RBAC)
├── quickstart   POST /demo/bootstrap, POST /decision, proof export + verify
├── configure    Protocol, governance, instances
├── verify       Proof retrieval, chain, package verification
├── audit        Compliance exports, anchoring, key registry
└── monitor      Health, metrics, drift detection
```

CLI tools:

```bash
python cli.py verify proof.json           # verify a proof package
python verify/verify_package.py proof.json # standalone verifier (zero deps)
```

---

## Project structure

```
provable_ai/     core library — engine, storage, signer, verifier, audit
server/          FastAPI application — 34 endpoints across 8 tag groups
sdk/             Python SDK · TypeScript SDK · Postman collection
verify/          Standalone verifier scripts — zero Zorynex dependency
web/             Browser proof verifier (verifier.html)
docs/            dev.md · auditor.md · cro.md · integration.md · demo_steps.md
tests/           576 tests across 13 files — all passing
examples/        Loan decisioning end-to-end example
migrations/      Alembic PostgreSQL migrations
```

---

## Tests

```bash
pytest tests/ -q              # 576 tests, all passing
pytest tests/test_chaos.py    # chaos scenarios: DB down, KMS down, disk full
```

---

## Regulatory alignment

| Regulation | How Zorynex addresses it |
|---|---|
| SR 11-7 | Version-locked execution captured at runtime — not reconstructed after the fact |
| EU AI Act Art. 9 | Governance enforcement gate — unapproved versions are blocked |
| EU AI Act Art. 13 | Signed proof artifact with full decision chain, verifiable offline |
| CFPB Adverse Action | `reason_code`, `feature_contributions`, `threshold_used` embedded in every proof |
| GDPR Art. 17 | Only input hashes stored — raw PII never enters the proof ledger |

---

## Honest limits

- **Tamper-evident**, not tamper-proof — detects modification, cannot physically prevent it
- **Verifiable**, not trustless — the signing key lives inside your control boundary
- **Secure by design**, not immune to ops mistakes — key management is your responsibility

---

## Commercial use

This repository is source-available for evaluation. Production use requires a commercial licence.

Contact **hanif@zorynex.co** — subject: Commercial Licence Enquiry.

---

[docs/dev.md](docs/dev.md) · [docs/auditor.md](docs/auditor.md) · [docs/cro.md](docs/cro.md) · [docs/integration.md](docs/integration.md) · [SECURITY.md](SECURITY.md) · [LICENSE](LICENSE)