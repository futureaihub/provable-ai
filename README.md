# Zorynex — Provable AI

[![License](https://img.shields.io/badge/license-Zorynex%20Source--Available-blue)](https://github.com/futureaihub/provable-ai/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](https://python.org)
[![Status](https://img.shields.io/badge/status-pilot--ready-green)](https://zorynex.co)

Infrastructure for **cryptographically verifiable AI decisions**.

Every AI decision your system makes becomes a signed proof artifact — independently verifiable by regulators, auditors, and enterprise clients. No trust required.

---

## What It Does

Zorynex converts AI loan and risk decisions into **cryptographic proof artifacts** that can be independently verified offline — without server access, without trusting internal logs, without reconstructing evidence after the fact.

Every decision is recorded the moment it fires. The record is tamper-evident by construction: a hash chain links each entry to the previous one, every entry is signed with Ed25519, and the ledger is anchored by a Merkle root.

---

## Core Features

- Deterministic decision protocols
- Governance enforcement — unauthorized model/agent/policy versions blocked at runtime
- Cryptographic execution ledger (SHA-256 hash chain + Ed25519 per-entry signatures)
- Signed proof artifact export
- Independent offline verification CLI (no server access required)
- Replay-based tamper detection
- Environment drift detection
- PostgreSQL backend for production deployments

---

## Quick Start

Clone the repository

```bash
git clone https://github.com/futureaihub/provable-ai.git
cd provable-ai
```

Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the API server

```bash
uvicorn server.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ZORYNEX_SIGNING_KEY` | Production | — | Ed25519 private key hex. Generate with the command below. |
| `ZORYNEX_DATABASE_URL` | Production | — | PostgreSQL connection string. Falls back to SQLite if not set. |
| `ZORYNEX_DB_PATH` | Optional | `zorynex.db` | SQLite file path (dev/pilot only). |
| `ZORYNEX_ALLOWED_ORIGINS` | Optional | `http://localhost:5173` | CORS allowed origins, comma-separated. |

**Generate a signing key:**

```bash
python -c "
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
print(SigningKey.generate().encode(encoder=HexEncoder).decode())
"
```

```bash
export ZORYNEX_SIGNING_KEY=<output from above>
```

---

## Demo

A complete step-by-step demo is provided in `docs/demo_steps.md`.

The demo covers:

1. Governance seeding (approve model, agent, policy versions)
2. Protocol compilation
3. Instance creation
4. Decision transitions
5. Deterministic replay validation
6. Proof export
7. Independent offline verification
8. Drift detection

---

## Example Verification

Export a proof:

```bash
curl http://127.0.0.1:8000/ledger/<instance_id>/export > proof.json
```

Verify independently (offline, no server needed):

```bash
python cli.py verify proof.json
```

Expected output:

```
VALID: Proof verified successfully
Final state: approved
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Liveness check — returns storage backend and public key |
| POST | `/compile` | Compile a decision protocol spec |
| POST | `/instances` | Create a new decision instance |
| POST | `/instances/{id}/transition` | Record an AI decision transition |
| GET | `/ledger/{id}/export` | Export signed proof artifact |
| GET | `/ledger/{id}/replay` | Verify ledger integrity |
| GET | `/ledger/{id}/count` | Count ledger entries |
| POST | `/governance/models` | Approve a model version |
| POST | `/governance/agents` | Approve an agent version |
| POST | `/governance/policies` | Approve a policy version |
| GET | `/governance/status` | List all approved versions |
| GET | `/system/root` | Compute system Merkle root |
| GET | `/system/drift/compare` | Compare system roots across environments |
| GET | `/instance/{id}/drift/compare` | Compare instance root |
| POST | `/external/verify-proof` | Verify a proof package via API |

---

## Architecture

```
provable_ai/   → Core execution engine
server/        → API server (FastAPI)
tools/         → verify_core.py, offline_verify.py, verify_proof.py
tests/         → Full test suite (73 tests)
docs/          → Demo, architecture, and positioning documents
cli.py         → Verification CLI tool
index.html     → Project landing page
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

All 73 tests should pass.

---

## Production Deployment

For production, set `ZORYNEX_DATABASE_URL` to your PostgreSQL connection string. The system automatically switches from SQLite to PostgreSQL — no code changes needed.

```bash
export ZORYNEX_DATABASE_URL="postgresql://user:pass@host:5432/zorynex"
export ZORYNEX_SIGNING_KEY="<your hex key>"
export ZORYNEX_ALLOWED_ORIGINS="https://yourdomain.com"
uvicorn server.main:app --host 0.0.0.0 --port 8000
```

For KMS-based key management (AWS, Azure, GCP), see the stub in `provable_ai/signer.py`.

---

## Positioning

See `docs/positioning.md` — how Provable AI differs from AI observability tools, ML monitoring platforms, and audit logging systems.

Provable AI provides **cryptographic decision verification**, not just monitoring.

---

## License

Released under the **Zorynex Source-Available License**.

Permitted for non-commercial evaluation. Production deployment, enterprise integration, and commercial use require a commercial license.

**Commercial licensing and pilot enquiries:**
[hanif@zorynex.co](mailto:hanif@zorynex.co) · [zorynex.co](https://zorynex.co)
