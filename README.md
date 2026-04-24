# Provable AI

[![License](https://img.shields.io/badge/license-Zorynex%20Source--Available-blue)](https://github.com/futureaihub/provable-ai/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-73%20passing-brightgreen)](https://github.com/futureaihub/provable-ai/tree/main/tests)
[![Status](https://img.shields.io/badge/status-experimental-orange)](https://github.com/futureaihub/provable-ai)

Infrastructure for **cryptographically verifiable AI decisions**.

Every AI decision your system makes becomes a **signed proof artifact** — independently verifiable by regulators, auditors, and enterprise clients. No trust required. No server access needed.

---

## What It Does

Provable AI converts AI loan and risk decisions into **cryptographic proof artifacts** that regulators and auditors can independently verify.

Instead of trusting internal logs or opaque AI outputs, decisions are recorded as **deterministic state transitions** backed by:

- **SHA-256 hash chains** — tamper-evident ledger
- **Ed25519 signatures** — every decision cryptographically signed via PyNaCl
- **Merkle roots** — replay-verifiable state
- **Offline verification** — no server trust required

---

## Core Features

| # | Feature | Description |
|---|---------|-------------|
| 01 | Deterministic Decision Protocols | Workflow specs compile to protocol hash via grammar rules engine |
| 02 | Governance Enforcement | Models, agents, and policies validated at runtime — unauthorized blocked |
| 03 | Cryptographic Execution Ledger | SHA-256 hash chain + Ed25519 signature on every decision |
| 04 | Version-Locked Execution | Exact model + policy + canonical state captured at execution time |
| 05 | Signed Proof Artifact Export | Portable signed JSON — `curl /ledger/<id>/export > proof.json` |
| 06 | Independent Verification CLI | `python cli.py verify proof.json` — fully offline |
| 07 | Replay-based Tamper Detection | Merkle root replay via verify_core.py detects any modification |
| 08 | Environment Drift Detection | System root comparison across dev, staging, and production |

---

## Quick Start

**Clone and install:**

```bash
git clone https://github.com/futureaihub/provable-ai.git
cd provable-ai

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

**Start the server:**

```bash
uvicorn server.main:app --reload
```

**Record a decision:**

```bash
curl -X POST http://localhost:8000/decisions/record \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": "loan_9284",
    "workflow": "credit_approval_v3",
    "model_version": "credit_model_v3.1",
    "inputs": {"score": 720, "dti": 0.28},
    "output": "approved"
  }'
```

**Export a proof artifact:**

```bash
curl http://localhost:8000/ledger/loan_9284/export > proof.json
```

**Verify independently:**

```bash
python cli.py verify proof.json
```

```
✓ VALID: Proof verified successfully

  signature_algo   Ed25519
  hash_algo        SHA-256 chain
  model_version    credit_model_v3.1
  governance       all policies enforced
  state_locked     true
  tamper_detected  false
  replay_valid     true
  final_state      approved
```

---

## Production Deployment

**Docker (recommended):**

```bash
docker-compose -f docker-compose.prod.yml up -d
```

Production configuration includes:
- Authentication middleware
- Rate limiting
- Audit logging
- Secrets management via environment variables or AWS Secrets Manager
- Health check endpoint: `GET /health`

**Environment variables:**

```bash
SECRET_KEY=your-secret-key
SIGNING_KEY_PATH=provable_key.hex
LEDGER_DB_PATH=ledger.db
LOG_LEVEL=INFO
```

---

## Verification Tools

Three verification tools are available depending on context:

**`python cli.py verify proof.json`**
Primary CLI — full verification with human-readable output.

**`python tools/offline_verify.py proof.json`**
Standalone offline verifier — no dependencies on server or ledger. For use by auditors and regulators who receive a proof artifact without system access.

**`python tools/verify_core.py`**
Core verification module — used internally by both CLI tools. Implements full SHA-256 chain verification, Ed25519 signature check, and Merkle root replay.

---

## Regulatory Alignment

| Regulation | Requirement | How Provable AI Addresses It |
|-----------|------------|------------------------------|
| SR 11-7 | Model risk management, reproducible validation evidence | Version-locked execution + cryptographic proof artifacts |
| EU AI Act Art. 9 | Active risk management system for high-risk AI | Governance enforcement gate on every decision |
| EU AI Act Art. 13 | Transparency and documentation of AI decisions | Signed proof artifact with full decision chain |
| CFPB Adverse Action | Proof of AI decision correctness | Independent verification CLI for auditors |

---

## Tests

```bash
pytest tests/ -v
```

73 tests covering:
- Engine determinism and state transition correctness
- Grammar rules enforcement
- Cryptographic signing and verification
- Hash chain integrity
- Tamper detection replay

---

## Licence

This project is licensed under the **Zorynex Source-Available Licence**.

- **Evaluation use:** Free to view, clone, and run locally for non-commercial evaluation
- **Commercial use:** Requires a commercial licence from Zorynex

See [LICENSE](LICENSE) for full terms.

Commercial licensing: [hanif@zorynex.co](mailto:hanif@zorynex.co)

---

## Contact

**Hanif Shaik** — Founder, Zorynex  
[hanif@zorynex.co](mailto:hanif@zorynex.co)  
[zorynex.co](https://zorynex.co)  
[github.com/futureaihub/provable-ai](https://github.com/futureaihub/provable-ai)
