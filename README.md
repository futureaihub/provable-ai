# Provable AI

![License](https://img.shields.io/badge/license-Zerivox%20Source--Available-blue)

Infrastructure for cryptographically verifiable AI decisions.

---

## What It Does

Provable AI converts AI loan and risk decisions into **signed proof artifacts** that regulators, auditors, and enterprise clients can **independently verify**.

Instead of trusting internal logs or opaque AI outputs, decisions are recorded as **deterministic state transitions backed by cryptographic proof**.

---

## Core Features

- Deterministic decision protocols
- Governance enforcement for models, agents, and policies
- Cryptographic execution ledger
- Signed proof artifact export
- Independent verification CLI
- Replay-based tamper detection
- Environment drift detection

---

## Demo

A complete step-by-step demo is provided.

See:

docs/demo_steps.md

The demo shows:

1. Protocol compilation  
2. Instance creation  
3. Decision transitions  
4. Deterministic replay validation  
5. Proof export  
6. Independent verification  
7. Drift detection  

---

## Architecture

Detailed architecture documentation:

docs/integration.md

This document explains:

- Deterministic protocol execution
- Governance validation layer
- Cryptographic ledger design
- Proof export system
- Independent verification flow

---

## Positioning

See:

docs/positioning.md

This explains how Provable AI differs from:

- AI observability tools
- ML monitoring platforms
- audit logging systems

Provable AI provides **cryptographic decision verification**, not just monitoring.

---

## Repository Structure

```
provable_ai/   → Core execution engine  
server/        → API server (FastAPI)  
tools/         → Offline verification utilities  
tests/         → System and compiler tests  
landing/       → Project landing page  
docs/          → Demo, architecture, and positioning documents  
cli.py         → Verification CLI tool
```

---

## Example Verification

Export a proof:

```
curl http://127.0.0.1:8000/ledger/<instance_id>/export > proof.json
```

Verify independently:

```
python cli.py verify proof.json
```

Expected output:

```
VALID: Proof verified successfully
```

---

## License

This repository is released under the **Zerivox Source-Available License**.

You are permitted to **view, download, and evaluate** the software for **non-commercial purposes only**.

The following uses require a **commercial license**:

- Production deployment
- Enterprise integration
- Commercial products or services
- Redistribution of the software
- Derivative works used commercially

---

## Commercial Licensing

For commercial licensing, enterprise deployment, or partnerships contact:

**zerivoxfounder@gmail.com**

See the `LICENSE` file for full terms.# provable-ai
