# Zorynex — Loan Decision Verification Demo

This demo shows how Zorynex converts AI-driven decisions into
cryptographically verifiable audit records that can be independently
verified offline — without server access and without trusting internal logs.

**Scenario:** A fintech uses an AI model to approve loans.
Regulators and auditors must be able to verify which model made the decision,
what decision path was executed, whether the process was tampered with,
and whether execution followed the approved policy.

---

## Before You Start

Start the API server:

```bash
uvicorn server.main:app --reload
```

Check it is running:

```bash
curl http://127.0.0.1:8000/health
```

Expected:

```json
{
  "status": "ok",
  "service": "Zorynex Provable AI",
  "storage_backend": "sqlite",
  "public_key": "<your public key hex>"
}
```

---

## Step 0 — Seed Governance Registry

**This step is required before any transitions will succeed.**

Approve the model version, agent version, and policy version that your
AI system will use. Unauthorized versions are blocked at runtime.

```bash
curl -X POST http://127.0.0.1:8000/governance/models \
-H "Content-Type: application/json" \
-d '{"model_version": "credit_model_v1"}'
```

```bash
curl -X POST http://127.0.0.1:8000/governance/agents \
-H "Content-Type: application/json" \
-d '{"agent_version": "loan_agent_v1"}'
```

```bash
curl -X POST http://127.0.0.1:8000/governance/policies \
-H "Content-Type: application/json" \
-d '{"policy_version": "policy_v1", "active": true}'
```

Verify governance is seeded:

```bash
curl http://127.0.0.1:8000/governance/status
```

Expected:

```json
{
  "approved_models": [{"model_version": "credit_model_v1", "created_at": "..."}],
  "approved_agents": [{"agent_version": "loan_agent_v1", "created_at": "..."}],
  "approved_policies": [{"policy_version": "policy_v1", "active": 1, "created_at": "..."}]
}
```

---

## Step 1 — Compile Deterministic Loan Protocol

Compile a workflow protocol describing the allowed decision states.

```
submitted → review → approved
```

```bash
curl -X POST http://127.0.0.1:8000/compile \
-H "Content-Type: application/json" \
-d '{
  "source": "{\"states\":[\"submitted\",\"review\",\"approved\"],\"initial_state\":\"submitted\",\"transitions\":[{\"from_state\":\"submitted\",\"to_state\":\"review\"},{\"from_state\":\"review\",\"to_state\":\"approved\"}]}"
}'
```

Expected:

```json
{
  "determinism_certificate": {
    "protocol_hash": "<64-char hex>",
    "proof_hash": "<64-char hex>",
    "grammar_version": "0.1",
    "compiler_version": "0.1"
  }
}
```

The `protocol_hash` is deterministic — the same spec always produces the same hash.

---

## Step 2 — Create Loan Instance

Create a new loan decision instance.

```bash
curl -X POST http://127.0.0.1:8000/instances \
-H "Content-Type: application/json" \
-d '{"instance_id": "loan_demo_1"}'
```

Expected:

```json
{
  "instance_id": "loan_demo_1",
  "state": "submitted"
}
```

---

## Step 3 — Transition to Review

The AI risk model evaluates the loan.

```bash
curl -X POST http://127.0.0.1:8000/instances/loan_demo_1/transition \
-H "Content-Type: application/json" \
-d '{
  "target_state": "review",
  "actor": "risk_model",
  "input_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "output_hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
  "model_version": "credit_model_v1",
  "agent_version": "loan_agent_v1",
  "policy_version": "policy_v1",
  "metadata_json": "{\"score\": 720, \"reason\": \"income_verified\"}"
}'
```

Expected:

```json
{
  "new_state": "review",
  "version": 1,
  "ledger_hash": "<64-char hex>"
}
```

The decision is now recorded in the cryptographic ledger.

---

## Step 4 — Transition to Approved

The system approves the loan.

```bash
curl -X POST http://127.0.0.1:8000/instances/loan_demo_1/transition \
-H "Content-Type: application/json" \
-d '{
  "target_state": "approved",
  "actor": "risk_model",
  "input_hash": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "output_hash": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
  "model_version": "credit_model_v1",
  "agent_version": "loan_agent_v1",
  "policy_version": "policy_v1",
  "metadata_json": "{\"decision\": \"approved\", \"amount\": 50000}"
}'
```

Expected:

```json
{
  "new_state": "approved",
  "version": 2,
  "ledger_hash": "<64-char hex>"
}
```

---

## Step 5 — Check Ledger Entry Count

```bash
curl http://127.0.0.1:8000/ledger/loan_demo_1/count
```

Expected:

```json
{
  "instance_id": "loan_demo_1",
  "entry_count": 2
}
```

---

## Step 6 — Deterministic Replay Validation

Rebuild the execution path from the ledger.

```bash
curl http://127.0.0.1:8000/ledger/loan_demo_1/replay
```

Expected:

```json
{
  "valid": true,
  "final_state": "approved"
}
```

This confirms the ledger reconstructs the same decision state.

---

## Step 7 — Export Signed Proof Package

Export a portable cryptographic proof artifact.

```bash
curl http://127.0.0.1:8000/ledger/loan_demo_1/export > proof_demo.json
```

The proof package contains:

- `type` — proof package identifier
- `public_key` — Ed25519 public key
- `signature` — outer package signature (covers entire proof blob)
- `proof.protocol` — compiled decision protocol
- `proof.instance` — instance metadata
- `proof.ledger` — all signed ledger entries
- `proof.instance_root` — Merkle root of all ledger hashes

This artifact is self-contained and can be verified offline forever.

---

## Step 8 — Independent Offline Verification

Verify the proof without the Zorynex server.

```bash
python cli.py verify proof_demo.json
```

Expected output:

```
VALID: Proof verified successfully
Final state: approved
Instance:    loan_demo_1
```

This is **trustless verification** — no server access required, no trust assumptions.

---

## Step 9 — System Integrity Root

Retrieve the cryptographic root representing the full system state.

```bash
curl http://127.0.0.1:8000/system/root
```

Expected:

```json
{
  "system_root": "<64-char Merkle root hex>"
}
```

Save this value. You can use it to detect drift between environments.

---

## Step 10 — Cross-Environment Drift Detection

Compare system roots between environments (e.g. prod vs staging).

```bash
curl "http://127.0.0.1:8000/system/drift/compare?external_root=<paste_root_here>"
```

Expected when roots match:

```json
{
  "match": true,
  "current_root": "...",
  "external_root": "..."
}
```

A mismatch indicates environmental drift or tampering.

---

## What This Demo Proves

- Deterministic state machine enforcement
- AI governance validation (unauthorized models blocked)
- Cryptographic execution ledger (hash chain + Ed25519 signatures)
- Replay-based decision validation
- Immutable decision records (frozen on export)
- Signed proof artifact generation
- Independent offline verification
- Merkle root system integrity
- Cross-environment drift detection

---

## Key Insight

Zorynex converts opaque AI decisions into **cryptographically provable execution records** that auditors, regulators, and enterprise clients can independently verify — without trusting internal systems, without server access, and without reconstructing evidence after the fact.
