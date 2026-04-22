# Provable AI — Loan Decision Verification Demo

This demo shows how Provable AI converts AI-driven decisions into
cryptographically verifiable audit records that can be independently verified.

The scenario demonstrates a simplified **AI loan approval workflow** where each
decision step is:

• deterministically enforced  
• cryptographically recorded  
• replayable and auditable  
• exportable as a portable proof artifact  

---

# Scenario

A fintech startup uses an AI model to approve loans.

Regulators and auditors must be able to verify:

- which model made the decision
- what decision path was executed
- whether the process was tampered with
- whether execution followed the approved policy

Provable AI provides cryptographic proof of the full decision lifecycle.

---

# 1. Compile Deterministic Loan Protocol

Compile a workflow protocol describing the allowed decision states.

submitted → review → approved

Run:

```bash
curl -X POST http://127.0.0.1:8000/compile \
-H "Content-Type: application/json" \
-d '{
  "source": "{\"states\":[\"submitted\",\"review\",\"approved\"],\"initial_state\":\"submitted\",\"transitions\":[{\"from_state\":\"submitted\",\"to_state\":\"review\"},{\"from_state\":\"review\",\"to_state\":\"approved\"}]}"
}'
```

Expected result:

determinism_certificate

Includes:

protocol_hash

This guarantees deterministic protocol compilation.

---

# 2. Create Loan Instance

Create a new loan decision instance.

```bash
curl -X POST http://127.0.0.1:8000/instances \
-H "Content-Type: application/json" \
-d '{"instance_id":"loan_demo_1"}'
```

Expected:

```json
{
 "instance_id": "loan_demo_1",
 "state": "submitted"
}
```

---

# 3. Transition to Review

The AI risk model evaluates the loan.

```bash
curl -X POST http://127.0.0.1:8000/instances/loan_demo_1/transition \
-H "Content-Type: application/json" \
-d '{
 "target_state":"review",
 "actor":"risk_model",
 "input_hash":"input_hash_001",
 "output_hash":"output_hash_001",
 "model_version":"gpt-4.1",
 "agent_version":"v1",
 "policy_version":"1.0",
 "metadata_json":"{}"
}'
```

Expected:

```json
{
 "new_state": "review",
 "version": 1,
 "ledger_hash": "<hash>"
}
```

The decision is now recorded in the cryptographic ledger.

---

# 4. Transition to Approved

The system approves the loan.

```bash
curl -X POST http://127.0.0.1:8000/instances/loan_demo_1/transition \
-H "Content-Type: application/json" \
-d '{
 "target_state":"approved",
 "actor":"risk_model",
 "input_hash":"input_hash_002",
 "output_hash":"output_hash_002",
 "model_version":"gpt-4.1",
 "agent_version":"v1",
 "policy_version":"1.0",
 "metadata_json":"{}"
}'
```

Expected:

```json
{
 "new_state": "approved",
 "version": 2,
 "ledger_hash": "<hash>"
}
```

The instance is now finalized and immutable.

---

# 5. Deterministic Replay Validation

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

# 6. Export Signed Proof Package

Export a portable cryptographic proof.

```bash
curl http://127.0.0.1:8000/ledger/loan_demo_1/export > proof_demo.json
```

The proof package contains:

protocol  
instance  
ledger  
instance_root  
public_key  
signature  

This artifact can be verified independently.

---

# 7. Independent Offline Verification

Verify the proof without the Provable AI server.

```bash
python cli.py verify proof_demo.json
```

Expected output:

VALID: Proof verified successfully  
Final state: approved

This demonstrates **trustless verification**.

---

# 8. System Integrity Root

Retrieve the cryptographic root representing the full system state.

```bash
curl http://127.0.0.1:8000/system/root
```

Expected:

```json
{
 "system_root": "<hash>"
}
```

---

# 9. Cross-Environment Drift Detection

Compare system roots between environments.

```bash
curl "http://127.0.0.1:8000/system/drift/compare?external_root=<paste_root_here>"
```

Expected:

```json
{
 "match": true,
 "current_root": "...",
 "external_root": "..."
}
```

A mismatch indicates environmental drift or tampering.

---

# Demonstrated Capabilities

This demo demonstrates:

- Deterministic state machine enforcement
- AI governance validation
- Cryptographic execution ledger
- Replay-based decision validation
- Immutable decision records
- Signed proof artifact generation
- Independent offline verification
- Merkle root system integrity
- Cross-environment drift detection

---

# Key Insight

Provable AI converts opaque AI decisions into **cryptographically provable execution records** that auditors, regulators, and enterprise clients can independently verify.