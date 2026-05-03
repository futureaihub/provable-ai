"""
Zorynex — Real-World Integration Example: Loan Decisioning
============================================================
Demonstrates end-to-end usage of Zorynex in a credit underwriting system.

This example shows how to:
  1. Configure governance (approved models, agents, policies)
  2. Record a credit decision with cryptographic proof
  3. Handle a multi-step loan lifecycle (application → review → decision → funding)
  4. Verify the proof chain offline (no server needed)
  5. Detect tampering
  6. Export a compliance-ready proof package

Run:
    python examples/loan_decisioning.py

Requirements:
    pip install pynacl  (for Ed25519 signing)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.engine import GovernanceEngine
from provable_ai.signer import EnvSigner
from provable_ai.storage import SQLiteStorage
from provable_ai.verifier import verify_chain, verify_proof


# ── Configuration ─────────────────────────────────────────────────────────────

# In production: set ZORYNEX_SIGNING_KEY env var to a 64-char hex Ed25519 key
# Generate: python -c "from nacl.signing import SigningKey; print(SigningKey.generate().encode().hex())"
DEMO_KEY = os.environ.get(
    "ZORYNEX_SIGNING_KEY",
    "a" * 64,  # demo key — NEVER use in production
)

GOVERNANCE = {
    "approved_models": [
        "credit-model-v3.1",
        "fraud-model-v2.0",
    ],
    "approved_agents": [
        "underwriter-agent-v1.0",
        "fraud-check-agent-v1.0",
    ],
    "approved_policies": [
        "credit-policy-v2",
        "fair-lending-policy-v1",
    ],
}


# ── Loan application data ─────────────────────────────────────────────────────

LOAN_APPLICATION = {
    "application_id": "loan_9284_2026",
    "applicant":      "ANON-7f3a",           # anonymised — no PII in proof
    "loan_amount":    250_000,
    "loan_purpose":   "primary_residence",
}

CREDIT_INPUTS = {
    # These are HASHED before storage — raw values never appear in the proof
    "credit_score":   "742",
    "debt_to_income": "0.28",
    "loan_to_value":  "0.80",
    "employment":     "verified_w2_3yr",
    "bureau":         "experian",
}


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup_engine(db_path: str) -> GovernanceEngine:
    """Create storage, configure governance, return engine."""
    storage = SQLiteStorage(db_path=db_path)
    signer  = EnvSigner()

    for model in GOVERNANCE["approved_models"]:
        storage.add_approved_model(model)
    for agent in GOVERNANCE["approved_agents"]:
        storage.add_approved_agent(agent)
    for policy in GOVERNANCE["approved_policies"]:
        storage.add_approved_policy(policy)

    return GovernanceEngine(storage=storage, signer=signer)


# ── Loan lifecycle ────────────────────────────────────────────────────────────

def run_loan_lifecycle(engine: GovernanceEngine) -> list:
    """
    Record the complete loan lifecycle as cryptographic proofs.

    Each state transition is a separate, linked proof. The chain proves:
    - The AI model that made each decision
    - The policy that governed it
    - The sequence of events in exact order
    - That no step was inserted, deleted, or modified

    Returns list of ProofV1 objects.
    """
    instance_id = LOAN_APPLICATION["application_id"]
    proofs      = []

    print(f"\n{'='*60}")
    print(f"Loan Application: {instance_id}")
    print(f"{'='*60}")

    # Step 1: Initial application received
    print("\n[1/4] Recording application receipt...")
    proof1 = engine.record_decision(
        instance_id     = instance_id,
        from_state      = "received",
        to_state        = "under_review",
        model_version   = "credit-model-v3.1",
        agent_version   = "underwriter-agent-v1.0",
        policy_version  = "credit-policy-v2",
        reason_code     = "APPLICATION_COMPLETE",
        policy_rule     = "credit-policy-v2.rule_1_completeness",
        raw_inputs      = CREDIT_INPUTS,
        feature_contributions = [
            {"feature": "application_completeness", "contribution": "1.0"},
        ],
        threshold_used  = "all_required_fields_present",
        metadata        = {"channel": "web", "loan_amount": str(LOAN_APPLICATION["loan_amount"])},
    )
    proofs.append(proof1)
    print(f"   ✓ proof_id: {proof1.proof_id[:24]}...")
    print(f"   ✓ hash:     {proof1.ledger.current_hash[:24]}...")

    # Step 2: Fraud check
    print("\n[2/4] Recording fraud check...")
    proof2 = engine.record_decision(
        instance_id     = instance_id,
        from_state      = "under_review",
        to_state        = "fraud_checked",
        model_version   = "fraud-model-v2.0",
        agent_version   = "fraud-check-agent-v1.0",
        policy_version  = "fair-lending-policy-v1",
        reason_code     = "FRAUD_SCORE_ACCEPTABLE",
        policy_rule     = "fair-lending-policy-v1.rule_3_fraud",
        raw_inputs      = CREDIT_INPUTS,
        feature_contributions = [
            {"feature": "velocity_check",  "contribution": "0.40"},
            {"feature": "identity_match",  "contribution": "0.60"},
        ],
        threshold_used  = "fraud_score_below_0.05",
        metadata        = {"fraud_score": "0.02"},
    )
    proofs.append(proof2)
    print(f"   ✓ proof_id: {proof2.proof_id[:24]}...")
    print(f"   ✓ chain:    prev={proof2.ledger.previous_hash[:16]}...")

    # Step 3: Credit decision
    print("\n[3/4] Recording credit decision...")
    proof3 = engine.record_decision(
        instance_id     = instance_id,
        from_state      = "fraud_checked",
        to_state        = "approved",
        model_version   = "credit-model-v3.1",
        agent_version   = "underwriter-agent-v1.0",
        policy_version  = "credit-policy-v2",
        reason_code     = "SCORE_ABOVE_THRESHOLD",
        policy_rule     = "credit-policy-v2.rule_7_credit_score",
        raw_inputs      = CREDIT_INPUTS,
        feature_contributions = [
            {"feature": "credit_score",   "contribution": "0.45"},
            {"feature": "debt_to_income", "contribution": "0.30"},
            {"feature": "loan_to_value",  "contribution": "0.25"},
        ],
        threshold_used  = "credit_score_gte_720",
        metadata        = {"decision_time_ms": "47"},
    )
    proofs.append(proof3)
    print(f"   ✓ proof_id: {proof3.proof_id[:24]}...")
    print(f"   ✓ Decision: APPROVED")

    # Step 4: Funding authorized
    print("\n[4/4] Recording funding authorization...")
    proof4 = engine.record_decision(
        instance_id     = instance_id,
        from_state      = "approved",
        to_state        = "funded",
        model_version   = "credit-model-v3.1",
        agent_version   = "underwriter-agent-v1.0",
        policy_version  = "credit-policy-v2",
        reason_code     = "FUNDING_CONDITIONS_MET",
        policy_rule     = "credit-policy-v2.rule_12_funding",
        raw_inputs      = {"conditions": "all_satisfied"},
        metadata        = {"funded_amount": str(LOAN_APPLICATION["loan_amount"])},
    )
    proofs.append(proof4)
    print(f"   ✓ proof_id: {proof4.proof_id[:24]}...")
    print(f"   ✓ Loan funded: ${LOAN_APPLICATION['loan_amount']:,}")

    return proofs


# ── Verification ──────────────────────────────────────────────────────────────

def demonstrate_verification(engine: GovernanceEngine, proofs: list) -> None:
    """Show offline verification — no server, no database, no trust required."""
    print(f"\n{'='*60}")
    print("Offline Verification Demo")
    print(f"{'='*60}")

    # Convert ProofV1 objects to dicts for verification
    proof_dicts = [p.model_dump(mode="json") for p in proofs]

    # Verify each proof individually
    print("\n[A] Individual proof verification:")
    for i, pd in enumerate(proof_dicts, 1):
        result = verify_proof(pd)
        status = "✓ VALID" if result.valid else "✗ INVALID"
        print(f"   Step {i}: {status} — {pd['decision']['to_state']}")
        print(f"           key_id={result.key_id}  seq={pd['ledger']['sequence_id']}")

    # Verify the complete chain
    print("\n[B] Full chain verification:")
    chain_result = verify_chain(proof_dicts)
    if chain_result.valid:
        print(f"   ✓ CHAIN VALID")
        print(f"   Steps verified:  {chain_result.sequence_verified}")
        print(f"   Final state:     {chain_result.final_state}")
        print(f"   Chain intact:    {chain_result.chain_intact}")
    else:
        print(f"   ✗ CHAIN INVALID: {chain_result.failure_reason}")

    # Demonstrate tamper detection
    print("\n[C] Tamper detection demo:")
    tampered = proof_dicts.copy()
    tampered_entry = dict(proof_dicts[2])  # step 3 = approval
    tampered_entry = json.loads(json.dumps(proof_dicts[2]))  # deep copy
    tampered_entry["decision"]["to_state"] = "rejected"  # tamper the outcome
    tampered[2] = tampered_entry

    tamper_result = verify_proof(tampered[2])
    print(f"   Original decision:  approved")
    print(f"   Tampered decision:  rejected")
    print(f"   Verification:       {'✓ Tamper DETECTED' if not tamper_result.valid else '✗ Tamper NOT detected'}")
    if not tamper_result.valid:
        print(f"   Failure reason:     {tamper_result.failure_reason.get('type', 'Unknown')}")


# ── PII Protection ────────────────────────────────────────────────────────────

def demonstrate_pii_protection(proofs: list) -> None:
    """Show that raw inputs never appear in the proof."""
    print(f"\n{'='*60}")
    print("PII Protection Demo")
    print(f"{'='*60}")

    proof_str = json.dumps([p.model_dump(mode="json") for p in proofs])

    sensitive_values = [
        CREDIT_INPUTS["credit_score"],
        CREDIT_INPUTS["debt_to_income"],
        "experian",
    ]

    all_protected = True
    for val in sensitive_values:
        if val in proof_str:
            print(f"   ✗ EXPOSED: {val}")
            all_protected = False
        else:
            print(f"   ✓ Protected: {val!r} not in proof")

    # But the hash IS present
    proof0 = proofs[0].model_dump(mode="json")
    inputs_hash = proof0["decision_context"]["inputs_hash"]
    print(f"\n   inputs_hash:  {inputs_hash[:32]}...")
    print(f"   (SHA-256 of canonical inputs — verifiable but not reversible)")

    if all_protected:
        print("\n   ✓ All sensitive inputs are hashed — no PII in proof chain")


# ── Export ────────────────────────────────────────────────────────────────────

def export_proof_package(proofs: list, output_path: str) -> None:
    """Write a compliance-ready proof package to disk."""
    proof_dicts = [p.model_dump(mode="json") for p in proofs]

    package = {
        "type":         "zorynex-proof-package-v1",
        "application":  LOAN_APPLICATION,
        "chain_length": len(proofs),
        "final_state":  proof_dicts[-1]["decision"]["to_state"],
        "chain_root":   proofs[-1].ledger.current_hash,
        "proofs":       proof_dicts,
        "verification": "Use verify/verify_signature.py or verify/verify_batch.py",
    }

    with open(output_path, "w") as f:
        json.dump(package, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Proof Package Exported")
    print(f"{'='*60}")
    print(f"   File:        {output_path}")
    print(f"   Size:        {Path(output_path).stat().st_size:,} bytes")
    print(f"   Proofs:      {len(proofs)}")
    print(f"   Chain root:  {proofs[-1].ledger.current_hash[:32]}...")
    print(f"\n   Verify with:")
    print(f"   python verify/verify_signature.py {output_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    os.environ.setdefault("ZORYNEX_SIGNING_KEY", DEMO_KEY)

    with tempfile.TemporaryDirectory() as tmp:
        db_path   = os.path.join(tmp, "demo.db")
        pkg_path  = os.path.join(tmp, "loan_proof.json")

        engine = setup_engine(db_path)
        proofs = run_loan_lifecycle(engine)

        demonstrate_verification(engine, proofs)
        demonstrate_pii_protection(proofs)
        export_proof_package(proofs, pkg_path)

    print(f"\n{'='*60}")
    print("Session 5 integration example complete.")
    print("All proofs cryptographically signed and chain-linked.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()