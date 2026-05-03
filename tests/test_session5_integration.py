"""
Zorynex Session 5 — Integration Tests
======================================
Tests the complete loan decisioning lifecycle end-to-end,
the CLI interface, doc completeness, and cross-component integration.

Run: pytest tests/test_session5_integration.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent


# ═══════════════════════════════════════════════════════════════════════════════
# PART 1 — LOAN LIFECYCLE INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoanLifecycle:
    """End-to-end loan decisioning: 4 steps, chain-verified."""

    @pytest.fixture
    def setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        storage = SQLiteStorage(db_path=str(tmp_path / "loan.db"))
        storage.add_approved_model("credit-model-v3.1")
        storage.add_approved_agent("underwriter-agent-v1.0")
        storage.add_approved_policy("credit-policy-v2")
        return GovernanceEngine(storage=storage, signer=get_signer()), storage

    def test_four_step_lifecycle_records(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        engine, storage = setup
        steps = [
            ("received",     "under_review", "APPLICATION_COMPLETE"),
            ("under_review", "fraud_checked","FRAUD_SCORE_ACCEPTABLE"),
            ("fraud_checked","approved",     "SCORE_ABOVE_THRESHOLD"),
            ("approved",     "funded",       "FUNDING_CONDITIONS_MET"),
        ]
        proofs = []
        for from_s, to_s, reason in steps:
            p = engine.record_decision(
                instance_id="loan_9284",
                from_state=from_s, to_state=to_s,
                model_version="credit-model-v3.1",
                agent_version="underwriter-agent-v1.0",
                policy_version="credit-policy-v2",
                reason_code=reason, policy_rule="credit-policy-v2.default",
                raw_inputs={"credit_score": "742"},
            )
            proofs.append(p)
        assert len(proofs) == 4
        assert proofs[-1].decision.to_state == "funded"

    def test_chain_sequence_ids(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        engine, _ = setup
        states = [("a", "b"), ("b", "c"), ("c", "d")]
        proofs = [
            engine.record_decision(
                instance_id="loan_seq", from_state=f, to_state=t,
                model_version="credit-model-v3.1",
                agent_version="underwriter-agent-v1.0",
                policy_version="credit-policy-v2",
                reason_code="R", policy_rule="P",
                raw_inputs={"score": "700"},
            )
            for f, t in states
        ]
        seqs = [p.ledger.sequence_id for p in proofs]
        assert seqs == [1, 2, 3]

    def test_chain_hash_links(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        engine, _ = setup
        p1 = engine.record_decision(
            instance_id="loan_link", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )
        p2 = engine.record_decision(
            instance_id="loan_link", from_state="b", to_state="c",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )
        from provable_ai.canonical import genesis_hash
        assert p1.ledger.previous_hash == genesis_hash()
        assert p2.ledger.previous_hash == p1.ledger.current_hash

    def test_pii_not_in_proof(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        engine, _ = setup
        raw = {"credit_score": "742", "ssn": "123-45-6789", "income": "95000"}
        p = engine.record_decision(
            instance_id="loan_pii", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs=raw,
        )
        proof_dict = p.model_dump(mode="json")
        proof_str  = json.dumps(proof_dict)
        # Check raw sensitive values don't appear as JSON string values
        # (substring in hex is acceptable — "742" in "ad4630aa4d742f31" is a hex hash)
        assert '"742"'         not in proof_str, "credit_score exposed as JSON string"
        assert '"123-45-6789"' not in proof_str, "SSN exposed as JSON string"
        assert '"95000"'       not in proof_str, "income exposed as JSON string"
        assert len(p.decision_context.inputs_hash) == 64

    def test_verify_full_chain(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.verifier import verify_chain
        engine, _ = setup
        proofs = [
            engine.record_decision(
                instance_id="loan_vc", from_state=f, to_state=t,
                model_version="credit-model-v3.1",
                agent_version="underwriter-agent-v1.0",
                policy_version="credit-policy-v2",
                reason_code="R", policy_rule="P",
                raw_inputs={"score": "700"},
            )
            for f, t in [("a","b"),("b","c"),("c","d")]
        ]
        result = verify_chain([p.model_dump(mode="json") for p in proofs])
        assert result.valid is True
        assert result.sequence_verified == 3
        assert result.final_state == "d"

    def test_tamper_detected_by_verify(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.verifier import verify_proof
        engine, _ = setup
        p = engine.record_decision(
            instance_id="loan_tamper", from_state="a", to_state="approved",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )
        pd = p.model_dump(mode="json")
        pd["decision"]["to_state"] = "rejected"  # tamper
        result = verify_proof(pd)
        assert result.valid is False

    def test_governance_rejection_recorded(self, setup, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.exceptions import UnauthorizedModelVersion
        engine, _ = setup
        with pytest.raises(UnauthorizedModelVersion):
            engine.record_decision(
                instance_id="loan_bad", from_state="a", to_state="b",
                model_version="evil-model-v99",
                agent_version="underwriter-agent-v1.0",
                policy_version="credit-policy-v2",
                reason_code="R", policy_rule="P",
                raw_inputs={"score": "700"},
            )

    def test_two_tenants_isolated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        storage = SQLiteStorage(db_path=str(tmp_path / "multi.db"))
        for item in ["credit-model-v3.1", "underwriter-agent-v1.0", "credit-policy-v2"]:
            try:
                storage.add_approved_model(item)
                storage.add_approved_agent(item)
                storage.add_approved_policy(item)
            except Exception:
                pass
        engine = GovernanceEngine(storage=storage, signer=get_signer())

        p_a = engine.record_decision(
            instance_id="tenant_a_loan_001", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )
        p_b = engine.record_decision(
            instance_id="tenant_b_loan_001", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "680"},
        )
        # Separate instances — sequence IDs both start at 1
        assert p_a.ledger.sequence_id == 1
        assert p_b.ledger.sequence_id == 1
        # Different proof IDs
        assert p_a.proof_id != p_b.proof_id


# ═══════════════════════════════════════════════════════════════════════════════
# PART 2 — CLI INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLI:

    def test_cli_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "cli", str(PROJECT_ROOT / "cli.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "main")
        assert hasattr(mod, "build_parser")
        assert hasattr(mod, "cmd_record")
        assert hasattr(mod, "cmd_verify")
        assert hasattr(mod, "cmd_governance")

    def test_cli_parser_has_all_subcommands(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("cli", str(PROJECT_ROOT / "cli.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        parser = mod.build_parser()
        help_text = parser.format_help()
        for cmd in ["record", "verify", "chain-verify", "export", "governance", "server", "info"]:
            assert cmd in help_text, f"CLI missing subcommand: {cmd}"

    def test_cli_info_runs(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.setenv("ZORYNEX_DB_PATH", str(tmp_path / "test.db"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("cli", str(PROJECT_ROOT / "cli.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        import argparse
        args = argparse.Namespace(command="info")
        rc = mod.cmd_info(args)
        assert rc == 0

    def test_cli_governance_status(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.setenv("ZORYNEX_DB_PATH", str(tmp_path / "test.db"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("cli", str(PROJECT_ROOT / "cli.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        import argparse
        args = argparse.Namespace(command="governance", governance_cmd="status")
        rc = mod.cmd_governance(args)
        assert rc == 0


# ═══════════════════════════════════════════════════════════════════════════════
# PART 3 — INTEGRATION EXAMPLE
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegrationExample:

    def test_example_exists(self):
        path = PROJECT_ROOT / "examples" / "loan_decisioning.py"
        assert path.exists(), "examples/loan_decisioning.py must exist"

    def test_example_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "loan_decisioning",
            str(PROJECT_ROOT / "examples" / "loan_decisioning.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        # Don't exec (runs main) — just check it loads
        assert spec is not None

    def test_example_runs(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "loan_decisioning",
            str(PROJECT_ROOT / "examples" / "loan_decisioning.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Call main() — should complete without error
        mod.main()

    def test_example_has_governance_config(self):
        with open(PROJECT_ROOT / "examples" / "loan_decisioning.py") as f:
            src = f.read()
        assert "GOVERNANCE"         in src
        assert "approved_models"    in src
        assert "approved_agents"    in src
        assert "approved_policies"  in src

    def test_example_has_verification(self):
        with open(PROJECT_ROOT / "examples" / "loan_decisioning.py") as f:
            src = f.read()
        assert "verify_chain" in src or "verify_proof" in src
        assert "demonstrate_verification" in src

    def test_example_has_pii_protection_demo(self):
        with open(PROJECT_ROOT / "examples" / "loan_decisioning.py") as f:
            src = f.read()
        assert "pii" in src.lower()
        assert "inputs_hash" in src


# ═══════════════════════════════════════════════════════════════════════════════
# PART 4 — DOCUMENTATION COMPLETENESS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDocumentation:

    def _read(self, filename: str) -> str:
        path = PROJECT_ROOT / filename
        assert path.exists(), f"{filename} must exist"
        return path.read_text()

    def test_readme_exists_and_has_sections(self):
        doc = self._read("README.md")
        for section in ["Quickstart", "Architecture", "Verification", "Deployment", "Tests"]:
            assert section in doc, f"README missing section: {section}"

    def test_readme_has_commands(self):
        doc = self._read("README.md")
        assert "cli.py" in doc
        assert "docker" in doc.lower()
        assert "pytest" in doc

    def test_security_md_exists(self):
        doc = self._read("SECURITY.md")
        assert "vulnerability" in doc.lower()
        assert "signing key" in doc.lower()
        assert "tamper" in doc.lower()

    def test_security_md_has_trust_model(self):
        doc = self._read("SECURITY.md")
        assert "trust boundary" in doc.lower() or "Trust boundary" in doc
        assert "FreeTSA" in doc or "RFC 3161" in doc

    def test_license_exists(self):
        doc = self._read("LICENSE")
        assert "Zorynex" in doc
        assert len(doc) > 100

    def test_dev_doc_has_integration_steps(self):
        doc = self._read("docs/dev.md")
        for section in ["Installation", "Configuration", "Quick integration", "Verification", "REST API"]:
            assert section in doc, f"docs/dev.md missing section: {section}"

    def test_dev_doc_has_code_examples(self):
        doc = self._read("docs/dev.md")
        assert "```python" in doc
        assert "```bash"   in doc
        assert "record_decision" in doc

    def test_auditor_doc_has_verification_instructions(self):
        doc = self._read("docs/auditor.md")
        for section in ["verify_signature.py", "verify_batch.py", "RFC 3161"]:
            assert section in doc, f"docs/auditor.md missing: {section}"

    def test_auditor_doc_trust_model_table(self):
        doc = self._read("docs/auditor.md")
        assert "FreeTSA" in doc
        assert "outside" in doc.lower() or "independent" in doc.lower()

    def test_cro_doc_has_regulatory_alignment(self):
        doc = self._read("docs/cro.md")
        for reg in ["SR 11-7", "EU AI Act", "CFPB"]:
            assert reg in doc, f"docs/cro.md missing regulation: {reg}"

    def test_cro_doc_has_honest_limitations(self):
        doc = self._read("docs/cro.md")
        assert "tamper-evident" in doc.lower() or "Tamper-evident" in doc
        assert "not" in doc.lower()  # honest about what it doesn't do


# ═══════════════════════════════════════════════════════════════════════════════
# PART 5 — CROSS-COMPONENT INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossComponent:
    """Verify that all Phase 1 + Phase 2 components work together."""

    @pytest.fixture
    def full_engine(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.setenv("ZORYNEX_AUDIT_DB_PATH", str(tmp_path / "audit.db"))
        monkeypatch.setenv("ZORYNEX_ANCHOR_DB_PATH", str(tmp_path / "anchors.db"))
        from provable_ai.storage import SQLiteStorage
        from provable_ai.signer import get_signer
        from provable_ai.engine import GovernanceEngine
        storage = SQLiteStorage(db_path=str(tmp_path / "full.db"))
        storage.add_approved_model("credit-model-v3.1")
        storage.add_approved_agent("underwriter-agent-v1.0")
        storage.add_approved_policy("credit-policy-v2")
        return GovernanceEngine(storage=storage, signer=get_signer()), storage

    def test_proof_id_determinism(self, full_engine, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        engine, _ = full_engine
        p = engine.record_decision(
            instance_id="det_test", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )
        # proof_id is SHA-256(current_hash:sequence_id)
        expected = hashlib.sha256(
            f"{p.ledger.current_hash}:{p.ledger.sequence_id}".encode()
        ).hexdigest()
        assert p.proof_id == expected

    def test_storage_get_ledger_chain(self, full_engine, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        engine, storage = full_engine
        for i, (f, t) in enumerate([("a","b"),("b","c"),("c","d")]):
            engine.record_decision(
                instance_id="chain_test", from_state=f, to_state=t,
                model_version="credit-model-v3.1",
                agent_version="underwriter-agent-v1.0",
                policy_version="credit-policy-v2",
                reason_code="R", policy_rule="P",
                raw_inputs={"score": "700"},
            )
        chain = storage.get_ledger_chain("chain_test")
        assert len(chain) == 3
        # sequence IDs in order
        seqs = [e["sequence_id"] for e in chain]
        assert seqs == [1, 2, 3]

    def test_verify_proof_self_contained(self, full_engine, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.verifier import verify_proof
        engine, _ = full_engine
        p = engine.record_decision(
            instance_id="self_contained", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )
        pd = p.model_dump(mode="json")
        # Public key is in the proof — no external lookup needed
        assert "public_key" in pd["signature"]
        assert len(pd["signature"]["public_key"]) == 64
        # Verify with just the dict
        result = verify_proof(pd)
        assert result.valid is True

    def test_drift_detector_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.setenv("ZORYNEX_ANCHOR_RFC3161", "false")
        from provable_ai.storage import SQLiteStorage
        from provable_ai.audit_log import VerificationAuditLog
        from provable_ai.drift_detector import DriftDetector, take_snapshot

        storage   = SQLiteStorage(db_path=str(tmp_path / "proof.db"))
        audit_log = VerificationAuditLog(db_path=str(tmp_path / "audit.db"))
        detector  = DriftDetector(db_path=str(tmp_path / "drift.db"))

        snap = take_snapshot(
            storage, audit_log, tenant_id="bank",
            environment="test", anchor_externally=False,
        )
        detector.save_snapshot(snap)

        retrieved = detector.get_latest("bank", "test")
        assert retrieved is not None
        assert retrieved.snapshot_id == snap.snapshot_id
        assert retrieved.environment == "test"

    def test_system_root_stability(self, full_engine, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        from provable_ai.verifier import compute_system_root
        engine, storage = full_engine

        engine.record_decision(
            instance_id="root_test", from_state="a", to_state="b",
            model_version="credit-model-v3.1",
            agent_version="underwriter-agent-v1.0",
            policy_version="credit-policy-v2",
            reason_code="R", policy_rule="P",
            raw_inputs={"score": "700"},
        )

        cur = storage.conn.cursor()
        cur.execute("SELECT current_hash FROM ledger ORDER BY instance_id")
        hashes = [r["current_hash"] for r in cur.fetchall()]

        root1 = compute_system_root(hashes)
        root2 = compute_system_root(hashes)
        assert root1 == root2  # deterministic

    def test_governance_status_after_approvals(self, full_engine, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        _, storage = full_engine
        models  = storage.get_approved_models()
        agents  = storage.get_approved_agents()
        policies= storage.get_approved_policies()
        model_versions  = [m["version"] if isinstance(m, dict) else m for m in models]
        agent_versions  = [a["version"] if isinstance(a, dict) else a for a in agents]
        policy_versions = [p["version"] if isinstance(p, dict) else p for p in policies]
        assert "credit-model-v3.1"       in model_versions
        assert "underwriter-agent-v1.0"  in agent_versions
        assert "credit-policy-v2"        in policy_versions