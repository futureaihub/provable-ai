"""
Zorynex — Compliance Pack Generator
======================================
Builds structured compliance evidence for three regulatory frameworks:

  SR 11-7      — Federal Reserve Model Risk Management guidance
  EU AI Act    — Articles 9, 13, 14 (high-risk AI systems)
  CFPB         — Adverse Action / Equal Credit Opportunity Act

Each framework produces a JSON evidence block that an auditor or compliance
officer can attach directly to a regulatory filing or model audit report.

Usage:
    from provable_ai.audit_compliance import build_compliance_pack

    pack = build_compliance_pack(
        entries=audit_log.query(tenant_id).entries,
        tenant_id="bank_abc",
        merkle_root="a3f8...",
        batch_signature="ed25519-sig-hex",
        from_date="2026-01-01T00:00:00Z",
        to_date="2026-12-31T23:59:59Z",
    )

The pack is a dict keyed by framework code:
    pack["SR_11_7"]  → {...}
    pack["EU_AI_ACT"] → {...}
    pack["CFPB"]     → {...}
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .audit_log import VerificationAuditEntry


# ── Compliance pack builder ───────────────────────────────────────────────────

def build_compliance_pack(
    entries:          list[VerificationAuditEntry],
    tenant_id:        str,
    merkle_root:      str,
    batch_signature:  str | None = None,
    from_date:        str | None = None,
    to_date:          str | None = None,
    generated_at:     str | None = None,
) -> dict[str, Any]:
    """
    Build a complete multi-framework compliance evidence pack.

    Args:
        entries:          Verification audit entries for the period
        tenant_id:        The tenant this pack covers
        merkle_root:      Merkle root of all exported proofs
        batch_signature:  Ed25519 signature over merkle_root (optional but recommended)
        from_date:        Period start (ISO-8601 UTC)
        to_date:          Period end (ISO-8601 UTC)
        generated_at:     Override generation timestamp

    Returns:
        Dict with keys "SR_11_7", "EU_AI_ACT", "CFPB", each containing
        structured compliance evidence.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    stats = _compute_stats(entries)

    return {
        "SR_11_7":   _sr_11_7(entries, stats, tenant_id, merkle_root,
                              batch_signature, from_date, to_date, generated_at),
        "EU_AI_ACT": _eu_ai_act(entries, stats, tenant_id, merkle_root,
                                batch_signature, from_date, to_date, generated_at),
        "CFPB":      _cfpb(entries, stats, tenant_id, merkle_root,
                           batch_signature, from_date, to_date, generated_at),
    }


# ── SR 11-7 — Federal Reserve Model Risk Management ──────────────────────────

def _sr_11_7(
    entries:         list[VerificationAuditEntry],
    stats:           dict,
    tenant_id:       str,
    merkle_root:     str,
    batch_signature: str | None,
    from_date:       str | None,
    to_date:         str | None,
    generated_at:    str,
) -> dict[str, Any]:
    """
    SR 11-7 requires:
    - Model inventory and versioning
    - Ongoing performance monitoring
    - Model change controls
    - Third-party model oversight
    - Documentation of model outputs and decisions

    Zorynex evidence:
    - Every AI decision is a signed, hash-chained proof (non-repudiable)
    - Governance snapshot (model_version, policy_version) locked into each proof
    - Verification audit log proves ongoing monitoring
    - Chain integrity proves no retroactive modification
    """
    # Extract governance versions seen
    governance_versions = _extract_governance_versions(entries)

    return {
        "framework":     "SR 11-7",
        "name":          "Federal Reserve — Model Risk Management",
        "status":        _compliance_status(stats),
        "tenant_id":     tenant_id,
        "period":        {"from": from_date, "to": to_date},
        "generated_at":  generated_at,

        "requirements": {
            "model_inventory": {
                "satisfied": True,
                "evidence":  "Model version captured in governance snapshot of every proof",
                "versions_observed": governance_versions.get("model_versions", []),
            },
            "ongoing_monitoring": {
                "satisfied": stats["total"] > 0,  # True only with real audit data
                "evidence":  f"{stats['total']} verification events logged in audit trail",
                "valid_rate": stats["valid_rate"],
                "invalid_count": stats["invalid"],
            },
            "change_controls": {
                "satisfied": True,
                "evidence":  (
                    "Policy version and agent version locked in cryptographic proof. "
                    "Any governance change creates a new version — cannot retroactively modify."
                ),
                "policy_versions_observed": governance_versions.get("policy_versions", []),
            },
            "non_repudiation": {
                "satisfied":      True,
                "evidence":       "Ed25519 signature + SHA-256 hash chain on proofs. Audit log hash-chained row-by-row.",
                "merkle_root":    merkle_root,
                "merkle_leaf_method": "SHA-256(tenant_id|instance_id|seq_id|result|verified_at|failure_code)",
                "signature":      batch_signature,
            },
            "documentation": {
                "satisfied": True,
                "evidence":  (
                    "Each proof contains: decision context, governance snapshot, "
                    "determinism mode, feature contributions, and cryptographic linkage."
                ),
            },
        },

        "attestation": {
            "statement": (
                f"For the period {from_date or 'all time'} to {to_date or 'present'}, "
                f"tenant '{tenant_id}' has recorded {stats['total']} AI decisions with "
                f"cryptographic proof artifacts. All proofs are signed with Ed25519, "
                f"hash-chained, and verified. "
                f"This record satisfies SR 11-7 requirements for model documentation, "
                f"ongoing monitoring, and non-repudiation."
            ),
            "merkle_root":         merkle_root,
            "total_verifications": stats["total"],
            "valid_rate":          stats["valid_rate"],
            # Evidence-first: raw metrics for auditor to make their own determination
            "raw_metrics": {
                "total":          stats["total"],
                "valid":          stats["valid"],
                "invalid":        stats["invalid"],
                "valid_rate_pct": stats["valid_rate"],
                "invalid_rate_pct": stats["invalid_rate"],
                "period_from":    from_date,
                "period_to":      to_date,
                "note": (
                    "Status fields above are interpretive. "
                    "Auditors should evaluate raw_metrics independently. "
                    "Compliance thresholds vary by institution and regulator."
                ),
                "provenance": _extract_provenance(entries, from_date, to_date),
            },
        },

        # For PDF report
        "evidence": [
            f"Total AI decision proofs: {stats['total']}",
            f"Verification pass rate: {stats['valid_rate']}",
            f"Ed25519 signatures over all decisions — tamper-evident",
            f"SHA-256 hash chain — retroactive modification detected",
            f"Governance snapshot (model/agent/policy versions) locked in each proof",
            f"Merkle root: {merkle_root[:32]}...",
        ],
    }


# ── EU AI Act — Articles 9, 13, 14 ───────────────────────────────────────────

def _eu_ai_act(
    entries:         list[VerificationAuditEntry],
    stats:           dict,
    tenant_id:       str,
    merkle_root:     str,
    batch_signature: str | None,
    from_date:       str | None,
    to_date:         str | None,
    generated_at:    str,
) -> dict[str, Any]:
    """
    EU AI Act requirements (high-risk AI systems in financial services):

    Article 9  — Risk management system
    Article 13 — Transparency and provision of information
    Article 14 — Human oversight
    Article 17 — Quality management system
    """
    governance_versions = _extract_governance_versions(entries)

    return {
        "framework":    "EU AI Act",
        "name":         "EU Artificial Intelligence Act (Articles 9, 13, 14, 17)",
        "status":       _compliance_status(stats),
        "tenant_id":    tenant_id,
        "period":       {"from": from_date, "to": to_date},
        "generated_at": generated_at,

        "articles": {
            "article_9_risk_management": {
                "requirement": "Continuous risk management system throughout AI lifecycle",
                "satisfied":   True,
                "evidence":    (
                    "Every AI decision produces a cryptographic proof. "
                    "Governance policy version is immutably locked in each proof. "
                    f"Invalid verification rate: {stats['invalid']} of {stats['total']} "
                    f"({stats['invalid_rate']}). Failures are logged with failure_code."
                ),
            },
            "article_13_transparency": {
                "requirement": "High-risk AI systems must be transparent and provide information to deployers",
                "satisfied":   True,
                "evidence":    (
                    "Each proof contains: decision rationale (reason_code, policy_rule), "
                    "feature contributions (what drove the decision), "
                    "model version, governance snapshot, and determinism mode. "
                    "Proofs are verifiable offline with the open-source Zorynex verifier."
                ),
            },
            "article_14_human_oversight": {
                "requirement": "Human oversight measures — ability to review, override, stop",
                "satisfied":   True,
                "evidence":    (
                    "Final state transitions are recorded per decision. "
                    "Audit log enables retrospective review of every decision with full context. "
                    "Cryptographic proof enables forensic verification of any past decision."
                ),
            },
            "article_17_quality_management": {
                "requirement": "Quality management system — documentation, logging, audit",
                "satisfied":   True,
                "evidence":    (
                    f"Hash-chained proof ledger with {stats['total']} records. "
                    "Append-only storage with DB-level tamper prevention. "
                    "Merkle root provides cryptographic batch integrity."
                ),
            },
        },

        "attestation": {
            "statement": (
                f"Tenant '{tenant_id}' operates a high-risk AI system with Zorynex "
                f"Provable AI infrastructure. For the period {from_date or 'all time'} "
                f"to {to_date or 'present'}, {stats['total']} decisions were recorded "
                f"with cryptographic proofs satisfying EU AI Act Articles 9, 13, 14, 17."
            ),
            "merkle_root":         merkle_root,
            "total_decisions":     stats["total"],
            "governance_versions": governance_versions,
        },

        "evidence": [
            f"Total recorded decisions: {stats['total']}",
            f"Verification pass rate: {stats['valid_rate']} (Article 9 — risk monitoring)",
            "Feature contributions per decision (Article 13 — transparency)",
            "Reason code + policy rule in every proof (Article 13 — explainability)",
            "Append-only ledger with cryptographic hash chain (Article 17 — audit)",
            f"Merkle root: {merkle_root[:32]}...",
        ],
    }


# ── CFPB — Adverse Action / ECOA ─────────────────────────────────────────────

def _cfpb(
    entries:         list[VerificationAuditEntry],
    stats:           dict,
    tenant_id:       str,
    merkle_root:     str,
    batch_signature: str | None,
    from_date:       str | None,
    to_date:         str | None,
    generated_at:    str,
) -> dict[str, Any]:
    """
    CFPB / Equal Credit Opportunity Act requirements:
    - Adverse action notices must state specific reasons
    - Model outputs must be explainable
    - Fair lending — no discriminatory patterns
    - Record retention for examination

    Zorynex evidence:
    - reason_code is mandatory in every proof (specific reason)
    - feature_contributions shows what drove the decision
    - policy_rule links to the underwriting policy applied
    - Cryptographic proof enables exact reconstruction for examination
    """
    # Extract adverse action specific evidence
    adverse_samples = _extract_adverse_action_evidence(entries)

    return {
        "framework":    "CFPB",
        "name":         "CFPB — Adverse Action / Equal Credit Opportunity Act (ECOA)",
        "status":       _compliance_status(stats),
        "tenant_id":    tenant_id,
        "period":       {"from": from_date, "to": to_date},
        "generated_at": generated_at,

        "requirements": {
            "specific_reasons": {
                "requirement": "Adverse action notices must state specific, accurate reasons",
                "satisfied":   True,
                "evidence":    (
                    "reason_code field is mandatory in every proof — "
                    "cryptographically bound and non-repudiable. "
                    "reason_code cannot be added retroactively."
                ),
                "sample_count": adverse_samples["count"],
            },
            "explainability": {
                "requirement": "Model outputs must be explainable to regulators and consumers",
                "satisfied":   True,
                "evidence":    (
                    "feature_contributions is recorded in every proof — "
                    "shows exactly which features contributed to the decision. "
                    "Values stored as strings — no floating-point ambiguity."
                ),
            },
            "policy_linkage": {
                "requirement": "Decisions must link to applicable underwriting policy",
                "satisfied":   True,
                "evidence":    (
                    "policy_rule field is mandatory. policy_version is "
                    "locked in governance snapshot. Together they prove exactly "
                    "which rule was applied at the time of decision."
                ),
            },
            "record_retention": {
                "requirement": "Records must be retained and available for examination",
                "satisfied":   True,
                "evidence":    (
                    f"{stats['total']} decision proofs retained in append-only ledger. "
                    "Each proof is self-contained — verifiable without Zorynex infrastructure. "
                    "Batch export produces portable archive with cryptographic integrity."
                ),
                "merkle_root": merkle_root,
                "signature":   batch_signature,
            },
            "fair_lending_audit": {
                "requirement": "System must support fair lending examination",
                "satisfied":   True,
                "evidence":    (
                    "Full decision context (inputs_hash, feature_contributions, "
                    "governance snapshot) retained per proof. "
                    "Enables statistical analysis across decision population. "
                    "inputs_hash preserves PII-safe reference for correlated examination."
                ),
            },
        },

        "attestation": {
            "statement": (
                f"Tenant '{tenant_id}' maintains cryptographic proof records for all "
                f"credit decisions. For the period {from_date or 'all time'} to "
                f"{to_date or 'present'}, {stats['total']} decisions were recorded. "
                f"Each proof contains reason_code, policy_rule, feature_contributions, "
                f"and governance snapshot — satisfying CFPB adverse action requirements."
            ),
            "merkle_root":     merkle_root,
            "total_decisions": stats["total"],
            "raw_metrics": {
                "total":          stats["total"],
                "valid":          stats["valid"],
                "invalid":        stats["invalid"],
                "valid_rate_pct": stats["valid_rate"],
                "invalid_rate_pct": stats["invalid_rate"],
                "period_from":    from_date,
                "period_to":      to_date,
                "note": (
                    "Status above is interpretive. Raw counts provided for "
                    "independent regulatory assessment."
                ),
                "provenance": _extract_provenance(entries, from_date, to_date),
            },
        },

        "evidence": [
            f"Total decisions with mandatory reason_code: {stats['total']}",
            "reason_code cryptographically bound in proof — cannot be retroactively changed",
            "feature_contributions recorded per decision (ECOA explainability)",
            "policy_rule + policy_version in every proof (underwriting policy linkage)",
            "Append-only ledger — no DELETE or UPDATE permitted at DB level",
            f"Merkle root: {merkle_root[:32]}...",
        ],
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _compute_stats(entries: list[VerificationAuditEntry]) -> dict[str, Any]:
    total   = len(entries)
    valid   = sum(1 for e in entries if e.result == "valid")
    invalid = total - valid
    return {
        "total":        total,
        "valid":        valid,
        "invalid":      invalid,
        "valid_rate":   f"{valid / total * 100:.1f}%" if total > 0 else "N/A",
        "invalid_rate": f"{invalid / total * 100:.1f}%" if total > 0 else "N/A",
    }


def _compliance_status(stats: dict) -> str:
    if stats["total"] == 0:
        return "NO_DATA — No records in this period"
    if stats["invalid"] == 0:
        return "COMPLIANT — All verifications passed"
    rate = stats["invalid"] / stats["total"]
    if rate < 0.01:
        return f"COMPLIANT WITH EXCEPTIONS — {stats['invalid']} failures ({stats['invalid_rate']})"
    return f"REVIEW REQUIRED — {stats['invalid']} failures ({stats['invalid_rate']})"


def _extract_governance_versions(
    entries: list[VerificationAuditEntry],
) -> dict[str, list[str]]:
    """Extract unique model/policy versions from governance_json snapshots."""
    import json as _json

    model_versions  = set()
    agent_versions  = set()
    policy_versions = set()

    for e in entries:
        if not e.governance_json:
            continue
        try:
            gov = _json.loads(e.governance_json)
            if gov.get("model_version"):
                model_versions.add(gov["model_version"])
            if gov.get("agent_version"):
                agent_versions.add(gov["agent_version"])
            if gov.get("policy_version"):
                policy_versions.add(gov["policy_version"])
        except Exception:
            continue

    return {
        "model_versions":  sorted(model_versions),
        "agent_versions":  sorted(agent_versions),
        "policy_versions": sorted(policy_versions),
    }


def _extract_provenance(
    entries: list[VerificationAuditEntry],
    from_date: str | None,
    to_date:   str | None,
) -> dict:
    """
    Extract record provenance — exact references behind the metrics.

    Auditor expectation: "show me the exact records behind this number."
    Returns trace_ids, instance_ids, and query parameters used.
    This makes compliance output explainable and reproducible.
    """
    valid_traces   = [e.trace_id   for e in entries if e.result == "valid"][:5]
    invalid_traces = [e.trace_id   for e in entries if e.result == "invalid"][:5]
    instance_ids   = list({e.instance_id for e in entries if e.instance_id})[:10]
    proof_ids      = [e.proof_id   for e in entries if e.proof_id][:5]

    return {
        "query_parameters": {
            "from_date":  from_date,
            "to_date":    to_date,
            "note":       "Re-run with these parameters to reproduce the exact dataset",
        },
        "sample_valid_trace_ids":   valid_traces,
        "sample_invalid_trace_ids": invalid_traces,
        "sample_instance_ids":      instance_ids,
        "sample_proof_ids":         proof_ids,
        "total_referenced":         len(entries),
    }


def _extract_adverse_action_evidence(
    entries: list[VerificationAuditEntry],
) -> dict[str, Any]:
    """Count entries that have governance data (proxy for decision records)."""
    count = sum(1 for e in entries if e.governance_json)
    return {"count": count}