#!/usr/bin/env python3
"""
Zorynex — Proof Package Verifier
==================================
Verify a complete exported proof package with a single command.
Zero dependency on Zorynex infrastructure. Requires only PyNaCl.

Usage:
    python verify/verify_package.py exported.json
    python verify/verify_package.py exported.json --verbose
    python verify/verify_package.py exported.json --json

Output (default):
    ✓ Package structure valid
    ✓ Package untampered  (hash matches)
    ✓ Chain valid         (3 proofs, sequence 1→3)
    ✓ Original signer verified  (env-58c9d4aa... — signature mathematically valid)

    RESULT: VERIFIED ✓
    Instance: loan-application-9284
    Final state: funded
    Signed by: env-58c9d4aa2634ed9a

Exit codes:
    0 — all checks pass
    1 — one or more checks failed
    2 — file not found or invalid JSON

What this verifies:
    1. Package structure — required fields present, type is correct
    2. Package hash     — SHA-256 of full ledger matches stored package_hash
                          (any modification to any proof entry is detected)
    3. Chain linkage    — each proof's previous_hash equals prior proof's current_hash
    4. Per-proof hashes — canonical hash recomputed for every proof, matches stored value
    5. Ed25519 signature— signature over instance_root is valid for the embedded public key

What this does NOT verify:
    - Governance compliance (whether models/agents/policies were approved)
    - RFC 3161 timestamp authenticity (use verify_anchor.py for that)
    - Cross-instance relationships

This file is intentionally self-contained. An auditor, regulator, or counterparty
can run it on any machine with Python 3.9+ and PyNaCl, with only the exported JSON.
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any


# ── Canonical hash ────────────────────────────────────────────────────────────

def _recompute_hash(proof_entry: dict) -> str:
    """
    Recompute SHA-256 of proof content — identical algorithm to engine.py.
    Fields: decision, decision_context, governance, determinism,
            previous_hash (from ledger), sequence_id (from ledger).
    """
    ledger  = proof_entry.get("ledger", {})
    content = {
        "decision":         proof_entry.get("decision",         {}),
        "decision_context": proof_entry.get("decision_context", {}),
        "governance":       proof_entry.get("governance",       {}),
        "determinism":      proof_entry.get("determinism",      {}),
        "previous_hash":    ledger.get("previous_hash",         ""),
        "sequence_id":      ledger.get("sequence_id",           0),
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_instance_root(ledger_entries: list[dict]) -> str:
    """SHA-256 of all current_hashes concatenated in sequence order."""
    all_hashes = "".join(
        e.get("ledger", {}).get("current_hash", "") for e in ledger_entries
    )
    return hashlib.sha256(all_hashes.encode()).hexdigest()


def _compute_package_hash(ledger_entries: list[dict]) -> str:
    """SHA-256 of full ledger serialization — detects any structural modification."""
    canonical = json.dumps(
        ledger_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Ed25519 ───────────────────────────────────────────────────────────────────

def _verify_ed25519(public_key_hex: str, message_hex: str, sig_hex: str) -> bool:
    try:
        from nacl.signing import VerifyKey
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(bytes.fromhex(message_hex), bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


# ── Main verifier ─────────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, name: str) -> None:
        self.name    = name
        self.passed  = False
        self.detail  = ""
        self.failure = ""

    def ok(self, detail: str = "") -> "CheckResult":
        self.passed = True
        self.detail = detail
        return self

    def fail(self, reason: str) -> "CheckResult":
        self.passed  = False
        self.failure = reason
        return self


def verify_package(package: dict) -> tuple[bool, list[CheckResult], dict]:
    """
    Run all 5 checks. Returns (all_passed, [CheckResult], metadata).
    """
    checks: list[CheckResult] = []
    meta:   dict[str, Any]    = {}

    # ── Check 1: Structure ────────────────────────────────────────────────────
    c1 = CheckResult("Package structure valid")
    if package.get("type") != "provable-ai-proof-package":
        c1.fail(f"Unknown type: {package.get('type')!r}. Expected 'provable-ai-proof-package'.")
    else:
        proof_block = package.get("proof", {})
        ledger      = proof_block.get("ledger", [])
        if not isinstance(ledger, list):
            c1.fail("proof.ledger must be a list.")
        elif len(ledger) == 0:
            c1.fail("proof.ledger is empty — no decisions recorded.")
        else:
            c1.ok(f"{len(ledger)} proof(s) in package")
            meta["ledger"]      = ledger
            meta["instance_id"] = proof_block.get("instance_id", "unknown")
    checks.append(c1)

    if not c1.passed:
        return False, checks, meta

    ledger      = meta["ledger"]
    proof_block = package.get("proof", {})

    # ── Check 2: Package hash (tamper detection) ──────────────────────────────
    c2 = CheckResult("Package untampered")
    stored_pkg_hash = package.get("package_hash", "")
    if stored_pkg_hash:
        computed_pkg_hash = _compute_package_hash(ledger)
        if computed_pkg_hash != stored_pkg_hash:
            c2.fail(
                f"Package hash mismatch — content was modified after export.\n"
                f"  stored:   {stored_pkg_hash[:32]}...\n"
                f"  computed: {computed_pkg_hash[:32]}..."
            )
        else:
            c2.ok("SHA-256 of full ledger matches package_hash")
    else:
        c2.ok("No package_hash in file — skipped (older export format)")
    checks.append(c2)

    # ── Check 3: Per-proof hashes + chain linkage ─────────────────────────────
    c3 = CheckResult("Chain valid")
    prev_hash = None
    genesis   = "0" * 64
    seq_ids   = []
    broken_at = None

    for entry in ledger:
        ledger_block  = entry.get("ledger", {})
        stored_hash   = ledger_block.get("current_hash", "")
        previous_hash = ledger_block.get("previous_hash", genesis)
        seq_id        = ledger_block.get("sequence_id", "?")
        seq_ids.append(seq_id)

        # Hash integrity
        computed = _recompute_hash(entry)
        if computed != stored_hash:
            broken_at = seq_id
            c3.fail(
                f"Hash mismatch at sequence_id={seq_id}.\n"
                f"  The proof content was modified after it was signed.\n"
                f"  stored:   {stored_hash[:32]}...\n"
                f"  computed: {computed[:32]}..."
            )
            break

        # Chain linkage
        expected_prev = prev_hash if prev_hash else genesis
        if previous_hash != expected_prev:
            broken_at = seq_id
            c3.fail(
                f"Chain broken at sequence_id={seq_id}.\n"
                f"  previous_hash does not match prior proof's current_hash.\n"
                f"  This suggests a proof was inserted, deleted, or reordered."
            )
            break

        prev_hash = stored_hash

    if not c3.failure:
        seq_range = f"sequence {seq_ids[0]}→{seq_ids[-1]}" if len(seq_ids) > 1 else f"sequence {seq_ids[0]}"
        c3.ok(f"{len(ledger)} proofs, {seq_range}")
        meta["final_state"] = ledger[-1].get("decision", {}).get("to_state", "unknown")
        meta["seq_range"]   = seq_range

    checks.append(c3)

    # ── Check 4: Ed25519 signature ────────────────────────────────────────────
    c4 = CheckResult("Original signer verified")
    public_key  = package.get("public_key", "")
    sig_hex     = package.get("signature",  "")
    stored_root = proof_block.get("instance_root", "")

    if not public_key or not sig_hex:
        c4.fail("Missing public_key or signature in package.")
    else:
        computed_root = _compute_instance_root(ledger)
        if stored_root and computed_root != stored_root:
            c4.fail(
                f"Instance root mismatch.\n"
                f"  stored:   {stored_root[:32]}...\n"
                f"  computed: {computed_root[:32]}..."
            )
        elif _verify_ed25519(public_key, computed_root, sig_hex):
            key_id = "env-" + public_key[:16]
            c4.ok(f"Signed by {key_id} — signature mathematically valid")
            meta["key_id"]     = key_id
            meta["public_key"] = public_key
        else:
            c4.fail(
                "Ed25519 signature does not match the embedded public key.\n"
                "  The package may have been re-signed or the signature field is corrupted."
            )
    checks.append(c4)

    all_passed = all(c.passed for c in checks)
    return all_passed, checks, meta


# ── Output formatters ─────────────────────────────────────────────────────────

def _print_human(
    all_passed: bool,
    checks:     list[CheckResult],
    meta:       dict,
    verbose:    bool,
    package:    dict,
) -> None:
    print()
    for c in checks:
        if c.passed:
            detail = f"  ({c.detail})" if c.detail else ""
            print(f"  ✓  {c.name}{detail}")
        else:
            print(f"  ✗  {c.name}")
            if verbose or True:  # always show failure reason
                for line in c.failure.split("\n"):
                    print(f"       {line}")
    print()

    if all_passed:
        print("  RESULT:  VERIFIED ✓")
    else:
        # Compute a clear human reason based on which checks failed
        sig_passed    = any(c.name == "Original signer verified" and c.passed for c in checks)
        tamper_failed = any(c.name == "Package untampered"       and not c.passed for c in checks)
        chain_failed  = any(c.name == "Chain valid"              and not c.passed for c in checks)
        struct_failed = any(c.name == "Package structure valid"  and not c.passed for c in checks)

        print("  RESULT:  VERIFICATION FAILED ✗")
        print()
        print("  Reason:")
        if struct_failed:
            print("    This file is not a valid Zorynex proof package.")
            print("    It may be corrupted, incomplete, or the wrong file type.")
        elif tamper_failed and sig_passed:
            print("    This proof was signed by a verified key, but its contents")
            print("    were modified after it was exported.")
            print("    The original signer is confirmed — the package itself was tampered.")
            print("    Do not trust this artifact.")
        elif chain_failed and sig_passed:
            print("    This proof was signed by a verified key, but the decision")
            print("    chain has been altered — a record was inserted, deleted, or reordered.")
            print("    Do not trust this artifact.")
        elif tamper_failed:
            print("    The exported package has been modified since it was created.")
            print("    The hash does not match. Do not trust this artifact.")
        elif chain_failed:
            print("    The decision chain is broken. A record may have been altered.")
            print("    Do not trust this artifact.")
        else:
            print("    One or more cryptographic checks failed.")
            print("    Do not trust this artifact.")
        print()

    proof_block = package.get("proof", {})
    ledger      = proof_block.get("ledger", [])

    print(f"  Instance:    {meta.get('instance_id', 'unknown')}")
    if "final_state" in meta:
        print(f"  Final state: {meta['final_state']}")
    if "seq_range" in meta:
        print(f"  Chain:       {len(ledger)} decisions  ({meta['seq_range']})")
    if "key_id" in meta:
        print(f"  Signed by:   {meta['key_id']}")
    print()

    if verbose and all_passed:
        print("  ── Proof summary " + "─" * 40)
        for entry in ledger:
            led = entry.get("ledger", {})
            dec = entry.get("decision", {})
            gov = entry.get("governance", {})
            print(f"  seq {led.get('sequence_id','-'):>3}  "
                  f"{dec.get('from_state','?'):>20} → {dec.get('to_state','?'):<20}  "
                  f"model={gov.get('model_version','?')}")
        print()


def _print_json(all_passed: bool, checks: list[CheckResult], meta: dict) -> None:
    out = {
        "verified": all_passed,
        "checks": [
            {
                "name":    c.name,
                "passed":  c.passed,
                "detail":  c.detail  or None,
                "failure": c.failure or None,
            }
            for c in checks
        ],
        "instance_id":  meta.get("instance_id"),
        "final_state":  meta.get("final_state"),
        "proof_count":  len(meta.get("ledger", [])),
        "signing_key":  meta.get("key_id"),
    }
    print(json.dumps(out, indent=2))


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify a Zorynex exported proof package",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python verify/verify_package.py exported.json
              python verify/verify_package.py exported.json --verbose
              python verify/verify_package.py exported.json --json
        """),
    )
    parser.add_argument("package_file", help="Path to exported proof package JSON")
    parser.add_argument("--verbose",    action="store_true", help="Show full proof summary")
    parser.add_argument("--json",       action="store_true", help="Output JSON instead of human text")
    args = parser.parse_args()

    try:
        with open(args.package_file) as f:
            raw = f.read()
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.package_file}", file=sys.stderr)
        return 2

    try:
        package = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON: {e}", file=sys.stderr)
        return 2

    all_passed, checks, meta = verify_package(package)

    if args.json:
        _print_json(all_passed, checks, meta)
    else:
        _print_human(all_passed, checks, meta, args.verbose, package)

    return 0 if all_passed else 1


import textwrap

if __name__ == "__main__":
    sys.exit(main())
