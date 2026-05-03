"""Zorynex offline proof verifier — standalone, no server needed."""
from __future__ import annotations
import json, hashlib


def _recompute_hash(proof_dict: dict) -> str:
    """Recompute canonical SHA-256 — must match engine.py exactly."""
    ledger = proof_dict.get("ledger", {})
    content = {
        "decision":         proof_dict.get("decision", {}),
        "decision_context": proof_dict.get("decision_context", {}),
        "governance":       proof_dict.get("governance", {}),
        "determinism":      proof_dict.get("determinism", {}),
        "previous_hash":    ledger.get("previous_hash", ""),
        "sequence_id":      ledger.get("sequence_id", 0),
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _compute_instance_root(ledger_entries: list) -> str:
    combined = "".join(
        e.get("ledger", {}).get("current_hash", "") for e in ledger_entries
    )
    return hashlib.sha256(combined.encode()).hexdigest()


def _compute_package_hash(ledger_entries: list) -> str:
    """SHA-256 of full ledger serialization — detects any structural modification."""
    canonical = json.dumps(ledger_entries, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_proof(proof_file_path: str) -> tuple[bool, str, str | None]:
    """
    Verify a proof package exported by Engine.export_proof().

    Checks:
    1. Package type and structure valid
    2. package_hash: full ledger serialization unchanged
    3. Per-proof hash: recomputed canonical hash matches stored hash
    4. Chain linkage: previous_hash matches prior current_hash
    5. Instance root: SHA-256 of all current_hashes matches stored root
    6. Signature: Ed25519 over instance_root

    Returns (valid, message, final_state).
    """
    try:
        with open(proof_file_path) as f:
            package = json.load(f)
    except Exception as e:
        return False, f"Cannot read proof file: {e}", None

    if package.get("type") != "provable-ai-proof-package":
        return False, f"Unknown type: {package.get('type')}", None

    proof_block   = package.get("proof", {})
    ledger        = proof_block.get("ledger", [])
    stored_root   = proof_block.get("instance_root", "")
    stored_pkg_h  = package.get("package_hash", "")
    sig_hex       = package.get("signature", "")
    pub_key_hex   = package.get("public_key", "")

    if not ledger:
        return True, "No transitions", None

    # --- Check 1: package_hash covers full ledger structure ---
    if stored_pkg_h:
        computed_pkg_h = _compute_package_hash(ledger)
        if computed_pkg_h != stored_pkg_h:
            return False, (
                f"Package hash mismatch: ledger was modified after export. "
                f"stored={stored_pkg_h[:16]}... computed={computed_pkg_h[:16]}..."
            ), None

    # --- Check 2: per-proof canonical hash integrity ---
    prev_hash = None
    for entry in ledger:
        stored_hash = entry.get("ledger", {}).get("current_hash", "")
        computed    = _recompute_hash(entry)
        if computed != stored_hash:
            return False, (
                f"Hash mismatch at seq {entry.get('ledger',{}).get('sequence_id')}"
            ), None
        chain_prev = entry.get("ledger", {}).get("previous_hash", "")
        if prev_hash is not None and chain_prev != prev_hash:
            return False, "Chain broken: previous_hash mismatch", None
        prev_hash = stored_hash

    # --- Check 3: instance root ---
    computed_root = _compute_instance_root(ledger)
    if stored_root and computed_root != stored_root:
        return False, "Instance root mismatch", None

    # --- Check 4: Ed25519 signature ---
    if sig_hex and pub_key_hex:
        try:
            from nacl.signing import VerifyKey
            vk = VerifyKey(bytes.fromhex(pub_key_hex))
            vk.verify(bytes.fromhex(computed_root), bytes.fromhex(sig_hex))
        except Exception as e:
            return False, f"Signature invalid: {e}", None

    final_state = ledger[-1].get("decision", {}).get("to_state")
    return True, "Proof valid", final_state