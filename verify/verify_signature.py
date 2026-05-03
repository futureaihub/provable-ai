#!/usr/bin/env python3
"""
Zorynex — Standalone Ed25519 Signature Verifier
=================================================
Verify a Zorynex proof signature with ZERO dependency on Zorynex infrastructure.
Requires only: PyNaCl (pip install pynacl)

Usage:
    python verify_signature.py proof.json
    python verify_signature.py proof.json --public-key <64-char-hex>
    cat proof.json | python verify_signature.py -

Output:
    EXIT 0 — signature valid
    EXIT 1 — signature invalid or error

What this verifies:
    1. proof.json is valid JSON with required fields
    2. Canonical hash is recomputed from proof content — matches stored hash
    3. Ed25519 signature over hash bytes is valid for the given public key

What this does NOT verify:
    - Hash chain linkage (use verify_batch.py for full chain)
    - Anchor timestamps (use verify_anchor.py)
    - Governance policy compliance
    - Merkle membership

This file is intentionally self-contained. An auditor or regulator can run
it on any machine with Python + PyNaCl installed, offline, with only the
proof.json file.
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any


# ── Canonical hash recomputation ──────────────────────────────────────────────

_HASH_FIELDS_INCLUDED = (
    "decision", "decision_context", "governance", "determinism",
    "previous_hash", "sequence_id",
)
_HASH_FIELDS_EXCLUDED = (
    "timestamp", "current_hash", "signature", "public_key", "key_id",
    "type", "instance_id", "proof_id", "tenant_id",
)


def _recompute_hash(proof: dict) -> str:
    """
    Recompute SHA-256 over canonical content — identical to engine.py.

    Fields included: decision, decision_context, governance, determinism,
                     previous_hash, sequence_id
    Fields excluded: timestamp, current_hash, signature, public_key, key_id,
                     type, instance_id, proof_id, tenant_id

    Canonical form: json.dumps(sort_keys=True, separators=(",",":"),
                                ensure_ascii=False)
    """
    ledger = proof.get("ledger", {})
    content = {
        "decision":          proof.get("decision", {}),
        "decision_context":  proof.get("decision_context", {}),
        "governance":        proof.get("governance", {}),
        "determinism":       proof.get("determinism", {}),
        "previous_hash":     ledger.get("previous_hash", ""),
        "sequence_id":       ledger.get("sequence_id", 0),
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Ed25519 verification ──────────────────────────────────────────────────────

def verify_ed25519(public_key_hex: str, message_hex: str, signature_hex: str) -> bool:
    """
    Verify Ed25519 signature.
    message_hex:   the current_hash (32 bytes as 64 hex chars)
    signature_hex: the proof signature (64 bytes as 128 hex chars)
    public_key_hex: the signer's public key (32 bytes as 64 hex chars)
    """
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(bytes.fromhex(message_hex), bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


# ── Main verifier ─────────────────────────────────────────────────────────────

def verify_proof_signature(proof: dict, override_pubkey: str | None = None) -> dict[str, Any]:
    """
    Verify a single proof's hash and signature.

    Returns:
        {
          "valid":       bool,
          "hash_valid":  bool,   -- recomputed hash matches stored hash
          "sig_valid":   bool,   -- Ed25519 signature valid
          "proof_id":    str,
          "instance_id": str,
          "key_id":      str,
          "failure":     str | None,
        }
    """
    result: dict[str, Any] = {
        "valid": False, "hash_valid": False, "sig_valid": False,
        "proof_id": proof.get("proof_id"), "instance_id": proof.get("instance_id"),
        "key_id": proof.get("signature", {}).get("key_id"),
        "failure": None,
    }

    # ── Step 1: recompute hash ────────────────────────────────────────────────
    ledger = proof.get("ledger", {})
    stored_hash = ledger.get("current_hash", "")
    computed_hash = _recompute_hash(proof)

    if computed_hash != stored_hash:
        result["failure"] = (
            f"Hash mismatch: stored={stored_hash[:16]}... "
            f"computed={computed_hash[:16]}..."
        )
        return result
    result["hash_valid"] = True

    # ── Step 2: verify Ed25519 signature ─────────────────────────────────────
    sig_block = proof.get("signature", {})
    sig_value = sig_block.get("value", "")
    public_key = override_pubkey or sig_block.get("public_key", "")

    if not public_key:
        result["failure"] = (
            "public_key not in proof.signature block and not provided via --public-key. "
            "Pass it explicitly: --public-key <64-hex-chars>"
        )
        return result

    if not sig_value or len(sig_value) != 128:
        result["failure"] = f"Invalid signature length: {len(sig_value)} (expected 128 hex chars)"
        return result

    if not verify_ed25519(public_key, computed_hash, sig_value):
        result["failure"] = "Ed25519 signature verification failed"
        return result

    result["sig_valid"] = True
    result["valid"] = True
    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify a Zorynex proof signature")
    parser.add_argument("proof_file", help="Path to proof.json or - for stdin")
    parser.add_argument("--public-key", help="Ed25519 public key (64 hex chars)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.proof_file == "-":
        raw = sys.stdin.read()
    else:
        with open(args.proof_file) as f:
            raw = f.read()

    try:
        proof = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON: {e}", file=sys.stderr)
        return 1

    result = verify_proof_signature(proof, override_pubkey=args.public_key)

    if not args.quiet:
        status = "VALID" if result["valid"] else "INVALID"
        print(f"\nSignature verification: {status}")
        print(f"  proof_id:    {result['proof_id']}")
        print(f"  instance_id: {result['instance_id']}")
        print(f"  key_id:      {result['key_id']}")
        print(f"  hash_valid:  {result['hash_valid']}")
        print(f"  sig_valid:   {result['sig_valid']}")
        if result["failure"]:
            print(f"  failure:     {result['failure']}")
        print()

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())