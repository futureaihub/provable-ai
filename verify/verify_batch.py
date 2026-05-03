#!/usr/bin/env python3
"""
Zorynex — Standalone Batch + Inclusion Proof Verifier
=======================================================
Verify a signed batch export with ZERO dependency on Zorynex infrastructure.
Requires only: PyNaCl (pip install pynacl)

Usage:
    # Verify entire batch export
    python verify_batch.py batch_export.json

    # Verify that a specific proof_id is in the batch
    python verify_batch.py batch_export.json --proof-id <proof_id_hex>

    # Verify a pre-computed inclusion proof
    python verify_batch.py --inclusion-proof inclusion_proof.json

Output:
    EXIT 0 — batch / proof valid
    EXIT 1 — invalid or tampered

What this verifies:
    1. Merkle root recomputed from all proof_ids matches batch.merkle_root
    2. Ed25519 signature over Merkle root matches batch.merkle_signature
    3. (Optional) Inclusion proof: single proof_id is in the Merkle tree
       without revealing any other proof_ids

Algorithm (matches audit_batch.py exactly):
    leaves        = sorted([SHA-256(proof_id) for proof_id in proof_ids])
    single leaf   = SHA-256(leaf + leaf)   (duplicate if odd count)
    internal node = SHA-256(left_bytes + right_bytes)
    root          = top of tree
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any


# ── Merkle tree ───────────────────────────────────────────────────────────────

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_merkle_root(proof_ids: list[str]) -> str:
    """
    Compute Merkle root from a list of proof_ids.
    Leaf type 1: SHA-256(proof_id.encode("utf-8"))
    """
    if not proof_ids:
        return "0" * 64

    sorted_ids = sorted(proof_ids)
    leaves = [_sha256_hex(pid.encode("utf-8")) for pid in sorted_ids]

    if len(leaves) == 1:
        leaves = leaves + leaves

    current = leaves[:]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        next_level = []
        for i in range(0, len(current), 2):
            left  = bytes.fromhex(current[i])
            right = bytes.fromhex(current[i + 1])
            next_level.append(_sha256_hex(left + right))
        current = next_level

    return current[0]


def verify_inclusion_proof(proof_dict: dict) -> bool:
    """
    Verify a Merkle inclusion proof.

    proof_dict fields:
        leaf_hash    — SHA-256(proof_id)
        path         — [{hash: str, position: "left"|"right"}, ...]
        root         — expected Merkle root
        signed_root  — the root that was signed (must equal root)
        signature    — Ed25519 hex signature over root
        public_key   — Ed25519 public key hex
    """
    try:
        leaf_hash   = proof_dict["leaf_hash"]
        path        = proof_dict["path"]
        root        = proof_dict["root"]
        signed_root = proof_dict.get("signed_root", root)
        signature   = proof_dict.get("signature", "")
        public_key  = proof_dict.get("public_key", "")

        # Reconstruct root from leaf + path
        current = leaf_hash
        for step in path:
            sibling  = step["hash"]
            position = step["position"]
            if position == "left":
                combined = bytes.fromhex(sibling) + bytes.fromhex(current)
            else:
                combined = bytes.fromhex(current) + bytes.fromhex(sibling)
            current = _sha256_hex(combined)

        if current != root:
            return False

        # Binding check: root must equal signed_root
        if signed_root and current != signed_root:
            return False

        # Ed25519 signature check if provided
        if signature and public_key:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
            vk = VerifyKey(bytes.fromhex(public_key))
            vk.verify(bytes.fromhex(root), bytes.fromhex(signature))

        return True
    except Exception:
        return False


# ── Batch verifier ────────────────────────────────────────────────────────────

def verify_batch(batch: dict) -> dict[str, Any]:
    """
    Verify a complete batch export.

    Returns:
        {
          "valid":               bool,
          "merkle_root_valid":   bool,
          "signature_valid":     bool,
          "proof_count":         int,
          "tenant_id":           str,
          "exported_at":         str,
          "failure":             str | None,
        }
    """
    result: dict[str, Any] = {
        "valid": False, "merkle_root_valid": False, "signature_valid": False,
        "proof_count": 0, "tenant_id": batch.get("tenant_id"),
        "exported_at": batch.get("exported_at"), "failure": None,
    }

    proofs    = batch.get("proofs", [])
    proof_ids = [p.get("proof_id") for p in proofs if p.get("proof_id")]
    result["proof_count"] = len(proof_ids)

    stored_root = batch.get("merkle_root", "")
    computed_root = build_merkle_root(proof_ids)

    if computed_root != stored_root:
        result["failure"] = (
            f"Merkle root mismatch: stored={stored_root[:16]}... "
            f"computed={computed_root[:16]}..."
        )
        return result
    result["merkle_root_valid"] = True

    # Verify Ed25519 signature over root
    sig_block  = batch.get("merkle_signature", {})
    sig_value  = sig_block.get("value", "")
    public_key = sig_block.get("public_key", "")

    if not sig_value or not public_key:
        result["failure"] = "merkle_signature missing value or public_key"
        return result

    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        vk = VerifyKey(bytes.fromhex(public_key))
        vk.verify(bytes.fromhex(computed_root), bytes.fromhex(sig_value))
        result["signature_valid"] = True
        result["valid"] = True
    except Exception as e:
        result["failure"] = f"Ed25519 signature invalid: {e}"

    return result


def verify_proof_in_batch(batch: dict, target_proof_id: str) -> dict[str, Any]:
    """Verify a specific proof_id is in the batch via inclusion proof."""
    proofs    = batch.get("proofs", [])
    proof_ids = [p.get("proof_id") for p in proofs if p.get("proof_id")]

    if target_proof_id not in proof_ids:
        return {"valid": False, "failure": f"proof_id not found in batch ({len(proof_ids)} proofs)"}

    sig_block = batch.get("merkle_signature", {})
    root      = batch.get("merkle_root", "")

    # Build the inclusion proof on-the-fly
    sorted_ids  = sorted(proof_ids)
    leaves      = [_sha256_hex(pid.encode("utf-8")) for pid in sorted_ids]
    target_leaf = _sha256_hex(target_proof_id.encode("utf-8"))

    if len(leaves) == 1:
        leaves = leaves + leaves

    target_idx = leaves.index(target_leaf)
    path: list[dict] = []
    current = leaves[:]
    idx = target_idx

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        sibling_idx = idx ^ 1
        sibling     = current[sibling_idx]
        path.append({"hash": sibling, "position": "right" if idx % 2 == 0 else "left"})
        next_level = []
        for i in range(0, len(current), 2):
            left  = bytes.fromhex(current[i])
            right = bytes.fromhex(current[i + 1])
            next_level.append(_sha256_hex(left + right))
        idx     = idx // 2
        current = next_level

    inc_proof = {
        "leaf_hash":   target_leaf,
        "path":        path,
        "root":        root,
        "signed_root": root,
        "signature":   sig_block.get("value", ""),
        "public_key":  sig_block.get("public_key", ""),
    }
    valid = verify_inclusion_proof(inc_proof)
    return {
        "valid":       valid,
        "proof_id":    target_proof_id,
        "leaf_hash":   target_leaf,
        "merkle_root": root,
        "failure":     None if valid else "Inclusion proof failed",
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify a Zorynex batch export")
    parser.add_argument("batch_file", nargs="?", help="Path to batch_export.json")
    parser.add_argument("--proof-id",        help="Verify this proof_id is in the batch")
    parser.add_argument("--inclusion-proof", help="Path to pre-computed inclusion_proof.json")
    parser.add_argument("--quiet",           action="store_true")
    args = parser.parse_args()

    # Verify a standalone inclusion proof
    if args.inclusion_proof:
        with open(args.inclusion_proof) as f:
            inc = json.load(f)
        valid = verify_inclusion_proof(inc)
        if not args.quiet:
            print(f"\nInclusion proof: {'VALID' if valid else 'INVALID'}")
            print(f"  leaf_hash:   {inc.get('leaf_hash', '')[:16]}...")
            print(f"  merkle_root: {inc.get('root', '')[:16]}...")
            print()
        return 0 if valid else 1

    if not args.batch_file:
        parser.print_help()
        return 1

    with open(args.batch_file) as f:
        batch = json.load(f)

    # Verify specific proof membership
    if args.proof_id:
        result = verify_proof_in_batch(batch, args.proof_id)
        if not args.quiet:
            status = "VALID" if result["valid"] else "INVALID"
            print(f"\nProof membership: {status}")
            print(f"  proof_id:    {result.get('proof_id', '')[:16]}...")
            print(f"  merkle_root: {result.get('merkle_root', '')[:16]}...")
            if result.get("failure"):
                print(f"  failure:     {result['failure']}")
            print()
        return 0 if result["valid"] else 1

    # Verify full batch
    result = verify_batch(batch)
    if not args.quiet:
        status = "VALID" if result["valid"] else "INVALID"
        print(f"\nBatch verification: {status}")
        print(f"  tenant_id:           {result['tenant_id']}")
        print(f"  exported_at:         {result['exported_at']}")
        print(f"  proof_count:         {result['proof_count']}")
        print(f"  merkle_root_valid:   {result['merkle_root_valid']}")
        print(f"  signature_valid:     {result['signature_valid']}")
        if result["failure"]:
            print(f"  failure:             {result['failure']}")
        print()

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())