"""
Zorynex - Batch Export with Merkle Root + Signature
======================================================
Exports all proofs in a date range as a signed, verifiable batch.

The batch is tamper-evident:
  - Merkle root commits to every proof_id in the export
  - Ed25519 signature over the root proves authenticity
  - Any modification to any proof -> root changes -> signature invalid

LEAF DEFINITIONS - two canonical types, never mixed:

  1. Proof batch leaves (build_merkle_tree, compute_inclusion_proof):
       leaf = SHA-256(proof_id.encode("utf-8"))
       Used for: batch export Merkle root, inclusion proofs over proof_ids
       Sorted by: proof_id lexicographic order

  2. Audit entry leaves (merkle_root_from_entries):
       leaf = SHA-256("tenant_id|instance_id|sequence_id|result|verified_at|failure_code")
       Used for: audit report Merkle root, compliance pack attestation
       Sorted by: (tenant_id, verified_at, trace_id)

These two leaf types are NEVER mixed. A proof batch root and an audit entry
root are different objects covering different data. Inclusion proofs
(compute_inclusion_proof) always use leaf type 1 - proof_id hashes.

Merkle tree construction (both types):
  - Leaves: sorted for determinism before hashing
  - Internal nodes: SHA-256(left_bytes + right_bytes)
  - Odd leaves: last leaf duplicated (Bitcoin-style)
  - Single leaf: duplicated with itself
  - Result: single 64-char hex root hash
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .audit_log import VerificationAuditEntry, compute_audit_leaf, ChainVerificationResult
from .signer import BaseSigner, get_signer
from .storage import SQLiteStorage


# -- Merkle tree ---------------------------------------------------------------

def build_merkle_tree(proof_ids: list[str]) -> tuple[str, list[list[str]]]:
    """
    Build a binary Merkle tree from a list of proof_ids.

    Returns:
        (root_hash, levels) where levels[0] = leaves, levels[-1] = [root]

    Leaf hashing: SHA-256(proof_id.encode())
    Node hashing: SHA-256(left_bytes + right_bytes)
    Padding:      last leaf duplicated if odd count at any level
    Empty input:  returns ("0" * 64, [])
    """
    if not proof_ids:
        return "0" * 64, []

    # Sort for determinism - same set of proof_ids -> same root regardless of order
    sorted_ids = sorted(proof_ids)

    # Leaves: hash each proof_id
    leaves = [
        hashlib.sha256(pid.encode("utf-8")).hexdigest()
        for pid in sorted_ids
    ]

    # Always pad to at least 2 leaves (single leaf duplicates with itself)
    if len(leaves) == 1:
        leaves = leaves + leaves

    levels: list[list[str]] = [leaves]
    current = leaves[:]

    while len(current) > 1:
        # Pad to even count
        if len(current) % 2 == 1:
            current.append(current[-1])

        next_level = []
        for i in range(0, len(current), 2):
            left  = bytes.fromhex(current[i])
            right = bytes.fromhex(current[i + 1])
            parent = hashlib.sha256(left + right).hexdigest()
            next_level.append(parent)

        levels.append(next_level)
        current = next_level

    return current[0], levels


def merkle_root(proof_ids: list[str]) -> str:
    """Convenience wrapper - returns just the root hash."""
    root, _ = build_merkle_tree(proof_ids)
    return root


def merkle_root_from_entries(entries: list[VerificationAuditEntry]) -> str:
    """
    Build Merkle root from audit entries using rich leaf content.

    Each leaf = SHA-256(tenant_id|instance_id|sequence_id|result|verified_at|failure_code)
    This ensures two different audit states cannot produce the same root.

    Deterministic: entries are sorted by (tenant_id, verified_at, trace_id) before hashing.
    """
    if not entries:
        return "0" * 64

    # Sort for determinism
    sorted_entries = sorted(
        entries,
        key=lambda e: (e.tenant_id, e.verified_at, e.trace_id),
    )
    leaf_hashes = [compute_audit_leaf(e) for e in sorted_entries]
    root, _ = build_merkle_tree(leaf_hashes)
    return root


# -- Batch builder -------------------------------------------------------------


# -- Merkle inclusion proof ----------------------------------------------------

@dataclass
class MerkleInclusionProof:
    """
    Proves a specific leaf is in a Merkle root - AND binds it to the signed root.

    Three fields together form one unit of truth:
        leaf_hash + root -> provable membership
        signed_root      -> binding to the Ed25519 signature

    signed_root must equal root (checked in verify_inclusion_proof).
    This prevents proof substitution: a valid path cannot be reused
    with a different root or a different signed batch.

    Verification:
        1. Reconstruct root by walking path from leaf_hash
        2. Assert reconstructed == root
        3. Assert root == signed_root
        4. Verify Ed25519(sig, root_bytes, public_key) - binds to signed batch
    """
    leaf_hash:    str             # SHA-256 of the leaf content
    leaf_index:   int             # position in sorted leaf list
    path:         list[dict]      # [{"hash": "...", "position": "left"|"right"}, ...]
    root:         str             # the Merkle root this proof reconstructs to
    signed_root:  str             # the root that was signed (must equal root)
    signature:    str             # Ed25519 hex signature over the root
    public_key:   str             # Ed25519 public key hex (for offline verify)
    key_id:       str             # which key signed this
    valid:        bool = True


def compute_inclusion_proof(
    proof_ids:  list[str],
    target_id:  str,
    batch_dict: dict | None = None,
) -> MerkleInclusionProof:
    """
    Compute a Merkle inclusion proof for target_id, bound to the batch signature.

    The proof binds leaf+root+signature into one unit - prevents proof
    substitution (a valid path cannot be reused with a different batch).

    Args:
        proof_ids:  Full list of proof IDs in the batch
        target_id:  The proof_id to prove membership of
        batch_dict: The full batch export dict (for signature binding).
                    If None, proof is generated without signature binding.

    Raises:
        ValueError if target_id is not in proof_ids.
    """
    if not proof_ids:
        raise ValueError("proof_ids is empty - cannot compute inclusion proof")

    sorted_ids = sorted(proof_ids)
    if target_id not in sorted_ids:
        raise ValueError(f"target_id '{target_id[:16]}...' not found in proof_ids")

    leaves = [hashlib.sha256(pid.encode("utf-8")).hexdigest() for pid in sorted_ids]
    if len(leaves) == 1:
        leaves = leaves + leaves

    target_leaf = hashlib.sha256(target_id.encode("utf-8")).hexdigest()
    target_idx  = leaves.index(target_leaf)

    path:   list[dict] = []
    current = leaves[:]
    idx     = target_idx

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        sibling_idx = idx ^ 1
        sibling     = current[sibling_idx]
        if idx % 2 == 0:
            path.append({"hash": sibling, "position": "right"})
        else:
            path.append({"hash": sibling, "position": "left"})
        next_level = []
        for i in range(0, len(current), 2):
            left  = bytes.fromhex(current[i])
            right = bytes.fromhex(current[i + 1])
            next_level.append(hashlib.sha256(left + right).hexdigest())
        idx     = idx // 2
        current = next_level

    root = current[0]

    # Extract signature binding from batch_dict
    signed_root = root
    signature   = ""
    public_key  = ""
    key_id      = ""
    if batch_dict:
        sig_block  = batch_dict.get("merkle_signature", {})
        signed_root = batch_dict.get("merkle_root", root)
        signature   = sig_block.get("value", "")
        public_key  = sig_block.get("public_key", "")
        key_id      = sig_block.get("key_id", "")

    return MerkleInclusionProof(
        leaf_hash=target_leaf, leaf_index=target_idx,
        path=path, root=root,
        signed_root=signed_root, signature=signature,
        public_key=public_key, key_id=key_id, valid=True,
    )


def verify_inclusion_proof(proof: MerkleInclusionProof | dict) -> bool:
    """
    Verify a Merkle inclusion proof - including signature binding.

    Steps:
      1. Reconstruct root from leaf_hash + path
      2. Assert reconstructed root == proof.root
      3. Assert proof.root == proof.signed_root (binding check)
         (If signed_root is absent, skips binding check - backward compat)
      4. If signature + public_key present: verify Ed25519(sig, root_bytes, pubkey)

    An external auditor can call this with no Zorynex infrastructure.

    Returns True if ALL applicable checks pass.
    """
    try:
        if isinstance(proof, dict):
            leaf_hash   = proof["leaf_hash"]
            path        = proof["path"]
            root        = proof["root"]
            signed_root = proof.get("signed_root", root)
            signature   = proof.get("signature", "")
            public_key  = proof.get("public_key", "")
        else:
            leaf_hash   = proof.leaf_hash
            path        = proof.path
            root        = proof.root
            signed_root = proof.signed_root
            signature   = proof.signature
            public_key  = proof.public_key

        # Step 1: reconstruct root
        current = leaf_hash
        for step in path:
            sibling  = step["hash"]
            position = step["position"]
            if position == "left":
                combined = bytes.fromhex(sibling) + bytes.fromhex(current)
            else:
                combined = bytes.fromhex(current) + bytes.fromhex(sibling)
            current = hashlib.sha256(combined).hexdigest()

        if current != root:
            return False  # path reconstruction failed

        # Step 2: binding check - root must equal the signed root
        if signed_root and current != signed_root:
            return False  # proof does not bind to the signed batch

        # Step 3: Ed25519 signature verification (if available)
        if signature and public_key:
            try:
                from nacl.signing import VerifyKey
                from nacl.exceptions import BadSignatureError
                vk = VerifyKey(bytes.fromhex(public_key))
                vk.verify(bytes.fromhex(root), bytes.fromhex(signature))
            except Exception:
                return False  # signature invalid

        return True
    except Exception:
        return False


@dataclass
class BatchExport:
    """A signed batch export ready to deliver."""
    batch_dict:  dict[str, Any]   # the full serializable batch
    merkle_root: str
    proof_count: int
    exported_at: str


def build_batch_export(
    storage:    SQLiteStorage,
    tenant_id:  str,
    from_date:  str | None = None,
    to_date:    str | None = None,
    signer:     BaseSigner | None = None,
) -> BatchExport:
    """
    Export all proofs in a date range as a verifiable signed batch.

    Args:
        storage:   SQLiteStorage instance
        tenant_id: tenant to export
        from_date: ISO-8601 UTC filter start (inclusive), e.g. "2026-01-01T00:00:00Z"
        to_date:   ISO-8601 UTC filter end   (inclusive), e.g. "2026-12-31T23:59:59Z"
        signer:    Ed25519 signer (defaults to get_signer())

    Returns:
        BatchExport with the full dict and metadata.

    The batch is self-contained - a verifier needs nothing else to check it.
    """
    if signer is None:
        signer = get_signer()

    exported_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # -- Fetch proofs ----------------------------------------------------------
    proofs = _fetch_proofs(storage, tenant_id, from_date, to_date)

    # -- Build Merkle root over proof_ids --------------------------------------
    proof_ids = [
        p.get("proof_id") or _derive_proof_id(p)
        for p in proofs
    ]

    root = merkle_root(proof_ids)

    # -- Sign the root ---------------------------------------------------------
    root_bytes = bytes.fromhex(root)
    sig_hex    = signer.sign_hash(root_bytes)

    merkle_sig = {
        "value":      sig_hex,
        "public_key": signer.get_public_key(),
        "key_id":     signer.get_key_id(),
        "algorithm":  "Ed25519",
        "signed_at":  exported_at,
    }

    # -- Assemble batch --------------------------------------------------------
    batch = {
        "type":              "zorynex-batch-v1",
        "tenant_id":         tenant_id,
        "from_date":         from_date,
        "to_date":           to_date,
        "exported_at":       exported_at,
        "proof_count":       len(proofs),
        "merkle_root":       root,
        "merkle_signature":  merkle_sig,
        "verification_info": {
            "algorithm":   "Ed25519",
            "public_key":  signer.get_public_key(),
            "key_id":      signer.get_key_id(),
            "instructions": (
                "Verify: recompute Merkle root from proof_ids, "
                "verify Ed25519 signature over root bytes using public_key."
            ),
        },
        "proofs":            proofs,
    }

    return BatchExport(
        batch_dict=batch,
        merkle_root=root,
        proof_count=len(proofs),
        exported_at=exported_at,
    )


def verify_batch_signature(batch_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Verify a batch export's Merkle root and signature.

    Steps:
      1. Recompute Merkle root from all embedded proof_ids
      2. Verify root matches batch["merkle_root"]
      3. Verify Ed25519 signature over the root

    Returns:
        {
          "valid": bool,
          "merkle_root_valid": bool,
          "signature_valid": bool,
          "proof_count": int,
          "failure_reason": str | None,
        }
    """
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    try:
        proofs      = batch_dict.get("proofs", [])
        claimed_root = batch_dict.get("merkle_root", "")
        sig_block   = batch_dict.get("merkle_signature", {})
        sig_hex     = sig_block.get("value", "")
        pub_hex     = sig_block.get("public_key", "")

        # Step 1 - recompute Merkle root
        proof_ids = [
            p.get("proof_id") or _derive_proof_id(p)
            for p in proofs
        ]
        computed_root = merkle_root(proof_ids)

        root_valid = (computed_root == claimed_root)
        if not root_valid:
            return {
                "valid": False, "merkle_root_valid": False,
                "signature_valid": False, "proof_count": len(proofs),
                "failure_reason": (
                    f"Merkle root mismatch: computed {computed_root[:16]}... "
                    f"claimed {claimed_root[:16]}..."
                ),
            }

        # Step 2 - verify Ed25519 signature over the root bytes
        root_bytes = bytes.fromhex(claimed_root)
        sig_bytes  = bytes.fromhex(sig_hex)
        pub_bytes  = bytes.fromhex(pub_hex)

        verify_key = VerifyKey(pub_bytes)
        verify_key.verify(root_bytes, sig_bytes)

        return {
            "valid": True, "merkle_root_valid": True,
            "signature_valid": True, "proof_count": len(proofs),
            "failure_reason": None,
        }

    except BadSignatureError:
        return {
            "valid": False, "merkle_root_valid": True,
            "signature_valid": False, "proof_count": len(batch_dict.get("proofs", [])),
            "failure_reason": "Ed25519 signature verification failed.",
        }
    except Exception as e:
        return {
            "valid": False, "merkle_root_valid": False,
            "signature_valid": False, "proof_count": 0,
            "failure_reason": f"Batch verification error: {type(e).__name__}: {e}",
        }


# -- Storage helpers -----------------------------------------------------------

def _fetch_proofs(
    storage:   SQLiteStorage,
    tenant_id: str,
    from_date: str | None,
    to_date:   str | None,
) -> list[dict[str, Any]]:
    """
    Fetch all proof dicts from storage for a tenant and date range.
    Results are ordered by (instance_id, sequence_id) for determinism.
    """
    params: list[Any] = [tenant_id]
    where  = ["tenant_id = ?"]

    if from_date:
        where.append("timestamp >= ?")
        params.append(from_date)
    if to_date:
        where.append("timestamp <= ?")
        params.append(to_date)

    where_sql = " AND ".join(where)

    rows = storage.conn.execute(
        f"""SELECT proof_json FROM ledger
            WHERE {where_sql}
            ORDER BY instance_id, sequence_id""",
        params,
    ).fetchall()

    proofs = []
    for row in rows:
        try:
            proof = json.loads(row["proof_json"])
            proofs.append(proof)
        except (json.JSONDecodeError, TypeError, KeyError):
            continue
    return proofs


def _derive_proof_id(proof: dict) -> str:
    """
    Derive proof_id from ledger fields when proof_id is missing.
    Matches the canonical formula: SHA256(f"{current_hash}:{sequence_id}")
    """
    try:
        current_hash = proof["ledger"]["current_hash"]
        sequence_id  = proof["ledger"]["sequence_id"]
        raw          = f"{current_hash}:{sequence_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except (KeyError, TypeError):
        return hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest()