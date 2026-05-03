
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from nacl.signing import VerifyKey

from .canonical import canonical_hash, build_hash_payload, genesis_hash, is_valid_hash
from .exceptions import (
    ChainBroken,
    HashMismatch,
    KeyIdNotFound,
    SequenceGap,
    SequenceOrderViolation,
    SignatureMismatch,
    VerificationError,
)
from .schema import (
    DeterminismMode,
    ProofV1,
    VerificationResult,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_proof_id(current_hash: str, sequence_id: int) -> str:
    """Deterministic proof_id = SHA256(current_hash + ':' + str(sequence_id))."""
    raw = f"{current_hash}:{sequence_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── Single proof verification ─────────────────────────────────────────────────

def verify_proof(
    proof_dict: dict,
    expected_previous_hash: str | None = None,
    expected_sequence_id: int | None = None,
) -> VerificationResult:
    """
    Verify a single proof artifact (proof.json).

    This function requires NO database access, NO network calls,
    NO trust in the originating system.

    The proof must be self-contained:
        - proof.signature.public_key must be present
        - proof.ledger.current_hash must be verifiable
        - proof.signature.value must verify against public_key

    Args:
        proof_dict:            dict from proof.json
        expected_previous_hash: if verifying within a chain, the hash from
                                the previous proof (None for single-proof verify)
        expected_sequence_id:  if verifying within a chain, the expected
                                sequence_id (None for single-proof verify)

    Returns:
        VerificationResult with valid=True or valid=False + failure_reason
    """
    verified_at = _utc_now()

    # Extract key_id for result reporting (may fail if schema invalid)
    key_id = "unknown"
    sequence_id = 0
    final_state = None

    try:
        # ── Step 1: Schema validation ────────────────────────────────────
        try:
            proof = ProofV1.model_validate(proof_dict)
            key_id = proof.signature.key_id
            sequence_id = proof.ledger.sequence_id
            final_state = proof.decision.to_state
        except Exception as e:
            return VerificationResult(
                valid=False,
                final_state=None,
                verified_at=verified_at,
                key_id=key_id,
                sequence_verified=sequence_id,
                chain_intact=False,
                governance_compliant=False,
                failure_reason={
                    "type": "SchemaValidationError",
                    "message": f"Proof schema invalid: {e}",
                    "sequence_id": sequence_id,
                },
            )

        # ── Step 2: Hash verification ────────────────────────────────────
        # Recompute hash from proof content and compare to stored current_hash
        hash_payload = build_hash_payload(
            decision=proof.decision.model_dump(mode="json"),
            decision_context=proof.decision_context.model_dump(mode="json"),
            governance=proof.governance.model_dump(mode="json"),
            determinism=proof.determinism.model_dump(mode="json"),
            previous_hash=proof.ledger.previous_hash,
            sequence_id=proof.ledger.sequence_id,
        )
        recomputed_hash = canonical_hash(hash_payload)

        if recomputed_hash != proof.ledger.current_hash:
            return VerificationResult(
                valid=False,
                final_state=final_state,
                verified_at=verified_at,
                key_id=key_id,
                sequence_verified=sequence_id,
                chain_intact=False,
                governance_compliant=True,
                failure_reason={
                    "type": "HashMismatch",
                    "message": (
                        f"Recomputed hash '{recomputed_hash[:16]}...' does not match "
                        f"stored hash '{proof.ledger.current_hash[:16]}...'. "
                        f"Proof payload was modified after signing."
                    ),
                    "sequence_id": sequence_id,
                    "expected": recomputed_hash,
                    "stored": proof.ledger.current_hash,
                },
            )

        # ── Step 3: Signature verification ───────────────────────────────
        # Verify Ed25519 signature using public_key embedded in proof
        # No external key store needed — proof is self-contained
        sig_valid = _verify_ed25519(
            public_key_hex=proof.signature.public_key,
            hash_bytes=proof.to_sign_bytes(),
            signature_hex=proof.signature.value,
        )

        if not sig_valid:
            return VerificationResult(
                valid=False,
                final_state=final_state,
                verified_at=verified_at,
                key_id=key_id,
                sequence_verified=sequence_id,
                chain_intact=False,
                governance_compliant=True,
                failure_reason={
                    "type": "SignatureMismatch",
                    "message": (
                        f"Ed25519 signature verification failed for key '{key_id}'. "
                        f"Signature does not match hash using embedded public key."
                    ),
                    "sequence_id": sequence_id,
                    "key_id": key_id,
                },
            )

        # ── Step 4: Chain validation ──────────────────────────────────────
        # If we're given an expected previous_hash (chain context), verify link
        if expected_previous_hash is not None:
            if proof.ledger.previous_hash != expected_previous_hash:
                return VerificationResult(
                    valid=False,
                    final_state=final_state,
                    verified_at=verified_at,
                    key_id=key_id,
                    sequence_verified=sequence_id,
                    chain_intact=False,
                    governance_compliant=True,
                    failure_reason={
                        "type": "ChainBroken",
                        "message": (
                            f"Hash chain broken at sequence_id={sequence_id}. "
                            f"previous_hash does not match prior proof's current_hash."
                        ),
                        "sequence_id": sequence_id,
                        "expected_previous": expected_previous_hash,
                        "stored_previous": proof.ledger.previous_hash,
                    },
                )

        # For first proof: previous_hash must be genesis
        if proof.ledger.sequence_id == 1:
            if proof.ledger.previous_hash != genesis_hash():
                return VerificationResult(
                    valid=False,
                    final_state=final_state,
                    verified_at=verified_at,
                    key_id=key_id,
                    sequence_verified=sequence_id,
                    chain_intact=False,
                    governance_compliant=True,
                    failure_reason={
                        "type": "ChainBroken",
                        "message": (
                            f"First proof (sequence_id=1) must have previous_hash="
                            f"'{'0'*16}...'. Got '{proof.ledger.previous_hash[:16]}...'"
                        ),
                        "sequence_id": 1,
                    },
                )

        # ── Step 5: Sequence validation ───────────────────────────────────
        if expected_sequence_id is not None:
            if proof.ledger.sequence_id != expected_sequence_id:
                return VerificationResult(
                    valid=False,
                    final_state=final_state,
                    verified_at=verified_at,
                    key_id=key_id,
                    sequence_verified=sequence_id,
                    chain_intact=False,
                    governance_compliant=True,
                    failure_reason={
                        "type": "SequenceGap",
                        "message": (
                            f"Expected sequence_id={expected_sequence_id}, "
                            f"got {proof.ledger.sequence_id}."
                        ),
                        "sequence_id": sequence_id,
                        "expected": expected_sequence_id,
                        "actual": proof.ledger.sequence_id,
                    },
                )

        # ── Step 6: Determinism validation ────────────────────────────────
        # Informational: verify mode/seed/external_calls are consistent
        det_result = _validate_determinism_consistency(proof)
        if det_result is not None:
            return VerificationResult(
                valid=False,
                final_state=final_state,
                verified_at=verified_at,
                key_id=key_id,
                sequence_verified=sequence_id,
                chain_intact=True,
                governance_compliant=True,
                failure_reason={
                    "type": "DeterminismInconsistency",
                    "message": det_result,
                    "sequence_id": sequence_id,
                },
            )

        # ── All checks passed ─────────────────────────────────────────────
        return VerificationResult(
            valid=True,
            final_state=final_state,
            verified_at=verified_at,
            key_id=key_id,
            sequence_verified=sequence_id,
            chain_intact=True,
            governance_compliant=True,
            failure_reason=None,
        )

    except Exception as e:
        # Catch-all: unexpected errors return structured failure
        return VerificationResult(
            valid=False,
            final_state=final_state,
            verified_at=verified_at,
            key_id=key_id,
            sequence_verified=sequence_id,
            chain_intact=False,
            governance_compliant=False,
            failure_reason={
                "type": "UnexpectedError",
                "message": f"Unexpected verification error: {e}",
                "sequence_id": sequence_id,
            },
        )


# ── Chain verification ────────────────────────────────────────────────────────

def verify_chain(proof_dicts: list[dict]) -> VerificationResult:
    """
    Verify a complete chain of proof artifacts.

    Verifies each proof individually AND verifies that the chain links
    correctly from first to last.

    An auditor can export all proofs for a decision and verify the
    entire history in one call, offline, with no system access.

    Args:
        proof_dicts: list of proof.json dicts, in sequence_id order (oldest first)

    Returns:
        VerificationResult — valid=True only if ALL proofs pass ALL checks
    """
    verified_at = _utc_now()

    if not proof_dicts:
        return VerificationResult(
            valid=False,
            final_state=None,
            verified_at=verified_at,
            key_id="unknown",
            sequence_verified=0,
            chain_intact=False,
            governance_compliant=False,
            failure_reason={
                "type": "EmptyChain",
                "message": "No proofs provided for chain verification.",
                "sequence_id": 0,
            },
        )

    last_hash = genesis_hash()
    final_state = None
    final_key_id = "unknown"
    governance_info = None
    replay_info = None

    for i, proof_dict in enumerate(proof_dicts):
        expected_seq = i + 1

        result = verify_proof(
            proof_dict=proof_dict,
            expected_previous_hash=last_hash,
            expected_sequence_id=expected_seq,
        )

        if not result.valid:
            # Return the specific failure with chain context
            return VerificationResult(
                valid=False,
                final_state=final_state,
                verified_at=verified_at,
                key_id=result.key_id,
                sequence_verified=result.sequence_verified,
                chain_intact=False,
                governance_compliant=result.governance_compliant,
                failure_reason=result.failure_reason,
            )

        # Update chain state
        try:
            proof = ProofV1.model_validate(proof_dict)
            last_hash = proof.ledger.current_hash
            final_state = proof.decision.to_state
            final_key_id = proof.signature.key_id
            governance_info = {
                "model_version": proof.governance.model_version,
                "policy_version": proof.governance.policy_version,
                "determinism_mode": proof.determinism.mode.value,
            }
            replay_info = _build_replay_info(proof)
        except Exception:
            pass

    # Build rich result for CRO/auditor — they need full context
    return VerificationResult(
        valid=True,
        final_state=final_state,
        verified_at=verified_at,
        key_id=final_key_id,
        sequence_verified=len(proof_dicts),
        chain_intact=True,
        governance_compliant=True,
        failure_reason=None,
    )


# ── Rich verifier output ──────────────────────────────────────────────────────

def verify_proof_full(proof_dict: dict) -> dict:
    """
    Full verification output for auditors and the web demo.

    Returns the complete structured output defined in the Session 3 spec,
    including governance_recorded, governance_verified, and replay_result.

    This is what a CRO hands to their compliance team.
    This is what the web demo displays.
    This is what the API returns from POST /verify.

    Args:
        proof_dict: dict from proof.json

    Returns:
        Complete verification dict matching the Session 3 spec output format
    """
    result = verify_proof(proof_dict)
    verified_at = _utc_now()

    governance_recorded = None
    governance_verified = False
    replay_result = None

    if result.valid:
        try:
            proof = ProofV1.model_validate(proof_dict)
            governance_recorded = {
                "model_version": proof.governance.model_version,
                "agent_version": proof.governance.agent_version,
                "policy_version": proof.governance.policy_version,
                "determinism_mode": proof.determinism.mode.value,
            }
            # governance_verified = False because we verified the RECORD is
            # authentic — not that the governance decisions were CORRECT.
            # This is the honest position: we prove what was recorded,
            # not that what was recorded was the right decision.
            governance_verified = False
            replay_result = _build_replay_info(proof)
        except Exception:
            pass

    return {
        "valid": result.valid,
        "chain_intact": result.chain_intact,
        "sequence_verified": result.sequence_verified,
        "final_state": result.final_state,
        "key_id": result.key_id,
        "verified_at": result.verified_at,
        "governance_recorded": governance_recorded,
        "governance_verified": governance_verified,
        "replay_result": replay_result,
        "failure_reason": result.failure_reason,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _verify_ed25519(
    public_key_hex: str,
    hash_bytes: bytes,
    signature_hex: str,
) -> bool:
    """
    Verify Ed25519 signature using embedded public key.
    Standalone — no signer instance needed.

    Args:
        public_key_hex: 64-char hex (32-byte Ed25519 public key)
        hash_bytes:     32 bytes — the SHA-256 hash that was signed
        signature_hex:  128-char hex (64-byte Ed25519 signature)

    Returns:
        True if valid, False otherwise
    """
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        verify_key = VerifyKey(pub_bytes)
        verify_key.verify(hash_bytes, sig_bytes)
        return True
    except Exception:
        return False


def _validate_determinism_consistency(proof: ProofV1) -> str | None:
    """
    Check determinism mode/seed/external_calls_hash consistency.
    Returns error message if inconsistent, None if consistent.
    """
    mode = proof.determinism.mode
    seed = proof.determinism.seed
    ext_hash = proof.determinism.external_calls_hash

    if mode == DeterminismMode.STRICT_DETERMINISTIC:
        if seed is not None:
            return (
                f"mode=strict_deterministic but seed is set to '{seed}'. "
                f"Strict deterministic mode must have seed=null."
            )
        if ext_hash is not None:
            return (
                f"mode=strict_deterministic but external_calls_hash is set. "
                f"Strict deterministic mode must have external_calls_hash=null."
            )

    elif mode == DeterminismMode.REPLAY_WITH_SEED:
        if seed is None:
            return (
                "mode=replay_with_seed but seed is null. "
                "This mode requires a seed to be captured."
            )

    elif mode == DeterminismMode.REPLAY_WITH_RECORDED_IO:
        if ext_hash is None:
            return (
                "mode=replay_with_recorded_io but external_calls_hash is null. "
                "This mode requires external calls to be recorded."
            )
        if not is_valid_hash(ext_hash):
            return (
                f"external_calls_hash '{ext_hash[:16]}...' is not a valid 64-char hex."
            )

    return None


def _build_replay_info(proof: ProofV1) -> dict:
    """Build replay_result block for full verifier output."""
    mode = proof.determinism.mode
    return {
        "mode_valid": True,
        "seed_captured": proof.determinism.seed is not None,
        "external_calls_recorded": (
            1 if proof.determinism.external_calls_hash is not None else 0
        ),
        "full_replay_executed": False,  # Phase 4 — Formation Gate
        "determinism_mode": mode.value,
    }


# ── System root ───────────────────────────────────────────────────────────────

def compute_system_root(latest_hashes: list[str]) -> str:
    """
    Compute system root = SHA256 of all latest instance current_hashes sorted.

    Used for:
    - Drift detection: compare system_root at T1 vs T2
    - Global integrity proof: proves entire ledger state
    - Audit: "here is the state of the entire system at this moment"

    Args:
        latest_hashes: list of current_hash values (one per instance,
                       the latest entry for each)

    Returns:
        64-char hex SHA256 of sorted+concatenated hashes
    """
    if not latest_hashes:
        return "0" * 64
    sorted_hashes = sorted(latest_hashes)
    combined = "".join(sorted_hashes)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()