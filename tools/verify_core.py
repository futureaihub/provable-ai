
import json
import hashlib
from dataclasses import dataclass
from typing import Optional

from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder

SCHEMA_VERSION = "1.0"


# ============================================================
# RESULT TYPE
# ============================================================

@dataclass
class VerificationResult:
    valid: bool
    reason: str
    final_state: Optional[str] = None
    instance_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "final_state": self.final_state,
            "instance_id": self.instance_id,
        }


# ============================================================
# HELPERS
# ============================================================

def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _merkle_root(hashes: list) -> Optional[str]:
    if not hashes:
        return None
    layer = hashes[:]
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            next_layer.append(_sha256(left + right))
        layer = next_layer
    return layer[0]


def _build_entry_payload(entry: dict, previous_hash: Optional[str]) -> dict:
    """
    Reconstruct the canonical payload dict for a ledger entry.
    Must exactly match what engine.py writes on transition.
    Single definition here prevents drift between verifiers.
    """
    return {
        "previous_hash": previous_hash,
        "protocol_hash": entry["protocol_hash"],
        "instance_id": entry["instance_id"],
        "from_state": entry["from_state"],
        "to_state": entry["to_state"],
        "actor": entry["actor"],
        "input_hash": entry["input_hash"],
        "output_hash": entry["output_hash"],
        "model_version": entry["model_version"],
        "agent_version": entry["agent_version"],
        "policy_version": entry["policy_version"],
        "metadata_json": entry["metadata_json"],
        "schema_version": entry.get("schema_version", SCHEMA_VERSION),
        "version": entry["version"],
        "timestamp": entry["timestamp"],
    }


# ============================================================
# CORE VERIFICATION
# ============================================================

def verify_package(package: dict) -> VerificationResult:
    """
    Verify a proof package dict (already parsed from JSON).
    Called by both the CLI and the server /external/verify-proof endpoint.
    """
    try:
        # Step 1: type header
        if package.get("type") != "provable-ai-proof-package":
            return VerificationResult(False, "Invalid proof type")

        public_key_hex = package.get("public_key")
        proof = package.get("proof")
        signature_hex = package.get("signature")

        if not public_key_hex or not proof or not signature_hex:
            return VerificationResult(False, "Proof package missing required fields")

        # Step 2: outer package signature
        try:
            verify_key = VerifyKey(public_key_hex, encoder=HexEncoder)
            verify_key.verify(_canonical(proof), bytes.fromhex(signature_hex))
        except Exception:
            return VerificationResult(False, "Outer package signature invalid")

        # Step 3: protocol hash integrity
        protocol = proof.get("protocol")
        instance = proof.get("instance")
        ledger = proof.get("ledger", [])
        instance_root = proof.get("instance_root")

        if not protocol or not instance:
            return VerificationResult(False, "Proof missing protocol or instance")

        computed_protocol_hash = _sha256_bytes(_canonical(protocol))
        if computed_protocol_hash != instance.get("protocol_hash"):
            return VerificationResult(
                False,
                "Protocol hash mismatch — spec may have been swapped"
            )

        # Step 4: ledger replay
        state = protocol["initial_state"]
        previous_hash = None
        expected_version = 1
        ledger_hashes = []

        for i, entry in enumerate(ledger):

            # 4a: schema version
            if entry.get("schema_version") != SCHEMA_VERSION:
                return VerificationResult(
                    False,
                    f"Entry {i+1}: schema version mismatch "
                    f"(expected {SCHEMA_VERSION}, got {entry.get('schema_version')})"
                )

            # 4b: version sequence
            if entry.get("version") != expected_version:
                return VerificationResult(
                    False,
                    f"Entry {i+1}: version sequence broken "
                    f"(expected {expected_version}, got {entry.get('version')})"
                )

            # 4c: hash recompute
            payload = _build_entry_payload(entry, previous_hash)
            rebuilt_hash = _sha256_bytes(_canonical(payload))
            if rebuilt_hash != entry.get("current_hash"):
                return VerificationResult(
                    False,
                    f"Entry {i+1}: hash mismatch — record may have been altered"
                )

            # 4d: per-entry signature
            try:
                verify_key.verify(
                    _canonical(payload),
                    bytes.fromhex(entry["signature"])
                )
            except Exception:
                return VerificationResult(
                    False,
                    f"Entry {i+1}: ledger entry signature invalid"
                )

            # 4e: transition validity
            valid_transition = any(
                t["from_state"] == state and t["to_state"] == entry["to_state"]
                for t in protocol.get("transitions", [])
            )
            if not valid_transition:
                return VerificationResult(
                    False,
                    f"Entry {i+1}: invalid transition "
                    f"{state!r} -> {entry['to_state']!r} not in protocol"
                )

            ledger_hashes.append(entry["current_hash"])
            state = entry["to_state"]
            previous_hash = entry["current_hash"]
            expected_version += 1

        # Step 5: Merkle instance root
        computed_root = _merkle_root(sorted(ledger_hashes))
        if computed_root != instance_root:
            return VerificationResult(
                False,
                "Instance Merkle root mismatch — ledger may be incomplete or reordered"
            )

        return VerificationResult(
            valid=True,
            reason="Proof verified successfully",
            final_state=state,
            instance_id=instance.get("instance_id")
        )

    except KeyError as e:
        return VerificationResult(False, f"Proof package missing field: {e}")
    except Exception as e:
        return VerificationResult(False, f"Verification error: {e}")


def verify_file(path: str) -> VerificationResult:
    """Load a proof.json from disk and verify it."""
    try:
        with open(path, "r") as f:
            package = json.load(f)
        return verify_package(package)
    except FileNotFoundError:
        return VerificationResult(False, f"File not found: {path}")
    except json.JSONDecodeError as e:
        return VerificationResult(False, f"Invalid JSON: {e}")