import json
import hashlib
import sys
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder


SCHEMA_VERSION = "1.0"


# ============================================================
# Helpers
# ============================================================

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256(data: str):
    return hashlib.sha256(data.encode()).hexdigest()


def merkle_root(hashes):

    if not hashes:
        return None

    layer = hashes[:]

    while len(layer) > 1:

        next_layer = []

        for i in range(0, len(layer), 2):

            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left

            next_layer.append(
                sha256(left + right)
            )

        layer = next_layer

    return layer[0]


# ============================================================
# Verification Logic
# ============================================================

def verify_proof(path):

    with open(path, "r") as f:
        package = json.load(f)

    if package.get("type") != "provable-ai-proof-package":
        return False, "Invalid proof type", None

    public_key = package["public_key"]
    proof = package["proof"]
    signature = package["signature"]

    verify_key = VerifyKey(public_key, encoder=HexEncoder)

    # -------------------------
    # Signature verification
    # -------------------------

    try:
        verify_key.verify(
            canonical(proof).encode(),
            bytes.fromhex(signature)
        )
    except Exception:
        return False, "Signature invalid", None

    # -------------------------
    # Protocol integrity
    # -------------------------

    protocol = proof["protocol"]

    protocol_hash = sha256(canonical(protocol))

    if protocol_hash != proof["instance"]["protocol_hash"]:
        return False, "Protocol hash mismatch", None

    # -------------------------
    # Strict replay
    # -------------------------

    state = protocol["initial_state"]
    previous_hash = None
    expected_version = 1

    ledger_hashes = []

    for entry in proof["ledger"]:

        if entry["schema_version"] != SCHEMA_VERSION:
            return False, "Schema version mismatch", None

        if entry["version"] != expected_version:
            return False, "Version mismatch", None

        payload = {
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
            "schema_version": entry["schema_version"],
            "version": entry["version"],
            "timestamp": entry["timestamp"],
        }

        rebuilt_hash = sha256(
            canonical(payload)
        )

        if rebuilt_hash != entry["current_hash"]:
            return False, "Ledger hash mismatch", None

        # Verify ledger entry signature
        try:
            verify_key.verify(
                canonical(payload).encode(),
                bytes.fromhex(entry["signature"])
            )
        except Exception:
            return False, "Ledger signature invalid", None

        # Transition validity
        if not any(
            t["from_state"] == state and
            t["to_state"] == entry["to_state"]
            for t in protocol["transitions"]
        ):
            return False, "Invalid transition", None

        ledger_hashes.append(entry["current_hash"])

        state = entry["to_state"]
        previous_hash = entry["current_hash"]
        expected_version += 1

    # -------------------------
    # Merkle instance root
    # -------------------------

    computed_root = merkle_root(
        sorted(ledger_hashes)
    )

    if computed_root != proof["instance_root"]:
        return False, "Instance root mismatch", None

    return True, "Proof verified successfully", state


# ============================================================
# CLI Entry
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python offline_verify.py proof.json")
        sys.exit(1)

    valid, message, final_state = verify_proof(sys.argv[1])

    if valid:

        print("VALID:", message)

        if final_state:
            print("Final state:", final_state)

        sys.exit(0)

    else:

        print("INVALID:", message)
        sys.exit(1)