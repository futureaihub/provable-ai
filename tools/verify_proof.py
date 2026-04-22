import json
import hashlib
import sys


def canonical(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":")
    )


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def verify_proof(proof_data, dump_data):

    proof = proof_data["proof"]
    ledger = dump_data["ledger"]
    instance = dump_data["instance"]
    protocol_row = dump_data["protocol"]

    # ------------------------------------------------------------
    # 1️⃣ Verify protocol hash integrity
    # ------------------------------------------------------------
    spec = json.loads(protocol_row["spec_json"])
    computed_protocol_hash = sha256(canonical(spec))

    if computed_protocol_hash != protocol_row["protocol_hash"]:
        return False, "Protocol hash mismatch"

    # ------------------------------------------------------------
    # 2️⃣ Verify hash chain + version continuity
    # ------------------------------------------------------------
    previous_hash = None
    expected_version = 1
    state = spec["initial_state"]

    for entry in ledger:

        if entry["version"] != expected_version:
            return False, "Version continuity failure"

        payload = {
            "previous_hash": previous_hash,
            "protocol_hash": entry["protocol_hash"],
            "instance_id": entry["instance_id"],
            "from_state": entry["from_state"],
            "to_state": entry["to_state"],
            "actor": entry["actor"],
            "version": entry["version"],
            "timestamp": entry["timestamp"],
        }

        computed_hash = sha256(canonical(payload))

        if computed_hash != entry["current_hash"]:
            return False, "Hash chain mismatch"

        # Validate state transition
        valid = any(
            t["from_state"] == state and
            t["to_state"] == entry["to_state"]
            for t in spec["transitions"]
        )

        if not valid:
            return False, "Invalid state transition"

        state = entry["to_state"]
        previous_hash = entry["current_hash"]
        expected_version += 1

    # ------------------------------------------------------------
    # 3️⃣ Verify instance version alignment
    # ------------------------------------------------------------
    if instance["version"] != expected_version - 1:
        return False, "Instance version mismatch"

    # ------------------------------------------------------------
    # 4️⃣ Verify deterministic root anchor
    # ------------------------------------------------------------
    concatenated = "".join(e["current_hash"] for e in ledger)
    computed_root = sha256(concatenated)

    if computed_root != proof["root_hash"]:
        return False, "Root hash mismatch"

    # ------------------------------------------------------------
    # 5️⃣ Verify final state
    # ------------------------------------------------------------
    if state != proof["final_state"]:
        return False, "Final state mismatch"

    # ------------------------------------------------------------
    # 6️⃣ Verify protocol hash in proof
    # ------------------------------------------------------------
    if proof["protocol_hash"] != protocol_row["protocol_hash"]:
        return False, "Proof protocol hash mismatch"

    return True, "Proof verified successfully"


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: python verify_proof.py proof.json dump.json")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        proof_data = json.load(f)

    with open(sys.argv[2], "r") as f:
        dump_data = json.load(f)

    valid, message = verify_proof(proof_data, dump_data)

    if valid:
        print("VERIFIED ✓")
        print(message)
        sys.exit(0)
    else:
        print("FAILED ✗")
        print(message)
        sys.exit(1)