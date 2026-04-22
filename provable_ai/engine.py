import json
import hashlib
from datetime import datetime

from .storage import SQLiteStorage
from .signer import Signer


class Engine:

    SCHEMA_VERSION = "1.0"

    def __init__(self, db_path="provable_ai.db"):
        self.storage = SQLiteStorage(db_path)
        self.signer = Signer()

    # ============================================================
    # INTERNAL
    # ============================================================

    def _canonical(self, obj: dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def _verify_protocol_integrity(self, protocol_row):
        spec = json.loads(protocol_row["spec_json"])
        if self._hash(self._canonical(spec)) != protocol_row["protocol_hash"]:
            raise Exception("Protocol tampered")
        return spec

    # ============================================================
    # MERKLE TREE
    # ============================================================

    def _merkle_root(self, hashes):
        if not hashes:
            return None

        layer = hashes[:]

        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else left
                next_layer.append(self._hash(left + right))
            layer = next_layer

        return layer[0]

    # ============================================================
    # PROTOCOL
    # ============================================================

    def compile(self, spec: dict):

        protocol_hash = self._hash(self._canonical(spec))

        if not self.storage.get_protocol_by_hash(protocol_hash):
            self.storage.register_protocol(protocol_hash, spec)

        return {
            "protocol_hash": protocol_hash,
            "proof_hash": protocol_hash,
            "grammar_version": "0.1",
            "compiler_version": "0.1"
        }

    # ============================================================
    # INSTANCE
    # ============================================================

    def create_instance(self, instance_id: str):

        protocol = self.storage.get_latest_protocol()
        if not protocol:
            raise Exception("No protocol compiled")

        if self.storage.get_instance(instance_id):
            raise Exception("Instance already exists")

        self.storage.create_instance(
            instance_id,
            protocol["protocol_hash"],
            protocol["initial_state"]
        )

        return {
            "instance_id": instance_id,
            "state": protocol["initial_state"]
        }

    # ============================================================
    # TRANSITION
    # ============================================================

    def transition(
        self,
        instance_id: str,
        to_state: str,
        actor: str,
        input_hash: str,
        output_hash: str,
        model_version: str,
        agent_version: str,
        policy_version: str,
        metadata_json: str
    ):

        required = [
            input_hash,
            output_hash,
            model_version,
            agent_version,
            policy_version,
            metadata_json
        ]

        if any(v is None or v == "" for v in required):
            raise Exception("AI Execution Envelope incomplete")

        # Governance
        if not self.storage.is_model_approved(model_version):
            raise Exception("Model version not approved")

        if not self.storage.is_agent_approved(agent_version):
            raise Exception("Agent version not approved")

        if not self.storage.is_policy_active(policy_version):
            raise Exception("Policy version not active")

        instance = self.storage.get_instance(instance_id)
        if not instance:
            raise Exception("Instance not found")

        if instance["frozen"] == 1:
            raise Exception("Instance is frozen.")

        protocol_row = self.storage.get_protocol_by_hash(instance["protocol_hash"])
        spec = self._verify_protocol_integrity(protocol_row)

        current_state = instance["current_state"]
        version = instance["version"]

        if not any(
            t["from_state"] == current_state and t["to_state"] == to_state
            for t in spec["transitions"]
        ):
            raise Exception("Invalid transition")

        ledger = self.storage.get_ledger(instance_id)
        previous_hash = ledger[-1]["current_hash"] if ledger else None

        timestamp = datetime.utcnow().isoformat()

        payload = {
            "previous_hash": previous_hash,
            "protocol_hash": instance["protocol_hash"],
            "instance_id": instance_id,
            "from_state": current_state,
            "to_state": to_state,
            "actor": actor,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "model_version": model_version,
            "agent_version": agent_version,
            "policy_version": policy_version,
            "metadata_json": metadata_json,
            "schema_version": self.SCHEMA_VERSION,
            "version": version + 1,
            "timestamp": timestamp,
        }

        current_hash = self._hash(self._canonical(payload))
        signature = self.signer.sign(payload)

        self.storage.insert_ledger_entry({
            **payload,
            "current_hash": current_hash,
            "signature": signature
        })

        self.storage.update_instance_state(
            instance_id,
            to_state,
            version + 1
        )

        return {
            "new_state": to_state,
            "version": version + 1,
            "ledger_hash": current_hash
        }

    # ============================================================
    # REPLAY
    # ============================================================

    def replay(self, instance_id: str):

        instance = self.storage.get_instance(instance_id)
        if not instance:
            raise Exception("Instance not found")

        protocol_row = self.storage.get_protocol_by_hash(instance["protocol_hash"])
        spec = self._verify_protocol_integrity(protocol_row)

        ledger = self.storage.get_ledger(instance_id)

        state = spec["initial_state"]
        previous_hash = None
        expected_version = 1

        for entry in ledger:

            if entry["schema_version"] != self.SCHEMA_VERSION:
                return {"valid": False, "reason": "schema mismatch"}

            if entry["version"] != expected_version:
                return {"valid": False, "reason": "version mismatch"}

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

            rebuilt_hash = self._hash(self._canonical(payload))

            if rebuilt_hash != entry["current_hash"]:
                return {"valid": False, "reason": "hash mismatch"}

            if not self.signer.verify(payload, entry["signature"]):
                return {"valid": False, "reason": "signature invalid"}

            state = entry["to_state"]
            previous_hash = entry["current_hash"]
            expected_version += 1

        return {"valid": True, "final_state": state}

    # ============================================================
    # INSTANCE ROOT
    # ============================================================

    def _compute_instance_root(self, instance_id: str):

        ledger = self.storage.get_ledger(instance_id)
        if not ledger:
            return None

        hashes = [e["current_hash"] for e in ledger]
        hashes.sort()

        return self._merkle_root(hashes)

    # ============================================================
    # SYSTEM ROOT
    # ============================================================

    def compute_system_root(self):

        roots = []

        for inst in self.storage.list_instances():
            r = self._compute_instance_root(inst["instance_id"])
            if r:
                roots.append(r)

        if not roots:
            return None

        roots.sort()

        return self._merkle_root(roots)

    # ============================================================
    # DRIFT COMPARE
    # ============================================================

    def compare_system_root(self, external_root: str):

        current = self.compute_system_root()

        return {
            "match": current == external_root,
            "current_root": current,
            "external_root": external_root
        }

    # ============================================================
    # PROOF EXPORT (FREEZE)
    # ============================================================

    def export_proof(self, instance_id: str):

        replay = self.replay(instance_id)
        if not replay["valid"]:
            return replay

        instance = self.storage.get_instance(instance_id)
        ledger = self.storage.get_ledger(instance_id)

        proof = {
            "instance": instance,
            "protocol": json.loads(
                self.storage.get_protocol_by_hash(
                    instance["protocol_hash"]
                )["spec_json"]
            ),
            "ledger": ledger,
            "instance_root": self._compute_instance_root(instance_id)
        }

        signature = self.signer.sign(proof)

        self.storage.freeze_instance(instance_id)

        return {
            "valid": True,
            "type": "provable-ai-proof-package",
            "public_key": self.signer.public_key(),
            "proof": proof,
            "signature": signature
        }

    # ============================================================
    # BLOCKCHAIN ANCHOR
    # ============================================================

    def export_blockchain_anchor(self):

        system_root = self.compute_system_root()
        if not system_root:
            return {"valid": False, "reason": "No instances"}

        anchor_payload = {
            "version": "1.0",
            "timestamp": datetime.utcnow().isoformat(),
            "system_root": system_root
        }

        signature = self.signer.sign(anchor_payload)

        return {
            "valid": True,
            "blockchain_anchor": {
                "type": "provable-ai-blockchain-anchor",
                "public_key": self.signer.public_key(),
                "anchor": anchor_payload,
                "signature": signature
            }
        }