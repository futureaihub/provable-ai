from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import hashlib

from provable_ai.engine import Engine


# ============================================================
# APP INIT
# ============================================================

app = FastAPI(title="Provable AI Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = Engine("provable_ai.db")


# ============================================================
# MODELS
# ============================================================

class CompileRequest(BaseModel):
    source: str


class CreateInstanceRequest(BaseModel):
    instance_id: str


class TransitionRequest(BaseModel):
    target_state: str
    actor: str
    input_hash: str
    output_hash: str
    model_version: str
    agent_version: str
    policy_version: str
    metadata_json: str


# ============================================================
# IDENTITY
# ============================================================

@app.get("/identity")
def identity():
    return {
        "service": "Provable AI Execution Engine",
        "version": "1.0"
    }


# ============================================================
# PROTOCOL
# ============================================================

@app.post("/compile")
def compile_protocol(req: CompileRequest):
    try:
        spec = json.loads(req.source)
        return {
            "determinism_certificate": engine.compile(spec)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/protocol/graph")
def get_protocol_graph():
    protocol = engine.storage.get_latest_protocol()
    if not protocol:
        raise HTTPException(status_code=404, detail="No protocol compiled")
    return protocol


# ============================================================
# INSTANCES
# ============================================================

@app.post("/instances")
def create_instance(req: CreateInstanceRequest):
    try:
        return engine.create_instance(req.instance_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/instances")
def list_instances():
    return engine.storage.list_instances()


@app.get("/instances/{instance_id}")
def get_instance(instance_id: str):
    inst = engine.storage.get_instance(instance_id)
    if not inst:
        raise HTTPException(status_code=404, detail="Instance not found")
    return inst


@app.post("/instances/{instance_id}/transition")
def transition(instance_id: str, req: TransitionRequest):
    try:
        return engine.transition(
            instance_id=instance_id,
            to_state=req.target_state,
            actor=req.actor,
            input_hash=req.input_hash,
            output_hash=req.output_hash,
            model_version=req.model_version,
            agent_version=req.agent_version,
            policy_version=req.policy_version,
            metadata_json=req.metadata_json
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================
# LEDGER
# ============================================================

@app.get("/ledger/{instance_id}")
def get_ledger(instance_id: str):
    return engine.storage.get_ledger(instance_id)


@app.get("/ledger/{instance_id}/replay")
def replay(instance_id: str):
    return engine.replay(instance_id)


@app.get("/ledger/{instance_id}/export")
def export(instance_id: str):
    return engine.export_proof(instance_id)


@app.get("/ledger/{instance_id}/dump")
def dump(instance_id: str):

    instance = engine.storage.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")

    protocol_row = engine.storage.get_protocol_by_hash(
        instance["protocol_hash"]
    )
    if not protocol_row:
        raise HTTPException(status_code=404, detail="Protocol not found")

    ledger = engine.storage.get_ledger(instance_id)

    return {
        "public_key": engine.signer.public_key(),
        "instance": instance,
        "protocol": protocol_row,
        "ledger": ledger
    }


# ============================================================
# SYSTEM ROOT / BLOCKCHAIN
# ============================================================

@app.get("/system/root")
def system_root():
    return {
        "system_root": engine.compute_system_root()
    }


@app.get("/system/blockchain-anchor")
def blockchain_anchor():
    return engine.export_blockchain_anchor()


# ============================================================
# DRIFT DETECTION API (Layer 4)
# ============================================================

@app.get("/system/drift/compare")
def compare_system_root(external_root: str = Query(...)):
    return engine.compare_system_root(external_root)


@app.get("/instance/{instance_id}/drift/compare")
def compare_instance_root(
    instance_id: str,
    external_root: str = Query(...)
):
    return engine.compare_instance_root(instance_id, external_root)


# ============================================================
# EXTERNAL VERIFY ENDPOINT
# ============================================================

@app.post("/external/verify-proof")
def external_verify(proof_package: dict):

    try:

        if proof_package.get("type") != "provable-ai-proof-package":
            return {"valid": False, "reason": "Invalid proof type"}

        public_key = proof_package["public_key"]
        proof = proof_package["proof"]
        signature = proof_package["signature"]

        from nacl.signing import VerifyKey
        from nacl.encoding import HexEncoder

        verify_key = VerifyKey(public_key, encoder=HexEncoder)

        canonical_proof = json.dumps(
            proof,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

        try:
            verify_key.verify(canonical_proof, bytes.fromhex(signature))
        except Exception:
            return {"valid": False, "reason": "Signature invalid"}

        protocol = proof["protocol"]

        computed_protocol_hash = hashlib.sha256(
            json.dumps(
                protocol,
                sort_keys=True,
                separators=(",", ":")
            ).encode()
        ).hexdigest()

        if computed_protocol_hash != proof["instance"]["protocol_hash"]:
            return {"valid": False, "reason": "Protocol hash mismatch"}

        ledger = proof["ledger"]
        state = protocol["initial_state"]
        previous_hash = None
        expected_version = 1

        for entry in ledger:

            if entry["version"] != expected_version:
                return {"valid": False, "reason": "Version mismatch"}

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
                "schema_version": entry.get("schema_version", "1.0"),
                "version": entry["version"],
                "timestamp": entry["timestamp"],
            }

            rebuilt_hash = hashlib.sha256(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":")
                ).encode()
            ).hexdigest()

            if rebuilt_hash != entry["current_hash"]:
                return {"valid": False, "reason": "Ledger hash mismatch"}

            if not any(
                t["from_state"] == state and
                t["to_state"] == entry["to_state"]
                for t in protocol["transitions"]
            ):
                return {"valid": False, "reason": "Invalid transition"}

            state = entry["to_state"]
            previous_hash = entry["current_hash"]
            expected_version += 1

        return {
            "valid": True,
            "instance_id": proof["instance"]["instance_id"],
            "final_state": state
        }

    except Exception as e:
        return {"valid": False, "reason": str(e)}