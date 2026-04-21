
import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from provable_ai.engine import Engine

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("zorynex.server")

# ============================================================
# CONFIG
# ============================================================

_raw_origins = os.getenv("ZORYNEX_ALLOWED_ORIGINS", "http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

_raw_keys = os.getenv("ZORYNEX_API_KEYS", "").strip()
VALID_API_KEYS = set(k.strip() for k in _raw_keys.split(",") if k.strip())

DISABLE_AUTH = os.getenv("ZORYNEX_DISABLE_AUTH", "").lower() == "true"
RATE_LIMIT = os.getenv("ZORYNEX_RATE_LIMIT", "60")

# ============================================================
# APP INIT
# ============================================================

limiter = Limiter(key_func=get_remote_address, default_limits=[f"{RATE_LIMIT}/minute"])

app = FastAPI(
    title="Zorynex Provable AI",
    description="Cryptographic proof infrastructure for AI decision governance.",
    version="1.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = Engine(os.getenv("ZORYNEX_DB_PATH", "zorynex.db"))

# ============================================================
# API KEY AUTHENTICATION
# ============================================================

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """
    Validates API key from X-API-Key header.

    Production: set ZORYNEX_API_KEYS=key1,key2,key3
    Local dev:  set ZORYNEX_DISABLE_AUTH=true

    Returns the key string used as identity in audit logs.
    """
    if DISABLE_AUTH:
        return "dev-no-auth"

    if not VALID_API_KEYS:
        raise HTTPException(
            status_code=503,
            detail=(
                "Server misconfigured: ZORYNEX_API_KEYS env var is not set. "
                "Set ZORYNEX_DISABLE_AUTH=true for local dev."
            )
        )

    if not api_key or api_key not in VALID_API_KEYS:
        logger.warning("Rejected request - invalid or missing API key")
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Provide X-API-Key header."
        )

    return api_key


# ============================================================
# AUDIT LOGGING
# ============================================================

def _audit(
    request: Request,
    api_key: str,
    action: str,
    resource: Optional[str] = None,
    result: str = "ok"
):
    ip = request.client.host if request.client else "unknown"
    ts = datetime.now(timezone.utc).isoformat()
    masked_key = (api_key[:8] + "...") if len(api_key) > 8 else api_key
    entry = {
        "timestamp": ts,
        "api_key": masked_key,
        "ip": ip,
        "action": action,
        "resource": resource,
        "result": result,
        "method": request.method,
        "path": str(request.url.path),
    }
    try:
        engine.storage.insert_audit_log(entry)
    except Exception:
        pass  # never let audit failure break a request
    logger.info(
        f"AUDIT | {ts} | key={masked_key} | ip={ip} | "
        f"action={action} | resource={resource} | result={result}"
    )


# ============================================================
# REQUEST MODELS
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

class ApproveModelRequest(BaseModel):
    model_version: str

class ApproveAgentRequest(BaseModel):
    agent_version: str

class ApprovePolicyRequest(BaseModel):
    policy_version: str
    active: bool = True


# ============================================================
# HEALTH — no auth, required by load balancers and monitoring
# ============================================================

@app.get("/health")
@limiter.limit("120/minute")
def health(request: Request):
    from provable_ai.storage import _USE_POSTGRES
    return {
        "status": "ok",
        "service": "Zorynex Provable AI",
        "version": "1.0.0",
        "storage_backend": "postgresql" if _USE_POSTGRES else "sqlite",
        "auth_enabled": not DISABLE_AUTH,
        "public_key": engine.signer.public_key(),
    }

@app.get("/identity")
def identity():
    return {"service": "Zorynex Provable AI Execution Engine", "version": "1.0.0"}


# ============================================================
# PROTOCOL
# ============================================================

@app.post("/compile")
@limiter.limit(f"{RATE_LIMIT}/minute")
def compile_protocol(
    request: Request,
    req: CompileRequest,
    api_key: str = Depends(verify_api_key)
):
    try:
        spec = json.loads(req.source)
        result = engine.compile(spec)
        _audit(request, api_key, "compile_protocol",
               resource=result["protocol_hash"])
        return {"determinism_certificate": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/protocol/graph")
@limiter.limit(f"{RATE_LIMIT}/minute")
def get_protocol_graph(request: Request, api_key: str = Depends(verify_api_key)):
    protocol = engine.storage.get_latest_protocol()
    if not protocol:
        raise HTTPException(status_code=404, detail="No protocol compiled")
    return protocol


# ============================================================
# INSTANCES
# ============================================================

@app.post("/instances")
@limiter.limit(f"{RATE_LIMIT}/minute")
def create_instance(
    request: Request,
    req: CreateInstanceRequest,
    api_key: str = Depends(verify_api_key)
):
    try:
        result = engine.create_instance(req.instance_id)
        _audit(request, api_key, "create_instance", resource=req.instance_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/instances")
@limiter.limit(f"{RATE_LIMIT}/minute")
def list_instances(request: Request, api_key: str = Depends(verify_api_key)):
    return engine.storage.list_instances()

@app.get("/instances/{instance_id}")
@limiter.limit(f"{RATE_LIMIT}/minute")
def get_instance(
    request: Request,
    instance_id: str,
    api_key: str = Depends(verify_api_key)
):
    inst = engine.storage.get_instance(instance_id)
    if not inst:
        raise HTTPException(status_code=404, detail="Instance not found")
    return inst

@app.post("/instances/{instance_id}/transition")
@limiter.limit(f"{RATE_LIMIT}/minute")
def transition(
    request: Request,
    instance_id: str,
    req: TransitionRequest,
    api_key: str = Depends(verify_api_key)
):
    try:
        result = engine.transition(
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
        _audit(request, api_key, "transition",
               resource=f"{instance_id}:{req.target_state}")
        return result
    except Exception as e:
        _audit(request, api_key, "transition",
               resource=instance_id, result=f"error:{str(e)[:80]}")
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================
# LEDGER
# ============================================================

@app.get("/ledger/{instance_id}")
@limiter.limit(f"{RATE_LIMIT}/minute")
def get_ledger(
    request: Request,
    instance_id: str,
    api_key: str = Depends(verify_api_key)
):
    return engine.storage.get_ledger(instance_id)

@app.get("/ledger/{instance_id}/count")
@limiter.limit(f"{RATE_LIMIT}/minute")
def ledger_count(
    request: Request,
    instance_id: str,
    api_key: str = Depends(verify_api_key)
):
    ledger = engine.storage.get_ledger(instance_id)
    return {"instance_id": instance_id, "entry_count": len(ledger)}

@app.get("/ledger/{instance_id}/replay")
@limiter.limit(f"{RATE_LIMIT}/minute")
def replay(
    request: Request,
    instance_id: str,
    api_key: str = Depends(verify_api_key)
):
    result = engine.replay(instance_id)
    _audit(request, api_key, "replay", resource=instance_id,
           result="valid" if result.get("valid") else "invalid")
    return result

@app.get("/ledger/{instance_id}/export")
@limiter.limit("30/minute")
def export(
    request: Request,
    instance_id: str,
    api_key: str = Depends(verify_api_key)
):
    result = engine.export_proof(instance_id)
    _audit(request, api_key, "export_proof", resource=instance_id,
           result="valid" if result.get("valid") else "invalid")
    return result

@app.get("/ledger/{instance_id}/dump")
@limiter.limit(f"{RATE_LIMIT}/minute")
def dump(
    request: Request,
    instance_id: str,
    api_key: str = Depends(verify_api_key)
):
    instance = engine.storage.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    protocol_row = engine.storage.get_protocol_by_hash(instance["protocol_hash"])
    if not protocol_row:
        raise HTTPException(status_code=404, detail="Protocol not found")
    ledger = engine.storage.get_ledger(instance_id)
    _audit(request, api_key, "dump", resource=instance_id)
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
@limiter.limit(f"{RATE_LIMIT}/minute")
def system_root(request: Request, api_key: str = Depends(verify_api_key)):
    return {"system_root": engine.compute_system_root()}

@app.get("/system/blockchain-anchor")
@limiter.limit(f"{RATE_LIMIT}/minute")
def blockchain_anchor(request: Request, api_key: str = Depends(verify_api_key)):
    return engine.export_blockchain_anchor()


# ============================================================
# DRIFT DETECTION
# ============================================================

@app.get("/system/drift/compare")
@limiter.limit(f"{RATE_LIMIT}/minute")
def compare_system_root(
    request: Request,
    external_root: str = Query(...),
    api_key: str = Depends(verify_api_key)
):
    result = engine.compare_system_root(external_root)
    _audit(request, api_key, "drift_system",
           result="match" if result["match"] else "mismatch")
    return result

@app.get("/instance/{instance_id}/drift/compare")
@limiter.limit(f"{RATE_LIMIT}/minute")
def compare_instance_root(
    request: Request,
    instance_id: str,
    external_root: str = Query(...),
    api_key: str = Depends(verify_api_key)
):
    try:
        result = engine.compare_instance_root(instance_id, external_root)
        _audit(request, api_key, "drift_instance", resource=instance_id,
               result="match" if result["match"] else "mismatch")
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================
# EXTERNAL VERIFY
# ============================================================

@app.post("/external/verify-proof")
@limiter.limit("30/minute")
def external_verify(
    request: Request,
    proof_package: dict,
    api_key: str = Depends(verify_api_key)
):
    from tools.verify_core import verify_package
    result = verify_package(proof_package)
    instance_id = (proof_package.get("proof") or {}).get("instance", {}).get("instance_id")
    _audit(request, api_key, "external_verify", resource=instance_id,
           result="valid" if result.valid else f"invalid:{result.reason[:60]}")
    return result.to_dict()


# ============================================================
# GOVERNANCE MANAGEMENT
# ============================================================

@app.post("/governance/models")
@limiter.limit("30/minute")
def approve_model(
    request: Request,
    req: ApproveModelRequest,
    api_key: str = Depends(verify_api_key)
):
    try:
        engine.storage.approve_model(req.model_version)
        _audit(request, api_key, "approve_model", resource=req.model_version)
        return {"approved": req.model_version}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/governance/agents")
@limiter.limit("30/minute")
def approve_agent(
    request: Request,
    req: ApproveAgentRequest,
    api_key: str = Depends(verify_api_key)
):
    try:
        engine.storage.approve_agent(req.agent_version)
        _audit(request, api_key, "approve_agent", resource=req.agent_version)
        return {"approved": req.agent_version}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/governance/policies")
@limiter.limit("30/minute")
def approve_policy(
    request: Request,
    req: ApprovePolicyRequest,
    api_key: str = Depends(verify_api_key)
):
    try:
        engine.storage.approve_policy(req.policy_version, req.active)
        _audit(request, api_key, "approve_policy",
               resource=f"{req.policy_version}:active={req.active}")
        return {"approved": req.policy_version, "active": req.active}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/governance/status")
@limiter.limit(f"{RATE_LIMIT}/minute")
def governance_status(request: Request, api_key: str = Depends(verify_api_key)):
    return engine.storage.get_governance_status()


# ============================================================
# AUDIT LOG ACCESS
# ============================================================

@app.get("/audit/logs")
@limiter.limit("20/minute")
def get_audit_logs(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    api_key: str = Depends(verify_api_key)
):
    """
    Returns recent audit log entries.
    Answers the auditor question: who accessed what proof and when?
    """
    logs = engine.storage.get_audit_logs(limit=limit)
    return {"logs": logs, "count": len(logs)}
