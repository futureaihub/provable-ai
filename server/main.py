"""
Zorynex FastAPI Server
======================
Minimal orchestration layer. No business logic here.
All cryptographic work happens in the provable_ai modules.

Endpoints:
    POST  /decision         Record an AI decision → proof artifact
    GET   /proof/{id}       Get proof by instance_id (latest or by sequence)
    GET   /chain/{id}       Get full proof chain for instance
    POST  /verify           Verify a submitted proof.json
    GET   /health           Liveness check
    GET   /ready            Readiness check (DB + signer available)
    GET   /metrics          Prometheus metrics
    GET   /system/root      System integrity root hash

Security rules:
    ✗ API never returns private key
    ✗ API never stores raw inputs (inputs_hash only)
    ✓ API orchestrates — all logic in provable_ai modules
    ✓ Every response includes trace_id for log correlation
    ✓ RBAC enforced on all endpoints
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from provable_ai.canonical import canonical_hash
from provable_ai.engine import GovernanceEngine
from provable_ai.exceptions import (
    ChainBroken,
    DuplicateSequenceId,
    GovernanceError,
    LedgerError,
    SequenceGap,
    SigningError,
    VerificationError,
    ZorynexError,
)
from provable_ai.schema import DeterminismMode
from provable_ai.signer import get_signer
from provable_ai.storage import SQLiteStorage
from provable_ai.verifier import (
    compute_system_root,
    verify_proof_full,
)
from provable_ai.audit_log import get_audit_log, compute_audit_leaf
from provable_ai.audit_anchor import get_anchor_store, anchor_chain_hash
from provable_ai.audit_keyregistry import get_key_registry, auto_register_signer, KEY_REGISTRY_GENESIS
from server.webhook import verify_webhook_request, sign_webhook, _nonce_store, nonce_store_size
from server.auth import AuthContext, require_role as _phase2_require_role, _API_KEYS
from provable_ai.drift_detector import (
    DriftDetector, get_drift_detector, take_snapshot,
    snapshot_to_dict, drift_result_to_dict,
)
from provable_ai.audit_batch import compute_inclusion_proof, verify_inclusion_proof, MerkleInclusionProof
from provable_ai.audit_batch import build_batch_export, verify_batch_signature, merkle_root, merkle_root_from_entries
from provable_ai.audit_compliance import build_compliance_pack
from provable_ai.audit_report import generate_audit_report

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)
logger = logging.getLogger("zorynex.server")


def _log(level: str, message: str, **fields) -> None:
    entry = {
        "level": level,
        "message": message,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    entry.update(fields)
    getattr(logger, level.lower(), logger.info)(json.dumps(entry))


def _admin_audit(action: str, request: Request, **fields) -> None:
    """
    Emit a structured admin audit trail event.
    Tracks platform admin actions separately from AI decision events.
    These events answer: who changed governance? who exported proof X?
    who rotated a key? who had a failed login?
    """
    api_key = request.headers.get("X-API-Key", "unknown")
    # Mask key — show first 8 chars only
    actor = api_key[:8] + "..." if len(api_key) > 8 else api_key
    entry = {
        "level":      "audit",
        "event_type": "admin_audit",
        "action":     action,
        "actor":      actor,
        "tenant_id":  getattr(request.state, "tenant_id", "default"),
        "trace_id":   getattr(request.state, "trace_id",  ""),
        "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip":         request.client.host if request.client else "unknown",
        **fields,
    }
    logger.info(json.dumps(entry))


# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Zorynex Provable AI",
    version="2.0.0",
    description="""
## Zorynex — Provable AI Infrastructure

> **Testing locally?** Click **Authorize** (🔒 top right) and enter:
>
> | Field | Value |
> |-------|-------|
> | `X-API-Key` | `dev-key` |
> | `X-Tenant-Id` | `default` *(or leave blank — not required in dev mode)* |
>
> **`X-Tenant-Id` is optional in local development** (`ZORYNEX_REQUIRE_TENANT` defaults to `false`).
> Set `ZORYNEX_REQUIRE_TENANT=true` in production to enforce tenant isolation.
>
> Running with custom keys? The key is the part before `:` in `ZORYNEX_API_KEYS`.
> Example: `ZORYNEX_API_KEYS=mykey:admin` → enter `mykey` as `X-API-Key`.

Every AI decision becomes a **cryptographic proof artifact** — tamper-evident,
chain-linked, independently verifiable with zero server access.

---

### Authentication

All endpoints require two headers. Click **Authorize** to set them.

| Header | Description | Example |
|--------|-------------|---------|
| `X-API-Key` | Your API key. Role determines access level (admin / auditor / system). | `prod-key-abc123` |
| `X-Tenant-Id` | Tenant namespace for data isolation. Use `default` for single-tenant. | `default` |

**Roles:**
- `admin` — full access including governance configuration
- `system` — record decisions, create instances
- `auditor` — read-only access to proofs, audit log, compliance exports

---

### Developer lifecycle

```
POST /protocol/compile   → define your workflow states
POST /governance/model   → approve model versions
POST /governance/agent   → approve agent versions
POST /governance/policy  → approve policy versions
POST /instance/create    → create a workflow instance
POST /decision           → record a cryptographic proof
GET  /proof/export/{id}  → export verifiable proof package
GET  /audit/chain-verify → verify chain integrity
```

---

### Verification (offline — no server needed)

**Browser** — for auditors, drag-and-drop, no code needed:
```
http://127.0.0.1:8000/verify-ui
```

**CLI:**
```bash
python verify/verify_package.py proof_package.json
python verify/verify_batch.py   batch_export.json
```
""",
    docs_url="/docs",
    redoc_url=None,  # We serve a custom ReDoc with pinned CDN — see /redoc route below
    openapi_tags=[
        {
            "name": "quickstart",
            "description": (
                "🚀 **New here? Start with `POST /demo/bootstrap`.** "
                "You'll have your first verifiable AI decision proof in under 2 minutes — no configuration needed.\n\n"
                "Then: `POST /decision` → `GET /proof/export/{id}?inline=true` → `POST /verify-package`\n\n"
                "→ **[Interactive guide with curl commands](/quickstart)** — copy-paste ready"
            ),
        },
        {
            "name": "configure",
            "description": (
                "⚙️ **`[Intermediate]`** Production setup.\n\n"
                "Define the governance rules that control which AI models, agents, "
                "and policies are authorised to write decisions. "
                "Every proof is permanently linked to the governance configuration active at signing time — "
                "changing approvals does not alter existing proofs."
            ),
        },
        {
            "name": "create",
            "description": (
                "⚙️ **`[Intermediate]`** Workflow instances.\n\n"
                "An instance tracks the state machine for one entity — a loan application, "
                "fraud review, credit decision — through its full lifecycle. "
                "Each state transition becomes an immutable proof entry."
            ),
        },
        {
            "name": "execute",
            "description": (
                "⚙️ **`[Intermediate]`** Full decision control.\n\n"
                "Advanced `POST /decision` usage: explicit governance fields, "
                "feature contributions, threshold values, determinism modes, "
                "and external call hashing. "
                "For simple usage, see the **quickstart** section above."
            ),
        },
        {
            "name": "verify",
            "description": (
                "🔍 **`[Auditor]`** Proof retrieval and verification.\n\n"
                "Retrieve individual proofs, browse the full decision chain, "
                "and verify signature + chain integrity. "
                "Verification is cryptographically self-contained — "
                "no server trust required.\n\n"
                "→ **[Web Verifier UI](/verify-ui)** — drag-and-drop, no API key needed"
            ),
        },
        {
            "name": "audit",
            "description": (
                "🛡️ **`[Advanced]`** Audit log, compliance exports, and anchoring.\n\n"
                "Structured evidence for regulators: "
                "SR 11-7 / EU AI Act / CFPB compliance packs, "
                "batch Merkle exports, RFC 3161 external timestamps, "
                "key registry, and drift detection. "
                "For compliance teams, auditors, and legal review."
            ),
        },
        {
            "name": "monitor",
            "description": (
                "🩺 **`[DevOps]`** Infrastructure health and observability.\n\n"
                "Liveness and readiness probes, Prometheus metrics, "
                "system root hash, drift detection, and snapshots. "
                "For SREs and infrastructure teams running Zorynex in production."
            ),
        },
        {
            "name": "webhook",
            "description": (
                "🔗 **`[Advanced]`** Inbound webhook receiver.\n\n"
                "HMAC-SHA256 signature verification and nonce-based replay protection "
                "for receiving proof events from external systems."
            ),
        },
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── State ─────────────────────────────────────────────────────────────────────

_storage: SQLiteStorage | None = None
_engine: GovernanceEngine | None = None
_start = time.time()


@app.on_event("startup")
async def _startup_banner() -> None:
    """Print diagnostic banner on startup — makes first-run debugging immediate."""
    from server.auth import _API_KEYS as _active_keys

    env_name   = os.environ.get("ZORYNEX_ENV", "development")
    db_path    = os.environ.get("ZORYNEX_DB_PATH", "provable_ai.db")
    port       = os.environ.get("ZORYNEX_PORT", "8000")
    base_url   = f"http://127.0.0.1:{port}"

    # DB + migration status
    try:
        _storage_check = get_storage()
        db_status      = "connected"
        backend        = "SQLite" if "sqlite" in str(type(_storage_check)).lower() else "PostgreSQL"
    except Exception as e:
        db_status = f"ERROR: {e}"
        backend   = "unknown"

    # Signing key identity
    try:
        key_id = get_signer().get_key_id()
    except Exception as e:
        key_id = f"ERROR: {e}"

    print()
    print("=" * 62)
    print("  Zorynex Provable AI  ·  Cryptographic proof infrastructure")
    print("=" * 62)
    print(f"  Environment:      {env_name}")
    print(f"  Database:         {backend}  ({db_path})")
    print(f"  Schema migration: complete")
    print(f"  Signing key:      {key_id}")
    print(f"  Tenant mode:      {'enforced' if _REQUIRE_TENANT else 'optional (dev)'}")
    print()
    print(f"  Swagger UI →  {base_url}/docs")
    print(f"  ReDoc      →  {base_url}/redoc")
    print(f"  Quickstart →  {base_url}/quickstart")
    print(f"  Verify UI  →  {base_url}/verify-ui")
    print(f"  Dashboard  →  {base_url}/dashboard")
    print()
    print("  ── Authorize in Swagger " + "─" * 31)
    for key, role in _active_keys.items():
        print(f"  X-API-Key:    {key:<32} [{role}]")
    print(f"  X-Tenant-Id:  default")
    print()
    if env_name == "development":
        print("  Custom keys:")
        print('  export ZORYNEX_API_KEYS="mykey:admin,readkey:auditor"')
        print()
    print("  Verify exported proofs:")
    print("    python verify/verify_package.py <proof.json>")
    print("=" * 62)
    print()

# Simple in-memory metrics counters
_metrics = {
    "zorynex_decisions_total":             0,
    "zorynex_verification_requests_total": 0,
    "zorynex_signing_errors_total":        0,
    "zorynex_governance_rejections_total": 0,
    "zorynex_rate_limit_hits_total":       0,
    "zorynex_webhook_received_total":      0,
    "zorynex_webhook_replay_blocked":      0,
    "zorynex_auth_failures_total":         0,
}


def get_storage() -> SQLiteStorage:
    global _storage
    if _storage is None:
        db_path = os.environ.get("ZORYNEX_DB_PATH", "provable_ai.db")
        _storage = SQLiteStorage(db_path=db_path)
        # Seed governance from environment
        _seed_governance(_storage)
    return _storage


def get_engine() -> GovernanceEngine:
    global _engine
    if _engine is None:
        storage = get_storage()
        signer = get_signer()
        _engine = GovernanceEngine(storage=storage, signer=signer)
    return _engine


def _seed_governance(storage: SQLiteStorage) -> None:
    """
    Seed approved governance from environment variables.
    In production, manage governance via a separate admin API.
    """
    models = os.environ.get("ZORYNEX_APPROVED_MODELS", "").split(",")
    agents = os.environ.get("ZORYNEX_APPROVED_AGENTS", "").split(",")
    policies = os.environ.get("ZORYNEX_APPROVED_POLICIES", "").split(",")
    for m in models:
        if m.strip():
            storage.add_approved_model(m.strip())
    for a in agents:
        if a.strip():
            storage.add_approved_agent(a.strip())
    for p in policies:
        if p.strip():
            storage.add_approved_policy(p.strip())


# ── Auth ──────────────────────────────────────────────────────────────────────

API_KEY_HEADER = APIKeyHeader(name="X-API-Key",   auto_error=False)
ROLE_HEADER   = APIKeyHeader(name="X-Role",       auto_error=False)
TENANT_HEADER = APIKeyHeader(name="X-Tenant-Id",  auto_error=False)


def _build_openapi_schema():
    """
    Override FastAPI's OpenAPI schema to produce a clean two-scheme Authorize dialog.

    Problem without this:
        FastAPI auto-generates "APIKeyHeader" from Security(_API_KEY_HEADER).
        Our manual code adds "ApiKeyAuth" + "TenantIdAuth".
        Result: THREE schemes in the dialog, endpoint security points to "APIKeyHeader",
        user fills in "ApiKeyAuth" but Swagger sends nothing → 401.

    Fix:
        1. Generate schema normally (gets all three schemes).
        2. Remove the auto-generated "APIKeyHeader" scheme.
        3. Rewrite every per-endpoint security requirement that references
           "APIKeyHeader" to reference "ApiKeyAuth" instead.
        4. Set global security = [{ApiKeyAuth: [], TenantIdAuth: []}].
        Result: ONE Authorize dialog, TWO fields, works on every endpoint.
    """
    from fastapi.openapi.utils import get_openapi
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title       = app.title,
        version     = app.version,
        description = app.description,
        tags        = app.openapi_tags,
        routes      = app.routes,
    )

    # Step 1: Add our two named schemes
    schemes = schema.setdefault("components", {}).setdefault("securitySchemes", {})
    schemes["ApiKeyAuth"] = {
        "type":        "apiKey",
        "in":          "header",
        "name":        "X-API-Key",
        "description": (
            "Your Zorynex API key. "
            "Role is determined by the key: **admin** | **system** | **auditor**. "
            "Default dev key: `dev-key` (role: admin)."
        ),
    }
    schemes["TenantIdAuth"] = {
        "type":        "apiKey",
        "in":          "header",
        "name":        "X-Tenant-Id",
        "description": (
            "Tenant namespace for data isolation. "
            "Use `default` for single-tenant / local development. "
            "Optional when `ZORYNEX_REQUIRE_TENANT=false` (the default)."
        ),
    }

    # Step 2: Remove the auto-generated "APIKeyHeader" scheme entirely
    schemes.pop("APIKeyHeader", None)

    # Step 3: Rewrite per-endpoint security refs from APIKeyHeader → ApiKeyAuth
    for path_item in schema.get("paths", {}).values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            op_security = operation.get("security", [])
            new_security = []
            for req in op_security:
                if "APIKeyHeader" in req:
                    # Replace with our two-scheme requirement
                    new_security.append({"ApiKeyAuth": [], "TenantIdAuth": []})
                else:
                    new_security.append(req)
            if new_security:
                operation["security"] = new_security

    # Step 4: Global security — every endpoint requires both headers
    schema["security"] = [{"ApiKeyAuth": [], "TenantIdAuth": []}]

    app.openapi_schema = schema
    return schema


app.openapi = _build_openapi_schema

_VALID_ROLES = {"admin", "auditor", "system"}

# In production: load from DB or secrets manager
# For Phase 1: from environment variable
_API_KEYS = {
    k: v for k, v in [
        pair.split(":", 1) for pair in
        os.environ.get("ZORYNEX_API_KEYS", "dev-key:admin").split(",")
        if ":" in pair
    ]
}


def _get_role(api_key: str | None) -> str | None:
    if not api_key:
        return None
    return _API_KEYS.get(api_key)


def require_role(*allowed_roles: str):
    """Delegate to Phase 2 auth.py require_role — has correct required_roles/your_role structure."""
    return _phase2_require_role(*allowed_roles)


# ── Middleware ────────────────────────────────────────────────────────────────

# Read once at startup
_REQUIRE_TENANT = os.environ.get("ZORYNEX_REQUIRE_TENANT", "false").lower() == "true"
_TENANT_EXEMPT_PATHS = {"/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/verify-ui", "/quickstart"}


@app.middleware("http")
async def trace_middleware(request: Request, call_next):
    trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
    request.state.trace_id = trace_id

    # Tenant enforcement
    raw_tenant = request.headers.get("X-Tenant-Id", "").strip()
    path = request.url.path

    if _REQUIRE_TENANT and not raw_tenant and path not in _TENANT_EXEMPT_PATHS:
        return JSONResponse(
            status_code=400,
            content={
                "error": "MISSING_TENANT_ID",
                "message": (
                    "X-Tenant-Id header is required. "
                    "Use 'default' for single-tenant deployments. "
                    "Silent defaulting is disabled to prevent cross-tenant data leaks."
                ),
                "trace_id": trace_id,
            },
        )

    tenant_id = raw_tenant or "default"
    request.state.tenant_id = tenant_id

    start = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)
    response.headers["X-Trace-Id"] = trace_id
    response.headers["X-Tenant-Id"] = tenant_id
    response.headers["X-Duration-Ms"] = str(duration_ms)
    return response


# ── Request / Response models ─────────────────────────────────────────────────

# ── Request / Response models ─────────────────────────────────────────────────

class DecisionRequest(BaseModel):
    model_config = {
        "protected_namespaces": (),   # suppress "model_" namespace warning
        "json_schema_extra": {
            "example": {
                "instance_id": "loan-application-9284",
                "from_state":  "pending",
                "to_state":    "under_review",
                "raw_inputs":  {"credit_score": "742"},
                "_hint": "Simple mode — governance auto-resolved. Add model_version/agent_version/policy_version for full control."
            }
        }
    }
    instance_id:           str
    from_state:            str
    to_state:              str
    # ── Governance fields — optional in simple mode ──
    # If omitted, the first approved model/agent/policy is used automatically.
    model_version:         str | None           = None
    agent_version:         str | None           = None
    policy_version:        str | None           = None
    reason_code:           str | None           = None
    policy_rule:           str | None           = None
    # ── Input/output data ──
    raw_inputs:            dict[str, Any]        = Field(default_factory=dict)
    feature_contributions: list[dict[str, str]] = Field(default_factory=list)
    threshold_used:        str | None           = None
    metadata:              dict[str, Any]        = Field(default_factory=dict)
    determinism_mode:      str                  = "strict_deterministic"
    random_seed:           str | None           = None
    external_calls:        list[dict] | None    = None


class DecisionResponse(BaseModel):
    proof_id:     str
    sequence_id:  int
    instance_id:  str
    current_hash: str
    proof_url:    str
    trace_id:     str


class ProtocolCompileRequest(BaseModel):
    """
    Workflow protocol specification.
    states:        all valid states in this workflow
    initial_state: the state every new instance starts in
    transitions:   allowed (from_state, to_state) pairs — empty list = open workflow
    """
    model_config = {
        "json_schema_extra": {
            "example": {
                "states":       ["received", "under_review", "approved", "rejected", "funded"],
                "initial_state":"received",
                "transitions":  [
                    {"from_state": "received",     "to_state": "under_review"},
                    {"from_state": "under_review", "to_state": "approved"},
                    {"from_state": "under_review", "to_state": "rejected"},
                    {"from_state": "approved",     "to_state": "funded"},
                ],
                "metadata": {"workflow": "loan-decisioning-v2"},
            }
        }
    }
    states:        list[str]
    initial_state: str
    transitions:   list[dict[str, str]] = Field(default_factory=list)
    metadata:      dict[str, Any]        = Field(default_factory=dict)


class ProtocolCompileResponse(BaseModel):
    protocol_hash: str
    states:        list[str]
    initial_state: str
    message:       str


class InstanceCreateRequest(BaseModel):
    model_config = {
        "json_schema_extra": {
            "example": {
                "instance_id":   "loan-application-9284",
                "protocol_hash": "leave blank to use most recently compiled protocol",
            }
        }
    }
    instance_id:   str
    protocol_hash: str | None = None


class InstanceCreateResponse(BaseModel):
    instance_id:   str
    initial_state: str
    protocol_hash: str
    message:       str


class GovernanceApproveRequest(BaseModel):
    model_config = {
        "json_schema_extra": {
            "example": {
                "name":    "credit_model",
                "version": "v3.1",
            }
        }
    }
    name:    str = Field(..., description="Human-readable name, e.g. 'credit_model'")
    version: str = Field(..., description="Version string, e.g. 'v3.1'")


class GovernanceApproveResponse(BaseModel):
    name:     str
    version:  str
    approved: bool
    message:  str


# ── Endpoints ─────────────────────────────────────────────────────────────────



# ── Configure ─────────────────────────────────────────────────────────────────

@app.get("/auth/test", tags=["monitor"])
async def auth_test(
    request: Request,
    role: str = Depends(require_role("admin", "auditor", "system")),
):
    """
    Test your authentication headers. Returns what the server received.

    Use this to verify:
    - Your X-API-Key is being sent and recognised
    - Your X-Tenant-Id is being received
    - Your role matches what you expect

    Access: any valid role
    """
    from server.auth import _API_KEYS as _active_keys
    tenant_id = getattr(request.state, "tenant_id", "default")
    api_key   = request.headers.get("X-API-Key", "")
    return {
        "status":        "authenticated",
        "received": {
            "X-API-Key":    api_key if api_key else "(not received)",
            "X-Tenant-Id":  request.headers.get("X-Tenant-Id", "(not sent — defaulted)"),
        },
        "resolved": {
            "role":      _active_keys.get(api_key, "(unknown key)"),
            "tenant_id": tenant_id,
        },
        "active_keys": [
            {"key": k, "role": v} for k, v in _active_keys.items()
        ],
        "hint": (
            "If 'role' shows '(unknown key)', your X-API-Key value "
            "does not match any active key. Check ZORYNEX_API_KEYS env var."
        ),
    }


@app.post("/protocol/compile", tags=["configure"], openapi_extra={
    "requestBody": {"content": {"application/json": {"example": {
        "states": ["received", "under_review", "approved", "rejected"],
        "initial_state": "received",
        "transitions": [
            {"from_state": "received",     "to_state": "under_review"},
            {"from_state": "under_review", "to_state": "approved"},
            {"from_state": "under_review", "to_state": "rejected"}
        ]
    }}}}
})
async def compile_protocol(
    request: Request,
    body: ProtocolCompileRequest,
    role: str = Depends(require_role("admin")),
):
    """
    **`[Intermediate]`** Define a workflow protocol.

    Specifies the valid states and transitions for your AI decision process.
    Call once per workflow type — identical specs produce identical hashes
    (content-addressed, safe to call repeatedly).

    The `protocol_hash` links every instance and proof to its governing workflow.

    Access: admin
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    spec = {
        "states":        body.states,
        "initial_state": body.initial_state,
        "transitions":   body.transitions,
        "metadata":      body.metadata,
    }
    try:
        result        = get_engine().compile(spec)
        protocol_hash = result["protocol_hash"]
        _log("info", "protocol_compiled", trace_id=trace_id,
             tenant_id=tenant_id, protocol_hash=protocol_hash)
        return ProtocolCompileResponse(
            protocol_hash = protocol_hash,
            states        = body.states,
            initial_state = body.initial_state,
            message       = f"Protocol compiled. hash={protocol_hash[:16]}...",
        )
    except ZorynexError as e:
        raise HTTPException(status_code=400, detail={"error": e.code, "message": e.message})
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "COMPILE_ERROR", "message": str(e)})


# ── Create ─────────────────────────────────────────────────────────────────────

@app.post("/instance/create", tags=["create"], openapi_extra={
    "requestBody": {"content": {"application/json": {"example": {
        "instance_id": "loan-9284"
    }}}}
})
async def create_instance(
    request: Request,
    body: InstanceCreateRequest,
    role: str = Depends(require_role("admin", "system")),
):
    """
    Create a workflow instance. An instance tracks the state machine for one
    entity (a loan, a fraud review, a credit decision, etc.).

    Omit protocol_hash to use the most recently compiled protocol.

    Access: admin, system
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    engine    = get_engine()
    try:
        if body.protocol_hash:
            stored = engine.storage.get_protocol(body.protocol_hash)
            if not stored:
                raise HTTPException(status_code=404, detail={
                    "error":   "PROTOCOL_NOT_FOUND",
                    "message": f"Protocol {body.protocol_hash[:16]}... not found. "
                               "Compile it first via POST /protocol/compile.",
                })
            engine._active_protocol_hash = body.protocol_hash
            if body.protocol_hash not in engine._protocols:
                engine._protocols[body.protocol_hash] = stored
        result        = engine.create_instance(body.instance_id)
        protocol_hash = engine._active_protocol_hash or ""
        _log("info", "instance_created", trace_id=trace_id,
             tenant_id=tenant_id, instance_id=body.instance_id, state=result["state"])
        return InstanceCreateResponse(
            instance_id   = body.instance_id,
            initial_state = result["state"],
            protocol_hash = protocol_hash,
            message       = f"Instance '{body.instance_id}' created in state '{result['state']}'.",
        )
    except HTTPException:
        raise
    except ValueError as e:
        msg = str(e)
        code = "INSTANCE_ALREADY_EXISTS" if "already exists" in msg else                "PROTOCOL_REQUIRED"       if "No protocol"   in msg else                "INSTANCE_ERROR"
        raise HTTPException(status_code=409, detail={
            "error":   code,
            "message": msg,
            "hint":    "Use a unique instance_id per workflow entity (loan, claim, decision)."
            if "already exists" in msg else
            "Compile a protocol first via POST /protocol/compile.",
        })
    except ZorynexError as e:
        raise HTTPException(status_code=400, detail={"error": e.code, "message": e.message})


# ── Governance ─────────────────────────────────────────────────────────────────

@app.post("/governance/model", tags=["configure"], openapi_extra={
    "requestBody": {"content": {"application/json": {"example": {
        "name": "credit_model", "version": "v3.1"
    }}}}
})
async def approve_model(
    request: Request,
    body: GovernanceApproveRequest,
    role: str = Depends(require_role("admin")),
):
    """
    **`[Intermediate]`** Approve a model version for use in decisions.

    Only approved model versions can write to the proof chain.
    Unapproved versions are rejected with `UNAUTHORIZED_MODEL_VERSION`.

    Access: admin
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    try:
        storage  = get_storage()
        existing = [m["version"] for m in storage.get_approved_models()]
        already  = body.version in existing
        storage.add_approved_model(body.version, model_name=body.name)
        _admin_audit("governance.model_approved", request, model_version=model_version)
        _log("info", "model_approved", trace_id=trace_id,
             tenant_id=tenant_id, model_name=body.name, model_version=body.version,
             already_approved=already)
        return GovernanceApproveResponse(
            name=body.name, version=body.version, approved=True,
            message=(
                f"Model '{body.name}:{body.version}' was already approved — updated name."
                if already else
                f"Model '{body.name}:{body.version}' approved."
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "GOVERNANCE_ERROR", "message": str(e)})


@app.post("/governance/agent", tags=["configure"], openapi_extra={
    "requestBody": {"content": {"application/json": {"example": {
        "name": "underwriter", "version": "v1.0"
    }}}}
})
async def approve_agent(
    request: Request,
    body: GovernanceApproveRequest,
    role: str = Depends(require_role("admin")),
):
    """
    **`[Intermediate]`** Approve an agent version for use in decisions.

    Access: admin
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    try:
        get_storage().add_approved_agent(body.version, agent_name=body.name)
        _admin_audit("governance.agent_approved", request)
        _log("info", "agent_approved", trace_id=trace_id,
             tenant_id=tenant_id, agent_name=body.name, agent_version=body.version)
        return GovernanceApproveResponse(
            name=body.name, version=body.version, approved=True,
            message=f"Agent '{body.name}:{body.version}' approved.",
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "GOVERNANCE_ERROR", "message": str(e)})


@app.post("/governance/policy", tags=["configure"], openapi_extra={
    "requestBody": {"content": {"application/json": {"example": {
        "name": "credit_policy", "version": "v2"
    }}}}
})
async def approve_policy(
    request: Request,
    body: GovernanceApproveRequest,
    role: str = Depends(require_role("admin")),
):
    """
    **`[Intermediate]`** Approve a policy version for use in decisions.

    Access: admin
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    try:
        get_storage().add_approved_policy(body.version, policy_name=body.name)
        _admin_audit("governance.policy_approved", request)
        _log("info", "policy_approved", trace_id=trace_id,
             tenant_id=tenant_id, policy_name=body.name, policy_version=body.version)
        return GovernanceApproveResponse(
            name=body.name, version=body.version, approved=True,
            message=f"Policy '{body.name}:{body.version}' approved.",
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "GOVERNANCE_ERROR", "message": str(e)})


@app.get("/governance/status", tags=["configure"])
async def governance_status(
    request: Request,
    role: str = Depends(require_role("admin", "auditor")),
):
    """
    Return the current governance configuration — all approved models, agents,
    policies, and the active signing key ID.
    Access: admin, auditor
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    storage   = get_storage()
    try:
        # get_approved_models/agents/policies now return [{name, version}] dicts
        models   = storage.get_approved_models()
        agents   = storage.get_approved_agents()
        policies = storage.get_approved_policies()

        return {
            "approved_models":   [
                {"model_name": m["name"], "model_version": m["version"]} for m in models
            ],
            "approved_agents":   [
                {"agent_name": a["name"], "agent_version": a["version"]} for a in agents
            ],
            "approved_policies": [
                {"policy_name": p["name"], "policy_version": p["version"]} for p in policies
            ],
            "counts": {
                "models":   len(models),
                "agents":   len(agents),
                "policies": len(policies),
            },
            "signing_key_id":    get_signer().get_key_id(),
            "tenant_id":         tenant_id,
            "trace_id":          trace_id,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "GOVERNANCE_STATUS_ERROR", "message": str(e)})


# ── Export (developer-facing alias) ───────────────────────────────────────────

@app.get("/proof/export/{instance_id}", tags=["quickstart"])
async def export_proof_package(
    request: Request,
    instance_id: str,
    inline: bool = Query(
        False,
        description=(
            "**Set to `true` to get the full verifiable proof package.**\n\n"
            "- `false` (default) — returns metadata + download URL only\n"
            "- `true` — returns complete self-contained package for `/verify-package`, "
            "CLI verifier, and `/verify-ui` drag-and-drop"
        ),
    ),
    role: str = Depends(require_role("admin", "auditor", "system")),
):
    """
    **`[Beginner]`** Export a complete, verifiable proof package.

    ⚠️ **You must set `inline = true`** to get the verifiable package.

    - `inline = false` (default) — returns metadata + download URL only. Not verifiable.
    - `inline = true` — returns the full self-contained package. This is what you paste into
      `POST /verify-package`, drag into `/verify-ui`, or save as `proof.json` for the CLI.

    The package is **self-contained** — verifiable with zero server access:
    - [/verify-ui](/verify-ui) — browser drag-and-drop, no API key needed
    - `python verify/verify_package.py proof.json` — CLI
    - `POST /verify-package` — API

    The response also includes `verify_ui_url` — click it directly instead of typing `/verify-ui` manually.

    Access: admin, auditor, system
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    engine    = get_engine()
    storage   = get_storage()
    chain     = storage.get_ledger_chain(instance_id)
    if not chain:
        raise HTTPException(status_code=404, detail={
            "error":   "INSTANCE_NOT_FOUND",
            "message": f"No decisions recorded for instance '{instance_id}'.",
            "hint":    "Record decisions via POST /decision before exporting a proof package.",
        })
    try:
        import json as _json
        if instance_id not in engine._instances:
            last = chain[-1]
            pj   = last.get("proof_json", "{}")
            if pj and pj != "{}":
                pd = _json.loads(pj)
                engine._instances[instance_id] = {
                    "state":         pd["decision"]["to_state"],
                    "protocol_hash": pd["governance"].get("policy_version", ""),
                }
        package    = engine.export_proof(instance_id)
        proof_count= len(package.get("proof", {}).get("ledger", []))
        _admin_audit("proof.exported", request, instance_id=instance_id)
        _log("info", "proof_exported", trace_id=trace_id, tenant_id=tenant_id,
             instance_id=instance_id, proof_count=proof_count)

        if inline:
            return package

        # Default: metadata only — safe for large chains
        return {
            "instance_id":    instance_id,
            "proof_count":    proof_count,
            "package_hash":   package.get("package_hash", ""),
            "instance_root":  package.get("proof", {}).get("instance_root", ""),
            "signature":      package.get("signature", ""),
            "public_key":     package.get("public_key", ""),
            "valid":          package.get("valid", True),
            "full_package_url": f"/proof/export/{instance_id}?inline=true",
            "verify_ui_url":  f"/verify-ui/{instance_id}",
            "verify_cli":     f"python verify/verify_package.py <proof.json>",
            "verify_hint":    "Download full package via ?inline=true, then drag into /verify-ui or run the CLI verifier.",
            "trace_id":       trace_id,
        }
    except ZorynexError as e:
        raise HTTPException(status_code=400, detail={"error": e.code, "message": e.message})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "EXPORT_ERROR", "message": str(e)})


# ── Execute ─────────────────────────────────────────────────────────────────────

@app.post("/decision", response_model=DecisionResponse, tags=["quickstart"], openapi_extra={
    "requestBody": {"content": {"application/json": {
        "examples": {
            "simple_mode": {
                "summary": "Simple mode — governance auto-resolves (4 fields minimum)",
                "value": {
                    "instance_id": "loan-9284",
                    "from_state":  "received",
                    "to_state":    "under_review",
                    "raw_inputs":  {"credit_score": "742", "debt_to_income": "0.28"}
                }
            },
            "full_mode": {
                "summary": "Full mode — all governance fields explicit (recommended for production)",
                "value": {
                    "instance_id":   "loan-9284",
                    "from_state":    "received",
                    "to_state":      "under_review",
                    "model_version": "credit-model-v3.1",
                    "agent_version": "underwriter-v1.0",
                    "policy_version":"credit-policy-v2",
                    "reason_code":   "SCORE_ABOVE_THRESHOLD",
                    "policy_rule":   "credit-policy-v2.rule_7",
                    "raw_inputs":    {"credit_score": "742", "debt_to_income": "0.28"},
                    "feature_contributions": [
                        {"feature": "credit_score",   "contribution": "0.65"},
                        {"feature": "debt_to_income", "contribution": "-0.12"}
                    ],
                    "threshold_used": "700",
                    "metadata":       {"channel": "web", "bureau": "experian"}
                }
            }
        }
    }}}
})
async def record_decision(
    request: Request,
    body: DecisionRequest,
    role: str = Depends(require_role("admin", "system")),
):
    """
    **`[Beginner]`** Record an AI decision as a cryptographic proof.

    **Simple mode** (governance auto-resolved — just 4 fields):
    ```json
    { "instance_id": "loan-001", "from_state": "pending",
      "to_state": "approved", "raw_inputs": {"credit_score": "742"} }
    ```

    **Full mode** — include `model_version`, `agent_version`, `policy_version`,
    `reason_code`, `policy_rule` for explicit governance control.

    Rules:
    - `raw_inputs` are SHA-256 hashed — the raw values are never stored
    - Returns `proof_id` + `current_hash` — the permanent record

    Access: admin, system
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    engine = get_engine()
    engine.trace_id = trace_id
    t0 = time.time()

    try:
        det_mode = DeterminismMode(body.determinism_mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid determinism_mode '{body.determinism_mode}'. "
                   f"Valid: strict_deterministic, replay_with_seed, replay_with_recorded_io"
        )

    try:
        # ── Auto-resolve governance if not provided (simple mode) ────────────
        _storage     = get_storage()
        _models      = _storage.get_approved_models()
        _agents      = _storage.get_approved_agents()
        _policies    = _storage.get_approved_policies()

        _model_version  = body.model_version  or (_models[0]["version"]  if _models  else None)
        _agent_version  = body.agent_version  or (_agents[0]["version"]  if _agents  else None)
        _policy_version = body.policy_version or (_policies[0]["version"] if _policies else None)

        if not _model_version:
            raise HTTPException(status_code=422, detail={
                "error": "NO_APPROVED_MODEL",
                "message": "model_version not provided and no approved models found.",
                "hint": "Approve a model via POST /governance/model first.",
            })
        if not _agent_version:
            raise HTTPException(status_code=422, detail={
                "error": "NO_APPROVED_AGENT",
                "message": "agent_version not provided and no approved agents found.",
                "hint": "Approve an agent via POST /governance/agent first.",
            })
        if not _policy_version:
            raise HTTPException(status_code=422, detail={
                "error": "NO_APPROVED_POLICY",
                "message": "policy_version not provided and no approved policies found.",
                "hint": "Approve a policy via POST /governance/policy first.",
            })

        _reason_code = body.reason_code or "DECISION"
        _policy_rule = body.policy_rule or f"{_policy_version}.default"

        proof = engine.record_decision(
            instance_id=body.instance_id,
            from_state=body.from_state,
            to_state=body.to_state,
            model_version=_model_version,
            agent_version=_agent_version,
            policy_version=_policy_version,
            reason_code=_reason_code,
            policy_rule=_policy_rule,
            raw_inputs=body.raw_inputs,
            feature_contributions=body.feature_contributions,
            threshold_used=body.threshold_used,
            metadata=body.metadata,
            determinism_mode=det_mode,
            random_seed=body.random_seed,
            external_calls=body.external_calls,
        )
        _metrics["zorynex_decisions_total"] += 1
        duration_ms = round((time.time() - t0) * 1000, 2)

        _log("info", "decision_recorded",
             trace_id=trace_id,
             tenant_id=tenant_id,
             instance_id=body.instance_id,
             sequence_id=proof.ledger.sequence_id,
             key_id=proof.signature.key_id,
             duration_ms=duration_ms)

        return DecisionResponse(
            proof_id=proof.proof_id,
            sequence_id=proof.ledger.sequence_id,
            instance_id=proof.instance_id,
            current_hash=proof.ledger.current_hash,
            proof_url=f"/proof/{proof.instance_id}",
            trace_id=trace_id,
        )

    except GovernanceError as e:
        _metrics["zorynex_governance_rejections_total"] += 1
        _log("warning", "governance_rejection",
             trace_id=trace_id,
             tenant_id=tenant_id,
             instance_id=body.instance_id,
             error=e.message)
        raise HTTPException(status_code=422, detail={
            "error": e.code,
            "message": e.message,
            "context": e.context,
        })

    except SigningError as e:
        _metrics["zorynex_signing_errors_total"] += 1
        _log("error", "signing_error",
             trace_id=trace_id,
             tenant_id=tenant_id,
             instance_id=body.instance_id,
             error=e.message)
        raise HTTPException(status_code=503, detail={
            "error": e.code,
            "message": e.message,
        })

    except (ChainBroken, SequenceGap, DuplicateSequenceId) as e:
        _log("error", "chain_error",
             trace_id=trace_id,
             tenant_id=tenant_id,
             instance_id=body.instance_id,
             error=e.message)
        raise HTTPException(status_code=409, detail={
            "error": e.code,
            "message": e.message,
        })

    except ZorynexError as e:
        _log("error", "zorynex_error",
             trace_id=trace_id,
             error=e.message)
        raise HTTPException(status_code=400, detail={
            "error": e.code,
            "message": e.message,
        })


@app.get("/proof/{instance_id}", tags=["verify"])
async def get_proof(
    request: Request,
    instance_id: str,
    sequence_id: int | None = None,
    verbose:     bool       = False,
    role: str = Depends(require_role("admin", "auditor", "system")),
):
    """
    Get a proof by instance_id. Default: slim summary. Add ?verbose=true for full payload.

    **Default response** (fast, lightweight):
    ```json
    {
      "proof_id": "...", "sequence_id": 12,
      "current_hash": "...", "from_state": "pending", "to_state": "approved",
      "timestamp": "...", "signature_key_id": "...", "verify_url": "/verify"
    }
    ```

    **?verbose=true** — full canonical proof JSON for offline verification.

    Access: admin, auditor, system
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    storage  = get_storage()

    entry = storage.get_ledger_entry(instance_id, sequence_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error":   "PROOF_NOT_FOUND",
                "message": f"No proof found for instance '{instance_id}'"
                           + (f" at sequence_id={sequence_id}" if sequence_id else " (no decisions recorded yet)"),
                "hint":    "Record a decision first via POST /decision, then retrieve it here.",
            }
        )

    proof_id = _compute_proof_id(entry["current_hash"], entry["sequence_id"])

    if verbose:
        proof_data = {}
        if entry.get("proof_json") and entry["proof_json"] != "{}":
            try:
                proof_data = json.loads(entry["proof_json"])
            except Exception:
                pass
        return JSONResponse(content={
            "proof_id":    proof_id,
            "instance_id": instance_id,
            "sequence_id": entry["sequence_id"],
            "proof":       proof_data,
            "trace_id":    trace_id,
        })

    # Slim summary (default)
    return JSONResponse(content={
        "proof_id":        proof_id,
        "instance_id":     instance_id,
        "sequence_id":     entry["sequence_id"],
        "from_state":      entry.get("from_state", ""),
        "to_state":        entry.get("to_state",   ""),
        "current_hash":    entry["current_hash"],
        "previous_hash":   entry["previous_hash"],
        "timestamp":       entry.get("timestamp",  ""),
        "model_version":   entry.get("model_version", ""),
        "policy_version":  entry.get("policy_version", ""),
        "signature_key_id":entry.get("key_id",     ""),
        "chain_position":  f"{entry['sequence_id']} of {storage.get_max_sequence_id(instance_id)}",
        "verify_url":      "/verify",
        "full_proof_url":  f"/proof/{instance_id}?verbose=true",
        "trace_id":        trace_id,
    })


@app.get("/chain/{instance_id}", tags=["verify"])
async def get_chain(
    request: Request,
    instance_id: str,
    full: bool = False,
    role: str = Depends(require_role("admin", "auditor", "system")),
):
    """
    Get the proof chain for an instance.

    **Default** — lightweight summary (safe for 10,000-decision chains):
    ```json
    {
      "chain_length": 150, "current_state": "funded",
      "latest_hash": "...", "first_timestamp": "...", "last_timestamp": "...",
      "export_url": "/proof/export/{instance_id}"
    }
    ```

    **?full=true** — all entries with hashes. Use for small chains or audits.
    For large chains, use `GET /proof/export/{instance_id}` instead.

    Access: admin, auditor, system
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    storage  = get_storage()

    entries = storage.get_ledger_chain(instance_id)
    if not entries:
        raise HTTPException(
            status_code=404,
            detail={
                "error":   "CHAIN_NOT_FOUND",
                "message": f"No decision chain found for instance '{instance_id}'.",
                "hint":    "Record at least one decision via POST /decision to create a chain.",
            }
        )

    first = entries[0]
    last  = entries[-1]

    if full:
        chain = []
        for entry in entries:
            proof_data = {}
            if entry.get("proof_json") and entry["proof_json"] != "{}":
                try:
                    proof_data = json.loads(entry["proof_json"])
                except Exception:
                    pass
            chain.append({
                "sequence_id":  entry["sequence_id"],
                "proof_id":     _compute_proof_id(entry["current_hash"], entry["sequence_id"]),
                "from_state":   entry.get("from_state", ""),
                "to_state":     entry.get("to_state",   ""),
                "current_hash": entry["current_hash"],
                "timestamp":    entry.get("timestamp",  ""),
                "proof":        proof_data,
            })
        return JSONResponse(content={
            "instance_id":  instance_id,
            "chain_length": len(chain),
            "chain":        chain,
            "trace_id":     trace_id,
        })

    # Default: summary only
    return JSONResponse(content={
        "instance_id":       instance_id,
        "chain_length":      len(entries),
        "current_state":     last.get("to_state", ""),
        "initial_state":     first.get("from_state", ""),
        "latest_hash":       last["current_hash"],
        "first_timestamp":   first.get("timestamp", ""),
        "last_timestamp":    last.get("timestamp",  ""),
        "model_versions":    list({e.get("model_version","") for e in entries if e.get("model_version")}),
        "policy_versions":   list({e.get("policy_version","") for e in entries if e.get("policy_version")}),
        "chain_valid_url":   f"/audit/chain-verify",
        "export_url":        f"/proof/export/{instance_id}",
        "full_chain_url":    f"/chain/{instance_id}?full=true",
        "trace_id":          trace_id,
    })


@app.post("/verify-package", tags=["quickstart"])
async def verify_package_endpoint(
    request: Request,
    role: str = Depends(require_role("admin", "auditor", "system")),
):
    """
    **`[Auditor]`** Verify a complete exported proof package — 4 cryptographic checks.

    Submit the full package JSON (from `GET /proof/export/{id}?inline=true`).

    Checks run server-side (identical to the CLI and browser verifier):
    1. **Package structure** — type valid, ledger non-empty
    2. **Package untampered** — SHA-256 of full ledger matches `package_hash`
    3. **Chain valid** — per-proof canonical hash recomputed + linkage verified
    4. **Original signer verified** — Ed25519 over instance root verified

    Returns `verified: true/false` + per-check detail.
    HTTP 200 = all checks pass. HTTP 422 = one or more failed.

    → [Web Verifier UI](/verify-ui) — no API key needed, drag-and-drop

    Access: admin, auditor, system
    """
    import hashlib as _hashlib

    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    _metrics["zorynex_verification_requests_total"] += 1

    try:
        package = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={
            "error":   "INVALID_JSON",
            "message": "Request body must be valid JSON (the full proof package).",
            "hint":    "Export via GET /proof/export/{instance_id}?inline=true",
        })

    checks    = []
    meta: dict = {}
    all_passed = True

    # ── Check 1: Structure ──────────────────────────────────────────────────
    if package.get("type") != "provable-ai-proof-package":
        checks.append({"name": "Package structure valid", "passed": False,
                        "failure": f"Unknown type: {package.get('type')!r}"})
        all_passed = False
    else:
        proof_block = package.get("proof", {})
        ledger      = proof_block.get("ledger", [])
        if not isinstance(ledger, list) or len(ledger) == 0:
            checks.append({"name": "Package structure valid", "passed": False,
                            "failure": "proof.ledger is empty — no decisions recorded."})
            all_passed = False
        else:
            checks.append({"name": "Package structure valid", "passed": True,
                            "detail": f"{len(ledger)} proof(s) in package"})
            meta["ledger"]      = ledger
            meta["instance_id"] = proof_block.get("instance_id", "unknown")

    if not all_passed:
        return JSONResponse(status_code=422, content={
            "verified":    False,
            "checks":      checks,
            "instance_id": meta.get("instance_id"),
            "trace_id":    trace_id,
        })

    ledger = meta["ledger"]

    # ── Check 2: Package hash ───────────────────────────────────────────────
    stored_pkg_hash = package.get("package_hash", "")
    if stored_pkg_hash:
        ledger_canonical  = json.dumps(ledger, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False)
        computed_pkg_hash = _hashlib.sha256(ledger_canonical.encode()).hexdigest()
        if computed_pkg_hash == stored_pkg_hash:
            checks.append({"name": "Package untampered", "passed": True,
                            "detail": "SHA-256 of full ledger matches package_hash"})
        else:
            checks.append({"name": "Package untampered", "passed": False,
                            "failure": f"Hash mismatch — ledger modified after export. "
                                       f"stored={stored_pkg_hash[:24]}... "
                                       f"computed={computed_pkg_hash[:24]}..."})
            all_passed = False
    else:
        checks.append({"name": "Package untampered", "passed": True,
                        "detail": "No package_hash in package — skipped (older export format)"})

    # ── Check 3: Per-proof hashes + chain linkage ───────────────────────────
    from provable_ai.canonical import genesis_hash

    def _vhash(entry: dict) -> str:
        """Canonical SHA-256 — same algorithm as engine.py."""
        import hashlib as _h2
        led = entry.get("ledger", {})
        content = {
            "decision":         entry.get("decision",         {}),
            "decision_context": entry.get("decision_context", {}),
            "governance":       entry.get("governance",       {}),
            "determinism":      entry.get("determinism",      {}),
            "previous_hash":    led.get("previous_hash",      ""),
            "sequence_id":      led.get("sequence_id",        0),
        }
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        return _h2.sha256(canonical.encode()).hexdigest()

    prev_hash  = None
    seq_ids    = []
    chain_ok   = True
    chain_fail = ""

    for entry in ledger:
        led_block     = entry.get("ledger", {})
        stored_hash   = led_block.get("current_hash", "")
        previous_hash = led_block.get("previous_hash", genesis_hash())
        seq_id        = led_block.get("sequence_id", "?")
        seq_ids.append(seq_id)

        try:
            computed = _vhash(entry)
        except Exception as e:
            chain_fail = f"Could not recompute hash at seq={seq_id}: {e}"
            chain_ok   = False
            break

        if computed != stored_hash:
            chain_fail = (f"Hash mismatch at seq={seq_id}. "
                          f"stored={stored_hash[:16]}... computed={computed[:16]}...")
            chain_ok   = False
            break

        expected_prev = prev_hash if prev_hash else genesis_hash()
        if previous_hash != expected_prev:
            chain_fail = (f"Chain broken at seq={seq_id}. "
                          f"previous_hash does not match prior current_hash.")
            chain_ok   = False
            break

        prev_hash = stored_hash

    if chain_ok:
        seq_range = (f"sequence {seq_ids[0]}→{seq_ids[-1]}"
                     if len(seq_ids) > 1 else f"sequence {seq_ids[0]}")
        checks.append({"name": "Chain valid", "passed": True,
                        "detail": f"{len(ledger)} proofs, {seq_range}"})
        meta["final_state"] = ledger[-1].get("decision", {}).get("to_state", "unknown")
        meta["first_ts"]    = (ledger[0].get("ledger", {})).get("timestamp", "")
        meta["last_ts"]     = (ledger[-1].get("ledger", {})).get("timestamp", "")
        gov0 = ledger[0].get("governance", {})
        meta["model_version"]  = gov0.get("model_version",  "")
        meta["agent_version"]  = gov0.get("agent_version",  "")
        meta["policy_version"] = gov0.get("policy_version", "")
    else:
        checks.append({"name": "Chain valid", "passed": False, "failure": chain_fail})
        all_passed = False

    # ── Check 4: Ed25519 signature ──────────────────────────────────────────
    public_key   = package.get("public_key",  "")
    sig_hex      = package.get("signature",   "")
    stored_root  = package.get("proof", {}).get("instance_root", "")

    if not public_key or not sig_hex:
        checks.append({"name": "Original signer verified", "passed": False,
                        "failure": "Missing public_key or signature in package."})
        all_passed = False
    else:
        all_hashes    = "".join(e.get("ledger", {}).get("current_hash", "") for e in ledger)
        computed_root = _hashlib.sha256(all_hashes.encode()).hexdigest()

        if stored_root and computed_root != stored_root:
            checks.append({"name": "Original signer verified", "passed": False,
                            "failure": f"Instance root mismatch — contents modified after signing. "
                                       f"stored={stored_root[:16]}... "
                                       f"computed={computed_root[:16]}..."})
            all_passed = False
        else:
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(bytes.fromhex(public_key))
                vk.verify(bytes.fromhex(computed_root), bytes.fromhex(sig_hex))
                key_id = f"env-{public_key[:16]}"
                checks.append({"name": "Original signer verified", "passed": True,
                                "detail": f"Signed by {key_id} — signature mathematically valid"})
                meta["key_id"] = key_id
            except Exception as e:
                checks.append({"name": "Original signer verified", "passed": False,
                                "failure": f"Ed25519 signature invalid — package may have been re-signed or signature corrupted: {e}"})
                all_passed = False

    # ── Log + respond ───────────────────────────────────────────────────────
    _log(
        "info" if all_passed else "warning",
        "package_verification_complete",
        trace_id  = trace_id,
        tenant_id = tenant_id,
        verified  = all_passed,
        instance_id = meta.get("instance_id"),
        proof_count = len(ledger),
    )

    # ── Build human-readable failure reason ────────────────────────────────
    failure_reason = None
    if not all_passed:
        sig_passed    = any(c["name"] == "Original signer verified" and c["passed"]     for c in checks)
        tamper_failed = any(c["name"] == "Package untampered"          and not c["passed"] for c in checks)
        chain_failed  = any(c["name"] == "Chain valid"                 and not c["passed"] for c in checks)
        struct_failed = any(c["name"] == "Package structure valid"     and not c["passed"] for c in checks)

        if struct_failed:
            failure_reason = (
                "This file is not a valid Zorynex proof package. "
                "It may be corrupted, incomplete, or the wrong file type."
            )
        elif tamper_failed and sig_passed:
            failure_reason = (
                "This proof was signed by a verified key, but its contents were modified "
                "after it was exported. The original signer is confirmed — the package itself "
                "was tampered. Do not trust this artifact."
            )
        elif chain_failed and sig_passed:
            failure_reason = (
                "This proof was signed by a verified key, but the decision chain has been "
                "altered — a record was inserted, deleted, or reordered. "
                "Do not trust this artifact."
            )
        elif tamper_failed:
            failure_reason = (
                "The exported package has been modified since it was created. "
                "Do not trust this artifact."
            )
        elif chain_failed:
            failure_reason = (
                "The decision chain is broken — a record may have been altered. "
                "Do not trust this artifact."
            )
        else:
            failure_reason = "One or more cryptographic checks failed. Do not trust this artifact."

    return JSONResponse(
        status_code = 200 if all_passed else 422,
        content     = {
            "verified":      all_passed,
            "failure_reason": failure_reason,
            "instance_id":   meta.get("instance_id"),
            "final_state":   meta.get("final_state"),
            "proof_count":   len(ledger),
            "model_version": meta.get("model_version"),
            "policy_version":meta.get("policy_version"),
            "first_decision":meta.get("first_ts"),
            "last_decision": meta.get("last_ts"),
            "signing_key":   meta.get("key_id"),
            "checks":        checks,
            "trace_id":      trace_id,
        }
    )


@app.post("/verify", tags=["verify"])
async def verify_proof_endpoint(
    request: Request,
    role: str = Depends(require_role("admin", "auditor", "system")),
):
    """
    Verify a submitted proof.json.

    Submit the raw proof.json content as the request body.
    Returns full verification result including governance_recorded,
    governance_verified, and replay_result.

    This endpoint performs the same verification an auditor does offline.
    No database lookup — the proof is self-contained.

    Access: admin, auditor, system
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    _metrics["zorynex_verification_requests_total"] += 1

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    result = verify_proof_full(body)

    tenant_id = getattr(request.state, "tenant_id", "default")
    _log(
        "info" if result["valid"] else "warning",
        "verification_complete",
        trace_id=trace_id,
        tenant_id=tenant_id,
        valid=result["valid"],
        sequence_verified=result.get("sequence_verified"),
        key_id=result.get("key_id"),
    )

    # ── Audit log — every verify call recorded permanently ────────────────────
    try:
        get_audit_log().record(
            tenant_id=tenant_id,
            trace_id=trace_id,
            proof_dict=body,
            verify_result=result,
        )
    except Exception as e:
        # Audit log failure must never break the verify response
        _log("error", "audit_log_record_failed", trace_id=trace_id, error=str(e))

    return JSONResponse(
        content={**result, "trace_id": trace_id},
        status_code=200,
    )


@app.get("/health", tags=["monitor"])
async def health():
    """
    Liveness probe. Returns 200 when server is running. Access: public

    Version fields are explicitly labelled — no ambiguity:
    - **platform_version** — this API server release
    - **proof_schema_version** — the proof artifact format (zorynex-proof-v1)
    - **api_version** — the REST API version
    """
    return {
        "status":               "ok",
        "version":              "2.0.0",          # backward compatibility
        "platform_version":     "2.0.0",
        "proof_schema_version": "v1",
        "api_version":          "v2",
        "uptime_s":             round(time.time() - _start, 1),
    }


@app.get("/ready", tags=["monitor"])
async def ready():
    """
    Readiness check.
    Verifies DB connection and signer are available.
    Returns 200 if ready to accept traffic, 503 if not.
    """
    checks = {}
    ready = True

    # Check DB
    try:
        storage = get_storage()
        storage.get_ledger_count()
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"
        ready = False

    # Check signer
    try:
        signer = get_signer()
        _ = signer.get_key_id()
        checks["signer"] = "ok"
        checks["key_id"] = signer.get_key_id()
    except Exception as e:
        checks["signer"] = f"error: {e}"
        ready = False

    status_code = 200 if ready else 503
    return JSONResponse(
        content={"ready": ready, "checks": checks, "uptime_s": round(__import__("time").time() - _start, 1)},
        status_code=status_code,
    )


@app.get("/metrics", tags=["monitor"])
async def metrics(
    role: str = Depends(require_role("admin")),
):
    """
    Prometheus-format metrics.
    Access: admin only
    """
    uptime = round(time.time() - _start, 2)
    lines = [
        "# HELP zorynex_decisions_total Total AI decisions recorded",
        "# TYPE zorynex_decisions_total counter",
        f"zorynex_decisions_total {_metrics['zorynex_decisions_total']}",
        "",
        "# HELP zorynex_verification_requests_total Total verification requests",
        "# TYPE zorynex_verification_requests_total counter",
        f"zorynex_verification_requests_total {_metrics['zorynex_verification_requests_total']}",
        "",
        "# HELP zorynex_signing_errors_total Total signing errors",
        "# TYPE zorynex_signing_errors_total counter",
        f"zorynex_signing_errors_total {_metrics['zorynex_signing_errors_total']}",
        "",
        "# HELP zorynex_governance_rejections_total Total governance rejections",
        "# TYPE zorynex_governance_rejections_total counter",
        f"zorynex_governance_rejections_total {_metrics['zorynex_governance_rejections_total']}",
        "",
        "# HELP zorynex_rate_limit_hits_total Total rate limit hits",
        "# TYPE zorynex_rate_limit_hits_total counter",
        f"zorynex_rate_limit_hits_total {_metrics['zorynex_rate_limit_hits_total']}",
        "# HELP zorynex_webhook_received_total Total webhooks received",
        "# TYPE zorynex_webhook_received_total counter",
        f"zorynex_webhook_received_total {_metrics['zorynex_webhook_received_total']}",
        "# HELP zorynex_webhook_replay_blocked Total webhook replay attempts blocked",
        "# TYPE zorynex_webhook_replay_blocked counter",
        f"zorynex_webhook_replay_blocked {_metrics['zorynex_webhook_replay_blocked']}",
        "",
        "# HELP zorynex_auth_failures_total Authentication failures",
        "# TYPE zorynex_auth_failures_total counter",
        f"zorynex_auth_failures_total {_metrics['zorynex_auth_failures_total']}",
        "",
        "# HELP zorynex_nonce_store_size Active nonces in replay protection store",
        "# TYPE zorynex_nonce_store_size gauge",
        f"zorynex_nonce_store_size {nonce_store_size()}",
        "",
        "# HELP zorynex_uptime_seconds Server uptime in seconds",
        "# TYPE zorynex_uptime_seconds gauge",
        f"zorynex_uptime_seconds {uptime}",
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


@app.get("/system/root", tags=["monitor"])
async def system_root(
    role: str = Depends(require_role("admin", "auditor")),
):
    """
    Compute system root = SHA256 of all latest instance current_hashes.

    Used for:
    - Drift detection: compare root at T1 vs T2 — any change detected
    - Global integrity proof: proves the state of the entire ledger
    - Audit: "here is the state of all decisions at this moment"

    Access: admin, auditor
    """
    trace_id = str(uuid.uuid4())
    storage = get_storage()

    cur = storage.conn.cursor()
    cur.execute("""
        SELECT instance_id, current_hash FROM ledger
        WHERE sequence_id = (
            SELECT MAX(l2.sequence_id) FROM ledger l2
            WHERE l2.instance_id = ledger.instance_id
        )
        ORDER BY instance_id
    """)
    rows = cur.fetchall()

    latest_hashes = [row["current_hash"] for row in rows]
    root = compute_system_root(latest_hashes)

    return JSONResponse(content={
        "system_root": root,
        "instance_count": len(rows),
        "computed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trace_id": trace_id,
    })





@app.post("/audit/anchor", tags=["audit"])
async def audit_anchor_endpoint(
    request: Request,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """
    Write an external anchor for the current chain_hash.

    Records the current chain_hash to the anchor store (local file + stdout log).
    Call this periodically or before any compliance export.

    In production: configure ZORYNEX_ANCHOR_S3_BUCKET to also write to S3.

    Access: admin, auditor
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    chain_hash   = get_audit_log().get_latest_chain_hash(tenant_id)
    # RFC 3161 request — set ZORYNEX_TSA_URL env var to enable (default: freetsa.org)
    # Set ZORYNEX_TSA_TIMEOUT_S for network timeout control
    use_rfc3161 = os.environ.get("ZORYNEX_ANCHOR_RFC3161", "true").lower() == "true"
    record      = anchor_chain_hash(
        tenant_id=tenant_id, chain_hash=chain_hash,
        request_rfc3161=use_rfc3161,
    )

    _log("info", "chain_anchored",
         trace_id=trace_id, tenant_id=tenant_id,
         anchor_id=record.anchor_id, chain_hash=chain_hash[:16],
         backends=record.anchor_backends)

    return JSONResponse(content={
        "anchored":      True,
        "anchor_id":     record.anchor_id,
        "chain_hash":    chain_hash,
        "anchored_at":   record.anchored_at,
        "anchor_seq":    record.anchor_seq,
        "backends":      record.anchor_backends,
        "tenant_id":     tenant_id,
        "trace_id":      trace_id,
    })


@app.get("/audit/anchors", tags=["audit"])
async def audit_anchors_list_endpoint(
    request: Request,
    limit:   int = 20,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """List recent chain anchors for this tenant. Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    store   = get_anchor_store()
    anchors = store.list_anchors(tenant_id=tenant_id, limit=min(limit, 100))
    anchor_chain_ok = store.verify_anchor_chain(tenant_id=tenant_id)
    return JSONResponse(content={
        "tenant_id": tenant_id,
        "count":           len(anchors),
        "anchor_chain_valid": anchor_chain_ok["valid"],
        "anchors":           [
            {
                "anchor_id":   a.anchor_id,
                "chain_hash":  a.chain_hash,
                "anchored_at": a.anchored_at,
                "anchor_seq":  a.anchor_seq,
                "backends":    a.anchor_backends,
            }
            for a in anchors
        ],
        "trace_id":  trace_id,
    })


@app.get("/audit/keys", tags=["audit"])
async def audit_keys_endpoint(
    request: Request,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """
    List all signing keys (active and retired) with lifecycle metadata.

    Enables historical verification: auditors can confirm which key was
    active at any point in time, and verify signatures from retired keys.

    Access: admin, auditor
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    reg    = get_key_registry()
    active = reg.get_active(tenant_id="system")
    policy = reg.rotation_policy(tenant_id="system")

    return JSONResponse(content={
        "tenant_id":    tenant_id,
        "keys":         reg.to_dict(tenant_id="system"),
        "active_key_id": active.key_id if active else None,
        "rotation_policy": policy,
        "trace_id":     trace_id,
    })


@app.get("/audit/keys/chain-verify", tags=["audit"])
async def audit_keys_chain_verify_endpoint(
    request: Request,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """
    Verify the key registry hash chain for this system.

    Every key registration and rotation event is chained.
    Any modification to any key record (past or present) is detectable.

    Returns chain integrity status — expose this to auditors for full
    key lifecycle transparency.

    Access: admin, auditor
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))

    result = get_key_registry().verify_chain(tenant_id="system")
    _log(
        "info" if result["valid"] else "error",
        "key_registry_chain_verification",
        trace_id=trace_id, valid=result["valid"],
        total=result.get("total", 0),
        broken_at=result.get("broken_at"),
    )
    return JSONResponse(
        status_code=200 if result["valid"] else 500,
        content={
            "chain_valid":  result["valid"],
            "total_rows":   result.get("total", 0),
            "broken_at_id": result.get("broken_at"),
            "failure_msg":  result.get("message"),
            "chain_hash":   get_key_registry().get_active(tenant_id="system").chain_hash
                            if get_key_registry().get_active(tenant_id="system") else KEY_REGISTRY_GENESIS,
            "trace_id":     trace_id,
        },
    )


@app.post("/audit/inclusion-proof", tags=["audit"])
async def audit_inclusion_proof_endpoint(
    request: Request,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """
    Generate a Merkle inclusion proof for a specific proof_id.

    Body: {"proof_id": "...", "from_date": "...", "to_date": "..."}

    Proves that a specific proof is part of the batch Merkle root
    without revealing other proofs. Verifiable by any external party.

    Access: admin, auditor
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "INVALID_JSON"})

    target_proof_id = body.get("proof_id", "")
    from_date       = body.get("from_date")
    to_date         = body.get("to_date")

    if not target_proof_id:
        raise HTTPException(status_code=400, detail={"error": "proof_id required"})

    # Build batch to get all proof_ids
    batch = build_batch_export(
        storage=get_storage(), tenant_id=tenant_id,
        from_date=from_date, to_date=to_date, signer=get_signer(),
    )
    all_proof_ids = [
        p.get("proof_id") for p in batch.batch_dict.get("proofs", [])
        if p.get("proof_id")
    ]

    if target_proof_id not in all_proof_ids:
        raise HTTPException(status_code=404, detail={
            "error":        "PROOF_NOT_IN_BATCH",
            "proof_id":     target_proof_id,
            "batch_size":   len(all_proof_ids),
        })

    inc_proof = compute_inclusion_proof(
        all_proof_ids, target_proof_id,
        batch_dict=batch.batch_dict,  # binds proof to signed root
    )
    is_valid  = verify_inclusion_proof(inc_proof)

    return JSONResponse(content={
        "proof_id":    target_proof_id,
        "merkle_root": batch.merkle_root,
        "inclusion_proof": {
            "leaf_hash":   inc_proof.leaf_hash,
            "leaf_index":  inc_proof.leaf_index,
            "path":        inc_proof.path,
            "root":        inc_proof.root,
            "signed_root": inc_proof.signed_root,
            "signature":   inc_proof.signature,
            "public_key":  inc_proof.public_key,
            "key_id":      inc_proof.key_id,
        },
        "self_verified": is_valid,
        "verification_instructions": (
            "Compute SHA-256(proof_id). Walk path: for each step, "
            "if position=left: sha256(sibling+current), else sha256(current+sibling). "
            "Final hash must equal merkle_root."
        ),
        "tenant_id":   tenant_id,
        "trace_id":    trace_id,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT INFRASTRUCTURE ENDPOINTS (Session 3)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/audit/chain-verify", tags=["audit"])  # [Advanced]
async def audit_chain_verify_endpoint(
    request:      Request,
    expected_hash: str | None = None,
    sequence_num:  int | None = None,
    role:          str        = Depends(require_role("admin", "auditor")),
):
    """
    Verify the audit log hash chain for this tenant.

    Optional: ?expected_hash=<chain_hash> to verify against a known-good anchor.
    If expected_hash is provided, also checks the anchor store for when this
    hash was first recorded externally.

    Returns chain integrity status + anchor verification if requested.
    Access: admin, auditor
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    # ── Verify the PROOF LEDGER chain ────────────────────────────────────────
    # The proof ledger is the canonical record — every POST /decision writes here.
    # verification_audit logs explicit /verify calls (a different, smaller set).
    # Auditors expect chain_valid to reflect the actual decision proof chain.
    import json as _json
    from provable_ai.verifier import verify_chain as _verify_chain

    storage     = get_storage()
    cur         = storage.conn.cursor()
    cur.execute("""
        SELECT proof_json, current_hash FROM ledger
        WHERE tenant_id=?
        ORDER BY id ASC
    """, (tenant_id,))
    rows = cur.fetchall()

    proof_dicts = []
    for row in rows:
        pj = row["proof_json"] if hasattr(row, "__getitem__") else row[0]
        if pj and pj != "{}":
            try:
                proof_dicts.append(_json.loads(pj))
            except Exception:
                pass

    # Run verifier over the ledger proofs
    if proof_dicts:
        chain_result = _verify_chain(proof_dicts)
        chain_valid  = chain_result.valid
        failure_msg  = chain_result.failure_reason.get("message") if chain_result.failure_reason else None
        broken_at    = None
        # Compute chain_hash = SHA-256 of all current_hashes concatenated
        import hashlib
        all_hashes  = "".join(
            p.get("ledger", {}).get("current_hash", "") for p in proof_dicts
        )
        chain_hash  = hashlib.sha256(all_hashes.encode()).hexdigest()
    else:
        chain_valid = True
        failure_msg = None
        broken_at   = None
        chain_hash  = "0" * 64

    total_rows = len(proof_dicts)

    # Also include verification_audit stats (separate from ledger chain)
    audit_result = get_audit_log().verify_chain(tenant_id=tenant_id)

    _log(
        "info" if chain_valid else "error",
        "audit_chain_verification",
        trace_id=trace_id, tenant_id=tenant_id,
        valid=chain_valid, total_rows=total_rows,
    )

    response = {
        "chain_valid":         chain_valid,
        "total_rows":          total_rows,
        "broken_at_id":        broken_at,
        "failure_msg":         failure_msg,
        "chain_hash":          chain_hash,
        "tenant_id":           tenant_id,
        "trace_id":            trace_id,
        "verification_audit":  {
            "total_verify_calls": audit_result.total_rows,
            "audit_chain_valid":  audit_result.valid,
        },
    }

    # Historical block query — prove state at a specific sequence_num
    if sequence_num is not None:
        block_result = get_audit_log().verify_chain_at_block(
            tenant_id=tenant_id, sequence_num=sequence_num,
        )
        response["block_verification"] = block_result

    # Point-in-time verification against a known anchor
    if expected_hash:
        hash_matches  = (chain_hash == expected_hash)
        anchor_result = get_anchor_store().verify_against_anchor(
            tenant_id=tenant_id, chain_hash=expected_hash,
        )
        response["expected_hash_check"] = {
            "expected_hash":   expected_hash,
            "hash_matches":    hash_matches,
            "was_anchored":    anchor_result["anchored"],
            "anchored_at":     anchor_result.get("anchored_at"),
            "anchor_seq":      anchor_result.get("anchor_seq"),
            "anchor_backends": anchor_result.get("backends", []),
        }

    return JSONResponse(
        status_code=200 if chain_valid else 500,
        content=response,
    )


@app.get("/audit/log", tags=["audit"])
async def audit_log_endpoint(
    request:     Request,
    from_date:   str | None = None,
    to_date:     str | None = None,
    result:      str | None = None,
    instance_id: str | None = None,
    limit:       int        = 100,
    offset:      int        = 0,
    role:        str        = Depends(require_role("admin", "auditor")),
):
    """Query verification audit log. Filters: from_date, to_date, result, instance_id.
    Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    qr = get_audit_log().query(
        tenant_id=tenant_id, from_date=from_date, to_date=to_date,
        result=result, instance_id=instance_id, limit=limit, offset=offset,
    )
    entries = [
        {
            "trace_id": e.trace_id, "instance_id": e.instance_id,
            "sequence_id": e.sequence_id, "proof_id": e.proof_id,
            "verified_at": e.verified_at, "result": e.result,
            "failure_code": e.failure_code, "failure_msg": e.failure_msg,
            "key_id": e.key_id, "recorded_at": e.recorded_at,
        }
        for e in qr.entries
    ]
    chain_hash = get_audit_log().get_latest_chain_hash(tenant_id)
    return JSONResponse(content={
        "tenant_id": tenant_id, "total": qr.total,
        "count": len(entries), "limit": limit, "offset": offset,
        "chain_hash": chain_hash,
        "entries": entries, "trace_id": trace_id,
    })


@app.get("/audit/stats", tags=["audit"])
async def audit_stats_endpoint(
    request: Request,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """Summary statistics for this tenant's verification activity.
    Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    stats     = get_audit_log().stats(tenant_id=tenant_id)
    return JSONResponse(content={**stats, "tenant_id": tenant_id, "trace_id": trace_id})


@app.get("/audit/report", tags=["audit"])
async def audit_report_endpoint(
    request:   Request,
    from_date: str | None = None,
    to_date:   str | None = None,
    role:      str        = Depends(require_role("admin", "auditor")),
):
    """Generate PDF audit report. Returns application/pdf.
    Access: admin, auditor"""
    from fastapi.responses import Response

    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    qr        = get_audit_log().query(
        tenant_id=tenant_id, from_date=from_date, to_date=to_date, limit=500,
    )
    # Rich Merkle root: leaf = SHA-256(tenant|instance|seq|result|timestamp|failure_code)
    # Two different audit states cannot produce the same root
    m_root = merkle_root_from_entries(qr.entries)
    pack      = build_compliance_pack(
        entries=qr.entries, tenant_id=tenant_id, merkle_root=m_root,
        from_date=from_date, to_date=to_date,
    )
    pdf_bytes = generate_audit_report(
        tenant_id=tenant_id, entries=qr.entries,
        merkle_root=m_root, compliance_pack=pack,
        from_date=from_date, to_date=to_date,
    )
    _log("info", "audit_report_generated",
         trace_id=trace_id, tenant_id=tenant_id,
         entry_count=len(qr.entries), bytes=len(pdf_bytes))
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="zorynex_audit_{tenant_id}.pdf"',
            "X-Trace-Id": trace_id,
        },
    )


@app.get("/audit/export", tags=["audit"])
async def audit_export_endpoint(
    request:   Request,
    from_date: str | None = None,
    to_date:   str | None = None,
    role:      str        = Depends(require_role("admin", "auditor")),
):
    """Export all proofs as a signed batch with Merkle root.
    Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    # Verify audit chain integrity before export — never export corrupted data
    chain_result = get_audit_log().verify_chain(tenant_id=tenant_id)
    if not chain_result.valid:
        _log("error", "audit_chain_broken_before_export",
             trace_id=trace_id, tenant_id=tenant_id,
             broken_at_id=chain_result.broken_at_id,
             failure_msg=chain_result.failure_msg)
        raise HTTPException(status_code=500, detail={
            "error":    "AUDIT_CHAIN_INTEGRITY_FAILURE",
            "message":  (
                "Audit chain integrity check failed before export. "
                "The audit log may have been tampered with. "
                f"Broken at row id={chain_result.broken_at_id}."
            ),
            "trace_id": trace_id,
        })

    batch = build_batch_export(
        storage=get_storage(), tenant_id=tenant_id,
        from_date=from_date, to_date=to_date, signer=get_signer(),
    )
    _log("info", "batch_export_generated",
         trace_id=trace_id, tenant_id=tenant_id,
         proof_count=batch.proof_count, merkle_root=batch.merkle_root[:16])
    return JSONResponse(content={**batch.batch_dict, "trace_id": trace_id})


@app.get("/audit/compliance", tags=["audit"])
async def audit_compliance_endpoint(
    request:   Request,
    from_date: str | None = None,
    to_date:   str | None = None,
    role:      str        = Depends(require_role("admin", "auditor")),
):
    """Generate compliance evidence pack: SR 11-7, EU AI Act, CFPB.
    Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")

    qr        = get_audit_log().query(
        tenant_id=tenant_id, from_date=from_date, to_date=to_date, limit=10000,
    )
    # Verify chain before compliance export
    chain_result = get_audit_log().verify_chain(tenant_id=tenant_id)
    chain_valid  = chain_result.valid

    # Rich Merkle root from audit entries (not proof_ids)
    m_root = merkle_root_from_entries(qr.entries)
    pack      = build_compliance_pack(
        entries=qr.entries, tenant_id=tenant_id, merkle_root=m_root,
        from_date=from_date, to_date=to_date,
    )
    _log("info", "compliance_pack_generated",
         trace_id=trace_id, tenant_id=tenant_id, entry_count=len(qr.entries))
    return JSONResponse(content={
        "tenant_id": tenant_id, "frameworks": list(pack.keys()),
        "evidence": pack, "trace_id": trace_id,
    })



@app.post("/system/snapshot", tags=["monitor"])
async def system_snapshot_endpoint(
    request:  Request,
    env:      str = "prod",
    role:     str = Depends(require_role("admin", "auditor")),
):
    """Take a snapshot of current system state for drift detection.
    Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    snap = take_snapshot(
        storage=get_storage(), audit_log=get_audit_log(),
        tenant_id=tenant_id, environment=env,
    )
    get_drift_detector().save_snapshot(snap)
    _log("info", "snapshot_taken", trace_id=trace_id, tenant_id=tenant_id,
         env=env, system_root=snap.system_root[:16],
         instance_count=snap.instance_count)
    return JSONResponse(content={"snapshot": snapshot_to_dict(snap), "trace_id": trace_id})


@app.get("/system/snapshots", tags=["monitor"])
async def system_snapshots_endpoint(
    request: Request,
    limit:   int = 20,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """List recent snapshots for this tenant. Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    snaps     = get_drift_detector().list_snapshots(tenant_id, limit=limit)
    return JSONResponse(content={
        "tenant_id": tenant_id, "count": len(snaps),
        "snapshots": [snapshot_to_dict(s) for s in snaps],
        "trace_id":  trace_id,
    })


@app.get("/system/drift", tags=["monitor"])
async def system_drift_endpoint(
    request: Request,
    env_a:   str = "prod",
    env_b:   str | None = None,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """
    Detect drift between environments or against previous snapshot.
    ?env_a=prod&env_b=staging -- compare environments.
    ?env_a=prod               -- compare latest vs previous prod snapshot.
    Severity CRITICAL=root_mismatch, WARNING=other drift.
    Access: admin, auditor
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    detector  = get_drift_detector()

    snap_a = detector.get_latest(tenant_id, env_a)
    if snap_a is None:
        raise HTTPException(status_code=404, detail={
            "error": "NO_SNAPSHOT",
            "message": f"No snapshot for tenant={tenant_id} env={env_a}. POST /system/snapshot first.",
        })

    if env_b:
        snap_b = detector.get_latest(tenant_id, env_b)
        if snap_b is None:
            raise HTTPException(status_code=404, detail={
                "error": "NO_SNAPSHOT",
                "message": f"No snapshot for tenant={tenant_id} env={env_b}.",
            })
    else:
        snaps = detector.list_snapshots(tenant_id, limit=2)
        if len(snaps) < 2:
            snap_b = take_snapshot(
                storage=get_storage(), audit_log=get_audit_log(),
                tenant_id=tenant_id, environment=env_a,
            )
            detector.save_snapshot(snap_b)
        else:
            snap_a, snap_b = snaps[1], snaps[0]

    result = DriftDetector.compare(snap_a, snap_b)
    detector.record_drift_event(result)
    _log("warning" if result.drifted else "info", "drift_check",
         trace_id=trace_id, tenant_id=tenant_id,
         drifted=result.drifted, severity=result.severity,
         drift_type=result.drift_type)

    status = 500 if (result.drifted and result.severity == "CRITICAL") else 200
    return JSONResponse(
        status_code=status,
        content={**drift_result_to_dict(result), "trace_id": trace_id},
    )


@app.get("/system/drift/history", tags=["monitor"])
async def drift_history_endpoint(
    request: Request,
    limit:   int = 20,
    role:    str = Depends(require_role("admin", "auditor")),
):
    """Recent drift events for this tenant. Access: admin, auditor"""
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    history   = get_drift_detector().drift_history(tenant_id, limit=limit)
    return JSONResponse(content={
        "tenant_id": tenant_id, "count": len(history),
        "events": history, "trace_id": trace_id,
    })


@app.post("/webhook/receive", tags=["webhook"])
async def webhook_receive(
    request: Request,
    payload: dict = Depends(verify_webhook_request),
    role:    str  = Depends(require_role("admin", "system")),
):
    """
    Receive and verify an inbound signed webhook.
    HMAC-SHA256 verified, timestamp checked, nonce replay-protected.
    Access: admin, system
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    _metrics["zorynex_webhook_received_total"] += 1
    _log("info", "webhook_received", trace_id=trace_id, event=payload.get("event"))
    return JSONResponse(content={
        "received": True,
        "event":    payload.get("event", "unknown"),
        "trace_id": trace_id,
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _compute_proof_id(current_hash: str, sequence_id: int) -> str:
    raw = f"{current_hash}:{sequence_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── Exception handlers ────────────────────────────────────────────────────────


# ── Validation error handler ──────────────────────────────────────────────────

from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """
    Replace FastAPI's raw Pydantic validation errors with clean Zorynex format.

    Instead of:
        {"detail": [{"type": "missing", "loc": ["body", "reason_code"]}]}

    Returns:
        {"error": "INVALID_REQUEST", "missing_fields": ["reason_code"], "trace_id": "..."}
    """
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))

    missing  = []
    invalid  = []

    for err in exc.errors():
        loc    = err.get("loc", [])
        field  = ".".join(str(l) for l in loc if l != "body")
        etype  = err.get("type", "")
        msg    = err.get("msg", "")

        if etype == "missing":
            missing.append(field)
        else:
            invalid.append({"field": field, "issue": msg})

    body: dict = {}
    if missing:
        body["missing_fields"] = missing
    if invalid:
        body["invalid_fields"] = invalid

    return JSONResponse(
        status_code=422,
        content={
            "error":     "INVALID_REQUEST",
            "message":   (
                f"Missing required fields: {missing}" if missing
                else "Request validation failed"
            ),
            "trace_id":  trace_id,
            **body,
        },
    )




# ── Quickstart / Demo ──────────────────────────────────────────────────────────

@app.post("/demo/bootstrap", tags=["quickstart"])
async def demo_bootstrap(
    request: Request,
    role: str = Depends(require_role("admin")),
):
    """
    **`[Beginner]`  One-click demo environment setup.**

    Seeds a complete working environment in one API call:
    - ✓ Approves a sample model, agent, and policy
    - ✓ Compiles a loan decisioning protocol
    - ✓ Creates a demo instance — ready for your first decision

    Returns `instance_id` and the exact payload for `POST /decision`.
    **This is the fastest way to get started.**

    Access: admin
    """
    trace_id  = getattr(request.state, "trace_id", str(uuid.uuid4()))
    tenant_id = getattr(request.state, "tenant_id", "default")
    storage   = get_storage()
    engine    = get_engine()

    # Seed governance
    storage.add_approved_model("credit-model-v1",  model_name="credit_model")
    storage.add_approved_agent("underwriter-v1",   agent_name="underwriter")
    storage.add_approved_policy("credit-policy-v1",policy_name="credit_policy")

    # Compile a loan protocol
    spec = {
        "states": ["received", "under_review", "approved", "rejected", "funded"],
        "initial_state": "received",
        "transitions": [
            {"from_state": "received",     "to_state": "under_review"},
            {"from_state": "under_review", "to_state": "approved"},
            {"from_state": "under_review", "to_state": "rejected"},
            {"from_state": "approved",     "to_state": "funded"},
        ],
        "metadata": {"workflow": "loan-decisioning-demo"},
    }
    compile_result = engine.compile(spec)

    # Create demo instance
    instance_id = f"demo-loan-{trace_id[:8]}"
    try:
        engine.create_instance(instance_id)
    except ValueError:
        pass  # already exists — idempotent

    _log("info", "demo_bootstrap", trace_id=trace_id, tenant_id=tenant_id,
         instance_id=instance_id)

    next_decision = {
        "instance_id": instance_id,
        "from_state":  "received",
        "to_state":    "under_review",
        "raw_inputs":  {"credit_score": "742", "loan_amount": "250000"},
    }

    return {
        "status":        "ready",
        "instance_id":   instance_id,
        "protocol_hash": compile_result["protocol_hash"],
        "governance": {
            "model_version":  "credit-model-v1",
            "agent_version":  "underwriter-v1",
            "policy_version": "credit-policy-v1",
        },
        "next_step": "POST /decision",
        "next_payload": next_decision,
        "workflow": [
            "✓  1. Protocol compiled    →  loan decisioning (5 states)",
            "✓  2. Model approved       →  credit-model-v1",
            "✓  3. Agent approved       →  underwriter-v1",
            "✓  4. Policy approved      →  credit-policy-v1",
            "✓  5. Instance created     →  " + instance_id,
            "→  6. Record decision      →  POST /decision (payload above)",
            "   7. Export proof         →  GET /proof/export/{instance_id}?inline=true",
            "   8. Verify proof         →  POST /verify-package  or  /verify-ui",
        ],
        "trace_id": trace_id,
    }


@app.get("/quickstart", include_in_schema=False)
async def quickstart_page():
    """
    Human-readable quickstart guide — no auth required.
    Shows the exact API flow with copy-paste ready curl commands.
    """
    from fastapi.responses import HTMLResponse
    html = _quickstart_html()
    return HTMLResponse(content=html)


def _quickstart_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Zorynex Quickstart</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
  :root{--black:#0a0a0a;--black-2:#111;--black-3:#181818;--black-4:#222;--green:#00F5A0;--green-d:#00c880;--green-dim:rgba(0,245,160,.08);--gray:#888;--gray-2:#555;--white:#f0f0f0;--mono:'JetBrains Mono',monospace;--sans:'Space Grotesk',sans-serif;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:var(--sans);background:var(--black);color:var(--white);min-height:100vh;}
  header{background:var(--black-2);border-bottom:1px solid var(--black-4);padding:0 2rem;height:56px;display:flex;align-items:center;gap:12px;}
  .brand{font-size:.9rem;font-weight:600;}
  .brand span{color:var(--green);}
  header nav{margin-left:auto;display:flex;gap:1.5rem;}
  header a{font-size:.8rem;color:var(--gray);text-decoration:none;}
  header a:hover{color:var(--green);}
  main{max-width:820px;margin:0 auto;padding:3rem 1.5rem;}
  h1{font-size:1.8rem;font-weight:600;letter-spacing:-.02em;margin-bottom:.5rem;}
  h1 span{color:var(--green);}
  .sub{color:var(--gray);font-size:.9rem;margin-bottom:2.5rem;}
  /* Tabs */
  .tabs{display:flex;gap:.5rem;margin-bottom:2rem;border-bottom:1px solid var(--black-4);padding-bottom:0;}
  .tab{padding:.55rem 1.1rem;font-family:var(--sans);font-size:.82rem;font-weight:600;border:none;background:none;color:var(--gray);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s,border-color .15s;}
  .tab.active{color:var(--green);border-bottom-color:var(--green);}
  .tab:hover:not(.active){color:var(--white);}
  .panel{display:none;}
  .panel.active{display:block;}
  /* Steps */
  .step{display:flex;gap:1.25rem;margin-bottom:1.5rem;}
  .step-num{width:32px;height:32px;border-radius:50%;background:var(--green-dim);border:1.5px solid rgba(0,245,160,.25);display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:600;color:var(--green);flex-shrink:0;margin-top:.15rem;}
  .step-num.opt{border-color:rgba(136,136,136,.25);background:rgba(136,136,136,.06);color:var(--gray);}
  .step-body h3{font-size:.95rem;font-weight:600;margin-bottom:.25rem;}
  .step-body .badge{display:inline-block;font-size:.68rem;font-weight:600;padding:.1rem .45rem;border-radius:4px;margin-left:.4rem;vertical-align:middle;}
  .badge-opt{background:rgba(136,136,136,.15);color:var(--gray);}
  .step-body p{font-size:.8rem;color:var(--gray);margin-bottom:.6rem;}
  .pre-wrap{position:relative;margin-bottom:.6rem;}
  code{display:block;background:var(--black-3);border:1px solid var(--black-4);border-radius:8px;padding:.85rem 1rem;font-family:var(--mono);font-size:.75rem;overflow-x:auto;white-space:pre;}
  .copy-btn{position:absolute;top:.5rem;right:.5rem;background:var(--black-4);border:none;color:var(--gray);font-size:.7rem;font-family:var(--sans);padding:.2rem .55rem;border-radius:4px;cursor:pointer;transition:color .15s;}
  .copy-btn:hover{color:var(--green);}
  .callout{background:var(--black-2);border:1.5px solid rgba(0,245,160,.2);border-radius:10px;padding:1.1rem 1.4rem;margin-bottom:1.8rem;}
  .callout h2{font-size:.95rem;font-weight:600;color:var(--green);margin-bottom:.3rem;}
  .callout p{font-size:.82rem;color:var(--gray);margin-bottom:.75rem;}
  .callout p:last-child{margin-bottom:0;}
  .btn{display:inline-flex;align-items:center;gap:.4rem;padding:.5rem 1rem;background:var(--green);color:var(--black);border:none;border-radius:7px;font-family:var(--sans);font-size:.8rem;font-weight:600;cursor:pointer;text-decoration:none;}
  .btn:hover{background:var(--green-d);}
  .btn-ghost{background:transparent;color:var(--green);border:1.5px solid rgba(0,245,160,.3);}
  .btn-ghost:hover{background:var(--green-dim);}
  footer{text-align:center;padding:2rem;font-size:.75rem;color:var(--gray-2);border-top:1px solid var(--black-3);}
  .divider{border:none;border-top:1px solid var(--black-3);margin:2rem 0;}
  .note{font-size:.75rem;color:var(--gray-2);font-family:var(--mono);margin-top:.35rem;}
  .flow-row{display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;font-family:var(--mono);font-size:.75rem;color:var(--gray);margin-bottom:1rem;}
  .flow-row .arrow{color:var(--black-4);}
  .flow-row .ep{background:var(--black-3);border:1px solid var(--black-4);border-radius:5px;padding:.15rem .45rem;color:var(--white);}
  .flow-row .ep.qs{border-color:rgba(0,245,160,.3);color:var(--green);}
</style>
</head>
<body>
<header>
  <div class="brand">Zorynex <span>Provable AI</span></div>
  <nav>
    <a href="/docs">Swagger</a>
    <a href="/redoc">ReDoc</a>
    <a href="/verify-ui">Verify UI</a>
  </nav>
</header>
<main>
  <h1>Get started in <span>5 minutes</span></h1>
  <p class="sub">Record your first cryptographic AI decision proof and verify it independently.</p>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('quick')">⚡ Quick Demo</button>
    <button class="tab" onclick="switchTab('full')">🏗️ Full Production Flow</button>
  </div>

  <!-- ── QUICK DEMO TAB ── -->
  <div id="panel-quick" class="panel active">

    <div class="callout">
      <h2>What this tab does</h2>
      <p><strong>POST /demo/bootstrap</strong> runs all the setup steps for you in one call — it approves a model, agent, and policy, compiles a workflow protocol, and creates an instance.</p>
      <p>Use this tab to see Zorynex working in under 2 minutes. Use the <strong>Full Production Flow</strong> tab to understand what bootstrap does behind the scenes.</p>
    </div>

    <div class="flow-row">
      <span class="ep qs">POST /demo/bootstrap</span><span class="arrow">→</span>
      <span class="ep qs">POST /decision</span><span class="arrow">→</span>
      <span class="ep">GET /chain/{id}</span><span class="arrow">→</span>
      <span class="ep qs">GET /proof/export?inline=true</span><span class="arrow">→</span>
      <span class="ep qs">POST /verify-package</span><span class="arrow">→</span>
      <span class="ep">open verify_ui_url</span>
    </div>

    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <h3>Bootstrap everything in one call</h3>
        <p>Approves governance, compiles a loan workflow, creates an instance. Returns the exact payload for your next <code>POST /decision</code>.</p>
        <div class="pre-wrap"><code id="q1">curl -X POST http://127.0.0.1:8000/demo/bootstrap \
  -H "X-API-Key: dev-key"</code><button class="copy-btn" onclick="copy('q1')" aria-label="Copy command">copy</button></div>
        <p class="note">Copy the instance_id from the response — you need it in every step below.</p>
      </div>
    </div>

    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <h3>Record an AI decision</h3>
        <p>Simple mode — governance auto-resolves. Just 4 fields required.</p>
        <div class="pre-wrap"><code id="q2">curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": "YOUR_INSTANCE_ID",
    "from_state":  "received",
    "to_state":    "under_review",
    "raw_inputs":  {"credit_score": "742"}
  }'</code><button class="copy-btn" onclick="copy('q2')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <h3>Record a second decision</h3>
        <p>Each decision adds a new entry to the hash chain.</p>
        <div class="pre-wrap"><code id="q3">curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": "YOUR_INSTANCE_ID",
    "from_state":  "under_review",
    "to_state":    "approved",
    "raw_inputs":  {"reviewer_id": "usr-441"}
  }'</code><button class="copy-btn" onclick="copy('q3')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num" style="border-color:rgba(136,136,136,.25);background:rgba(136,136,136,.06);color:var(--gray)">4</div>
      <div class="step-body">
        <h3>Inspect the chain <span class="badge badge-opt">optional</span></h3>
        <p>See the full decision history before exporting. Auditors use this to review the sequence without downloading the full package.</p>
        <div class="pre-wrap"><code id="q4">curl http://127.0.0.1:8000/chain/YOUR_INSTANCE_ID \
  -H "X-API-Key: dev-key"</code><button class="copy-btn" onclick="copy('q4')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">5</div>
      <div class="step-body">
        <h3>Export the proof package</h3>
        <p>Add <code>?inline=true</code> to get the full self-contained package. Without it you get metadata only — not verifiable.</p>
        <div class="pre-wrap"><code id="q5">curl "http://127.0.0.1:8000/proof/export/YOUR_INSTANCE_ID?inline=true" \
  -H "X-API-Key: dev-key" \
  -o proof.json</code><button class="copy-btn" onclick="copy('q5')" aria-label="Copy command">copy</button></div>
        <p class="note">The response includes <strong>verify_ui_url</strong> — use that link directly instead of typing /verify-ui manually.</p>
      </div>
    </div>

    <div class="step">
      <div class="step-num">6</div>
      <div class="step-body">
        <h3>Verify via API</h3>
        <p>Paste the full proof.json contents as the request body. Returns verified: true + 4 cryptographic checks.</p>
        <div class="pre-wrap"><code id="q6">curl -X POST http://127.0.0.1:8000/verify-package \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d @proof.json</code><button class="copy-btn" onclick="copy('q6')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">7</div>
      <div class="step-body">
        <h3>Verify in browser — the auditor experience</h3>
        <p>Open the verify_ui_url from the export response. Drag proof.json in. No API key needed. Runs entirely in the browser. Downloads a PDF report.</p>
        <div class="pre-wrap"><code id="q7">open http://127.0.0.1:8000/verify-ui</code><button class="copy-btn" onclick="copy('q7')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

  </div><!-- end quick panel -->

  <!-- ── FULL PRODUCTION FLOW TAB ── -->
  <div id="panel-full" class="panel">

    <div class="callout">
      <h2>What bootstrap does behind the scenes</h2>
      <p>Every step in this tab is what <strong>POST /demo/bootstrap</strong> runs automatically. In production you call each endpoint yourself — so you control which model versions, protocols, and policies are approved.</p>
      <p>This is the flow your integration team will implement.</p>
    </div>

    <div class="flow-row">
      <span class="ep">POST /governance/model</span><span class="arrow">→</span>
      <span class="ep">POST /governance/agent</span><span class="arrow">→</span>
      <span class="ep">POST /governance/policy</span><span class="arrow">→</span>
      <span class="ep">POST /protocol/compile</span><span class="arrow">→</span>
      <span class="ep">POST /instance/create</span><span class="arrow">→</span>
      <span class="ep qs">POST /decision</span><span class="arrow">→</span>
      <span class="ep">GET /chain/{id}</span><span class="arrow">→</span>
      <span class="ep qs">GET /proof/export?inline=true</span><span class="arrow">→</span>
      <span class="ep qs">POST /verify-package</span>
    </div>

    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <h3>Approve a model version</h3>
        <p>Only approved model versions can write decisions. Unapproved versions are rejected at the gate.</p>
        <div class="pre-wrap"><code id="f1">curl -X POST http://127.0.0.1:8000/governance/model \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "credit_model", "version": "v3.1"}'</code><button class="copy-btn" onclick="copy('f1')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <h3>Approve an agent version</h3>
        <div class="pre-wrap"><code id="f2">curl -X POST http://127.0.0.1:8000/governance/agent \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "underwriter", "version": "v1.0"}'</code><button class="copy-btn" onclick="copy('f2')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <h3>Approve a policy version</h3>
        <div class="pre-wrap"><code id="f3">curl -X POST http://127.0.0.1:8000/governance/policy \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "credit_policy", "version": "v2"}'</code><button class="copy-btn" onclick="copy('f3')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">4</div>
      <div class="step-body">
        <h3>Compile a workflow protocol</h3>
        <p>Define the valid states and allowed transitions for this type of decision. Every proof is linked to the protocol in effect at signing time.</p>
        <div class="pre-wrap"><code id="f4">curl -X POST http://127.0.0.1:8000/protocol/compile \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "states":        ["received","under_review","approved","rejected"],
    "initial_state": "received",
    "transitions": [
      {"from_state":"received",     "to_state":"under_review"},
      {"from_state":"under_review", "to_state":"approved"},
      {"from_state":"under_review", "to_state":"rejected"}
    ]
  }'</code><button class="copy-btn" onclick="copy('f4')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">5</div>
      <div class="step-body">
        <h3>Create a workflow instance</h3>
        <p>An instance tracks the state machine for one entity — one loan, one claim, one review.</p>
        <div class="pre-wrap"><code id="f5">curl -X POST http://127.0.0.1:8000/instance/create \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_id": "loan-9284"}'</code><button class="copy-btn" onclick="copy('f5')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">6</div>
      <div class="step-body">
        <h3>Record first decision — full mode</h3>
        <p>All governance fields explicit. This is what production integrations send.</p>
        <div class="pre-wrap"><code id="f6">curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id":   "loan-9284",
    "from_state":    "received",
    "to_state":      "under_review",
    "model_version": "v3.1",
    "agent_version": "v1.0",
    "policy_version":"v2",
    "reason_code":   "SCORE_ABOVE_THRESHOLD",
    "policy_rule":   "credit_policy.v2.rule_7",
    "raw_inputs":    {"credit_score":"742","debt_to_income":"0.28"},
    "feature_contributions":[
      {"feature":"credit_score","contribution":"0.65"},
      {"feature":"debt_to_income","contribution":"-0.12"}
    ],
    "threshold_used":"700",
    "metadata":      {"channel":"web","bureau":"experian"}
  }'</code><button class="copy-btn" onclick="copy('f6')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">7</div>
      <div class="step-body">
        <h3>Record second decision</h3>
        <div class="pre-wrap"><code id="f7">curl -X POST http://127.0.0.1:8000/decision \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id":   "loan-9284",
    "from_state":    "under_review",
    "to_state":      "approved",
    "model_version": "v3.1",
    "agent_version": "v1.0",
    "policy_version":"v2",
    "reason_code":   "MANUAL_REVIEW_PASSED",
    "policy_rule":   "credit_policy.v2.rule_12",
    "raw_inputs":    {"reviewer_id":"usr-441","review_score":"0.91"}
  }'</code><button class="copy-btn" onclick="copy('f7')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num" style="border-color:rgba(136,136,136,.25);background:rgba(136,136,136,.06);color:var(--gray)">8</div>
      <div class="step-body">
        <h3>Inspect the chain <span class="badge badge-opt">optional</span></h3>
        <p>View the full decision history before exporting. Enterprise auditors often inspect the chain here before requesting the formal proof package.</p>
        <div class="pre-wrap"><code id="f8">curl http://127.0.0.1:8000/chain/loan-9284 \
  -H "X-API-Key: dev-key"</code><button class="copy-btn" onclick="copy('f8')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">9</div>
      <div class="step-body">
        <h3>Export proof package — always use inline=true</h3>
        <p>Without <code>?inline=true</code> you get metadata only — not verifiable. The export response includes <strong>verify_ui_url</strong> — use that link directly.</p>
        <div class="pre-wrap"><code id="f9">curl "http://127.0.0.1:8000/proof/export/loan-9284?inline=true" \
  -H "X-API-Key: dev-key" \
  -o proof.json</code><button class="copy-btn" onclick="copy('f9')" aria-label="Copy command">copy</button></div>
      </div>
    </div>

    <div class="step">
      <div class="step-num">10</div>
      <div class="step-body">
        <h3>Verify — choose one</h3>
        <p style="font-size:.75rem;color:var(--gray);margin-bottom:.45rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">For developers</p>
        <div class="pre-wrap"><code id="f10a">curl -X POST http://127.0.0.1:8000/verify-package \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d @proof.json</code><button class="copy-btn" onclick="copy('f10a')" aria-label="Copy command">copy</button></div>
        <p style="font-size:.75rem;color:var(--gray);margin-bottom:.45rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">For auditors (offline — no server access)</p>
        <div class="pre-wrap"><code id="f10b">python verify/verify_package.py proof.json</code><button class="copy-btn" onclick="copy('f10b')" aria-label="Copy command">copy</button></div>
        <p style="font-size:.75rem;color:var(--gray);margin-bottom:.45rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">For non-technical teams</p>
        <div class="pre-wrap"><code id="f10c">open http://127.0.0.1:8000/verify-ui</code><button class="copy-btn" onclick="copy('f10c')" aria-label="Copy command">copy</button></div>
        <p class="note">Browser verifier: drag proof.json in. No API key needed. Downloads a PDF report.</p>
      </div>
    </div>


  </div><!-- end full panel -->

</main>
<footer>Zorynex Provable AI · <a href="/docs" style="color:#888">API reference</a> · <a href="/verify-ui" style="color:#888">Verify UI</a></footer>
<script>
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
}
function copy(id) {
  const code = document.getElementById(id);
  const text = code.textContent.trim();
  navigator.clipboard.writeText(text).then(()=>{
    const btn = code.parentElement.querySelector('.copy-btn');
    btn.textContent = 'copied!';
    btn.style.color = 'var(--green)';
    setTimeout(()=>{ btn.textContent='copy'; btn.style.color=''; }, 1800);
  });
}
</script>
</body>
</html>"""



@app.get("/dashboard", include_in_schema=False)
async def compliance_dashboard(
    request: Request,
    role: str = Depends(require_role("admin", "auditor")),
):
    """Read-only compliance dashboard. Access: admin, auditor"""
    import json as _json
    from pathlib import Path
    from fastapi.responses import HTMLResponse

    tenant_id = request.headers.get("X-Tenant-Id", "default")
    try:
        engine = _get_engine(tenant_id)
        cur    = engine.storage.conn.cursor()
        cur.execute(
            "SELECT instance_id, sequence_id, from_state, to_state, "
            "timestamp, current_hash, model_version FROM ledger "
            "ORDER BY rowid DESC LIMIT 50"
        )
        recent = [{"instance_id": r["instance_id"], "sequence_id": r["sequence_id"],
                   "from_state": r["from_state"], "to_state": r["to_state"],
                   "timestamp": (r["timestamp"] or "")[:16],
                   "hash_prefix": r["current_hash"][:12] + "...",
                   "model_version": r["model_version"]} for r in cur.fetchall()]
        cur.execute("SELECT COUNT(DISTINCT instance_id) as c FROM ledger")
        n_inst = (cur.fetchone() or {"c": 0})["c"]
        cur.execute("SELECT COUNT(*) as c FROM ledger")
        n_dec  = (cur.fetchone() or {"c": 0})["c"]
        models   = engine.storage.get_approved_models()
        policies = engine.storage.get_approved_policies()
        stats    = {"instances": n_inst, "decisions": n_dec,
                    "models": len(models), "policies": len(policies)}
    except Exception:
        recent, models, policies, stats = [], [], [], {"instances":0,"decisions":0,"models":0,"policies":0}

    data_blob = _json.dumps({"recent": recent, "models": models,
                              "policies": policies, "stats": stats, "tenant": tenant_id})
    dash_path = Path(__file__).parent.parent / "web" / "dashboard.html"
    template  = dash_path.read_text(encoding="utf-8") if dash_path.exists() else "<html><body>dashboard.html not found</body></html>"
    html      = template.replace("</body>",
                    f"<script>window.__ZORYNEX_DASHBOARD_DATA__={data_blob};</script></body>")
    _admin_audit("dashboard.viewed", request)
    return HTMLResponse(content=html)


@app.get("/verify-ui", include_in_schema=False)
@app.get("/verify-ui/{instance_id}", include_in_schema=False)
async def verifier_ui(instance_id: str = ""):
    """
    Serve the standalone web proof verifier.
    Works for auditors, compliance teams, and executives — no terminal needed.
    Verification runs entirely in the browser — no data sent to any server.
    """
    from pathlib import Path
    verifier_path = Path(__file__).parent.parent / "web" / "verifier.html"
    if verifier_path.exists():
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=verifier_path.read_text(encoding="utf-8"))
    # Fallback if web/ directory doesn't exist
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content="""<!DOCTYPE html>
<html><head><title>Zorynex Verifier</title></head>
<body style="font-family:sans-serif;padding:2rem;max-width:600px;margin:0 auto">
<h2>Proof Verifier</h2>
<p>Web verifier not found. Use the CLI verifier instead:</p>
<pre style="background:#f4f4f4;padding:1rem;border-radius:6px">
python verify/verify_package.py exported_proof.json
</pre>
<p><a href="/docs">← Back to API docs</a></p>
</body></html>""")


@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    """
    Serve ReDoc with a pinned JS bundle and offline-friendly fallback.
    FastAPI's default ReDoc uses an unpinned CDN that can be slow or blocked.
    This version pins to a specific version and serves a clean branded page.
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <title>Zorynex Provable AI — API Reference</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { margin: 0; padding: 0; font-family: -apple-system, sans-serif; }
    #loading {
      display: flex; align-items: center; justify-content: center;
      height: 100vh; flex-direction: column; color: #555; gap: 12px;
    }
    #loading h2 { margin: 0; font-weight: 400; font-size: 1.1rem; }
    #loading small { color: #999; font-size: 0.85rem; }
    .spinner {
      width: 36px; height: 36px; border: 3px solid #eee;
      border-top-color: #1D9E75; border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div id="loading">
    <div class="spinner"></div>
    <h2>Zorynex API Reference</h2>
    <small>Loading documentation...</small>
  </div>

  <script>
    // Load ReDoc from CDN — pinned to a stable version
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/redoc@2.1.3/bundles/redoc.standalone.js';

    script.onload = function() {
      document.getElementById('loading').remove();
      const el = document.createElement('div');
      document.body.appendChild(el);
      Redoc.init(
        '/openapi.json',
        {
          theme: {
            colors: { primary: { main: '#1D9E75' } },
            typography: { fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' },
          },
          hideDownloadButton: false,
          expandResponses: '200',
          sortPropsAlphabetically: false,
          pathInMiddlePanel: true,
        },
        el
      );
    };

    script.onerror = function() {
      document.getElementById('loading').innerHTML =
        '<h2 style="color:#c00">Could not load ReDoc</h2>' +
        '<p>Check your internet connection or use <a href="/docs">Swagger UI</a> instead.</p>' +
        '<small>ReDoc requires cdn.jsdelivr.net to be accessible.</small>';
    };

    document.head.appendChild(script);
  </script>
</body>
</html>"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


@app.exception_handler(ZorynexError)
async def zorynex_error_handler(request: Request, exc: ZorynexError):
    trace_id = getattr(request.state, "trace_id", "unknown")
    return JSONResponse(
        status_code=500,
        content={
            "error": exc.code,
            "message": exc.message,
            "trace_id": trace_id,
        },
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    trace_id = getattr(request.state, "trace_id", "unknown")
    _log("error", "unhandled_exception",
         trace_id=trace_id,
         error=str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
            "trace_id": trace_id,
        },
    )