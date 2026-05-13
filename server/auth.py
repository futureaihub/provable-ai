"""
Zorynex — Authentication & RBAC
================================
Three roles. Hard-enforced on every endpoint.

Roles:
    admin   — full access: record, read, verify, rotate keys, metrics
    auditor — read + verify only: cannot record or touch keys
    system  — record decisions only: cannot read back or verify

Key format (env var ZORYNEX_API_KEYS):
    "key1:admin,key2:auditor,key3:system"

Keys are loaded at startup. In Phase 3 this moves to DB KeyRegistry
with hashed storage and rotation. The interface (require_role / AuthContext)
is unchanged when that happens.

Known limitation: static env keys cannot be rotated without restart.
Phase 3 fix: DB-backed key management with hashing + rotation endpoint.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass
_auth_logger = logging.getLogger("zorynex.auth")
from typing import Callable

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

# ── Role constants ────────────────────────────────────────────────────────────

ROLE_ADMIN   = "admin"
ROLE_AUDITOR = "auditor"
ROLE_SYSTEM  = "system"

VALID_ROLES: frozenset[str] = frozenset({ROLE_ADMIN, ROLE_AUDITOR, ROLE_SYSTEM})

# ── Permission matrix ─────────────────────────────────────────────────────────
# Maps named actions → roles that may perform them.
# Everything not listed here is implicitly denied.

PERMISSIONS: dict[str, frozenset[str]] = {
    "record_decision": frozenset({ROLE_ADMIN, ROLE_SYSTEM}),
    "read_proof":      frozenset({ROLE_ADMIN, ROLE_AUDITOR, ROLE_SYSTEM}),
    "verify_proof":    frozenset({ROLE_ADMIN, ROLE_AUDITOR, ROLE_SYSTEM}),
    "manage_keys":     frozenset({ROLE_ADMIN}),
    "view_metrics":    frozenset({ROLE_ADMIN}),
    "system_root":     frozenset({ROLE_ADMIN, ROLE_AUDITOR}),
    "webhook_send":    frozenset({ROLE_ADMIN, ROLE_SYSTEM}),
}


@dataclass(frozen=True)
class AuthContext:
    """Resolved auth context — passed to every authenticated endpoint."""
    api_key: str
    role:    str
    key_id:  str   # first 8 chars only — safe to log, never the full key


# ── Key store ─────────────────────────────────────────────────────────────────

def _load_api_keys() -> dict[str, str]:
    """
    Load from ZORYNEX_API_KEYS env var.
    Format: "key1:admin,key2:auditor,key3:system"
    Returns: {api_key: role}
    """
    raw = os.environ.get("ZORYNEX_API_KEYS", "dev-key:admin")
    keys: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        key, role = pair.split(":", 1)
        key  = key.strip()
        role = role.strip().lower()
        if not key:
            continue
        if role not in VALID_ROLES:
            raise ValueError(
                f"Invalid role '{role}' for key '{key[:4]}...' in ZORYNEX_API_KEYS. "
                f"Valid: {sorted(VALID_ROLES)}"
            )
        keys[key] = role
    if not keys:
        raise ValueError("ZORYNEX_API_KEYS produced no valid key:role pairs.")
    return keys


# Loaded once at startup — before any request is handled
_API_KEYS: dict[str, str] = _load_api_keys()

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _resolve(api_key: str | None) -> AuthContext | None:
    if not api_key:
        return None
    role = _API_KEYS.get(api_key)
    if role is None:
        return None
    return AuthContext(api_key=api_key, role=role, key_id=api_key[:8] + "...")


# ── Dependency factories ──────────────────────────────────────────────────────

def require_role(*allowed_roles: str) -> Callable[..., AuthContext]:
    """
    FastAPI dependency factory.

    Raises 401 if key is missing/invalid.
    Raises 403 if key is valid but role is not in allowed_roles.
    Returns AuthContext on success.

    Usage:
        @app.post("/decision")
        async def record(auth: AuthContext = Depends(require_role("admin", "system"))):
            ...
    """
    allowed = frozenset(allowed_roles)

    def _check(api_key: str | None = Security(_API_KEY_HEADER)) -> AuthContext:
        ctx = _resolve(api_key)

        if ctx is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error":   "UNAUTHORIZED",
                    "message": "Missing or invalid X-API-Key header.",
                    "hint":    "Include a valid API key in the X-API-Key header.",
                },
                headers={"WWW-Authenticate": "ApiKey"},
            )

        if ctx.role not in allowed:
            import json as _j, datetime as _dt
            _audit_entry = {
                "level": "audit", "event_type": "admin_audit",
                "action": "auth.role_denied",
                "actor": ctx.api_key[:8] + "..." if len(ctx.api_key) > 8 else ctx.api_key,
                "your_role": ctx.role, "required_roles": sorted(allowed),
                "timestamp": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            _auth_logger.warning(_j.dumps(_audit_entry))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error":          "FORBIDDEN",
                    "message":        f"Role '{ctx.role}' cannot perform this action.",
                    "your_role":      ctx.role,
                    "required_roles": sorted(allowed),
                },
            )
        return ctx

    return _check


def require_permission(action: str) -> Callable[..., AuthContext]:
    """Named-permission variant — looks up allowed roles from PERMISSIONS matrix."""
    allowed = PERMISSIONS.get(action)
    if allowed is None:
        raise ValueError(f"Unknown permission: '{action}'")
    return require_role(*allowed)


# ── Pre-built dependencies (import directly in routes) ────────────────────────

RequireAdmin   = Depends(require_role(ROLE_ADMIN))
RequireAuditor = Depends(require_role(ROLE_ADMIN, ROLE_AUDITOR))
RequireSystem  = Depends(require_role(ROLE_ADMIN, ROLE_SYSTEM))
RequireRead    = Depends(require_role(ROLE_ADMIN, ROLE_AUDITOR, ROLE_SYSTEM))
RequireRecord  = Depends(require_permission("record_decision"))
RequireVerify  = Depends(require_permission("verify_proof"))
RequireKeys    = Depends(require_permission("manage_keys"))
RequireMetrics = Depends(require_permission("view_metrics"))