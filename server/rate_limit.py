"""
Zorynex — Two-Layer Rate Limiting
===================================
Layer 1: Per-tenant sliding window   — prevents one tenant starving others
Layer 2: Global server sliding window — hard ceiling regardless of tenant
Layer 3: Per-tenant decision write window — tighter limit for write operations

In-memory sliding window (token bucket via list of timestamps).
Thread-safe via Lock per window.

Phase 3 upgrade path: replace _Window with Redis ZADD/ZCOUNT — the
interface (check/stats) stays identical. No app code changes needed.

Known limitations:
    - Resets on process restart (acceptable for single-instance)
    - Not shared across instances (Phase 3: Redis)

Config (env vars):
    ZORYNEX_RATE_TENANT_RPM   default 60
    ZORYNEX_RATE_GLOBAL_RPM   default 500
    ZORYNEX_RATE_DECISION_RPM default 30
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable

from fastapi import Depends, HTTPException, Request, status


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class RateLimitConfig:
    tenant_rpm:   int = int(os.environ.get("ZORYNEX_RATE_TENANT_RPM",   "60"))
    global_rpm:   int = int(os.environ.get("ZORYNEX_RATE_GLOBAL_RPM",   "500"))
    decision_rpm: int = int(os.environ.get("ZORYNEX_RATE_DECISION_RPM", "30"))


CONFIG = RateLimitConfig()


# ── Sliding window ────────────────────────────────────────────────────────────

@dataclass
class _Window:
    """
    Thread-safe 60-second sliding window.
    Evicts expired timestamps on each check.
    Phase 3 upgrade: replace body with Redis ZADD / ZCOUNT / ZREMRANGEBYSCORE.
    """
    timestamps: list[float] = field(default_factory=list)
    lock: Lock = field(default_factory=Lock)

    def count_and_check(self, limit: int) -> tuple[bool, int]:
        """
        Record a new request timestamp.
        Returns (allowed, retry_after_seconds).
        """
        now          = time.monotonic()
        window_start = now - 60.0

        with self.lock:
            self.timestamps = [t for t in self.timestamps if t > window_start]

            if len(self.timestamps) >= limit:
                oldest      = self.timestamps[0]
                retry_after = int(60 - (now - oldest)) + 1
                return False, retry_after

            self.timestamps.append(now)
            return True, 0

    def current_count(self) -> int:
        now = time.monotonic()
        with self.lock:
            return sum(1 for t in self.timestamps if t > now - 60.0)


# ── Rate limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Three-layer in-memory rate limiter.

    check(tenant_id, action) — call on every request.
    stats()                  — for /metrics endpoint.
    """

    def __init__(self, config: RateLimitConfig = CONFIG) -> None:
        self.config            = config
        self._global: _Window  = _Window()
        self._tenant: defaultdict[str, _Window]           = defaultdict(_Window)
        self._tenant_writes: defaultdict[str, _Window]    = defaultdict(_Window)

    def check(self, tenant_id: str, action: str = "read") -> None:
        """
        Enforce all applicable rate limits.
        Raises HTTPException 429 with Retry-After header on violation.

        action: "read" | "write"
        """
        # ── Layer 2: Global ──────────────────────────────────────────────────
        ok, retry = self._global.count_and_check(self.config.global_rpm)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error":       "GLOBAL_RATE_LIMIT_EXCEEDED",
                    "message":     f"Global limit {self.config.global_rpm}/min exceeded. Retry in {retry}s.",
                    "limit":       self.config.global_rpm,
                    "retry_after": retry,
                    "scope":       "global",
                },
                headers={"Retry-After": str(retry)},
            )

        # ── Layer 1: Per-tenant ──────────────────────────────────────────────
        ok, retry = self._tenant[tenant_id].count_and_check(self.config.tenant_rpm)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error":       "TENANT_RATE_LIMIT_EXCEEDED",
                    "message":     f"Tenant limit {self.config.tenant_rpm}/min exceeded. Retry in {retry}s.",
                    "limit":       self.config.tenant_rpm,
                    "retry_after": retry,
                    "scope":       "tenant",
                    "tenant_id":   tenant_id,
                },
                headers={"Retry-After": str(retry)},
            )

        # ── Layer 3: Per-tenant write (decision rate) ────────────────────────
        if action == "write":
            ok, retry = self._tenant_writes[tenant_id].count_and_check(
                self.config.decision_rpm
            )
            if not ok:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error":       "DECISION_RATE_LIMIT_EXCEEDED",
                        "message":     f"Decision write limit {self.config.decision_rpm}/min exceeded. Retry in {retry}s.",
                        "limit":       self.config.decision_rpm,
                        "retry_after": retry,
                        "scope":       "tenant_decisions",
                        "tenant_id":   tenant_id,
                    },
                    headers={"Retry-After": str(retry)},
                )

    def stats(self) -> dict:
        """Current usage snapshot for /metrics."""
        tenant_stats = {
            tid: {
                "requests_60s": w.current_count(),
                "writes_60s":   self._tenant_writes[tid].current_count(),
            }
            for tid, w in self._tenant.items()
        }
        return {
            "global_requests_60s": self._global.current_count(),
            "global_limit_rpm":    self.config.global_rpm,
            "tenant_limit_rpm":    self.config.tenant_rpm,
            "decision_limit_rpm":  self.config.decision_rpm,
            "tenants":             tenant_stats,
            "backend":             "in-memory (Phase 3: Redis)",
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_limiter: RateLimiter | None = None


def get_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


# ── FastAPI dependency ────────────────────────────────────────────────────────

def rate_limit(action: str = "read") -> Depends:
    """
    FastAPI dependency. Reads tenant_id from request.state (set by trace_middleware).

    Usage:
        @app.post("/decision")
        async def record(request: Request, _: None = rate_limit("write")):
            ...
    """
    def _check(request: Request) -> None:
        tenant_id = getattr(request.state, "tenant_id", "unknown")
        get_limiter().check(tenant_id, action)

    return Depends(_check)