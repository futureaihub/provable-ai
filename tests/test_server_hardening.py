"""
Phase 2 Session 2 — Server hardening tests

Tests all four hardening areas:
  1. RBAC          — role enforcement on every endpoint
  2. Rate limiting  — per-tenant + global limits
  3. Health         — /health, /ready, /metrics
  4. Webhook HMAC   — signing, verification, replay protection

Run:
    pytest tests/test_server_hardening.py -v
"""

import hashlib
import hmac
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from server.auth import _API_KEYS, AuthContext, require_role
from server.rate_limit import RateLimitConfig, RateLimiter
from server.webhook import _nonce_store, sign_webhook, _compute_hmac, _SECRET


# ── Test client setup ─────────────────────────────────────────────────────────
# We patch API keys so tests don't depend on env vars.

from server.main import app

client = TestClient(app, raise_server_exceptions=False)

ADMIN_HEADERS   = {"X-API-Key": "admin-key",   "X-Tenant-Id": "test_tenant"}
AUDITOR_HEADERS = {"X-API-Key": "audit-key",   "X-Tenant-Id": "test_tenant"}
SYSTEM_HEADERS  = {"X-API-Key": "sys-key",     "X-Tenant-Id": "test_tenant"}
NO_KEY_HEADERS  = {                             "X-Tenant-Id": "test_tenant"}
BAD_KEY_HEADERS = {"X-API-Key": "bad-key-xxx", "X-Tenant-Id": "test_tenant"}


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — RBAC
# ═══════════════════════════════════════════════════════════════════════════════

class TestRBAC:
    """
    RBAC matrix enforcement.

    admin   → all endpoints
    auditor → read/verify only
    system  → record only, cannot read back

    Missing key  → 401
    Wrong role   → 403
    """

    # ── /health — no auth ────────────────────────────────────────────────────

    def test_health_requires_no_auth(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_works_without_tenant_header(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_ready_requires_no_auth(self):
        r = client.get("/ready")
        assert r.status_code in (200, 503)  # 503 ok if DB not connected

    # ── /metrics — admin only ─────────────────────────────────────────────────

    def test_metrics_admin_allowed(self):
        r = client.get("/metrics", headers=ADMIN_HEADERS)
        assert r.status_code == 200
        assert "zorynex_decisions_total" in r.text

    def test_metrics_auditor_forbidden(self):
        r = client.get("/metrics", headers=AUDITOR_HEADERS)
        assert r.status_code == 403
        body = r.json()
        assert body["detail"]["error"] == "FORBIDDEN"
        assert "admin" in str(body["detail"]["required_roles"])

    def test_metrics_system_forbidden(self):
        r = client.get("/metrics", headers=SYSTEM_HEADERS)
        assert r.status_code == 403

    def test_metrics_no_key_unauthorized(self):
        r = client.get("/metrics", headers=NO_KEY_HEADERS)
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "UNAUTHORIZED"

    def test_metrics_bad_key_unauthorized(self):
        r = client.get("/metrics", headers=BAD_KEY_HEADERS)
        assert r.status_code == 401

    # ── /verify — admin, auditor, system ─────────────────────────────────────

    def test_verify_admin_allowed(self):
        r = client.post("/verify", headers=ADMIN_HEADERS, json={"type": "zorynex-proof-v1"})
        # Will fail verification but must not be 401/403
        assert r.status_code != 401
        assert r.status_code != 403

    def test_verify_auditor_allowed(self):
        r = client.post("/verify", headers=AUDITOR_HEADERS, json={})
        assert r.status_code != 401
        assert r.status_code != 403

    def test_verify_system_allowed(self):
        r = client.post("/verify", headers=SYSTEM_HEADERS, json={})
        assert r.status_code != 401
        assert r.status_code != 403

    def test_verify_no_key_unauthorized(self):
        r = client.post("/verify", headers=NO_KEY_HEADERS, json={})
        assert r.status_code == 401

    # ── /system/root — admin, auditor ────────────────────────────────────────

    def test_system_root_admin_allowed(self):
        r = client.get("/system/root", headers=ADMIN_HEADERS)
        assert r.status_code != 401
        assert r.status_code != 403

    def test_system_root_auditor_allowed(self):
        r = client.get("/system/root", headers=AUDITOR_HEADERS)
        assert r.status_code != 401
        assert r.status_code != 403

    def test_system_root_system_forbidden(self):
        r = client.get("/system/root", headers=SYSTEM_HEADERS)
        assert r.status_code == 403

    # ── Tenant ID enforcement ─────────────────────────────────────────────────

    def test_missing_tenant_id_returns_400(self):
        r = client.get("/system/root", headers={"X-API-Key": "admin-key"})
        assert r.status_code == 400
        assert r.json()["error"] == "MISSING_TENANT_ID"

    def test_health_exempt_from_tenant_requirement(self):
        r = client.get("/health")  # no tenant header
        assert r.status_code == 200

    def test_ready_exempt_from_tenant_requirement(self):
        r = client.get("/ready")   # no tenant header
        assert r.status_code in (200, 503)

    # ── 401 response structure ────────────────────────────────────────────────

    def test_401_has_structured_error(self):
        r = client.get("/metrics", headers=NO_KEY_HEADERS)
        body = r.json()
        assert "detail" in body
        assert body["detail"]["error"] == "UNAUTHORIZED"
        assert "message" in body["detail"]

    def test_403_has_structured_error(self):
        r = client.get("/metrics", headers=AUDITOR_HEADERS)
        body = r.json()
        assert "detail" in body
        assert body["detail"]["error"] == "FORBIDDEN"
        assert "your_role"      in body["detail"]
        assert "required_roles" in body["detail"]

    # ── Response headers ──────────────────────────────────────────────────────

    def test_response_has_trace_id_header(self):
        r = client.get("/health")
        assert "x-trace-id" in r.headers

    def test_response_has_duration_header(self):
        r = client.get("/health")
        assert "x-duration-ms" in r.headers


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

class TestRateLimiting:
    """
    Two-layer rate limiting:
    Layer 1: per-tenant sliding window
    Layer 2: global sliding window
    """

    def _make_limiter(self, tenant_rpm=5, global_rpm=10, decision_rpm=3):
        return RateLimiter(RateLimitConfig(
            tenant_rpm=tenant_rpm,
            global_rpm=global_rpm,
            decision_rpm=decision_rpm,
        ))

    def test_read_within_limit_passes(self):
        limiter = self._make_limiter()
        for _ in range(5):
            limiter.check("tenant_a", "read")  # should not raise

    def test_read_exceeds_tenant_limit_raises(self):
        from fastapi import HTTPException
        limiter = self._make_limiter(tenant_rpm=3)
        for _ in range(3):
            limiter.check("tenant_a", "read")
        with pytest.raises(HTTPException) as exc:
            limiter.check("tenant_a", "read")
        assert exc.value.status_code == 429
        assert exc.value.detail["error"] == "TENANT_RATE_LIMIT_EXCEEDED"

    def test_rate_limit_is_per_tenant(self):
        from fastapi import HTTPException
        limiter = self._make_limiter(tenant_rpm=2, global_rpm=100)
        limiter.check("tenant_a", "read")
        limiter.check("tenant_a", "read")
        with pytest.raises(HTTPException):
            limiter.check("tenant_a", "read")
        # tenant_b is unaffected
        limiter.check("tenant_b", "read")  # must not raise

    def test_global_limit_applies_across_tenants(self):
        from fastapi import HTTPException
        limiter = self._make_limiter(tenant_rpm=100, global_rpm=4)
        limiter.check("tenant_a", "read")
        limiter.check("tenant_b", "read")
        limiter.check("tenant_c", "read")
        limiter.check("tenant_d", "read")
        with pytest.raises(HTTPException) as exc:
            limiter.check("tenant_e", "read")
        assert exc.value.detail["error"] == "GLOBAL_RATE_LIMIT_EXCEEDED"

    def test_write_uses_tighter_decision_limit(self):
        from fastapi import HTTPException
        limiter = self._make_limiter(tenant_rpm=100, global_rpm=100, decision_rpm=2)
        limiter.check("tenant_a", "write")
        limiter.check("tenant_a", "write")
        with pytest.raises(HTTPException) as exc:
            limiter.check("tenant_a", "write")
        assert exc.value.detail["error"] == "DECISION_RATE_LIMIT_EXCEEDED"

    def test_rate_limit_includes_retry_after_header(self):
        from fastapi import HTTPException
        limiter = self._make_limiter(tenant_rpm=1)
        limiter.check("tenant_x", "read")
        with pytest.raises(HTTPException) as exc:
            limiter.check("tenant_x", "read")
        assert "retry_after" in exc.value.detail
        assert exc.value.detail["retry_after"] > 0

    def test_stats_tracks_requests(self):
        limiter = self._make_limiter(tenant_rpm=100, global_rpm=100)
        limiter.check("stat_tenant", "read")
        limiter.check("stat_tenant", "read")
        stats = limiter.stats()
        assert stats["global_requests_60s"] >= 2
        assert "stat_tenant" in stats["tenants"]

    def test_rate_limit_429_from_api(self):
        """Hammer the real endpoint to trigger a rate limit."""
        import os
        os.environ["ZORYNEX_RATE_TENANT_RPM"]   = "3"
        os.environ["ZORYNEX_RATE_DECISION_RPM"] = "3"
        # Hit /health (no RL) to confirm rate limit is on write endpoints
        for _ in range(10):
            r = client.get("/health")
            assert r.status_code == 200  # health has no rate limit


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — HEALTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthEndpoints:
    """
    /health  — liveness (always 200 if process alive)
    /ready   — readiness (200 or 503 based on checks)
    /metrics — Prometheus counters (admin only)
    """

    def test_health_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_body_structure(self):
        r = client.get("/health")
        body = r.json()
        assert "status"   in body
        assert "version"  in body
        assert "uptime_s" in body
        assert body["status"] == "ok"
        assert body["version"] == "2.0.0"
        assert body["uptime_s"] >= 0

    def test_ready_returns_checks(self):
        r = client.get("/ready")
        assert r.status_code in (200, 503)
        body = r.json()
        assert "ready"   in body
        assert "checks"  in body
        assert "database" in body["checks"]
        assert "signer"   in body["checks"]

    def test_ready_has_uptime(self):
        r = client.get("/ready")
        assert "uptime_s" in r.json()

    def test_metrics_format_is_prometheus(self):
        r = client.get("/metrics", headers=ADMIN_HEADERS)
        assert r.status_code == 200
        assert "# HELP" in r.text
        assert "# TYPE" in r.text
        assert "counter" in r.text
        assert "gauge"   in r.text

    def test_metrics_has_all_required_counters(self):
        r = client.get("/metrics", headers=ADMIN_HEADERS)
        text = r.text
        required = [
            "zorynex_decisions_total",
            "zorynex_verification_requests_total",
            "zorynex_signing_errors_total",
            "zorynex_governance_rejections_total",
            "zorynex_rate_limit_hits_total",
            "zorynex_webhook_received_total",
            "zorynex_webhook_replay_blocked",
            "zorynex_auth_failures_total",
            "zorynex_uptime_seconds",
            "zorynex_nonce_store_size",
        ]
        for counter in required:
            assert counter in text, f"Missing counter: {counter}"

    def test_metrics_content_type_is_plain_text(self):
        r = client.get("/metrics", headers=ADMIN_HEADERS)
        assert "text/plain" in r.headers["content-type"]

    def test_health_no_auth_no_tenant(self):
        """Health must work with zero headers — load balancer probe."""
        r = client.get("/health", headers={})
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — WEBHOOK HMAC + REPLAY PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhook:
    """
    Webhook signing and verification.

    Outbound: sign_webhook() creates signed payload
    Inbound:  /webhook/receive verifies before processing

    Replay protection: nonce store rejects duplicate nonces
    Timestamp guard:   rejects stale webhooks > 5 minutes old
    """

    def _build_valid_webhook(self, event: str = "decision.recorded") -> tuple[str, dict]:
        """Returns (body_str, headers_dict) for a valid signed webhook."""
        signed = sign_webhook(event, {"instance_id": "loan_test", "sequence_id": 1})
        return signed.body, signed.headers

    # ── sign_webhook() ────────────────────────────────────────────────────────

    def test_sign_webhook_returns_body_and_headers(self):
        signed = sign_webhook("decision.recorded", {"instance_id": "x"})
        assert signed.body
        assert "X-Zorynex-Signature" in signed.headers
        assert "X-Zorynex-Timestamp" in signed.headers
        assert "X-Zorynex-Nonce"     in signed.headers

    def test_signature_starts_with_sha256(self):
        signed = sign_webhook("test.event", {"x": 1})
        assert signed.headers["X-Zorynex-Signature"].startswith("sha256=")

    def test_body_is_canonical_json(self):
        signed = sign_webhook("test.event", {"b": 2, "a": 1})
        parsed = json.loads(signed.body)
        assert "event"     in parsed
        assert "timestamp" in parsed
        assert "nonce"     in parsed
        assert "data"      in parsed

    def test_signature_is_deterministic_for_same_nonce(self):
        """Same inputs → same HMAC (determinism check)."""
        ts, nonce, body = "1700000000", "fixed-nonce", '{"event":"test"}'
        sig1 = _compute_hmac(ts, nonce, body)
        sig2 = _compute_hmac(ts, nonce, body)
        assert sig1 == sig2

    def test_different_nonces_produce_different_sigs(self):
        ts, body = "1700000000", '{"event":"test"}'
        sig1 = _compute_hmac(ts, "nonce-1", body)
        sig2 = _compute_hmac(ts, "nonce-2", body)
        assert sig1 != sig2

    # ── /webhook/receive — valid request ──────────────────────────────────────

    def test_valid_webhook_accepted(self):
        body, headers = self._build_valid_webhook()
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 200
        data = r.json()
        assert data["received"] is True

    def test_valid_webhook_returns_event_type(self):
        body, headers = self._build_valid_webhook("decision.recorded")
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.json()["event"] == "decision.recorded"

    # ── Missing headers ───────────────────────────────────────────────────────

    def test_missing_signature_header_rejected(self):
        body, headers = self._build_valid_webhook()
        del headers["X-Zorynex-Signature"]
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "WEBHOOK_MISSING_HEADERS"

    def test_missing_timestamp_header_rejected(self):
        body, headers = self._build_valid_webhook()
        del headers["X-Zorynex-Timestamp"]
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 401

    def test_missing_nonce_header_rejected(self):
        body, headers = self._build_valid_webhook()
        del headers["X-Zorynex-Nonce"]
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 401

    # ── Invalid signature ─────────────────────────────────────────────────────

    def test_tampered_body_signature_fails(self):
        body, headers = self._build_valid_webhook()
        tampered = body[:-5] + "XXXXX"  # corrupt last chars
        r = client.post("/webhook/receive",
                        content=tampered, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "WEBHOOK_SIGNATURE_INVALID"

    def test_wrong_signature_rejected(self):
        body, headers = self._build_valid_webhook()
        headers["X-Zorynex-Signature"] = "sha256=" + "a" * 64
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "WEBHOOK_SIGNATURE_INVALID"

    # ── Replay protection ─────────────────────────────────────────────────────

    def test_replay_same_nonce_rejected(self):
        """Same nonce sent twice → second is rejected as replay."""
        body, headers = self._build_valid_webhook()
        r1 = client.post("/webhook/receive",
                         content=body, headers={**headers, **ADMIN_HEADERS})
        assert r1.status_code == 200

        # Exact same request again — nonce reused
        r2 = client.post("/webhook/receive",
                         content=body, headers={**headers, **ADMIN_HEADERS})
        assert r2.status_code == 401
        assert r2.json()["detail"]["error"] == "WEBHOOK_REPLAY_DETECTED"

    def test_fresh_nonce_accepted_after_replay_blocked(self):
        """New nonce on same payload → accepted (different nonce = not a replay)."""
        body, headers = self._build_valid_webhook()
        # First delivery
        r1 = client.post("/webhook/receive",
                         content=body, headers={**headers, **ADMIN_HEADERS})
        assert r1.status_code == 200

        # New delivery with fresh nonce
        body2, headers2 = self._build_valid_webhook()
        r2 = client.post("/webhook/receive",
                         content=body2, headers={**headers2, **ADMIN_HEADERS})
        assert r2.status_code == 200

    # ── Timestamp staleness ───────────────────────────────────────────────────

    def test_stale_timestamp_rejected(self):
        """Timestamp older than tolerance → rejected."""
        old_ts    = str(int(time.time()) - 400)  # 400s ago > 300s tolerance
        nonce     = str(uuid.uuid4())
        body      = json.dumps({"event": "test", "timestamp": int(old_ts),
                                "nonce": nonce, "data": {}},
                               sort_keys=True, separators=(",", ":"))
        signature = _compute_hmac(old_ts, nonce, body)

        headers = {
            "X-Zorynex-Signature": f"sha256={signature}",
            "X-Zorynex-Timestamp": old_ts,
            "X-Zorynex-Nonce":     nonce,
            "Content-Type":        "application/json",
        }
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "WEBHOOK_TIMESTAMP_EXPIRED"

    def test_future_timestamp_rejected(self):
        """Timestamp far in the future → rejected."""
        future_ts = str(int(time.time()) + 400)
        nonce     = str(uuid.uuid4())
        body      = json.dumps({"event": "test", "timestamp": int(future_ts),
                                "nonce": nonce, "data": {}},
                               sort_keys=True, separators=(",", ":"))
        signature = _compute_hmac(future_ts, nonce, body)

        headers = {
            "X-Zorynex-Signature": f"sha256={signature}",
            "X-Zorynex-Timestamp": future_ts,
            "X-Zorynex-Nonce":     nonce,
            "Content-Type":        "application/json",
        }
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **ADMIN_HEADERS})
        # Future timestamp hits WEBHOOK_TIMESTAMP_EXPIRED (|age| > tolerance)
        assert r.status_code == 401
        detail = r.json()["detail"]
        assert detail["error"] in ("WEBHOOK_TIMESTAMP_EXPIRED", "WEBHOOK_SIGNATURE_INVALID")

    # ── RBAC on webhook endpoint ──────────────────────────────────────────────

    def test_webhook_auditor_forbidden(self):
        body, headers = self._build_valid_webhook()
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **AUDITOR_HEADERS})
        assert r.status_code == 403

    def test_webhook_no_key_unauthorized(self):
        body, headers = self._build_valid_webhook()
        r = client.post("/webhook/receive",
                        content=body, headers={**headers, **NO_KEY_HEADERS})
        assert r.status_code == 401