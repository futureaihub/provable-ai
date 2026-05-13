# Zorynex — Pilot Readiness Checklist

**Use this before starting a pilot deployment.**
Work through each section in order. Every item with ☐ must be confirmed before go-live.

---

## 1. Environment Setup

```
☐ Python 3.11+ installed and active
☐ pip install -r requirements.txt completed without errors
☐ pip install -r requirements-dev.txt completed (for test suite)
☐ bootstrap.py run successfully — .env generated
☐ source .env — environment variables loaded
☐ uvicorn server.main:app --reload — server starts cleanly
☐ http://localhost:8000/health returns { "status": "ok" }
☐ http://localhost:8000/ready returns { "ready": true }
```

---

## 2. Configuration

```
☐ ZORYNEX_SIGNING_KEY — set from bootstrap output (dev) or KMS (prod)
   Value: confirm via GET /health → signing_key field shows key prefix
☐ ZORYNEX_API_KEYS — at minimum one admin key set
   Format: "admin-key:admin,audit-key:auditor,svc-key:system"
☐ ZORYNEX_WEBHOOK_SECRET — set from bootstrap output
☐ ZORYNEX_BACKEND — "sqlite" (dev) or "postgres" (prod)
☐ ZORYNEX_DB_PATH — path exists and is writable (SQLite)
   OR DATABASE_URL — valid PostgreSQL connection string (prod)
☐ ZORYNEX_REQUIRE_TENANT — "false" (single-tenant) or "true" (multi-tenant)
☐ ZORYNEX_ANCHOR_RFC3161 — "true" recommended for production pilots

Full env var reference: docs/integration.md → Configuration section
```

---

## 3. KMS (Production Pilots Only)

```
☐ ZORYNEX_KMS_KEY_ID — set to your AWS KMS key ARN or alias
☐ ZORYNEX_KMS_REGION — AWS region of the KMS key
☐ IAM role running the server has kms:Sign permission on the key
☐ ZORYNEX_KMS_FALLBACK_KEY_ID — set for automatic failover
☐ KMS key policy reviewed — access restricted to server IAM role only
☐ Test: POST /decision → response includes key_id matching KMS key prefix
```

---

## 4. Database

```
☐ Database is writable by the server process
☐ Database backup configured — daily minimum
   SQLite: sqlite3 provable_ai.db ".backup '/backups/provable_ai_$(date +%Y%m%d).db'"
   PostgreSQL: pg_dump → compressed → off-site
☐ Backup restore tested at least once
☐ Disk space adequate — estimate: ~1KB per decision, plan for 1 year
☐ (PostgreSQL) Multiple workers confirmed safe: ZORYNEX_WORKERS=4 max
☐ (SQLite) Single worker only: do not set ZORYNEX_WORKERS > 1
```

---

## 5. Integration

```
☐ First decision recorded successfully:
   curl -X POST http://localhost:8000/decision \
     -H "X-API-Key: <your-key>" \
     -H "Content-Type: application/json" \
     -d '{"instance_id":"pilot-test-001","from_state":"start","to_state":"end","raw_inputs":{"test":"value"}}'
   → Returns proof_id, sequence_id: 1

☐ Proof exported:
   curl "http://localhost:8000/proof/export/pilot-test-001?inline=true" \
     -H "X-API-Key: <your-key>" -o pilot_test.json
   → File pilot_test.json exists with type: "provable-ai-proof-package"

☐ CLI verification passes:
   python verify/verify_package.py pilot_test.json
   → FINAL VERDICT: VALID EVIDENCE

☐ Browser verification works:
   Open http://localhost:8000/verify-ui
   Drag pilot_test.json into browser
   → 4 green checks, VERIFIED

☐ PDF report downloads from verify-ui
   → PDF shows Zorynex branding, all 4 checks, proof metadata
```

---

## 6. Governance

```
☐ At least one model version approved:
   GET /governance/status → approved_models is non-empty
☐ At least one agent version approved:
   GET /governance/status → approved_agents is non-empty
☐ At least one policy version approved:
   GET /governance/status → approved_policies is non-empty
☐ Governance rejection tested:
   POST /decision with unapproved model version
   → Returns 403 UNAUTHORIZED_MODEL_VERSION (not 200)
☐ Protocol compiled for your workflow:
   POST /protocol/compile with your state machine specification
☐ All workflow instances created before first decision
```

---

## 7. SIEM Integration (if required)

```
☐ SIEM transport configured: ZORYNEX_SIEM_TRANSPORT=webhook|syslog|splunk|datadog
☐ Test event received in SIEM: POST /demo/bootstrap → check SIEM for decision_recorded event
☐ Admin audit events visible in SIEM: governance.model_approved, proof.exported
☐ SIEM alert configured for CHAIN_BROKEN and SEQUENCE_GAP events
☐ See docs/siem.md for full SIEM configuration reference
```

---

## 8. Monitoring

```
☐ /health endpoint monitored — alert if not 200
☐ /ready endpoint monitored — alert if not 200
☐ GET /system/root called at start of pilot — record the hash value
   → Compare weekly: any change = ledger was modified
☐ Error rate monitored — alert if >0% on /decision
☐ Disk space monitored — alert at 80% of database volume
☐ KMS connectivity monitored — alert if signing_failed events appear in logs
```

---

## 9. Compliance Team Handoff

```
☐ Compliance team has auditor API key
☐ Compliance team can access /dashboard with their key
☐ Compliance team can access /verify-ui (no key required)
☐ docs/auditor.md shared with compliance team
☐ Compliance team has verified at least one proof independently:
   python verify/verify_package.py <proof.json>
   → FINAL VERDICT: VALID EVIDENCE
☐ Compliance team knows to call GET /audit/compliance for regulatory pack
```

---

## 10. Documentation

```
☐ docs/integration.md read by integration engineer
☐ docs/auditor.md read by compliance team
☐ docs/error_codes.md bookmarked by integration engineer
☐ docs/security-architecture.md shared with InfoSec team
☐ docs/data-handling.md shared with DPO / legal team
☐ SECURITY.md shared with security team
☐ Demo tested using docs/demo_steps.md — all steps work
```

---

## 11. Pre-Go-Live Sign-Off

```
☐ Integration engineer confirms: decisions recording correctly
☐ Compliance team confirms: verification working independently
☐ Security team confirms: security architecture reviewed
☐ KMS / signing key: confirmed not from development defaults
☐ Backup strategy: confirmed and tested
☐ Monitoring: confirmed active
☐ All tests passing: pytest tests/ -q → no failures

Sign-off: ________________________________  Date: __________
Role:     ________________________________
```

---

## Quick Reference

| What | Where |
|---|---|
| Server logs | stdout / journalctl -u zorynex |
| Chain integrity | GET /audit/chain-verify |
| System root hash | GET /system/root |
| Governance state | GET /governance/status |
| Compliance pack | GET /audit/compliance |
| Proof verification | python verify/verify_package.py proof.json |
| Hanif (Zorynex) | hanif@zorynex.co |