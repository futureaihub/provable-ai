# Zorynex — Error Code Reference

Every API failure returns a structured JSON body with a stable `error` type,
a human-readable `message`, and a `trace_id` for log correlation.

**Error response format:**

```json
{
  "error":    "UNAUTHORIZED_MODEL_VERSION",
  "message":  "Model version 'v2.9' is not approved. Approved: ['v3.1']",
  "hint":     "Approve this version via POST /governance/model first.",
  "trace_id": "a3f8c2d1-..."
}
```

---

## Error Index

| HTTP | Error Code | Category | Meaning |
|------|------------|----------|---------|
| 400 | `INVALID_PAYLOAD` | Request | Missing or malformed required fields |
| 400 | `INVALID_JSON` | Request | Request body is not valid JSON |
| 400 | `INVALID_REQUEST` | Request | Request structure is valid but semantically wrong |
| 400 | `COMPILE_ERROR` | Protocol | Protocol specification failed to compile |
| 400 | `SEQUENCE_GAP` | Ledger | Non-consecutive sequence_id detected |
| 400 | `CANONICAL_JSON_ERROR` | Proof | Payload contains non-canonical types (float, datetime) |
| 400 | `GOVERNANCE_ERROR` | Governance | Generic governance rule violated |
| 400 | `NO_APPROVED_MODEL` | Governance | No model versions have been approved yet |
| 400 | `NO_APPROVED_AGENT` | Governance | No agent versions have been approved yet |
| 400 | `NO_APPROVED_POLICY` | Governance | No policy versions have been approved yet |
| 400 | `MISSING_TENANT_ID` | Auth | `X-Tenant-Id` header absent in multi-tenant mode |
| 403 | `UNAUTHORIZED_MODEL_VERSION` | Governance | Model version not on the approved list |
| 403 | `POLICY_VIOLATION` | Governance | Decision violates an active governance policy rule |
| 403 | `AGENT_VERSION_MISMATCH` | Governance | Agent version not approved |
| 403 | `FORBIDDEN` | Auth | API key lacks permission for this operation |
| 404 | `INSTANCE_NOT_FOUND` | Ledger | Requested instance_id does not exist |
| 404 | `PROOF_NOT_FOUND` | Ledger | No proof found for this instance/sequence combination |
| 404 | `NO_SNAPSHOT` | Monitor | No system snapshot found to compare against |
| 409 | `DUPLICATE_SEQUENCE_ID` | Ledger | sequence_id already exists for this instance |
| 409 | `INSTANCE_FROZEN` | Ledger | Instance was exported and is now immutable |
| 409 | `INSTANCE_ALREADY_EXISTS` | Ledger | instance_id already registered |
| 422 | `VERIFICATION_FAILED` | Verification | One or more cryptographic checks failed |
| 422 | `HASH_MISMATCH` | Verification | Recomputed hash does not match stored hash |
| 422 | `SIGNATURE_MISMATCH` | Verification | Ed25519 signature does not verify |
| 422 | `SEQUENCE_ORDER_VIOLATION` | Verification | Chain sequence_ids not in ascending order |
| 422 | `KEY_ID_NOT_FOUND` | Verification | Signing key not found in key registry |
| 422 | `CHAIN_BROKEN` | Verification | previous_hash linkage broken in chain |
| 429 | `RATE_LIMITED` | Rate limit | Too many requests — per-tenant or global limit exceeded |
| 500 | `SIGNING_FAILED` | Signing | Signing operation failed after key was available |
| 500 | `KMS_UNAVAILABLE` | Signing | KMS/HSM cannot be reached |
| 500 | `INVALID_KEY_ID` | Signing | Requested key_id does not exist or is revoked |
| 500 | `EXPORT_ERROR` | Ledger | Unexpected failure during proof package export |
| 500 | `GOVERNANCE_STATUS_ERROR` | Governance | Unexpected failure reading governance state |
| 500 | `INTERNAL_ERROR` | Server | Unexpected server-side failure |
| 503 | `SIGNER_UNAVAILABLE` | Signing | All signers unavailable — primary and fallback both down |

---

## Detailed Reference

### Request Errors (400)

---

#### `INVALID_PAYLOAD`

```json
{
  "error":   "INVALID_PAYLOAD",
  "message": "Missing required fields: from_state, to_state",
  "hint":    "See POST /decision field reference in the integration guide."
}
```

**Cause:** One or more required fields are absent or null in the request body.

**Required fields for POST /decision (simple mode):** `instance_id`, `from_state`, `to_state`, `raw_inputs`

**Remediation:** Check the request body against the field reference in `docs/integration.md`. All string fields must be non-empty strings.

---

#### `INVALID_JSON`

```json
{
  "error":   "INVALID_JSON",
  "message": "Request body must be valid JSON (the full proof package).",
  "hint":    "Export via GET /proof/export/{instance_id}?inline=true"
}
```

**Cause:** The request body could not be parsed as JSON, or the body was empty.

**Common cause for POST /verify-package:** Pasting the metadata-only export response (without `?inline=true`) instead of the full package.

**Remediation:** Ensure `Content-Type: application/json` is set and the body is well-formed JSON.

---

#### `COMPILE_ERROR`

```json
{
  "error":   "COMPILE_ERROR",
  "message": "Protocol specification invalid: initial_state 'received' not in states list"
}
```

**Cause:** The protocol specification passed to `POST /protocol/compile` is logically invalid.

**Common causes:**
- `initial_state` not in `states` array
- A transition references a state not in `states`
- `states` array is empty
- `transitions` array is empty

---

#### `SEQUENCE_GAP`

```json
{
  "error":   "SEQUENCE_GAP",
  "message": "Sequence gap: expected 3, got 5",
  "context": { "expected_sequence_id": 3, "actual_sequence_id": 5 }
}
```

**Cause:** A gap exists in `sequence_id` numbering — one or more entries are missing from the chain.

**Severity:** High — this indicates entries were deleted from the ledger or never written. Treat as a potential integrity incident.

**Remediation:** Do not retry. Investigate the ledger for missing entries. Run `GET /audit/chain-verify` to identify the gap.

---

#### `CANONICAL_JSON_ERROR`

```json
{
  "error":   "CANONICAL_JSON_ERROR",
  "message": "Field 'threshold_used' has non-canonical type 'float'. Allowed: str, int, bool, list, dict, None. Floats → int or str.",
  "context": { "field": "threshold_used", "value_type": "float" }
}
```

**Cause:** A field in the decision payload contains a type not permitted in canonical JSON.

**Not allowed:** `float`, Python `datetime`, `Decimal`, custom objects.

**Remediation:** Convert floats to strings (`"0.65"` not `0.65`). Convert datetimes to ISO 8601 strings. Threshold values must be strings.

---

### Governance Errors (400 / 403)

---

#### `UNAUTHORIZED_MODEL_VERSION`

```json
{
  "error":   "UNAUTHORIZED_MODEL_VERSION",
  "message": "Model version 'credit-model-v2.9' is not approved. Approved: ['credit-model-v3.1']",
  "hint":    "Approve this version via POST /governance/model first.",
  "context": {
    "model_version":     "credit-model-v2.9",
    "approved_versions": ["credit-model-v3.1"]
  }
}
```

**Cause:** The `model_version` in the decision request is not on the approved governance list.

**This is enforcement, not logging.** The decision was not recorded.

**Remediation:**
1. Approve the model: `POST /governance/model` with `{"name": "...", "version": "..."}`
2. Or update the request to use an already-approved version
3. Check current approved list: `GET /governance/status`

---

#### `POLICY_VIOLATION`

```json
{
  "error":   "POLICY_VIOLATION",
  "message": "Policy violation: rule 'credit_policy.v2.rule_7' — threshold_used must not be negative"
}
```

**Cause:** The decision violates an active governance policy rule.

**Remediation:** Review the active policy rules. Check `GET /governance/status` for the current policy version and its constraints.

---

#### `AGENT_VERSION_MISMATCH`

```json
{
  "error":   "AGENT_VERSION_MISMATCH",
  "message": "Agent version 'underwriter-v0.9' does not match approved version 'underwriter-v1.0'"
}
```

**Cause:** The `agent_version` in the request is not on the approved agent list.

**Remediation:** Approve the agent version via `POST /governance/agent` or use an approved version.

---

#### `NO_APPROVED_MODEL` / `NO_APPROVED_AGENT` / `NO_APPROVED_POLICY`

```json
{
  "error":   "NO_APPROVED_MODEL",
  "message": "No approved models found. Approve at least one model before recording decisions."
}
```

**Cause:** A decision was attempted in simple mode (governance auto-resolves) but no versions have been approved yet.

**Remediation:** Run `POST /demo/bootstrap` for a demo environment, or run the governance approval sequence manually:
```bash
POST /governance/model   {"name": "...", "version": "..."}
POST /governance/agent   {"name": "...", "version": "..."}
POST /governance/policy  {"name": "...", "version": "..."}
```

---

#### `MISSING_TENANT_ID`

```json
{
  "error":   "MISSING_TENANT_ID",
  "message": "X-Tenant-Id header is required in multi-tenant mode.",
  "hint":    "Add header: X-Tenant-Id: your-tenant-id"
}
```

**Cause:** `ZORYNEX_REQUIRE_TENANT=true` is set but `X-Tenant-Id` header is absent.

**Remediation:** Add `X-Tenant-Id: <your-tenant-id>` to all requests. Use `default` for single-tenant deployments.

---

### Ledger Errors (404 / 409)

---

#### `INSTANCE_NOT_FOUND`

```json
{
  "error":   "INSTANCE_NOT_FOUND",
  "message": "No instance found with id 'loan-9284'",
  "hint":    "Create it first via POST /instance/create"
}
```

**Cause:** The `instance_id` does not exist in the ledger for this tenant.

**Remediation:** Create the instance via `POST /instance/create` before recording decisions. In simple mode (`POST /demo/bootstrap`), the instance is created automatically.

---

#### `INSTANCE_FROZEN`

```json
{
  "error":   "INSTANCE_FROZEN",
  "message": "Instance 'loan-9284' was exported and is now immutable. No further decisions can be recorded."
}
```

**Cause:** `GET /proof/export` was called on this instance, which freezes it. Frozen instances cannot accept new decisions.

**Remediation:** This is by design. If you need to continue recording decisions, create a new instance. Proof packages are designed to be final.

---

#### `DUPLICATE_SEQUENCE_ID`

```json
{
  "error":   "DUPLICATE_SEQUENCE_ID",
  "message": "Duplicate sequence_id=3 in ledger",
  "context": { "sequence_id": 3 }
}
```

**Cause:** Concurrent write attempt produced a duplicate sequence_id. Rare under normal conditions.

**Severity:** Should not occur in production with PostgreSQL advisory locking. If it does, investigate concurrent writes.

---

### Verification Errors (422)

---

#### `VERIFICATION_FAILED`

```json
{
  "error":         "VERIFICATION_FAILED",
  "verified":      false,
  "failure_reason": "This proof was signed by a verified key, but its contents were modified after export. Do not trust this artifact.",
  "checks": [
    {"name": "Package structure valid",  "passed": true},
    {"name": "Package untampered",       "passed": false, "failure": "Hash mismatch..."},
    {"name": "Chain valid",              "passed": false},
    {"name": "Original signer verified", "passed": true}
  ]
}
```

**Cause:** One or more of the 4 cryptographic checks failed.

**Check meaning:**

| Check | Passes when |
|-------|-------------|
| Package structure valid | File is a valid `provable-ai-proof-package` with non-empty ledger |
| Package untampered | SHA-256 of ledger matches `package_hash` |
| Chain valid | Every `previous_hash` links correctly to the preceding entry's `current_hash` |
| Original signer verified | Ed25519 signature over `instance_root` verifies against embedded `public_key` |

**Important:** "Original signer verified" can pass even when other checks fail. This means the proof was signed correctly but modified afterward — the signer is confirmed, but the content is not trusted.

**Remediation:** Do not use this artifact as evidence. Request a fresh export from the original system.

---

### Rate Limit (429)

---

#### `RATE_LIMITED`

```json
{
  "error":       "RATE_LIMITED",
  "message":     "Rate limit exceeded. Try again in 30 seconds.",
  "retry_after": 30
}
```

**Cause:** Per-tenant or global request rate exceeded.

**Default limits:** 100 requests/minute per tenant. Global limit configured per deployment.

**Remediation:** Implement exponential backoff. Use `retry_after` value from response.

---

### Signing Errors (500 / 503)

---

#### `KMS_UNAVAILABLE`

```json
{
  "error":   "KMS_UNAVAILABLE",
  "message": "KMS unavailable for key 'alias/zorynex-prod': Connection timeout",
  "context": { "key_id": "alias/zorynex-prod" }
}
```

**Cause:** The KMS endpoint cannot be reached. AWS KMS outage, network issue, or misconfigured VPC endpoint.

**Severity:** Critical — proofs cannot be signed until KMS is available. If `FailoverSigner` is configured, the fallback key activates automatically.

**Remediation:**
1. Check KMS availability in your AWS region
2. Verify VPC endpoint configuration
3. Check `ZORYNEX_KMS_FALLBACK_KEY_ID` is set for automatic failover
4. Run `GET /ready` to check signer status

---

#### `SIGNER_UNAVAILABLE`

```json
{
  "error":   "SIGNER_UNAVAILABLE",
  "message": "All signers unavailable — primary KMS and fallback both unreachable.",
  "hint":    "Check KMS connectivity. Decisions cannot be proven until a signer is available."
}
```

**Cause:** Both primary and fallback KMS keys are unreachable. `FailoverSigner` has exhausted all options.

**Severity:** Highest. No proofs can be produced. Decision pipeline should halt or queue until resolved.

**Remediation:**
1. Restore KMS connectivity immediately
2. Check AWS health dashboard
3. Consider configuring `EnvSigner` as an emergency local fallback for continuity (not recommended for production, but acceptable during outage)
4. All decisions during this window should be queued and re-signed when KMS is restored

---

## Stability Guarantees

**Error codes are stable across API versions.** The `error` field string will not change once published. If an error code is deprecated, it will remain in the response for at least 12 months with a `deprecated` flag.

**New error codes may be added** in any release. Your integration should handle unknown error codes gracefully (treat as `INTERNAL_ERROR`).

**The `message` field is human-readable and may change.** Do not parse `message` programmatically. Always use the `error` code for logic branching.

---

## Correlation and Debugging

Every error response includes `trace_id`. This correlates with:
- Server logs: `grep trace_id=<value> /var/log/zorynex/app.log`
- SIEM events: filter by `trace_id` field
- Audit log: `GET /audit/log?trace_id=<value>`

Include `trace_id` in all support requests.

---

## Integrity Violations

Two error codes indicate potential security incidents and must trigger immediate alerting:

| Code | Meaning | Response |
|------|---------|----------|
| `CHAIN_BROKEN` | previous_hash linkage broken — possible tamper | Stop processing. Alert security team. Preserve ledger state. |
| `SEQUENCE_GAP` | Entries missing from chain | Stop processing. Investigate deleted records. |

These are never expected in normal operation. If they occur, treat as a security incident.