# Zorynex — SIEM Integration Guide

Zorynex can forward audit events to external SIEM systems in real time.
Events are delivered non-blocking — SIEM failures never impact proof recording.

---

## Supported transports

| Transport | Protocol | Compatible with |
|---|---|---|
| Webhook | HTTP POST JSON | Elastic Logstash, Sumo Logic, any HTTP endpoint |
| Syslog | RFC 5424 UDP/TCP | Splunk syslog, rsyslog, syslog-ng, QRadar, ArcSight |
| Splunk HEC | HTTP Event Collector | Splunk Enterprise, Splunk Cloud |
| Datadog | Datadog Logs API | Datadog |

Multiple transports can be active simultaneously. Configure as many as needed.

---

## Quick start

```bash
# Webhook (simplest — works with most SIEMs)
export ZORYNEX_SIEM_WEBHOOK_URL=https://your-siem.example.com/ingest
export ZORYNEX_SIEM_WEBHOOK_SECRET=your-hmac-secret

# Splunk HEC
export ZORYNEX_SIEM_SPLUNK_URL=https://splunk.example.com:8088/services/collector
export ZORYNEX_SIEM_SPLUNK_TOKEN=your-hec-token
export ZORYNEX_SIEM_SPLUNK_INDEX=zorynex

# Datadog
export ZORYNEX_SIEM_DATADOG_API_KEY=your-datadog-api-key
export ZORYNEX_SIEM_DATADOG_ENV=production

# Syslog (UDP)
export ZORYNEX_SIEM_SYSLOG_HOST=syslog.example.com
export ZORYNEX_SIEM_SYSLOG_PORT=514
export ZORYNEX_SIEM_SYSLOG_PROTO=udp

# Minimum level to forward (default: info)
export ZORYNEX_SIEM_LEVEL=info

# Start server — SIEM router initialises automatically
python cli.py server
```

---

## Event schema

Every event has these fields:

```json
{
  "source":    "zorynex",
  "version":   "1.0",
  "event":     "decision_recorded",
  "level":     "info",
  "timestamp": "2026-05-01T12:00:00Z",
  "tenant_id": "bank_abc",
  "trace_id":  "uuid-...",
  "proof_id":  "a3f8c2d1...",
  "to_state":  "approved"
}
```

---

## Events reference

| Event | Level | Trigger | Key fields |
|---|---|---|---|
| `decision_recorded` | info | AI decision written to ledger | `proof_id`, `instance_id`, `to_state`, `model_version` |
| `governance_rejection` | warning | Unapproved model/agent/policy attempted | `reason`, `model_version`, `policy_version` |
| `signing_error` | error | Ed25519 or KMS signing failed | `error`, `key_id` |
| `chain_error` | error | Hash chain broken on write | `error`, `instance_id` |
| `audit_chain_verification` | info | Chain integrity checked | `valid`, `tenant_id` |
| `webhook_received` | info | Inbound webhook received | `event` |
| `drift_check` | info/warning | System snapshot compared | `drifted`, `severity`, `drift_type` |
| `snapshot_taken` | info | System root snapshot recorded | `environment`, `system_root`, `instance_count` |
| `chain_anchored` | info | RFC 3161 timestamp written | `chain_hash`, `rfc3161` |
| `kms_failover` | warning | KMS primary failed, using fallback | `primary_key_id`, `fallback_key_id` |
| `kms_failback` | info | KMS primary recovered | `primary_key_id` |

---

## Emit events from code

```python
from provable_ai.siem import emit, SIEMEvent, get_siem_router

# Simple emit
emit(
    "decision_recorded",
    tenant_id = "bank_abc",
    trace_id  = "uuid-...",
    proof_id  = "a3f8...",
    to_state  = "approved",
)

# Structured event
router = get_siem_router()
router.emit(SIEMEvent(
    event     = "governance_rejection",
    level     = "warning",
    tenant_id = "bank_abc",
    trace_id  = "uuid-...",
    extras    = {"model_version": "evil-model-v99", "reason": "not approved"},
))

# Hook into existing _log calls (no code change needed)
# In server/main.py, add one line to _log():
router.emit_from_log({"level": level, "message": message, **fields})
```

---

## Webhook HMAC verification

When `ZORYNEX_SIEM_WEBHOOK_SECRET` is set, each request includes:

```
X-Zorynex-Signature: sha256=<hmac-sha256-hex>
```

Verify in your receiver:

```python
import hmac, hashlib

def verify(body: bytes, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header)
```

---

## Splunk setup

1. Enable HTTP Event Collector in Splunk: **Settings → Data Inputs → HTTP Event Collector**
2. Create a new token, note the token value
3. Set the index to `zorynex` (or your preferred index)
4. Set `ZORYNEX_SIEM_SPLUNK_URL` and `ZORYNEX_SIEM_SPLUNK_TOKEN`

Zorynex batches up to 50 events per HTTP request (configurable via `ZORYNEX_SIEM_SPLUNK_BATCH`).

**Splunk search:**
```
index=zorynex source=zorynex event=decision_recorded | stats count by tenant_id
index=zorynex level=warning OR level=error | sort -_time
index=zorynex event=governance_rejection | table _time tenant_id model_version reason
```

---

## Datadog setup

1. Get your Datadog API key: **Organization Settings → API Keys**
2. Set `ZORYNEX_SIEM_DATADOG_API_KEY`
3. Events appear in **Logs** → search `source:zorynex`

**Datadog log query:**
```
source:zorynex event:decision_recorded
source:zorynex @level:warning env:production
source:zorynex event:governance_rejection @tenant_id:bank_abc
```

**Alert example** (governance rejection spike):
```
source:zorynex event:governance_rejection
Threshold: count > 5 over 5 minutes
Notify: #security-alerts
```

---

## Elastic / Logstash

Use the webhook transport and configure Logstash HTTP input:

```
# logstash.conf
input {
  http {
    port => 8080
    codec => json
  }
}
filter {
  mutate { add_field => { "[@metadata][index]" => "zorynex" } }
}
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    index => "zorynex-%{+YYYY.MM.dd}"
  }
}
```

```bash
export ZORYNEX_SIEM_WEBHOOK_URL=http://logstash:8080
```

---

## Filtering events

Only forward events at or above the configured level:

```bash
export ZORYNEX_SIEM_LEVEL=warning  # only warning + error + critical
export ZORYNEX_SIEM_LEVEL=error    # only error + critical
export ZORYNEX_SIEM_LEVEL=info     # all events (default)
```

---

## Operational notes

**Non-blocking:** Event delivery happens in background daemon threads. Proof recording is never delayed or failed due to SIEM issues.

**Queue depth:** Default queue holds 1000 events. If the SIEM is unreachable and the queue fills, new events are dropped (logged as warnings). The queue drains automatically when the SIEM recovers.

**Graceful shutdown:** Call `get_siem_router().flush()` before process exit to drain pending events.

**Metrics:**
```python
from provable_ai.siem import get_siem_router
print(get_siem_router().metrics())
# {"emitted": 1420, "dropped": 0, "queue_size": 0, "transports": ["webhook", "splunk"]}
```