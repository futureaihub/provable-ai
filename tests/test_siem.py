"""
Zorynex Phase 3 — SIEM Integration Tests
==========================================
All mock-based. No external SIEM, Splunk, or Datadog required.

Covers:
  1. SIEMEvent — schema, serialization, JSON output
  2. WebhookTransport — HTTP POST, HMAC signature, error handling
  3. SyslogTransport — RFC 5424 format, UDP/TCP, reconnect
  4. SplunkHECTransport — batching, envelope format, flush
  5. DatadogTransport — payload format, batch send
  6. SIEMRouter — queue, filtering, worker delivery, drop counter
  7. emit_from_log — log dict → SIEMEvent conversion
  8. Factory (from_env) — reads correct env vars per transport
  9. Thread safety — concurrent emits
  10. Non-fatal — SIEM failures never raise to caller
  11. Metrics — emitted/dropped/queue counters

Run: pytest tests/test_siem.py -v
"""

from __future__ import annotations

import json
import queue
import socket
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

from provable_ai.siem import (
    SIEMEvent,
    SIEMRouter,
    WebhookTransport,
    SyslogTransport,
    SplunkHECTransport,
    DatadogTransport,
    BaseTransport,
    emit,
    get_siem_router,
    siem_router_from_env,
    _LEVELS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event(
    event:     str  = "decision_recorded",
    level:     str  = "info",
    tenant_id: str  = "bank_abc",
    trace_id:  str  = "trace-001",
    **kwargs,
) -> SIEMEvent:
    return SIEMEvent(event=event, level=level, tenant_id=tenant_id,
                     trace_id=trace_id, extras=kwargs)


class _MockTransport(BaseTransport):
    name = "mock"

    def __init__(self, fail: bool = False, delay: float = 0):
        self.received: list[SIEMEvent] = []
        self.fail  = fail
        self.delay = delay
        self.flushed = False

    def send(self, event: SIEMEvent) -> None:
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("mock transport failure")
        self.received.append(event)

    def flush(self) -> None:
        self.flushed = True


def _router(*transports, min_level="info") -> SIEMRouter:
    return SIEMRouter(list(transports), min_level=min_level, workers=1)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 1 — SIEMEvent
# ═══════════════════════════════════════════════════════════════════════════════

class TestSIEMEvent:

    def test_to_dict_has_required_fields(self):
        e = _event()
        d = e.to_dict()
        assert d["source"]    == "zorynex"
        assert d["version"]   == "1.0"
        assert d["event"]     == "decision_recorded"
        assert d["level"]     == "info"
        assert d["tenant_id"] == "bank_abc"
        assert d["trace_id"]  == "trace-001"
        assert "timestamp"    in d

    def test_to_dict_includes_extras(self):
        e = _event(proof_id="abc", to_state="approved")
        d = e.to_dict()
        assert d["proof_id"]  == "abc"
        assert d["to_state"]  == "approved"

    def test_to_json_is_valid_json(self):
        e = _event(proof_id="abc")
        j = e.to_json()
        parsed = json.loads(j)
        assert parsed["event"] == "decision_recorded"

    def test_to_json_is_compact(self):
        e = _event()
        j = e.to_json()
        assert " : " not in j   # no spaces around colon
        assert " , " not in j   # no spaces after comma

    def test_timestamp_is_iso8601_utc(self):
        e = _event()
        ts = e.to_dict()["timestamp"]
        assert "T" in ts and ts.endswith("Z")
        assert len(ts) == 20  # YYYY-MM-DDTHH:MM:SSZ

    def test_default_level_is_info(self):
        e = SIEMEvent(event="test", tenant_id="t", trace_id="r")
        assert e.level == "info"

    def test_extras_empty_by_default(self):
        e = SIEMEvent(event="test", tenant_id="t", trace_id="r")
        assert e.extras == {}

    def test_all_levels_valid(self):
        for level in ["debug", "info", "warning", "error", "critical"]:
            e = _event(level=level)
            assert e.to_dict()["level"] == level


# ═══════════════════════════════════════════════════════════════════════════════
# PART 2 — WebhookTransport
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookTransport:

    def test_sends_post_request(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req)
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = WebhookTransport(url="http://siem.example.com/ingest", timeout=1)
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(_event())

        assert len(sent) == 1
        assert sent[0].get_method() == "POST"
        assert sent[0].full_url == "http://siem.example.com/ingest"

    def test_content_type_json(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req)
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = WebhookTransport(url="http://siem.example.com/ingest")
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(_event())

        assert sent[0].get_header("Content-type") == "application/json"

    def test_hmac_signature_added_when_secret_set(self):
        import hmac as _hmac, hashlib
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req)
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = WebhookTransport(url="http://siem.example.com/ingest", secret="my-secret")
        e = _event(proof_id="test")
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(e)

        req = sent[0]
        sig_header = req.get_header("X-zorynex-signature")
        assert sig_header is not None
        assert sig_header.startswith("sha256=")

        # Verify the signature
        body = req.data
        expected = "sha256=" + _hmac.new(b"my-secret", body, hashlib.sha256).hexdigest()
        assert sig_header == expected

    def test_no_signature_when_no_secret(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req)
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = WebhookTransport(url="http://siem.example.com/ingest")
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(_event())

        req = sent[0]
        assert req.get_header("X-zorynex-signature") is None

    def test_network_error_does_not_raise(self):
        from urllib.error import URLError
        transport = WebhookTransport(url="http://unreachable.example.com/ingest", timeout=0.01)
        with patch("provable_ai.siem.urlopen", side_effect=URLError("connection refused")):
            transport.send(_event())  # must not raise

    def test_from_env_returns_none_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("ZORYNEX_SIEM_WEBHOOK_URL", raising=False)
        assert WebhookTransport.from_env() is None

    def test_from_env_returns_transport_when_url_set(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_WEBHOOK_URL", "http://siem.example.com/ingest")
        t = WebhookTransport.from_env()
        assert t is not None
        assert t._url == "http://siem.example.com/ingest"


# ═══════════════════════════════════════════════════════════════════════════════
# PART 3 — SyslogTransport
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyslogTransport:

    def test_rfc5424_format(self):
        transport = SyslogTransport(host="localhost", port=514)
        msg = transport._format_rfc5424(_event(level="warning"))
        text = msg.decode("utf-8")
        # RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME ...
        assert text.startswith("<")
        assert ">1 " in text
        assert "zorynex" in text
        assert "decision_recorded" in text

    def test_priority_calculation(self):
        # facility=16 (local0), severity=info(6) → priority = 16*8+6 = 134
        transport = SyslogTransport(facility=16)
        msg = transport._format_rfc5424(_event(level="info")).decode()
        assert msg.startswith("<134>")

    def test_warning_severity(self):
        # facility=16, severity=warning(4) → 16*8+4 = 132
        transport = SyslogTransport(facility=16)
        msg = transport._format_rfc5424(_event(level="warning")).decode()
        assert msg.startswith("<132>")

    def test_error_severity(self):
        # facility=16, severity=error(3) → 16*8+3 = 131
        transport = SyslogTransport(facility=16)
        msg = transport._format_rfc5424(_event(level="error")).decode()
        assert msg.startswith("<131>")

    def test_udp_send(self):
        sent = []

        class FakeSocket:
            def sendto(self, data, addr):
                sent.append((data, addr))
            def close(self):
                pass

        transport = SyslogTransport(host="syslog.example.com", port=514, proto="udp")
        with patch("provable_ai.siem.socket.socket", return_value=FakeSocket()):
            transport.send(_event())

        assert len(sent) == 1
        assert sent[0][1] == ("syslog.example.com", 514)

    def test_udp_error_does_not_raise(self):
        transport = SyslogTransport(host="unreachable", port=514, proto="udp")
        with patch("provable_ai.siem.socket.socket") as MockSock:
            MockSock.return_value.sendto.side_effect = OSError("network error")
            MockSock.return_value.close = MagicMock()
            transport.send(_event())  # must not raise

    def test_from_env_returns_none_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("ZORYNEX_SIEM_SYSLOG_HOST", raising=False)
        assert SyslogTransport.from_env() is None

    def test_from_env_reads_port_and_proto(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_SYSLOG_HOST", "syslog.example.com")
        monkeypatch.setenv("ZORYNEX_SIEM_SYSLOG_PORT", "1514")
        monkeypatch.setenv("ZORYNEX_SIEM_SYSLOG_PROTO", "tcp")
        t = SyslogTransport.from_env()
        assert t._port  == 1514
        assert t._proto == "tcp"

    def test_message_contains_json(self):
        transport = SyslogTransport()
        msg = transport._format_rfc5424(_event(proof_id="abc123")).decode()
        assert "abc123" in msg
        assert "bank_abc" in msg


# ═══════════════════════════════════════════════════════════════════════════════
# PART 4 — SplunkHECTransport
# ═══════════════════════════════════════════════════════════════════════════════

class TestSplunkHECTransport:

    def test_envelope_structure(self):
        transport = SplunkHECTransport(url="http://splunk:8088/services/collector",
                                        token="my-token", index="zorynex")
        env = transport._splunk_envelope(_event(proof_id="abc"))
        assert "time"       in env
        assert env["index"] == "zorynex"
        assert "event"      in env
        assert env["event"]["proof_id"] == "abc"
        assert env["event"]["source"]   == "zorynex"

    def test_batches_events(self):
        sent_bodies = []

        def fake_urlopen(req, timeout=None):
            sent_bodies.append(req.data.decode())
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = SplunkHECTransport(
            url="http://splunk:8088/services/collector",
            token="tok", batch_size=3,
        )
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            for _ in range(3):
                transport.send(_event())  # 3rd event triggers flush
            # 3 events → 1 batch POST
            assert len(sent_bodies) == 1
            # Body contains 3 newline-delimited JSON objects
            lines = [l for l in sent_bodies[0].split("\n") if l]
            assert len(lines) == 3

    def test_flush_sends_remaining(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req.data.decode())
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = SplunkHECTransport(
            url="http://splunk:8088/services/collector",
            token="tok", batch_size=100,
        )
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(_event())
            transport.send(_event())
            assert len(sent) == 0  # not flushed yet (below batch_size)
            transport.flush()
            assert len(sent) == 1  # flushed

    def test_splunk_auth_header(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req)
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = SplunkHECTransport(
            url="http://splunk:8088/services/collector",
            token="my-hec-token", batch_size=1,
        )
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(_event())

        assert sent[0].get_header("Authorization") == "Splunk my-hec-token"

    def test_network_error_does_not_raise(self):
        transport = SplunkHECTransport(
            url="http://unreachable:8088/services/collector",
            token="tok", batch_size=1,
        )
        with patch("provable_ai.siem.urlopen", side_effect=Exception("network error")):
            transport.send(_event())  # must not raise

    def test_from_env_returns_none_without_url(self, monkeypatch):
        monkeypatch.delenv("ZORYNEX_SIEM_SPLUNK_URL", raising=False)
        monkeypatch.delenv("ZORYNEX_SIEM_SPLUNK_TOKEN", raising=False)
        assert SplunkHECTransport.from_env() is None

    def test_from_env_reads_index(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_SPLUNK_URL",   "http://splunk:8088/services/collector")
        monkeypatch.setenv("ZORYNEX_SIEM_SPLUNK_TOKEN", "tok")
        monkeypatch.setenv("ZORYNEX_SIEM_SPLUNK_INDEX", "my-index")
        t = SplunkHECTransport.from_env()
        assert t._index == "my-index"


# ═══════════════════════════════════════════════════════════════════════════════
# PART 5 — DatadogTransport
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatadogTransport:

    def test_payload_structure(self):
        transport = DatadogTransport(api_key="dd-key", service="zorynex", env="test")
        payload = transport._dd_payload(_event(proof_id="abc"))
        assert payload["ddsource"] == "zorynex"
        assert payload["service"]  == "zorynex"
        assert "zorynex" in payload["ddtags"]
        assert "test"    in payload["ddtags"]
        assert "proof_id" in payload  # extras merged in
        assert "message"  in payload  # full JSON

    def test_sends_with_api_key_header(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            sent.append(req)
            resp = MagicMock()
            resp.status = 202
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = DatadogTransport(api_key="dd-key-123")
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send(_event())

        assert sent[0].get_header("Dd-api-key") == "dd-key-123"

    def test_dd_url_uses_site(self):
        transport = DatadogTransport(api_key="k", site="datadoghq.eu")
        assert "datadoghq.eu" in transport._url

    def test_send_batch_posts_array(self):
        sent_bodies = []

        def fake_urlopen(req, timeout=None):
            sent_bodies.append(json.loads(req.data.decode()))
            resp = MagicMock()
            resp.status = 202
            resp.__enter__ = lambda s: s
            resp.__exit__  = MagicMock(return_value=False)
            return resp

        transport = DatadogTransport(api_key="k")
        events = [_event(event=f"event_{i}") for i in range(3)]
        with patch("provable_ai.siem.urlopen", fake_urlopen):
            transport.send_batch(events)

        assert len(sent_bodies) == 1
        assert len(sent_bodies[0]) == 3

    def test_network_error_does_not_raise(self):
        transport = DatadogTransport(api_key="k")
        with patch("provable_ai.siem.urlopen", side_effect=Exception("network")):
            transport.send(_event())  # must not raise

    def test_from_env_returns_none_without_api_key(self, monkeypatch):
        monkeypatch.delenv("ZORYNEX_SIEM_DATADOG_API_KEY", raising=False)
        assert DatadogTransport.from_env() is None

    def test_from_env_reads_site_and_service(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_DATADOG_API_KEY", "dd-key")
        monkeypatch.setenv("ZORYNEX_SIEM_DATADOG_SITE",    "datadoghq.eu")
        monkeypatch.setenv("ZORYNEX_SIEM_DATADOG_SERVICE", "my-app")
        t = DatadogTransport.from_env()
        assert "datadoghq.eu" in t._url
        assert t._service == "my-app"


# ═══════════════════════════════════════════════════════════════════════════════
# PART 6 — SIEMRouter
# ═══════════════════════════════════════════════════════════════════════════════

class TestSIEMRouter:

    def _wait_delivery(self, transport: _MockTransport, count: int, timeout: float = 2.0):
        deadline = time.time() + timeout
        while len(transport.received) < count and time.time() < deadline:
            time.sleep(0.01)

    def test_delivers_to_transport(self):
        t = _MockTransport()
        r = _router(t)
        r.emit(_event())
        self._wait_delivery(t, 1)
        assert len(t.received) == 1
        assert t.received[0].event == "decision_recorded"

    def test_delivers_to_multiple_transports(self):
        t1 = _MockTransport()
        t2 = _MockTransport()
        r  = _router(t1, t2)
        r.emit(_event())
        self._wait_delivery(t1, 1)
        self._wait_delivery(t2, 1)
        assert len(t1.received) == 1
        assert len(t2.received) == 1

    def test_filters_below_min_level(self):
        t = _MockTransport()
        r = _router(t, min_level="warning")
        r.emit(_event(level="info"))     # filtered
        r.emit(_event(level="warning"))  # passes
        r.emit(_event(level="error"))    # passes
        self._wait_delivery(t, 2)
        time.sleep(0.05)
        assert len(t.received) == 2

    def test_info_passes_when_min_level_info(self):
        t = _MockTransport()
        r = _router(t, min_level="info")
        r.emit(_event(level="info"))
        self._wait_delivery(t, 1)
        assert len(t.received) == 1

    def test_queue_full_increments_drop_counter(self):
        t = _MockTransport(delay=0.5)  # slow transport
        r = SIEMRouter([t], min_level="info", workers=1, queue_size=2)
        # Flood the queue
        for _ in range(20):
            r.emit(_event())
        # Some must have been dropped
        assert r.metrics()["dropped"] > 0

    def test_emitted_counter(self):
        t = _MockTransport()
        r = _router(t)
        for _ in range(5):
            r.emit(_event())
        assert r.metrics()["emitted"] == 5

    def test_transport_failure_does_not_crash_router(self):
        t = _MockTransport(fail=True)
        r = _router(t)
        r.emit(_event())  # transport fails internally
        time.sleep(0.1)   # let worker run
        # Router is still alive
        assert r.metrics()["emitted"] == 1

    def test_metrics_structure(self):
        t = _MockTransport()
        r = _router(t)
        m = r.metrics()
        assert "emitted"    in m
        assert "dropped"    in m
        assert "queue_size" in m
        assert "transports" in m
        assert "mock" in m["transports"]

    def test_enabled_true_with_transports(self):
        r = _router(_MockTransport())
        assert r.enabled is True

    def test_enabled_false_without_transports(self):
        r = _router()
        assert r.enabled is False

    def test_flush_calls_transport_flush(self):
        t = _MockTransport()
        r = _router(t)
        r.flush()
        assert t.flushed is True


# ═══════════════════════════════════════════════════════════════════════════════
# PART 7 — emit_from_log
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmitFromLog:

    def test_converts_log_dict_to_siem_event(self):
        t = _MockTransport()
        r = _router(t)
        r.emit_from_log({
            "level":     "warning",
            "message":   "governance_rejection",
            "tenant_id": "bank_abc",
            "trace_id":  "trace-001",
            "timestamp": "2026-05-01T00:00:00Z",
            "model_version": "bad-model",
        })
        deadline = time.time() + 1.0
        while not t.received and time.time() < deadline:
            time.sleep(0.01)
        assert len(t.received) == 1
        e = t.received[0]
        assert e.event     == "governance_rejection"
        assert e.level     == "warning"
        assert e.tenant_id == "bank_abc"
        assert e.extras.get("model_version") == "bad-model"

    def test_excludes_reserved_fields_from_extras(self):
        t = _MockTransport()
        r = _router(t)
        r.emit_from_log({
            "level":     "info",
            "message":   "test_event",
            "tenant_id": "t",
            "trace_id":  "r",
            "timestamp": "2026-05-01T00:00:00Z",
            "source":    "zorynex",
            "version":   "1.0",
            "proof_id":  "abc",   # should be in extras
        })
        deadline = time.time() + 1.0
        while not t.received and time.time() < deadline:
            time.sleep(0.01)
        e = t.received[0]
        assert "source"    not in e.extras
        assert "version"   not in e.extras
        assert "timestamp" not in e.extras
        assert e.extras.get("proof_id") == "abc"

    def test_missing_fields_use_defaults(self):
        t = _MockTransport()
        r = _router(t)
        r.emit_from_log({"message": "bare_event"})
        deadline = time.time() + 1.0
        while not t.received and time.time() < deadline:
            time.sleep(0.01)
        e = t.received[0]
        assert e.event     == "bare_event"
        assert e.level     == "info"
        assert e.tenant_id == "default"


# ═══════════════════════════════════════════════════════════════════════════════
# PART 8 — Factory (siem_router_from_env)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFactory:

    def test_no_env_vars_creates_empty_router(self, monkeypatch):
        for v in ["ZORYNEX_SIEM_WEBHOOK_URL", "ZORYNEX_SIEM_SYSLOG_HOST",
                  "ZORYNEX_SIEM_SPLUNK_URL",  "ZORYNEX_SIEM_DATADOG_API_KEY"]:
            monkeypatch.delenv(v, raising=False)
        r = siem_router_from_env()
        assert r.enabled is False
        assert r.metrics()["transports"] == []

    def test_webhook_url_activates_webhook_transport(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_WEBHOOK_URL", "http://siem.example.com/ingest")
        for v in ["ZORYNEX_SIEM_SYSLOG_HOST", "ZORYNEX_SIEM_SPLUNK_URL",
                  "ZORYNEX_SIEM_DATADOG_API_KEY"]:
            monkeypatch.delenv(v, raising=False)
        r = siem_router_from_env()
        assert "webhook" in r.metrics()["transports"]

    def test_multiple_transports_activated(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_WEBHOOK_URL",     "http://siem.example.com/ingest")
        monkeypatch.setenv("ZORYNEX_SIEM_SYSLOG_HOST",     "syslog.example.com")
        monkeypatch.setenv("ZORYNEX_SIEM_DATADOG_API_KEY", "dd-key")
        monkeypatch.delenv("ZORYNEX_SIEM_SPLUNK_URL", raising=False)
        monkeypatch.delenv("ZORYNEX_SIEM_SPLUNK_TOKEN", raising=False)
        r = siem_router_from_env()
        transports = r.metrics()["transports"]
        assert "webhook" in transports
        assert "syslog"  in transports
        assert "datadog" in transports

    def test_min_level_from_env(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIEM_LEVEL", "error")
        for v in ["ZORYNEX_SIEM_WEBHOOK_URL", "ZORYNEX_SIEM_SYSLOG_HOST",
                  "ZORYNEX_SIEM_SPLUNK_URL",  "ZORYNEX_SIEM_DATADOG_API_KEY"]:
            monkeypatch.delenv(v, raising=False)
        r = siem_router_from_env()
        assert r._min_level == _LEVELS["error"]


# ═══════════════════════════════════════════════════════════════════════════════
# PART 9 — Thread safety
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreadSafety:

    def test_concurrent_emits_all_delivered(self):
        t = _MockTransport()
        r = SIEMRouter([t], min_level="info", workers=3, queue_size=500)

        def worker():
            for _ in range(50):
                r.emit(_event())

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        # Wait for delivery
        deadline = time.time() + 3.0
        while len(t.received) < 250 and time.time() < deadline:
            time.sleep(0.02)

        assert len(t.received) == 250
        assert r.metrics()["emitted"] == 250

    def test_concurrent_metrics_reads_safe(self):
        t = _MockTransport()
        r = _router(t)
        errors = []

        def reader():
            try:
                for _ in range(100):
                    r.metrics()
            except Exception as e:
                errors.append(e)

        def emitter():
            for _ in range(100):
                r.emit(_event())

        threads = [threading.Thread(target=reader) for _ in range(3)] + \
                  [threading.Thread(target=emitter) for _ in range(2)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert errors == []


# ═══════════════════════════════════════════════════════════════════════════════
# PART 10 — Global emit() convenience function
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmitConvenience:

    def test_emit_uses_global_router(self, monkeypatch):
        import provable_ai.siem as siem_mod
        mock_router = MagicMock()
        monkeypatch.setattr(siem_mod, "_router", mock_router)
        emit("test_event", tenant_id="t", trace_id="r", proof_id="abc")
        mock_router.emit.assert_called_once()
        call_args = mock_router.emit.call_args[0][0]
        assert call_args.event     == "test_event"
        assert call_args.tenant_id == "t"
        assert call_args.extras.get("proof_id") == "abc"

    def test_emit_creates_siem_event(self, monkeypatch):
        import provable_ai.siem as siem_mod
        received = []

        class CapturingRouter:
            def emit(self, ev):
                received.append(ev)

        monkeypatch.setattr(siem_mod, "_router", CapturingRouter())
        emit("governance_rejection", level="warning", tenant_id="bank", to_state="rejected")
        assert len(received) == 1
        assert received[0].level == "warning"
        assert received[0].extras.get("to_state") == "rejected"