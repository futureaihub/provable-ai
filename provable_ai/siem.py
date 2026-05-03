"""
Zorynex — SIEM Integration
============================
Forwards Zorynex audit events to external security information and event
management (SIEM) systems.

Three transport modes (can be combined):
    1. Webhook    — POST JSON to any HTTP endpoint (generic, works with most SIEMs)
    2. Syslog     — RFC 5424 UDP/TCP syslog (Splunk, Elastic, QRadar, etc.)
    3. Splunk HEC — Splunk HTTP Event Collector (structured, batched)
    4. Datadog    — Datadog Logs API (structured, tagged)

Design principles:
    - Non-blocking: all transports run in a background thread pool
    - Non-fatal:    SIEM delivery failure never fails the primary operation
    - Structured:   all events are JSON with consistent field names
    - Filterable:   emit only events above a configured severity threshold
    - Idempotent:   duplicate delivery is acceptable; missing delivery is not

Event schema (every event has these fields):
    {
      "event":       str   — machine-readable event type (e.g. "decision_recorded")
      "level":       str   — "info" | "warning" | "error" | "critical"
      "timestamp":   str   — ISO-8601 UTC
      "tenant_id":   str   — which tenant this event belongs to
      "trace_id":    str   — request trace ID
      "source":      str   — "zorynex"
      "version":     str   — "1.0"
      ...extra       dict  — event-specific fields
    }

Environment variables:
    ZORYNEX_SIEM_LEVEL          Minimum level to forward: info|warning|error (default: info)

    # Webhook
    ZORYNEX_SIEM_WEBHOOK_URL    HTTP(S) endpoint to POST events to
    ZORYNEX_SIEM_WEBHOOK_SECRET Optional HMAC-SHA256 secret for X-Zorynex-Signature header
    ZORYNEX_SIEM_WEBHOOK_TIMEOUT_S  Seconds before timeout (default: 5)

    # Syslog
    ZORYNEX_SIEM_SYSLOG_HOST    Syslog server hostname
    ZORYNEX_SIEM_SYSLOG_PORT    Syslog server port (default: 514)
    ZORYNEX_SIEM_SYSLOG_PROTO   "udp" | "tcp" (default: udp)
    ZORYNEX_SIEM_SYSLOG_FACILITY Facility code 0-23 (default: 16 = local0)

    # Splunk HEC
    ZORYNEX_SIEM_SPLUNK_URL     e.g. https://splunk.example.com:8088/services/collector
    ZORYNEX_SIEM_SPLUNK_TOKEN   Splunk HEC token
    ZORYNEX_SIEM_SPLUNK_INDEX   Splunk index name (default: zorynex)
    ZORYNEX_SIEM_SPLUNK_BATCH   Max events per batch (default: 50)

    # Datadog
    ZORYNEX_SIEM_DATADOG_API_KEY  Datadog API key
    ZORYNEX_SIEM_DATADOG_SITE     Datadog site (default: datadoghq.com)
    ZORYNEX_SIEM_DATADOG_SERVICE  Service tag (default: zorynex)
    ZORYNEX_SIEM_DATADOG_ENV      Environment tag (default: production)

Usage:
    from provable_ai.siem import get_siem_router, SIEMEvent

    router = get_siem_router()

    # Emit from anywhere in the codebase
    router.emit(SIEMEvent(
        event     = "decision_recorded",
        level     = "info",
        tenant_id = "bank_abc",
        trace_id  = "uuid-...",
        proof_id  = "a3f8...",
        to_state  = "approved",
    ))

    # Or emit directly from the server _log hook (no code change needed)
    # by calling router.emit_from_log(log_dict)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("zorynex.siem")

_LEVELS = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}


# ── Event model ───────────────────────────────────────────────────────────────

@dataclass
class SIEMEvent:
    """
    A structured security event ready for SIEM ingestion.

    Required fields: event, level, tenant_id, trace_id
    Optional fields: any additional kwargs stored in extras
    """
    event:      str
    level:      str          = "info"
    tenant_id:  str          = "default"
    trace_id:   str          = ""
    extras:     dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source":    "zorynex",
            "version":   "1.0",
            "event":     self.event,
            "level":     self.level,
            "timestamp": _utcnow(),
            "tenant_id": self.tenant_id,
            "trace_id":  self.trace_id,
            **self.extras,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Base transport ────────────────────────────────────────────────────────────

class BaseTransport:
    """
    Base class for SIEM transports.
    All transports are non-blocking — delivery happens in the background.
    Failures are logged but never raise.
    """

    name: str = "base"

    def send(self, event: SIEMEvent) -> None:
        raise NotImplementedError

    def send_batch(self, events: list[SIEMEvent]) -> None:
        for e in events:
            self.send(e)

    def flush(self) -> None:
        """Optional: flush any buffered events."""


# ── Webhook transport ─────────────────────────────────────────────────────────

class WebhookTransport(BaseTransport):
    """
    POST each event as JSON to an HTTP endpoint.
    Includes HMAC-SHA256 signature header when secret is configured.

    Compatible with: Elastic Logstash HTTP input, Sumo Logic HTTP source,
    custom SIEM ingestion endpoints, any webhook receiver.
    """

    name = "webhook"

    def __init__(
        self,
        url:     str,
        secret:  str = "",
        timeout: float = 5.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url     = url
        self._secret  = secret.encode() if secret else b""
        self._timeout = timeout
        self._headers = headers or {}

    def send(self, event: SIEMEvent) -> None:
        body = event.to_json().encode("utf-8")
        hdrs = {
            "Content-Type": "application/json",
            "User-Agent":   "zorynex-siem/1.0",
            **self._headers,
        }

        if self._secret:
            sig = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            hdrs["X-Zorynex-Signature"] = f"sha256={sig}"

        try:
            req = Request(self._url, data=body, headers=hdrs, method="POST")
            with urlopen(req, timeout=self._timeout) as resp:
                status = resp.status
                if status >= 400:
                    logger.warning("Webhook SIEM rejected event: HTTP %d", status)
        except URLError as e:
            logger.warning("Webhook SIEM delivery failed: %s", e)
        except Exception as e:
            logger.warning("Webhook SIEM unexpected error: %s", e)

    @classmethod
    def from_env(cls) -> "WebhookTransport | None":
        url = os.environ.get("ZORYNEX_SIEM_WEBHOOK_URL", "")
        if not url:
            return None
        return cls(
            url     = url,
            secret  = os.environ.get("ZORYNEX_SIEM_WEBHOOK_SECRET", ""),
            timeout = float(os.environ.get("ZORYNEX_SIEM_WEBHOOK_TIMEOUT_S", "5")),
        )


# ── Syslog transport ──────────────────────────────────────────────────────────

class SyslogTransport(BaseTransport):
    """
    RFC 5424 syslog transport (UDP or TCP).

    Severity mapping: info→6, warning→4, error→3, critical→2
    Facility: configurable (default: 16 = local0)

    Compatible with: Splunk syslog, rsyslog, syslog-ng, Elastic Beats.
    """

    name = "syslog"

    _SEVERITY = {"debug": 7, "info": 6, "warning": 4, "error": 3, "critical": 2}

    def __init__(
        self,
        host:     str  = "localhost",
        port:     int  = 514,
        proto:    str  = "udp",
        facility: int  = 16,    # local0
        app_name: str  = "zorynex",
    ) -> None:
        self._host     = host
        self._port     = port
        self._proto    = proto.lower()
        self._facility = facility
        self._app_name = app_name
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()

    def _get_sock(self) -> socket.socket:
        if self._proto == "tcp":
            if self._sock is None or self._sock.fileno() == -1:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self._host, self._port))
                self._sock = sock
            return self._sock
        else:
            # UDP: stateless, create fresh each time
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _format_rfc5424(self, event: SIEMEvent) -> bytes:
        """
        Format event as RFC 5424 syslog message.
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        """
        severity = self._SEVERITY.get(event.level, 6)
        priority = self._facility * 8 + severity
        ts       = _utcnow()
        hostname = socket.gethostname()
        msg      = event.to_json()

        line = (
            f"<{priority}>1 {ts} {hostname} {self._app_name} - "
            f"{event.event} - {msg}"
        )
        return line.encode("utf-8")

    def send(self, event: SIEMEvent) -> None:
        data = self._format_rfc5424(event)
        with self._lock:
            try:
                if self._proto == "tcp":
                    sock = self._get_sock()
                    sock.sendall(data + b"\n")
                else:
                    sock = self._get_sock()
                    sock.sendto(data, (self._host, self._port))
                    sock.close()
            except OSError as e:
                logger.warning("Syslog SIEM delivery failed: %s", e)
                if self._proto == "tcp":
                    self._sock = None  # force reconnect next time

    def flush(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    @classmethod
    def from_env(cls) -> "SyslogTransport | None":
        host = os.environ.get("ZORYNEX_SIEM_SYSLOG_HOST", "")
        if not host:
            return None
        return cls(
            host     = host,
            port     = int(os.environ.get("ZORYNEX_SIEM_SYSLOG_PORT", "514")),
            proto    = os.environ.get("ZORYNEX_SIEM_SYSLOG_PROTO", "udp"),
            facility = int(os.environ.get("ZORYNEX_SIEM_SYSLOG_FACILITY", "16")),
        )


# ── Splunk HEC transport ──────────────────────────────────────────────────────

class SplunkHECTransport(BaseTransport):
    """
    Splunk HTTP Event Collector (HEC) transport.

    Batches events and POSTs them to the HEC endpoint.
    Each event is a separate JSON object (newline-delimited, Splunk format).

    https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
    """

    name = "splunk"

    def __init__(
        self,
        url:       str,
        token:     str,
        index:     str  = "zorynex",
        source:    str  = "zorynex",
        sourcetype:str  = "_json",
        batch_size:int  = 50,
        timeout:   float = 10.0,
    ) -> None:
        self._url        = url.rstrip("/")
        self._token      = token
        self._index      = index
        self._source     = source
        self._sourcetype = sourcetype
        self._batch_size = batch_size
        self._timeout    = timeout
        self._buffer:    list[dict] = []
        self._lock       = threading.Lock()

    def _splunk_envelope(self, event: SIEMEvent) -> dict:
        d = event.to_dict()
        return {
            "time":       time.time(),
            "index":      self._index,
            "source":     self._source,
            "sourcetype": self._sourcetype,
            "event":      d,
        }

    def send(self, event: SIEMEvent) -> None:
        with self._lock:
            self._buffer.append(self._splunk_envelope(event))
            if len(self._buffer) >= self._batch_size:
                self._flush_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()

        # Splunk HEC format: newline-delimited JSON objects
        body = "\n".join(json.dumps(e, separators=(",", ":")) for e in batch)
        body_bytes = body.encode("utf-8")

        try:
            req = Request(
                self._url,
                data    = body_bytes,
                headers = {
                    "Authorization": f"Splunk {self._token}",
                    "Content-Type":  "application/json",
                    "User-Agent":    "zorynex-siem/1.0",
                },
                method  = "POST",
            )
            with urlopen(req, timeout=self._timeout) as resp:
                if resp.status not in (200, 204):
                    logger.warning("Splunk HEC rejected batch: HTTP %d", resp.status)
        except Exception as e:
            logger.warning("Splunk HEC delivery failed (%d events): %s", len(batch), e)

    @classmethod
    def from_env(cls) -> "SplunkHECTransport | None":
        url   = os.environ.get("ZORYNEX_SIEM_SPLUNK_URL", "")
        token = os.environ.get("ZORYNEX_SIEM_SPLUNK_TOKEN", "")
        if not url or not token:
            return None
        return cls(
            url        = url,
            token      = token,
            index      = os.environ.get("ZORYNEX_SIEM_SPLUNK_INDEX", "zorynex"),
            batch_size = int(os.environ.get("ZORYNEX_SIEM_SPLUNK_BATCH", "50")),
        )


# ── Datadog transport ─────────────────────────────────────────────────────────

class DatadogTransport(BaseTransport):
    """
    Datadog Logs API transport.

    POSTs structured log events to the Datadog Logs intake endpoint.
    Tags events with service, env, and source for easy filtering.

    https://docs.datadoghq.com/api/latest/logs/#send-logs
    """

    name = "datadog"

    def __init__(
        self,
        api_key: str,
        site:    str = "datadoghq.com",
        service: str = "zorynex",
        env:     str = "production",
        timeout: float = 10.0,
    ) -> None:
        self._api_key = api_key
        self._url     = f"https://http-intake.logs.{site}/api/v2/logs"
        self._service = service
        self._env     = env
        self._timeout = timeout

    def _dd_payload(self, event: SIEMEvent) -> dict:
        d = event.to_dict()
        return {
            "ddsource": "zorynex",
            "ddtags":   f"env:{self._env},service:{self._service},event:{event.event}",
            "hostname": socket.gethostname(),
            "message":  event.to_json(),
            "service":  self._service,
            **d,
        }

    def send(self, event: SIEMEvent) -> None:
        payload = [self._dd_payload(event)]
        body    = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            req = Request(
                self._url,
                data    = body,
                headers = {
                    "DD-API-KEY":   self._api_key,
                    "Content-Type": "application/json",
                    "User-Agent":   "zorynex-siem/1.0",
                },
                method  = "POST",
            )
            with urlopen(req, timeout=self._timeout) as resp:
                if resp.status not in (200, 202):
                    logger.warning("Datadog rejected event: HTTP %d", resp.status)
        except Exception as e:
            logger.warning("Datadog delivery failed: %s", e)

    def send_batch(self, events: list[SIEMEvent]) -> None:
        if not events:
            return
        payload = [self._dd_payload(e) for e in events]
        body    = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            req = Request(
                self._url,
                data    = body,
                headers = {
                    "DD-API-KEY":   self._api_key,
                    "Content-Type": "application/json",
                    "User-Agent":   "zorynex-siem/1.0",
                },
                method  = "POST",
            )
            with urlopen(req, timeout=self._timeout) as resp:
                if resp.status not in (200, 202):
                    logger.warning("Datadog batch rejected: HTTP %d", resp.status)
        except Exception as e:
            logger.warning("Datadog batch delivery failed (%d events): %s", len(events), e)

    @classmethod
    def from_env(cls) -> "DatadogTransport | None":
        api_key = os.environ.get("ZORYNEX_SIEM_DATADOG_API_KEY", "")
        if not api_key:
            return None
        return cls(
            api_key = api_key,
            site    = os.environ.get("ZORYNEX_SIEM_DATADOG_SITE",    "datadoghq.com"),
            service = os.environ.get("ZORYNEX_SIEM_DATADOG_SERVICE", "zorynex"),
            env     = os.environ.get("ZORYNEX_SIEM_DATADOG_ENV",     "production"),
        )


# ── Router ────────────────────────────────────────────────────────────────────

class SIEMRouter:
    """
    Routes audit events to all configured transports in background threads.

    Non-blocking: events are placed on a queue and sent by a worker pool.
    Non-fatal:    delivery failures are logged but never propagate.
    Filterable:   events below min_level are discarded immediately.

    The worker pool uses daemon threads — they stop when the process exits.
    Call flush() on graceful shutdown to drain the queue.
    """

    def __init__(
        self,
        transports: list[BaseTransport],
        min_level:  str = "info",
        workers:    int = 2,
        queue_size: int = 1000,
    ) -> None:
        self._transports  = transports
        self._min_level   = _LEVELS.get(min_level.lower(), 1)
        self._queue: queue.Queue[SIEMEvent | None] = queue.Queue(maxsize=queue_size)
        self._dropped     = 0
        self._emitted     = 0
        self._lock        = threading.Lock()

        # Start background worker threads
        for i in range(workers):
            t = threading.Thread(
                target=self._worker,
                name=f"zorynex-siem-worker-{i}",
                daemon=True,
            )
            t.start()

        if transports:
            logger.info(
                "SIEMRouter ready: transports=%s min_level=%s workers=%d",
                [t.name for t in transports], min_level, workers,
            )

    def emit(self, event: SIEMEvent) -> None:
        """
        Enqueue an event for delivery. Non-blocking.
        If the queue is full, the event is dropped and the drop counter increments.
        """
        if _LEVELS.get(event.level.lower(), 1) < self._min_level:
            return

        with self._lock:
            self._emitted += 1

        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            logger.warning("SIEM queue full — event dropped: %s", event.event)

    def emit_from_log(self, log_dict: dict) -> None:
        """
        Convert a Zorynex structured log dict to a SIEMEvent and emit it.
        Used to hook into the server _log() function without code changes.
        """
        event = SIEMEvent(
            event     = log_dict.get("message", "unknown"),
            level     = log_dict.get("level", "info"),
            tenant_id = log_dict.get("tenant_id", "default"),
            trace_id  = log_dict.get("trace_id", ""),
            extras    = {k: v for k, v in log_dict.items()
                        if k not in ("message", "level", "tenant_id", "trace_id",
                                     "timestamp", "source", "version")},
        )
        self.emit(event)

    def _worker(self) -> None:
        """Background worker: drain queue and deliver to all transports."""
        while True:
            try:
                event = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if event is None:
                # Sentinel: graceful shutdown
                self._queue.task_done()
                return

            for transport in self._transports:
                try:
                    transport.send(event)
                except Exception as e:
                    logger.warning("Transport %s failed: %s", transport.name, e)

            self._queue.task_done()

    def flush(self, timeout: float = 10.0) -> None:
        """
        Flush all pending events. Call on graceful shutdown.
        Sends sentinel None to stop workers after queue is drained.
        """
        for transport in self._transports:
            try:
                transport.flush()
            except Exception:
                pass

        # Drain the queue
        deadline = time.time() + timeout
        while not self._queue.empty() and time.time() < deadline:
            time.sleep(0.05)

    def metrics(self) -> dict:
        with self._lock:
            return {
                "emitted":    self._emitted,
                "dropped":    self._dropped,
                "queue_size": self._queue.qsize(),
                "transports": [t.name for t in self._transports],
            }

    @property
    def enabled(self) -> bool:
        return len(self._transports) > 0


# ── Factory ───────────────────────────────────────────────────────────────────

def siem_router_from_env() -> SIEMRouter:
    """
    Build a SIEMRouter from environment variables.
    Transports are enabled only if their required env vars are set.
    Multiple transports can be active simultaneously.
    """
    transports: list[BaseTransport] = []

    wh = WebhookTransport.from_env()
    if wh:
        transports.append(wh)

    sl = SyslogTransport.from_env()
    if sl:
        transports.append(sl)

    sp = SplunkHECTransport.from_env()
    if sp:
        transports.append(sp)

    dd = DatadogTransport.from_env()
    if dd:
        transports.append(dd)

    min_level = os.environ.get("ZORYNEX_SIEM_LEVEL", "info")
    return SIEMRouter(transports=transports, min_level=min_level)


# ── Singleton ─────────────────────────────────────────────────────────────────

_router: SIEMRouter | None = None


def get_siem_router() -> SIEMRouter:
    global _router
    if _router is None:
        _router = siem_router_from_env()
    return _router


def emit(event_name: str, level: str = "info", tenant_id: str = "default",
         trace_id: str = "", **kwargs) -> None:
    """
    Convenience function: emit a SIEM event from anywhere.

    from provable_ai.siem import emit
    emit("decision_recorded", tenant_id=tid, trace_id=rid, proof_id=pid)
    """
    get_siem_router().emit(SIEMEvent(
        event=event_name, level=level,
        tenant_id=tenant_id, trace_id=trace_id,
        extras=kwargs,
    ))