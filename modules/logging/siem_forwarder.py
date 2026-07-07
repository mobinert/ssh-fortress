"""
SIEMForwarder — receives SSHEvent objects and fans them out to all
configured SIEM backends concurrently:

  • Elasticsearch (HTTP bulk API)
  • Splunk HEC
  • Syslog (UDP/TCP/TLS) with CEF, RFC5424, or JSON encoding
  • Apache Kafka
  • Generic webhook

Architecture:
  • Each backend runs in its own thread with an asyncio event loop
  • Per-backend queue (maxsize=10_000) with backpressure drop + counter
  • Batching with configurable size and flush interval
  • Exponential backoff on backend failures
  • Dropped event counter exposed via metrics
"""

from __future__ import annotations

import asyncio
import json
import queue
import socket
import ssl
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from modules.core import ConfigManager, get_logger
from modules.logging.log_parser import SSHEvent

_LOG = get_logger("logging.siem_forwarder")

_HOSTNAME = socket.gethostname()


# ── Base backend ─────────────────────────────────────────────────────────────

class _BaseBackend(ABC):
    BATCH_SIZE = 100
    FLUSH_INTERVAL = 5.0   # seconds

    def __init__(self, name: str, cfg: dict) -> None:
        self.name = name
        self._cfg = cfg
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=10_000)
        self._dropped = 0
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"siem-{name}"
        )
        self.BATCH_SIZE = cfg.get("batch_size", self.BATCH_SIZE)
        self.FLUSH_INTERVAL = float(cfg.get("flush_interval", self.FLUSH_INTERVAL))

    def start(self) -> None:
        self._thread.start()

    def enqueue(self, doc: dict) -> None:
        try:
            self._queue.put_nowait(doc)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:
                _LOG.warning("SIEM queue full — events dropped", backend=self.name, dropped=self._dropped)

    @abstractmethod
    def _send_batch(self, batch: list[dict]) -> None: ...

    def _run(self) -> None:
        batch: list[dict] = []
        deadline = time.monotonic() + self.FLUSH_INTERVAL
        backoff = 1.0

        while True:
            timeout = max(0.1, deadline - time.monotonic())
            try:
                doc = self._queue.get(timeout=timeout)
                batch.append(doc)
            except queue.Empty:
                pass

            should_flush = len(batch) >= self.BATCH_SIZE or time.monotonic() >= deadline
            if should_flush and batch:
                try:
                    self._send_batch(batch)
                    batch = []
                    backoff = 1.0
                except Exception as e:
                    _LOG.error("SIEM send failed", backend=self.name, error=str(e),
                               retry_in=backoff, events=len(batch))
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
                    # Keep batch for retry
                deadline = time.monotonic() + self.FLUSH_INTERVAL


# ── Elasticsearch backend ─────────────────────────────────────────────────────

class _ElasticsearchBackend(_BaseBackend):

    def __init__(self, cfg: dict) -> None:
        super().__init__("elasticsearch", cfg)
        from elasticsearch import Elasticsearch  # type: ignore[import]
        kwargs: dict[str, Any] = {
            "hosts": cfg.get("hosts", ["https://localhost:9200"]),
            "verify_certs": cfg.get("tls_verify", True),
        }
        if cfg.get("api_key"):
            kwargs["api_key"] = cfg["api_key"]
        elif cfg.get("username"):
            kwargs["http_auth"] = (cfg["username"], cfg["password"])
        if cfg.get("ca_cert"):
            kwargs["ca_certs"] = cfg["ca_cert"]
        self._es = Elasticsearch(**kwargs)
        self._index_pattern: str = cfg.get("index", "ssh-fortress-{YYYY.MM.dd}")

    def _send_batch(self, batch: list[dict]) -> None:
        from elasticsearch.helpers import bulk  # type: ignore[import]
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        index = self._index_pattern.replace("{YYYY.MM.dd}", today)
        actions = [{"_index": index, "_source": doc} for doc in batch]
        ok, errors = bulk(self._es, actions, raise_on_error=False)
        if errors:
            _LOG.warning("Elasticsearch bulk errors", count=len(errors))


# ── Splunk HEC backend ────────────────────────────────────────────────────────

class _SplunkBackend(_BaseBackend):

    def __init__(self, cfg: dict) -> None:
        super().__init__("splunk", cfg)
        import urllib.request
        self._url: str = cfg["hec_url"]
        self._token: str = cfg["hec_token"]
        self._index: str = cfg.get("index", "main")
        self._source: str = cfg.get("source", "ssh-fortress")
        self._sourcetype: str = cfg.get("sourcetype", "ssh:fortress")
        self._verify: bool = cfg.get("tls_verify", True)

    def _send_batch(self, batch: list[dict]) -> None:
        import urllib.request, urllib.error
        events = "".join(
            json.dumps({
                "time": doc.get("ts", datetime.now(timezone.utc).isoformat()),
                "host": _HOSTNAME,
                "source": self._source,
                "sourcetype": self._sourcetype,
                "index": self._index,
                "event": doc,
            })
            for doc in batch
        )
        req = urllib.request.Request(
            self._url,
            data=events.encode(),
            headers={"Authorization": f"Splunk {self._token}", "Content-Type": "application/json"},
            method="POST",
        )
        ctx = ssl.create_default_context() if self._verify else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ctx, timeout=10):
            pass


# ── Syslog backend ────────────────────────────────────────────────────────────

class _SyslogBackend(_BaseBackend):
    BATCH_SIZE = 1   # syslog is line-by-line

    def __init__(self, cfg: dict) -> None:
        super().__init__("syslog", cfg)
        self._host: str = cfg.get("host", "127.0.0.1")
        self._port: int = cfg.get("port", 514)
        self._proto: str = cfg.get("protocol", "UDP").upper()
        self._fmt: str = cfg.get("format", "CEF").upper()
        self._facility: int = cfg.get("facility", 4)
        self._sev_map: dict = cfg.get("severity_map", {"INFO": 6, "WARNING": 4, "ERROR": 3})
        self._tls_cfg = cfg.get("tls", {})
        self._sock: socket.socket | None = None
        self._connect()

    def _connect(self) -> None:
        if self._proto == "UDP":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self._proto == "TCP":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self._host, self._port))
            self._sock = s
        elif self._proto == "TLS":
            ctx = ssl.create_default_context()
            if self._tls_cfg.get("ca_cert"):
                ctx.load_verify_locations(self._tls_cfg["ca_cert"])
            if self._tls_cfg.get("client_cert"):
                ctx.load_cert_chain(self._tls_cfg["client_cert"], self._tls_cfg["client_key"])
            raw = socket.create_connection((self._host, self._port), timeout=10)
            self._sock = ctx.wrap_socket(raw, server_hostname=self._host)

    def _send_batch(self, batch: list[dict]) -> None:
        for doc in batch:
            msg = self._format(doc)
            data = msg.encode("utf-8")
            try:
                if self._proto == "UDP":
                    self._sock.sendto(data, (self._host, self._port))
                else:
                    self._sock.sendall(data + b"\n")
            except Exception:
                self._connect()
                raise

    def _format(self, doc: dict) -> str:
        if self._fmt == "CEF":
            return self._to_cef(doc)
        if self._fmt == "RFC5424":
            return self._to_rfc5424(doc)
        return json.dumps(doc)

    def _to_cef(self, doc: dict) -> str:
        sev = self._sev_map.get(doc.get("level", "INFO"), 6)

        def _cef_escape(value) -> str:
            # CEF extension values must escape '=' and '|' with a backslash.
            # (Kept out of the f-string: backslashes in f-string expressions are
            # a SyntaxError before Python 3.12.)
            return str(value).replace("=", "\\=").replace("|", "\\|")

        ext = " ".join(
            f"{k}={_cef_escape(v)}"
            for k, v in doc.items()
            if k not in ("ts", "event_type", "host")
        )
        return (
            f"CEF:0|SSH-Fortress|ssh-fortress|1.0|"
            f"{doc.get('event_type', 'UNKNOWN')}|{doc.get('event', 'SSH Event')}|"
            f"{sev}|{ext}"
        )

    def _to_rfc5424(self, doc: dict) -> str:
        pri = self._facility * 8 + self._sev_map.get(doc.get("level", "INFO"), 6)
        ts = doc.get("ts", datetime.now(timezone.utc).isoformat())
        return (
            f"<{pri}>1 {ts} {_HOSTNAME} ssh-fortress - - - "
            f"{json.dumps(doc)}"
        )


# ── Kafka backend ─────────────────────────────────────────────────────────────

class _KafkaBackend(_BaseBackend):

    def __init__(self, cfg: dict) -> None:
        super().__init__("kafka", cfg)
        from kafka import KafkaProducer  # type: ignore[import]
        self._topic: str = cfg.get("topic", "ssh-fortress-events")
        self._producer = KafkaProducer(
            bootstrap_servers=cfg.get("bootstrap_servers", ["localhost:9092"]),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            batch_size=cfg.get("batch_size", 500),
            linger_ms=cfg.get("linger_ms", 100),
            acks="all",
        )

    def _send_batch(self, batch: list[dict]) -> None:
        for doc in batch:
            self._producer.send(self._topic, doc)
        self._producer.flush(timeout=10)


# ── Webhook backend ───────────────────────────────────────────────────────────

class _WebhookBackend(_BaseBackend):

    def __init__(self, cfg: dict) -> None:
        super().__init__("webhook", cfg)
        import urllib.request
        self._url: str = cfg["url"]
        self._method: str = cfg.get("method", "POST")
        self._headers: dict = cfg.get("headers", {"Content-Type": "application/json"})
        if cfg.get("auth_header"):
            self._headers["Authorization"] = cfg["auth_header"]
        self._timeout: int = cfg.get("timeout", 10)
        self._retries: int = cfg.get("retry_count", 3)

    def _send_batch(self, batch: list[dict]) -> None:
        import urllib.request
        payload = json.dumps({"events": batch}).encode()
        req = urllib.request.Request(
            self._url, data=payload, headers=self._headers, method=self._method
        )
        for attempt in range(self._retries):
            try:
                with urllib.request.urlopen(req, timeout=self._timeout):
                    return
            except Exception as e:
                if attempt == self._retries - 1:
                    raise
                time.sleep(2 ** attempt)


# ── Orchestrator ──────────────────────────────────────────────────────────────

_BACKEND_MAP = {
    "elasticsearch": _ElasticsearchBackend,
    "splunk": _SplunkBackend,
    "syslog": _SyslogBackend,
    "kafka": _KafkaBackend,
    "webhook": _WebhookBackend,
}


class SIEMForwarder:
    """
    Receives SSHEvent objects (from LogAggregator) and fans them out
    to all enabled SIEM backends.
    """

    def __init__(self, cfg: ConfigManager) -> None:
        self._backends: list[_BaseBackend] = []
        siem_cfg = cfg.section("siem")
        if not siem_cfg.get("enabled", True):
            return

        backends_cfg = siem_cfg.get("backends", {})
        for name, klass in _BACKEND_MAP.items():
            bcfg = backends_cfg.get(name, {})
            if not bcfg.get("enabled", False):
                continue
            try:
                backend = klass(bcfg)
                backend.start()
                self._backends.append(backend)
                _LOG.info("SIEM backend started", backend=name)
            except Exception as e:
                _LOG.error("SIEM backend failed to start", backend=name, error=str(e))

    def __call__(self, event: SSHEvent) -> None:
        """Handler callable — registered with LogAggregator."""
        if not self._backends:
            return
        doc = self._enrich(event)
        for backend in self._backends:
            backend.enqueue(doc)

    def dropped_counts(self) -> dict[str, int]:
        return {b.name: b._dropped for b in self._backends}

    # ── private ──────────────────────────────────────────────────────────────

    @staticmethod
    def _enrich(event: SSHEvent) -> dict:
        doc = event.to_dict()
        doc["@timestamp"] = doc.pop("ts")
        doc["host"] = _HOSTNAME
        doc["data_source"] = "ssh-fortress"
        # ECS-compatible field names
        doc["source"] = {"ip": event.src_ip, "port": event.src_port}
        doc["user"] = {"name": event.username}
        doc["event"] = {
            "category": "authentication",
            "type": "info",
            "outcome": (
                "success" if "SUCCESS" in event.event_type.value else
                "failure" if "FAILURE" in event.event_type.value or "INVALID" in event.event_type.value else
                "unknown"
            ),
            "action": event.event_type.value,
        }
        return doc
