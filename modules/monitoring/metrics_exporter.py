"""
MetricsExporter — a zero-dependency Prometheus metrics endpoint.

Exposes SSH Fortress counters over HTTP in the Prometheus text exposition
format so the whole thing drops straight into Grafana / Alertmanager without
any push gateway. Backed only by the stdlib http.server, so there is nothing
extra to install.

    scrape:  GET http://127.0.0.1:9822/metrics

The metric rendering (`render_metrics`) is a pure function — the HTTP server
is a thin shell around it — which keeps it trivial to unit-test.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

from modules.core import ConfigManager, get_logger

_LOG = get_logger("monitoring.metrics")

_PREFIX = "ssh_fortress"

# (metric suffix, prom type, help text, summary key)
_COUNTERS: list[tuple[str, str, str]] = [
    ("attempts_total", "Total SSH authentication attempts seen", "total_attempts"),
    ("successes_total", "Successful SSH authentications", "successes"),
    ("failures_total", "Failed SSH authentications", "failures"),
    ("bans_total", "IP addresses banned", "bans"),
    ("root_attempts_total", "Attempts to log in as root", "root_attempts"),
    ("anomalies_total", "Anomalies detected", "total_anomalies"),
]
_GAUGES: list[tuple[str, str, str]] = [
    ("active_sessions", "Currently active SSH sessions", "active_sessions"),
    ("peak_sessions", "Peak concurrent SSH sessions", "peak_sessions"),
]


def render_metrics(
    summary: dict[str, Any],
    *,
    banned_count: int = 0,
    top_attackers: Optional[list] = None,
    top_threats: Optional[list[dict]] = None,
) -> str:
    """Render the full Prometheus exposition document from raw stats."""
    out: list[str] = []

    def emit(name: str, mtype: str, help_text: str, value: Any, labels: str = "") -> None:
        full = f"{_PREFIX}_{name}"
        out.append(f"# HELP {full} {help_text}")
        out.append(f"# TYPE {full} {mtype}")
        out.append(f"{full}{labels} {value}")

    for name, help_text, key in _COUNTERS:
        emit(name, "counter", help_text, int(summary.get(key, 0) or 0))
    for name, help_text, key in _GAUGES:
        emit(name, "gauge", help_text, int(summary.get(key, 0) or 0))

    emit("banned_ips", "gauge", "IP addresses currently banned", int(banned_count))

    # Per-attacker failure counts as a labelled gauge (bounded to the top N).
    if top_attackers:
        full = f"{_PREFIX}_attacker_failures"
        out.append(f"# HELP {full} Failures observed per source IP (top attackers)")
        out.append(f"# TYPE {full} gauge")
        for ip, data in top_attackers:
            fails = int((data or {}).get("failures", 0))
            out.append(f'{full}{{ip="{_escape(ip)}"}} {fails}')

    # Behavioural threat score per risky IP.
    if top_threats:
        full = f"{_PREFIX}_threat_score"
        out.append(f"# HELP {full} Behavioural threat score (0-100) per source IP")
        out.append(f"# TYPE {full} gauge")
        for t in top_threats:
            out.append(f'{full}{{ip="{_escape(t.get("ip", ""))}"}} {t.get("score", 0)}')

    out.append(f"# HELP {_PREFIX}_up SSH Fortress exporter liveness")
    out.append(f"# TYPE {_PREFIX}_up gauge")
    out.append(f"{_PREFIX}_up 1")
    return "\n".join(out) + "\n"


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


class MetricsExporter:
    """Serve `render_metrics()` over HTTP in a background thread."""

    def __init__(
        self,
        cfg: ConfigManager,
        collector: Optional[Callable[[], str]] = None,
    ) -> None:
        c = cfg.section("metrics")
        self.enabled: bool = c.get("enabled", False)
        self._bind: str = c.get("bind", "127.0.0.1")
        self._port: int = c.get("port", 9822)
        self._path: str = c.get("path", "/metrics")
        self._collector = collector or (lambda: render_metrics({}))
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not self.enabled:
            return
        path = self._path
        collector = self._collector

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path.rstrip("/") not in (path.rstrip("/"), ""):
                    self.send_error(404)
                    return
                try:
                    body = collector().encode()
                except Exception as exc:  # never let a scrape crash the server
                    self.send_error(500, str(exc))
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):  # silence default stderr logging
                return

        try:
            self._server = ThreadingHTTPServer((self._bind, self._port), _Handler)
        except OSError as exc:
            _LOG.error("Metrics exporter bind failed", bind=self._bind, port=self._port, error=str(exc))
            return
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="metrics-exporter"
        )
        self._thread.start()
        _LOG.info("Metrics exporter listening", url=f"http://{self._bind}:{self._port}{self._path}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
