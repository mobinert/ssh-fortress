"""
Structured logger — emits JSON lines to the fortress event log and
optionally to the console.  Every event carries a fixed envelope:

    {"ts": <iso8601>, "host": <str>, "pid": <int>,
     "level": <str>, "module": <str>, "event": <str>,
     "severity": <int>,          # CEF/syslog numeric
     ...extra fields...}
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import colorlog  # type: ignore[import]

# CEF / syslog severity map
_SEVERITY: dict[str, int] = {
    "CRITICAL": 2,
    "ERROR": 3,
    "WARNING": 4,
    "INFO": 6,
    "DEBUG": 7,
}

_HOSTNAME = socket.gethostname()
_PID = os.getpid()
_lock = threading.Lock()

_instances: dict[str, "StructuredLogger"] = {}


def get_logger(module: str, log_path: str | Path | None = None) -> "StructuredLogger":
    """Return a cached StructuredLogger for *module*."""
    if module not in _instances:
        _instances[module] = StructuredLogger(module, log_path)
    return _instances[module]


class StructuredLogger:
    """
    Thread-safe structured logger that writes JSON lines to a file and
    optionally pretty-prints coloured output to stderr.
    """

    def __init__(
        self,
        module: str,
        log_path: str | Path | None = None,
        console: bool = True,
        level: str = "INFO",
    ) -> None:
        self.module = module
        self._file: "open" | None = None  # type: ignore[type-arg]
        if log_path:
            path = Path(log_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file = path.open("a", buffering=1)  # line-buffered

        # coloured console handler
        self._console = console
        self._console_log = logging.getLogger(f"fortress.{module}")
        self._console_log.setLevel(getattr(logging, level.upper(), logging.INFO))
        if console and not self._console_log.handlers:
            handler = colorlog.StreamHandler(sys.stderr)
            handler.setFormatter(
                colorlog.ColoredFormatter(
                    "%(log_color)s%(asctime)s%(reset)s  %(cyan)s%(name)-22s%(reset)s"
                    " %(log_color)s%(levelname)-8s%(reset)s  %(message)s",
                    datefmt="%H:%M:%S",
                    log_colors={
                        "DEBUG": "white",
                        "INFO": "green",
                        "WARNING": "yellow",
                        "ERROR": "red",
                        "CRITICAL": "bold_red",
                    },
                )
            )
            self._console_log.addHandler(handler)

    # ── public API ───────────────────────────────────────────────────────────

    def debug(self, event: str, **extra: Any) -> None:
        self._emit("DEBUG", event, **extra)

    def info(self, event: str, **extra: Any) -> None:
        self._emit("INFO", event, **extra)

    def warning(self, event: str, **extra: Any) -> None:
        self._emit("WARNING", event, **extra)

    def error(self, event: str, **extra: Any) -> None:
        self._emit("ERROR", event, **extra)

    def critical(self, event: str, **extra: Any) -> None:
        self._emit("CRITICAL", event, **extra)

    def security_event(
        self,
        event: str,
        src_ip: str = "",
        username: str = "",
        action: str = "",
        **extra: Any,
    ) -> dict[str, Any]:
        """
        Emit a security-focused event envelope — same as info() but with
        mandatory SIEM-friendly fields and returns the envelope dict.
        """
        envelope = self._build_envelope(
            "INFO", event,
            src_ip=src_ip, username=username, action=action, **extra
        )
        self._write(envelope)
        return envelope

    def close(self) -> None:
        if self._file:
            self._file.close()

    # ── private ──────────────────────────────────────────────────────────────

    def _emit(self, level: str, event: str, **extra: Any) -> None:
        envelope = self._build_envelope(level, event, **extra)
        self._write(envelope)

    def _build_envelope(self, level: str, event: str, **extra: Any) -> dict[str, Any]:
        envelope: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "host": _HOSTNAME,
            "pid": _PID,
            "level": level,
            "severity": _SEVERITY.get(level, 6),
            "module": self.module,
            "event": event,
        }
        envelope.update(extra)
        return envelope

    def _write(self, envelope: dict[str, Any]) -> None:
        line = json.dumps(envelope, default=str)
        with _lock:
            if self._file:
                self._file.write(line + "\n")
            if self._console:
                lvl = envelope.get("level", "INFO")
                msg = (
                    f"{envelope.get('event', '')} "
                    + " ".join(
                        f"{k}={v}"
                        for k, v in envelope.items()
                        if k not in {"ts", "host", "pid", "level", "severity", "module", "event"}
                    )
                )
                getattr(self._console_log, lvl.lower(), self._console_log.info)(msg)
