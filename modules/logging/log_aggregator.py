"""
LogAggregator — tails auth.log (or /var/log/secure) using inotify when
available, falling back to polling.  For each parsed SSHEvent it calls
registered handlers (BruteForceProtector, SIEMForwarder, AnomalyDetector, …).

Design goals:
  • < 1 ms per event in the hot path (no I/O in handlers)
  • inotify-driven: 0 CPU when no events arrive
  • Handler registration at runtime (plugin model)
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable

from modules.core import ConfigManager, get_logger
from modules.logging.log_parser import LogParser, SSHEvent

_LOG = get_logger("logging.aggregator")

Handler = Callable[[SSHEvent], None]


class LogAggregator:

    def __init__(self, cfg: ConfigManager) -> None:
        self._log_path = Path(cfg.get("logging", "auth_log_path", default="/var/log/auth.log"))
        self._poll_interval: float = cfg.get("monitoring", "poll_interval", default=1)
        self._parser = LogParser()
        self._handlers: list[Handler] = []
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ── public API ───────────────────────────────────────────────────────────

    def add_handler(self, handler: Handler) -> None:
        self._handlers.append(handler)

    def start(self) -> None:
        if not self._log_path.exists():
            _LOG.warning("Log file not found", path=str(self._log_path))
        self._thread = threading.Thread(
            target=self._tail_loop, daemon=True, name="log-aggregator"
        )
        self._thread.start()
        _LOG.info("Log aggregator started", log=str(self._log_path))

    def stop(self) -> None:
        self._stop_event.set()

    # ── private ──────────────────────────────────────────────────────────────

    def _tail_loop(self) -> None:
        """Tail the log file.  Uses inotify if available, else polls."""
        try:
            self._tail_inotify()
        except ImportError:
            _LOG.debug("inotify unavailable — falling back to polling")
            self._tail_poll()

    def _tail_inotify(self) -> None:
        import inotify.adapters  # type: ignore[import]
        notifier = inotify.adapters.Inotify()
        notifier.add_watch(str(self._log_path.parent))

        with self._log_path.open() as fh:
            fh.seek(0, 2)  # seek to end
            for event in notifier.event_gen(yield_nones=False):
                if self._stop_event.is_set():
                    break
                _, type_names, path, filename = event
                if "IN_MODIFY" in type_names and filename == self._log_path.name:
                    self._drain(fh)

    def _tail_poll(self) -> None:
        with self._log_path.open() as fh:
            fh.seek(0, 2)
            while not self._stop_event.wait(self._poll_interval):
                self._drain(fh)
                # Handle log rotation
                try:
                    if os.stat(str(self._log_path)).st_ino != os.fstat(fh.fileno()).st_ino:
                        fh.close()
                        fh = self._log_path.open()
                        _LOG.info("Log rotated — reopened file")
                except OSError:
                    pass

    def _drain(self, fh) -> None:
        """Read all new lines and dispatch to handlers."""
        for line in fh:
            event = self._parser.parse(line)
            if event is None:
                continue
            for handler in self._handlers:
                try:
                    handler(event)
                except Exception as e:
                    _LOG.error("Handler error", handler=handler.__class__.__name__, error=str(e))
