"""
SessionMonitor — tracks active SSH sessions in real-time.

Reads SSHEvents from the LogAggregator and maintains a live session map.
Periodically writes sessions.json for dashboards / other tools.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from modules.core import ConfigManager, get_logger
from modules.logging.log_parser import SSHEvent, EventType

_LOG = get_logger("monitoring.session")


@dataclass
class Session:
    session_id: str                 # "{src_ip}:{src_port}"
    username: str
    src_ip: str
    src_port: int
    started_at: str                 # ISO8601
    method: str = ""
    key_fingerprint: str = ""
    country: str = ""
    ended_at: Optional[str] = None
    duration_s: Optional[float] = None
    is_active: bool = True


class SessionMonitor:

    def __init__(self, cfg: ConfigManager) -> None:
        self._enabled: bool = cfg.get("monitoring", "session_tracking", default=True)
        self._session_file = Path(
            cfg.get("monitoring", "active_session_log",
                    default="/var/lib/ssh-fortress/sessions.json")
        )
        self._flush_interval: float = 30.0
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._writer: threading.Thread | None = None

    def start(self) -> None:
        if not self._enabled:
            return
        self._session_file.parent.mkdir(parents=True, exist_ok=True)
        self._writer = threading.Thread(
            target=self._flush_loop, daemon=True, name="session-writer"
        )
        self._writer.start()

    def __call__(self, event: SSHEvent) -> None:
        """Handler callable for LogAggregator."""
        if not self._enabled:
            return

        sid = f"{event.src_ip}:{event.src_port}"

        with self._lock:
            if event.event_type in (EventType.AUTH_SUCCESS, EventType.PUBKEY_ACCEPTED):
                self._sessions[sid] = Session(
                    session_id=sid,
                    username=event.username,
                    src_ip=event.src_ip,
                    src_port=event.src_port,
                    started_at=event.timestamp.isoformat() if event.timestamp
                               else datetime.now(timezone.utc).isoformat(),
                    method=event.method,
                    key_fingerprint=event.key_fingerprint,
                )
                _LOG.info("Session started", user=event.username, src=sid)

            elif event.event_type in (EventType.DISCONNECT, EventType.CONNECTION_CLOSED):
                session = self._sessions.get(sid)
                if session:
                    now = datetime.now(timezone.utc)
                    session.ended_at = now.isoformat()
                    session.is_active = False
                    try:
                        start = datetime.fromisoformat(session.started_at)
                        session.duration_s = (now - start).total_seconds()
                    except Exception:
                        pass
                    _LOG.info(
                        "Session ended",
                        user=session.username,
                        src=sid,
                        duration_s=session.duration_s,
                    )
                    del self._sessions[sid]

    def active_sessions(self) -> list[dict]:
        with self._lock:
            return [asdict(s) for s in self._sessions.values() if s.is_active]

    def session_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.is_active)

    # ── private ──────────────────────────────────────────────────────────────

    def _flush_loop(self) -> None:
        while True:
            time.sleep(self._flush_interval)
            self._flush()

    def _flush(self) -> None:
        with self._lock:
            data = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "active_count": sum(1 for s in self._sessions.values() if s.is_active),
                "sessions": [asdict(s) for s in self._sessions.values()],
            }
        try:
            self._session_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            _LOG.error("Failed to write sessions file", error=str(e))
