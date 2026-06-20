"""
LogParser — parses /var/log/auth.log (or /var/log/secure) lines into
typed SSHEvent objects.  Zero external dependencies; pure regex.

Handles both old syslog format and systemd journal format.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    INVALID_USER = "INVALID_USER"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"
    CONNECTION_OPENED = "CONNECTION_OPENED"
    DISCONNECT = "DISCONNECT"
    ROOT_ATTEMPT = "ROOT_ATTEMPT"
    TOO_MANY_AUTH = "TOO_MANY_AUTH"
    PUBKEY_ACCEPTED = "PUBKEY_ACCEPTED"
    PASSWORD_ACCEPTED = "PASSWORD_ACCEPTED"
    BANNER_SENT = "BANNER_SENT"
    PORT_FORWARD = "PORT_FORWARD"
    UNKNOWN = "UNKNOWN"


@dataclass
class SSHEvent:
    raw: str
    event_type: EventType = EventType.UNKNOWN
    timestamp: Optional[datetime] = None
    src_ip: str = ""
    src_port: int = 0
    username: str = ""
    method: str = ""           # password | publickey | keyboard-interactive
    key_fingerprint: str = ""
    pid: int = 0
    host: str = field(default_factory=socket.gethostname)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type.value,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": self.username,
            "method": self.method,
            "key_fingerprint": self.key_fingerprint,
            "pid": self.pid,
            "host": self.host,
            **self.extra,
        }


# ── compiled patterns ────────────────────────────────────────────────────────

_SYSLOG_TS  = r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
_ISO_TS     = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)"
_HOST       = r"(\S+)"
_PROC       = r"sshd\[(\d+)\]"
_IP4        = r"((?:\d{1,3}\.){3}\d{1,3})"
_IP6        = r"([0-9a-fA-F:]+)"
_IP         = r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)"
_PORT       = r"(\d+)"
_USER       = r"(\S+)"
_ANY        = r"(.*)"

_PATTERNS: list[tuple[EventType, re.Pattern]] = [
    (EventType.AUTH_FAILURE, re.compile(
        rf"Failed (\w+) for (?:invalid user )?{_USER} from {_IP} port {_PORT}"
    )),
    (EventType.AUTH_SUCCESS, re.compile(
        rf"Accepted (\w+) for {_USER} from {_IP} port {_PORT}"
    )),
    (EventType.PUBKEY_ACCEPTED, re.compile(
        rf"Accepted publickey for {_USER} from {_IP} port {_PORT} ssh\S+: \S+ ({_ANY})"
    )),
    (EventType.INVALID_USER, re.compile(
        rf"Invalid user {_USER} from {_IP} port {_PORT}"
    )),
    (EventType.ROOT_ATTEMPT, re.compile(
        rf"(?:Failed|Attempted) .* for root from {_IP}"
    )),
    (EventType.TOO_MANY_AUTH, re.compile(
        rf"error: maximum authentication attempts exceeded for {_USER} from {_IP}"
    )),
    (EventType.DISCONNECT, re.compile(
        rf"Disconnected from (?:authenticating )?user {_USER} {_IP} port {_PORT}"
    )),
    (EventType.CONNECTION_CLOSED, re.compile(
        rf"Connection closed by (?:authenticating )?(?:invalid user )?{_USER} {_IP} port {_PORT}"
    )),
    (EventType.PORT_FORWARD, re.compile(
        rf"channel \d+: new \[(?:direct-tcpip|forwarded-tcpip)\]"
    )),
]

_SYSLOG_HEADER = re.compile(
    rf"^{_SYSLOG_TS}\s+{_HOST}\s+{_PROC}:\s+{_ANY}$"
)
_ISO_HEADER = re.compile(
    rf"^{_ISO_TS}\s+{_HOST}\s+{_PROC}:\s+{_ANY}$"
)

_CURRENT_YEAR = datetime.now().year


class LogParser:
    """Parse raw log lines into SSHEvent objects."""

    def parse(self, line: str) -> Optional[SSHEvent]:
        line = line.strip()
        if not line:
            return None
        if "sshd[" not in line:
            return None

        event = SSHEvent(raw=line)
        msg, pid = self._extract_header(line, event)
        if msg is None:
            return None

        event.pid = pid
        self._classify(msg, event)
        return event

    # ── private ──────────────────────────────────────────────────────────────

    def _extract_header(self, line: str, event: SSHEvent) -> tuple[Optional[str], int]:
        m = _SYSLOG_HEADER.match(line)
        if m:
            ts_str, host, pid, msg = m.group(1), m.group(2), int(m.group(3)), m.group(4)
            try:
                event.timestamp = datetime.strptime(
                    f"{_CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
            event.host = host
            return msg, pid

        m = _ISO_HEADER.match(line)
        if m:
            ts_str, host, pid, msg = m.group(1), m.group(2), int(m.group(3)), m.group(4)
            try:
                event.timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                pass
            event.host = host
            return msg, pid

        return None, 0

    def _classify(self, msg: str, event: SSHEvent) -> None:
        for etype, pattern in _PATTERNS:
            m = pattern.search(msg)
            if not m:
                continue
            event.event_type = etype
            groups = m.groups()

            if etype in (EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS):
                event.method, event.username = groups[0], groups[1]
                event.src_ip, event.src_port = groups[2], int(groups[3])

            elif etype == EventType.PUBKEY_ACCEPTED:
                event.username, event.src_ip = groups[0], groups[1]
                event.src_port = int(groups[2])
                event.method = "publickey"
                event.key_fingerprint = groups[3] if len(groups) > 3 else ""

            elif etype == EventType.INVALID_USER:
                event.username, event.src_ip = groups[0], groups[1]
                event.src_port = int(groups[2]) if len(groups) > 2 else 0

            elif etype == EventType.ROOT_ATTEMPT:
                event.username = "root"
                event.src_ip = groups[0] if groups else ""

            elif etype == EventType.TOO_MANY_AUTH:
                event.username, event.src_ip = groups[0], groups[1]

            elif etype in (EventType.DISCONNECT, EventType.CONNECTION_CLOSED):
                event.username, event.src_ip = groups[0], groups[1]
                event.src_port = int(groups[2]) if len(groups) > 2 else 0

            return

        event.event_type = EventType.UNKNOWN
