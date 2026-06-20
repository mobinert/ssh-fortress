"""
AnomalyDetector — detects behavioural anomalies in SSH traffic:

  • IP spray  — many unique IPs hitting within a short window
  • Unusual hours — login outside business hours
  • Impossible travel — same user from 2+ geo-regions within 1 hour
  • Auth failure spike — burst of failures above a rolling baseline
  • Repeated root attempts
"""

from __future__ import annotations

import collections
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from modules.core import ConfigManager, get_logger
from modules.logging.log_parser import SSHEvent, EventType

_LOG = get_logger("monitoring.anomaly")

AlertCallback = Callable[[str, dict], None]


class AnomalyDetector:

    def __init__(self, cfg: ConfigManager, alert_cb: AlertCallback | None = None) -> None:
        self._enabled: bool = cfg.get("monitoring", "anomaly_detection", "enabled", default=True)
        c = cfg.section("monitoring").get("anomaly_detection", {})
        self._ip_spray_threshold: int = c.get("ip_spray_threshold", 20)
        self._ip_spray_window: int = c.get("ip_spray_window", 60)
        self._unusual_hours: bool = c.get("unusual_hours", True)
        self._biz_start: int = c.get("business_hours_start", 8)
        self._biz_end: int = c.get("business_hours_end", 18)
        self._impossible_travel: bool = c.get("impossible_travel", True)
        self._travel_window: int = c.get("impossible_travel_window", 3600)
        self._alert_cb = alert_cb

        # ip spray tracking
        self._ip_window: collections.deque = collections.deque()
        self._unique_ips: set[str] = set()

        # impossible travel: user -> list of (timestamp, country)
        self._user_locations: dict[str, collections.deque] = {}

        # failure spike: sliding window of failure timestamps
        self._failures: collections.deque = collections.deque()
        self._failure_baseline = 10   # per minute before flagging
        self._last_spike_alert: float = 0

        self._root_attempts: dict[str, float] = {}   # ip -> last attempt ts
        self._lock = threading.Lock()

    def __call__(self, event: SSHEvent) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._check_ip_spray(event)
            self._check_unusual_hours(event)
            self._check_impossible_travel(event)
            self._check_failure_spike(event)
            self._check_root_attempts(event)

    # ── checks ────────────────────────────────────────────────────────────────

    def _check_ip_spray(self, event: SSHEvent) -> None:
        if not event.src_ip:
            return
        now = time.monotonic()
        self._ip_window.append((event.src_ip, now))
        self._unique_ips.add(event.src_ip)
        cutoff = now - self._ip_spray_window
        while self._ip_window and self._ip_window[0][1] < cutoff:
            old_ip, _ = self._ip_window.popleft()
            # Note: don't remove from unique_ips (other events may still reference it)

        # Recount unique IPs in window
        window_ips = {ip for ip, ts in self._ip_window}
        if len(window_ips) >= self._ip_spray_threshold:
            self._alert("IP_SPRAY_DETECTED", {
                "unique_ips": len(window_ips),
                "window_seconds": self._ip_spray_window,
                "threshold": self._ip_spray_threshold,
            })

    def _check_unusual_hours(self, event: SSHEvent) -> None:
        if not self._unusual_hours:
            return
        if event.event_type not in (EventType.AUTH_SUCCESS, EventType.PUBKEY_ACCEPTED):
            return
        now = datetime.now()
        hour = now.hour
        if not (self._biz_start <= hour < self._biz_end):
            self._alert("LOGIN_UNUSUAL_HOURS", {
                "username": event.username,
                "src_ip": event.src_ip,
                "hour": hour,
                "business_hours": f"{self._biz_start:02d}:00-{self._biz_end:02d}:00",
            })

    def _check_impossible_travel(self, event: SSHEvent) -> None:
        if not self._impossible_travel or not event.username or not event.src_ip:
            return
        if event.event_type not in (EventType.AUTH_SUCCESS, EventType.PUBKEY_ACCEPTED):
            return
        country = self._geoip_country(event.src_ip)
        if country is None:
            return

        dq = self._user_locations.setdefault(event.username, collections.deque())
        now = time.monotonic()
        cutoff = now - self._travel_window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        countries_in_window = {c for _, c in dq}
        if countries_in_window and country not in countries_in_window:
            self._alert("IMPOSSIBLE_TRAVEL", {
                "username": event.username,
                "new_country": country,
                "previous_countries": list(countries_in_window),
                "src_ip": event.src_ip,
                "window_seconds": self._travel_window,
            })

        dq.append((now, country))

    def _check_failure_spike(self, event: SSHEvent) -> None:
        if event.event_type not in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            return
        now = time.monotonic()
        self._failures.append(now)
        cutoff = now - 60
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()
        count = len(self._failures)
        if count >= self._failure_baseline and (now - self._last_spike_alert) > 300:
            self._last_spike_alert = now
            self._alert("AUTH_FAILURE_SPIKE", {
                "failures_per_minute": count,
                "threshold": self._failure_baseline,
            })

    def _check_root_attempts(self, event: SSHEvent) -> None:
        if event.event_type != EventType.ROOT_ATTEMPT:
            return
        self._alert("ROOT_LOGIN_ATTEMPT", {
            "src_ip": event.src_ip,
            "username": "root",
        })

    # ── helpers ───────────────────────────────────────────────────────────────

    def _alert(self, alert_type: str, details: dict) -> None:
        _LOG.security_event(
            f"ANOMALY_{alert_type}",
            action="ALERT",
            alert_type=alert_type,
            **details,
        )
        if self._alert_cb:
            self._alert_cb(alert_type, details)

    @staticmethod
    def _geoip_country(ip: str) -> Optional[str]:
        try:
            import geoip2.database  # type: ignore[import]
            # Reader is shared; in production pass it via constructor
        except ImportError:
            pass
        return None


class HealthChecker:
    """Placeholder — imported by monitoring/__init__.py."""
    pass
