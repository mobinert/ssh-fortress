"""
ThreatScorer — per-IP behavioural risk scoring (0–100).

Where BruteForceProtector answers a single yes/no question ("has this IP
exceeded N failures?"), the ThreatScorer builds a *behavioural profile* of
each source IP and blends several weighted signals into one risk score:

  • failure velocity      — how many auth failures inside the window
  • username spraying      — how many DISTINCT usernames the IP has tried
  • invalid-user probing   — hits against users that do not exist
  • root targeting         — any attempt against root
  • reputation             — flagged by AbuseIPDB / a feed
  • off-hours activity      — connections outside business hours
  • known-good discount     — an IP that has ever authenticated successfully

This enables *adaptive banning*: a slow, distributed spray that never trips
the raw failure counter can still be banned once its behaviour looks clearly
malicious, while a single fat-fingered password from a known-good host is not.

Pure, thread-safe, and dependency-free — every weight is configurable and the
score computation is a pure function so it is trivially unit-testable.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from modules.core import ConfigManager, get_logger

_LOG = get_logger("protection.threat_scorer")

# Default signal weights (each is the MAX contribution of that signal).
_DEFAULT_WEIGHTS = {
    "failure": 8,          # per failure, capped by failure_cap
    "failure_cap": 40,
    "distinct_user": 10,   # per distinct username, capped
    "distinct_user_cap": 30,
    "invalid_user": 8,     # per invalid-user hit, capped
    "invalid_user_cap": 24,
    "root_attempt": 30,    # flat, if any root attempt seen
    "reputation": 50,      # flat, if flagged by a reputation feed
    "off_hours": 6,        # flat, if activity outside business hours
    "known_good_discount": 40,  # subtracted if the IP ever authenticated OK
}


@dataclass
class ThreatProfile:
    """Rolling behavioural profile for a single source IP."""
    ip: str
    events: deque = field(default_factory=deque)     # (monotonic_ts, kind)
    usernames: set = field(default_factory=set)
    failures: int = 0
    invalid_users: int = 0
    root_attempts: int = 0
    reputation_flagged: bool = False
    off_hours: bool = False
    had_success: bool = False
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)


class ThreatScorer:
    """
    Maintain behavioural profiles and expose a 0–100 risk score per IP.

    Thread-safe; a reaper drops profiles idle longer than the window.
    """

    def __init__(self, cfg: Optional[ConfigManager] = None) -> None:
        c = cfg.section("threat_scoring") if cfg else {}
        self.enabled: bool = c.get("enabled", True)
        self._window: int = c.get("window", 900)          # 15 min behavioural window
        self._ban_threshold: int = c.get("ban_threshold", 70)
        self._bh_start: int = c.get("business_hours_start", 8)
        self._bh_end: int = c.get("business_hours_end", 18)

        self._weights = dict(_DEFAULT_WEIGHTS)
        self._weights.update(c.get("weights", {}) or {})

        self._profiles: dict[str, ThreatProfile] = {}
        self._lock = threading.RLock()

        if cfg is not None:
            self._reaper = threading.Thread(
                target=self._reap_loop, daemon=True, name="threat-reaper"
            )
            self._reaper.start()

    # ── recording ─────────────────────────────────────────────────────────────

    def record(
        self,
        ip: str,
        kind: str,
        username: str = "",
        *,
        invalid_user: bool = False,
        reputation_flagged: bool = False,
        when: Optional[datetime] = None,
    ) -> float:
        """
        Fold one observation into *ip*'s profile and return its new score.

        *kind* ∈ {"failure", "success", "invalid", "root"} (free-form; only
        these are weighted). Returns the updated 0–100 score.
        """
        if not ip:
            return 0.0
        now = time.monotonic()
        with self._lock:
            p = self._profiles.get(ip)
            if p is None:
                p = ThreatProfile(ip=ip)
                self._profiles[ip] = p

            p.events.append((now, kind))
            p.last_seen = now
            if username:
                p.usernames.add(username)

            if kind == "failure":
                p.failures += 1
            elif kind == "invalid":
                p.invalid_users += 1
                p.failures += 1
            elif kind == "root":
                p.root_attempts += 1
                p.failures += 1
            elif kind == "success":
                p.had_success = True

            if invalid_user:
                p.invalid_users += 1
            if reputation_flagged:
                p.reputation_flagged = True

            hour = (when or datetime.now()).hour
            if not (self._bh_start <= hour < self._bh_end):
                p.off_hours = True

            self._evict_old(p, now)
            return self._score(p)

    # ── reading ───────────────────────────────────────────────────────────────

    def score(self, ip: str) -> float:
        with self._lock:
            p = self._profiles.get(ip)
            if not p:
                return 0.0
            self._evict_old(p, time.monotonic())
            return self._score(p)

    def should_ban(self, ip: str) -> bool:
        """True when the IP's score has crossed the configured ban threshold."""
        return self.enabled and self.score(ip) >= self._ban_threshold

    def profile(self, ip: str) -> dict:
        with self._lock:
            p = self._profiles.get(ip)
            if not p:
                return {}
            return {
                "ip": p.ip,
                "score": round(self._score(p), 1),
                "failures": p.failures,
                "distinct_usernames": len(p.usernames),
                "invalid_users": p.invalid_users,
                "root_attempts": p.root_attempts,
                "reputation_flagged": p.reputation_flagged,
                "off_hours": p.off_hours,
                "had_success": p.had_success,
            }

    def top(self, n: int = 10) -> list[dict]:
        """Highest-risk IPs, most dangerous first."""
        with self._lock:
            profiles = [self.profile(ip) for ip in list(self._profiles)]
        profiles.sort(key=lambda d: d.get("score", 0), reverse=True)
        return profiles[:n]

    def classify(self, score: float) -> str:
        if score >= self._ban_threshold:
            return "CRITICAL"
        if score >= self._ban_threshold * 0.6:
            return "HIGH"
        if score >= self._ban_threshold * 0.3:
            return "SUSPICIOUS"
        return "LOW"

    # ── scoring core (pure) ────────────────────────────────────────────────────

    def _score(self, p: ThreatProfile) -> float:
        w = self._weights
        score = 0.0
        score += min(p.failures * w["failure"], w["failure_cap"])
        # Spraying = trying MORE than one username; a single username is normal.
        spray = max(0, len(p.usernames) - 1)
        score += min(spray * w["distinct_user"], w["distinct_user_cap"])
        score += min(p.invalid_users * w["invalid_user"], w["invalid_user_cap"])
        if p.root_attempts:
            score += w["root_attempt"]
        if p.reputation_flagged:
            score += w["reputation"]
        if p.off_hours:
            score += w["off_hours"]
        if p.had_success:
            score -= w["known_good_discount"]
        return max(0.0, min(100.0, score))

    def _evict_old(self, p: ThreatProfile, now: float) -> None:
        """Drop events older than the window and recompute derived counters."""
        cutoff = now - self._window
        changed = False
        while p.events and p.events[0][0] < cutoff:
            p.events.popleft()
            changed = True
        if changed:
            # Recompute counters from the surviving events so old bursts decay.
            p.failures = sum(1 for _, k in p.events if k in ("failure", "invalid", "root"))
            p.invalid_users = sum(1 for _, k in p.events if k == "invalid")
            p.root_attempts = sum(1 for _, k in p.events if k == "root")
            if not p.events:
                # nothing recent — reset the sticky flags too
                p.usernames.clear()
                p.off_hours = False

    def _reap_loop(self) -> None:
        while True:
            time.sleep(60)
            now = time.monotonic()
            with self._lock:
                idle = [
                    ip for ip, p in self._profiles.items()
                    if (now - p.last_seen) > self._window and not p.reputation_flagged
                ]
                for ip in idle:
                    del self._profiles[ip]
