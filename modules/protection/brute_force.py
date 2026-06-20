"""
BruteForceProtector — in-process IP tracker with progressive banning.

Architecture:
  • O(1) per-event decision using two dicts (attempt_log, ban_table)
  • A background reaper thread removes expired entries every 60 s
  • Optionally syncs bans to fail2ban via its socket for kernel-level drops
  • Emits SIEM events for every ban/unban
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from modules.core import ConfigManager, get_logger

_LOG = get_logger("protection.brute_force")


@dataclass
class _BanRecord:
    ip: str
    banned_at: float
    duration: float          # seconds
    offence_count: int = 1   # increments each time the IP is re-banned


class BruteForceProtector:
    """
    Track SSH auth failures and ban IPs that exceed the threshold.

    Thread-safe — designed to be called from the log-tail loop.
    """

    def __init__(
        self,
        cfg: ConfigManager,
        on_ban: Callable[[str, int], None] | None = None,
        on_unban: Callable[[str], None] | None = None,
    ) -> None:
        c = cfg.section("brute_force")
        self._max_attempts: int = c.get("max_attempts", 5)
        self._window: int = c.get("observation_window", 300)
        self._base_duration: int = c.get("block_duration", 3600)
        self._progressive: bool = c.get("progressive_ban", True)
        self._max_duration: int = c.get("max_ban_duration", 86400)
        self._whitelist: set[str] = set(c.get("whitelist_ips", []))
        self._whitelist_cidrs: list[str] = c.get("whitelist_cidrs", [])
        self._fail2ban_enabled: bool = c.get("fail2ban", {}).get("enabled", False)

        self._on_ban = on_ban
        self._on_unban = on_unban

        # ip -> deque of timestamps within the observation window
        self._attempts: dict[str, deque[float]] = {}
        # ip -> _BanRecord
        self._bans: dict[str, _BanRecord] = {}
        self._lock = threading.RLock()

        self._reaper = threading.Thread(target=self._reap_loop, daemon=True, name="bf-reaper")
        self._reaper.start()

    # ── public API ───────────────────────────────────────────────────────────

    def record_failure(self, ip: str, username: str = "") -> bool:
        """
        Record an auth failure for *ip*.  Returns True if the IP was just
        banned as a result of this call.
        """
        if self._is_whitelisted(ip):
            return False

        with self._lock:
            if ip in self._bans:
                return False  # already banned — drop silently

            now = time.monotonic()
            dq = self._attempts.setdefault(ip, deque())
            dq.append(now)

            # Evict timestamps outside the observation window
            cutoff = now - self._window
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self._max_attempts:
                self._ban(ip, username)
                return True
        return False

    def record_success(self, ip: str) -> None:
        """Successful auth: clear the attempt counter (but keep existing bans)."""
        with self._lock:
            self._attempts.pop(ip, None)

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def ban(self, ip: str, duration: int | None = None, reason: str = "manual") -> None:
        with self._lock:
            self._ban(ip, reason=reason, override_duration=duration)

    def unban(self, ip: str) -> bool:
        with self._lock:
            return self._unban(ip)

    def banned_ips(self) -> list[dict]:
        with self._lock:
            now = time.monotonic()
            return [
                {
                    "ip": rec.ip,
                    "banned_at": rec.banned_at,
                    "expires_in": max(0, rec.duration - (now - rec.banned_at)),
                    "offences": rec.offence_count,
                }
                for rec in self._bans.values()
            ]

    # ── private ──────────────────────────────────────────────────────────────

    def _ban(
        self,
        ip: str,
        username: str = "",
        reason: str = "",
        override_duration: int | None = None,
    ) -> None:
        existing = self._bans.get(ip)
        offence = (existing.offence_count + 1) if existing else 1
        if override_duration is not None:
            duration = float(override_duration)
        elif self._progressive:
            duration = float(min(self._base_duration * (2 ** (offence - 1)), self._max_duration))
        else:
            duration = float(self._base_duration)

        rec = _BanRecord(ip=ip, banned_at=time.monotonic(), duration=duration, offence_count=offence)
        self._bans[ip] = rec
        self._attempts.pop(ip, None)

        _LOG.security_event(
            "IP_BANNED",
            src_ip=ip,
            username=username,
            action="BAN",
            duration=duration,
            offence=offence,
            reason=reason,
        )

        self._apply_system_ban(ip)
        if self._on_ban:
            self._on_ban(ip, int(duration))

    def _unban(self, ip: str) -> bool:
        if ip not in self._bans:
            return False
        del self._bans[ip]
        self._lift_system_ban(ip)
        _LOG.security_event("IP_UNBANNED", src_ip=ip, action="UNBAN")
        if self._on_unban:
            self._on_unban(ip)
        return True

    def _apply_system_ban(self, ip: str) -> None:
        # nftables set approach — fast, atomic, no process per-IP
        try:
            subprocess.run(
                ["nft", "add", "element", "inet", "ssh_fortress", "banned_ips", f"{{{ip}}}"],
                capture_output=True, timeout=2,
            )
        except Exception:
            pass  # nftables may not be configured yet; RateLimiter handles that

        if self._fail2ban_enabled:
            try:
                subprocess.run(
                    ["fail2ban-client", "set", "sshd-fortress", "banip", ip],
                    capture_output=True, timeout=3,
                )
            except Exception:
                pass

    def _lift_system_ban(self, ip: str) -> None:
        try:
            subprocess.run(
                ["nft", "delete", "element", "inet", "ssh_fortress", "banned_ips", f"{{{ip}}}"],
                capture_output=True, timeout=2,
            )
        except Exception:
            pass
        if self._fail2ban_enabled:
            try:
                subprocess.run(
                    ["fail2ban-client", "set", "sshd-fortress", "unbanip", ip],
                    capture_output=True, timeout=3,
                )
            except Exception:
                pass

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist:
            return True
        if self._whitelist_cidrs:
            try:
                from netaddr import IPAddress, IPNetwork
                addr = IPAddress(ip)
                return any(addr in IPNetwork(cidr) for cidr in self._whitelist_cidrs)
            except Exception:
                pass
        return False

    def _reap_loop(self) -> None:
        """Background thread: expire bans and stale attempt windows."""
        while True:
            time.sleep(60)
            now = time.monotonic()
            with self._lock:
                expired_bans = [
                    ip for ip, rec in self._bans.items()
                    if (now - rec.banned_at) >= rec.duration
                ]
                for ip in expired_bans:
                    self._unban(ip)

                stale_ips = [
                    ip for ip, dq in self._attempts.items()
                    if not dq or (now - dq[-1]) > self._window
                ]
                for ip in stale_ips:
                    del self._attempts[ip]
