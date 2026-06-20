"""
GeoBlocker — allow-list or block-list SSH access by country using MaxMind
GeoLite2-Country.  Works alongside nftables (preferred) or iptables.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import threading
from pathlib import Path
from typing import Optional

from modules.core import ConfigManager, get_logger

_LOG = get_logger("protection.geo_blocker")


class GeoBlocker:

    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg
        c = cfg.section("geo_blocker")
        self._enabled: bool = c.get("enabled", False)
        self._mmdb_path: Path = Path(c.get("mmdb_path", "/var/lib/ssh-fortress/GeoLite2-Country.mmdb"))
        self._mode: str = c.get("mode", "allowlist")   # allowlist | blocklist
        self._countries: set[str] = set(c.get("countries", []))
        self._reader = None
        self._lock = threading.Lock()

    def start(self) -> None:
        if not self._enabled:
            return
        self._load_reader()

    def is_allowed(self, ip: str) -> bool:
        """Return True if this IP should be allowed to connect."""
        if not self._enabled or self._reader is None:
            return True
        if self._is_private(ip):
            return True

        country = self._country_for(ip)
        if country is None:
            # Unknown geo: allow in allowlist mode, block in blocklist mode
            return self._mode == "allowlist"

        if self._mode == "allowlist":
            allowed = country in self._countries
        else:
            allowed = country not in self._countries

        if not allowed:
            _LOG.security_event(
                "GEO_BLOCK", src_ip=ip, action="BLOCK",
                country=country, mode=self._mode,
            )
        return allowed

    def reload(self) -> None:
        with self._lock:
            self._reader = None
            self._load_reader()

    # ── private ──────────────────────────────────────────────────────────────

    def _load_reader(self) -> None:
        if not self._mmdb_path.exists():
            _LOG.warning("GeoIP DB not found — geo-blocking disabled", path=str(self._mmdb_path))
            return
        try:
            import geoip2.database  # type: ignore[import]
            with self._lock:
                self._reader = geoip2.database.Reader(str(self._mmdb_path))
            _LOG.info("GeoIP2 database loaded", path=str(self._mmdb_path))
        except Exception as e:
            _LOG.error("Failed to load GeoIP2 DB", error=str(e))

    def _country_for(self, ip: str) -> Optional[str]:
        if self._reader is None:
            return None
        try:
            with self._lock:
                response = self._reader.country(ip)
            return response.country.iso_code
        except Exception:
            return None

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
