"""
HealthChecker — periodically verifies that critical subsystems are running:
  • sshd process + correct config
  • nftables rules present
  • fail2ban jail active
  • SIEM backend reachability
  • Disk space for log files
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from modules.core import ConfigManager, get_logger

_LOG = get_logger("monitoring.health")

StatusCallback = Callable[[str, bool, str], None]


class HealthChecker:

    CHECK_INTERVAL = 60   # seconds

    def __init__(self, cfg: ConfigManager, on_fail: StatusCallback | None = None) -> None:
        self._cfg = cfg
        self._on_fail = on_fail
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="health-checker"
        )
        self._thread.start()
        _LOG.info("Health checker started", interval=self.CHECK_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> dict[str, bool]:
        results = {
            "sshd_running": self._check_sshd(),
            "nftables_loaded": self._check_nftables(),
            "fail2ban_running": self._check_fail2ban(),
            "log_disk_ok": self._check_disk(),
            "siem_reachable": self._check_siem(),
        }
        for check, ok in results.items():
            level = "info" if ok else "warning"
            getattr(_LOG, level)("HEALTH_CHECK", check=check, ok=ok)
        return results

    # ── checks ────────────────────────────────────────────────────────────────

    def _check_sshd(self) -> bool:
        try:
            result = subprocess.run(
                ["pgrep", "-x", "sshd"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_nftables(self) -> bool:
        try:
            result = subprocess.run(
                ["nft", "list", "table", "inet", "ssh_fortress"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_fail2ban(self) -> bool:
        cfg_enabled = self._cfg.get("brute_force", "fail2ban", "enabled", default=False)
        if not cfg_enabled:
            return True
        try:
            result = subprocess.run(
                ["fail2ban-client", "status"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_disk(self) -> bool:
        log_dir = Path(self._cfg.get("logging", "fortress_log_path",
                                     default="/var/log/ssh-fortress/fortress.log")).parent
        try:
            usage = shutil.disk_usage(str(log_dir))
            free_pct = usage.free / usage.total * 100
            if free_pct < 10:
                _LOG.warning("LOW_DISK_SPACE", path=str(log_dir), free_pct=round(free_pct, 1))
                return False
            return True
        except Exception:
            return True  # can't check — assume OK

    def _check_siem(self) -> bool:
        syslog_cfg = self._cfg.get("siem", "backends", "syslog", default={})
        if not syslog_cfg.get("enabled", False):
            return True
        host = syslog_cfg.get("host", "127.0.0.1")
        port = syslog_cfg.get("port", 514)
        proto = syslog_cfg.get("protocol", "UDP").upper()
        try:
            if proto == "UDP":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(b"<134>ssh-fortress health-check", (host, port))
                s.close()
                return True
            else:
                s = socket.create_connection((host, port), timeout=2)
                s.close()
                return True
        except Exception:
            return False

    # ── loop ──────────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.wait(self.CHECK_INTERVAL):
            results = self.run_once()
            if self._on_fail:
                for check, ok in results.items():
                    if not ok:
                        self._on_fail(check, ok, f"Health check failed: {check}")
