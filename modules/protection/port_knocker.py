"""
PortKnocker — listens for a TCP/UDP knock sequence and opens the SSH port
only for the knocking IP (via nftables timed set entry).

Runs in a background thread — zero impact on normal SSH traffic.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from collections import defaultdict, deque

from modules.core import ConfigManager, get_logger

_LOG = get_logger("protection.port_knocker")


class PortKnocker:

    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg
        c = cfg.section("port_knocking")
        self._enabled: bool = c.get("enabled", False)
        self._sequence: list[int] = c.get("sequence", [7000, 8000, 9000])
        self._timeout: int = c.get("timeout", 10)
        self._protocol: str = c.get("protocol", "tcp").lower()
        self._auto_close: bool = c.get("auto_close", True)
        self._close_after: int = c.get("close_after", 30)
        self._ssh_port: int = cfg.get("ssh", "port", default=22)

        # ip -> deque of (port_knocked, timestamp)
        self._progress: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._listeners: list[socket.socket] = []
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._enabled:
            return
        # Close SSH port to everyone; only open per-IP after correct knock
        self._close_ssh_globally()
        self._thread = threading.Thread(
            target=self._listen_loop, daemon=True, name="port-knocker"
        )
        self._thread.start()
        _LOG.info(
            "Port knocker active",
            sequence=self._sequence,
            protocol=self._protocol,
        )

    def stop(self) -> None:
        for s in self._listeners:
            try:
                s.close()
            except Exception:
                pass

    # ── private ──────────────────────────────────────────────────────────────

    def _listen_loop(self) -> None:
        socks: list[tuple[socket.socket, int]] = []
        sock_type = socket.SOCK_STREAM if self._protocol == "tcp" else socket.SOCK_DGRAM

        for port in self._sequence:
            s = socket.socket(socket.AF_INET, sock_type)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.settimeout(1.0)
            if self._protocol == "tcp":
                s.listen(5)
            socks.append((s, port))
            self._listeners.append(s)

        while True:
            for s, port in socks:
                try:
                    if self._protocol == "tcp":
                        conn, (ip, _) = s.accept()
                        conn.close()
                    else:
                        _, (ip, _) = s.recvfrom(16)
                    self._record_knock(ip, port)
                except socket.timeout:
                    pass
                except Exception:
                    pass

    def _record_knock(self, ip: str, port: int) -> None:
        now = time.monotonic()
        with self._lock:
            dq = self._progress[ip]
            # Remove expired entries
            while dq and now - dq[0][1] > self._timeout:
                dq.popleft()

            dq.append((port, now))
            # Check if knock sequence matches
            knocked = [p for p, _ in dq]
            seq_len = len(self._sequence)
            if len(knocked) >= seq_len and knocked[-seq_len:] == self._sequence:
                dq.clear()
                _LOG.security_event("PORT_KNOCK_SUCCESS", src_ip=ip, action="OPEN")
                threading.Thread(
                    target=self._open_for_ip,
                    args=(ip,),
                    daemon=True,
                ).start()

    def _open_for_ip(self, ip: str) -> None:
        # Add IP to nftables allowed set with a timeout
        timeout = f"{self._close_after}s"
        subprocess.run(
            ["nft", "add", "element", "inet", "ssh_fortress", "knock_allowed",
             f"{{{ip} timeout {timeout}}}"],
            capture_output=True,
        )
        _LOG.info("SSH port opened for IP", ip=ip, duration=self._close_after)

    def _close_ssh_globally(self) -> None:
        # Drop SSH for everyone except knock_allowed set
        subprocess.run([
            "nft", "add", "set", "inet", "ssh_fortress", "knock_allowed",
            "{ type ipv4_addr; flags dynamic,timeout; }"
        ], capture_output=True)
        subprocess.run([
            "nft", "insert", "rule", "inet", "ssh_fortress", "ssh_ratelimit",
            "tcp", "dport", str(self._ssh_port),
            "ip", "saddr", "!=", "@knock_allowed", "drop"
        ], capture_output=True)
        _LOG.info("SSH port closed globally — port knocking required")
