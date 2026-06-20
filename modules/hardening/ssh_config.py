"""
SSHConfigHardener — rewrites /etc/ssh/sshd_config to CIS Level 2 / NSA
hardening guide recommendations, with a full backup before any change.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from modules.core import ConfigManager, get_logger

_LOG = get_logger("hardening.ssh_config")


class SSHConfigHardener:
    """Apply SSH daemon hardening to the running system."""

    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg
        self._sshd_path = Path(cfg.get("ssh", "config_path", default="/etc/ssh/sshd_config"))

    # ── public API ───────────────────────────────────────────────────────────

    def apply(self, dry_run: bool = False) -> bool:
        """
        Build the hardened config, optionally write it, validate it, then
        reload sshd.  Returns True on success.
        """
        if not self._sshd_path.exists():
            _LOG.error("sshd_config not found", path=str(self._sshd_path))
            return False

        new_content = self._build_config()

        if dry_run:
            _LOG.info("DRY RUN — hardened config (not written)", preview=new_content[:400])
            return True

        self._backup()
        self._sshd_path.write_text(new_content)
        _LOG.info("Hardened sshd_config written", path=str(self._sshd_path))

        if not self._validate():
            _LOG.error("sshd -t validation FAILED — reverting to backup")
            self._restore_latest_backup()
            return False

        self._reload_sshd()
        _LOG.info("sshd reloaded successfully")
        return True

    def audit(self) -> list[dict[str, Any]]:
        """
        Compare current sshd_config against required hardening settings.
        Returns a list of {key, current, required, compliant} dicts.
        """
        if not self._sshd_path.exists():
            return []

        current = self._parse_current()
        required = self._required_settings()
        findings: list[dict[str, Any]] = []

        for key, req_value in required.items():
            cur_value = current.get(key.lower(), "NOT SET")
            compliant = str(cur_value).lower() == str(req_value).lower()
            findings.append(
                {"key": key, "current": cur_value, "required": req_value, "compliant": compliant}
            )
            if not compliant:
                _LOG.warning(
                    "AUDIT_FAIL", key=key, current=cur_value, required=req_value
                )
        return findings

    # ── private ──────────────────────────────────────────────────────────────

    def _required_settings(self) -> dict[str, str]:
        c = self._cfg
        return {
            "Port": str(c.get("ssh", "port", default=22)),
            "Protocol": "2",
            "PermitRootLogin": c.get("ssh", "permit_root_login", default="no"),
            "PasswordAuthentication": c.get("ssh", "password_auth", default="no"),
            "PubkeyAuthentication": c.get("ssh", "pubkey_auth", default="yes"),
            "ChallengeResponseAuthentication": c.get("ssh", "challenge_response_auth", default="no"),
            "KerberosAuthentication": c.get("ssh", "kerberos_auth", default="no"),
            "GSSAPIAuthentication": c.get("ssh", "gssapi_auth", default="no"),
            "X11Forwarding": c.get("ssh", "x11_forwarding", default="no"),
            "AllowTcpForwarding": c.get("ssh", "allow_tcp_forwarding", default="no"),
            "AllowAgentForwarding": c.get("ssh", "allow_agent_forwarding", default="no"),
            "PermitTunnel": c.get("ssh", "permit_tunnel", default="no"),
            "PrintMotd": c.get("ssh", "print_motd", default="no"),
            "MaxAuthTries": str(c.get("ssh", "max_auth_tries", default=3)),
            "MaxSessions": str(c.get("ssh", "max_sessions", default=5)),
            "LoginGraceTime": str(c.get("ssh", "login_grace_time", default=30)),
            "ClientAliveInterval": str(c.get("ssh", "client_alive_interval", default=300)),
            "ClientAliveCountMax": str(c.get("ssh", "client_alive_count_max", default=2)),
            "UsePAM": "yes",
            "StrictModes": "yes",
            "IgnoreRhosts": "yes",
            "HostbasedAuthentication": "no",
            "PermitEmptyPasswords": "no",
            "UsePrivilegeSeparation": "sandbox",
            "Compression": "no",
            "TCPKeepAlive": "no",
            "Banner": "/etc/issue.net",
            "LogLevel": "VERBOSE",
            "SyslogFacility": "AUTH",
        }

    def _build_config(self) -> str:
        c = self._cfg
        listen = "\n".join(
            f"ListenAddress {addr}"
            for addr in c.get("ssh", "listen_addresses", default=["0.0.0.0"])
        )
        kex = ",".join(c.get("ssh", "kex_algorithms", default=[]))
        ciphers = ",".join(c.get("ssh", "ciphers", default=[]))
        macs = ",".join(c.get("ssh", "macs", default=[]))
        hka = ",".join(c.get("ssh", "host_key_algorithms", default=[]))

        allow_users = c.get("ssh", "allow_users", default=[])
        allow_groups = c.get("ssh", "allow_groups", default=[])
        access_lines = ""
        if allow_users:
            access_lines += f"AllowUsers {' '.join(allow_users)}\n"
        if allow_groups:
            access_lines += f"AllowGroups {' '.join(allow_groups)}\n"

        sftp_block = ""
        if c.get("ssh", "sftp_enabled", default=True):
            chroot = c.get("ssh", "sftp_chroot", default="/home/%u")
            sftp_block = (
                "\n# SFTP Subsystem (chrooted)\n"
                "Subsystem sftp internal-sftp\n"
                f"Match Group sftponly\n"
                f"    ChrootDirectory {chroot}\n"
                "    ForceCommand internal-sftp\n"
                "    AllowTcpForwarding no\n"
                "    X11Forwarding no\n"
            )

        req = self._required_settings()
        main_block = "\n".join(f"{k} {v}" for k, v in req.items())

        return f"""# ============================================================
# SSH Fortress — Hardened sshd_config
# Generated: {datetime.now().isoformat()}
# DO NOT EDIT MANUALLY — managed by ssh-fortress
# ============================================================

{listen}

# ── Host Keys ────────────────────────────────────────────────
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# ── Cryptographic Policy ─────────────────────────────────────
KexAlgorithms {kex}
Ciphers {ciphers}
MACs {macs}
HostKeyAlgorithms {hka}

# ── Hardening Settings ───────────────────────────────────────
{main_block}

# ── Access Control ───────────────────────────────────────────
{access_lines}
# ── Subsystems ───────────────────────────────────────────────
{sftp_block}
"""

    def _parse_current(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in self._sshd_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0].lower()] = parts[1]
        return result

    def _backup(self) -> Path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self._sshd_path.with_suffix(f".fortress_backup_{ts}")
        shutil.copy2(self._sshd_path, backup_path)
        _LOG.info("Backup created", backup=str(backup_path))
        return backup_path

    def _restore_latest_backup(self) -> None:
        backups = sorted(self._sshd_path.parent.glob("sshd_config.fortress_backup_*"), reverse=True)
        if backups:
            shutil.copy2(backups[0], self._sshd_path)
            _LOG.info("Backup restored", source=str(backups[0]))

    def _validate(self) -> bool:
        result = subprocess.run(["sshd", "-t"], capture_output=True, text=True)
        if result.returncode != 0:
            _LOG.error("sshd -t failed", stderr=result.stderr)
        return result.returncode == 0

    def _reload_sshd(self) -> None:
        for cmd in (["systemctl", "reload", "sshd"], ["systemctl", "reload", "ssh"]):
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                return
        subprocess.run(["kill", "-HUP", "$(cat /var/run/sshd.pid)"], shell=True)
