"""
CryptoPolicy — removes weak host keys, regenerates strong ones (Ed25519 +
RSA-4096), and verifies moduli file to eliminate small DH groups.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from modules.core import ConfigManager, get_logger

_LOG = get_logger("hardening.crypto")
_SSH_DIR = Path("/etc/ssh")


class CryptoPolicy:

    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg

    def harden(self, dry_run: bool = False) -> None:
        self._remove_weak_host_keys(dry_run)
        self._generate_host_keys(dry_run)
        self._harden_moduli(dry_run)

    # ── host keys ────────────────────────────────────────────────────────────

    def _remove_weak_host_keys(self, dry_run: bool) -> None:
        weak = [
            "ssh_host_dsa_key", "ssh_host_dsa_key.pub",
            "ssh_host_ecdsa_key", "ssh_host_ecdsa_key.pub",
        ]
        for name in weak:
            path = _SSH_DIR / name
            if path.exists():
                if dry_run:
                    _LOG.info("DRY RUN — would remove weak key", path=str(path))
                else:
                    path.unlink()
                    _LOG.info("Removed weak host key", path=str(path))

    def _generate_host_keys(self, dry_run: bool) -> None:
        keys = [
            ("ed25519", "ssh_host_ed25519_key", []),
            ("rsa", "ssh_host_rsa_key", ["-b", "4096"]),
        ]
        for key_type, name, extra_args in keys:
            path = _SSH_DIR / name
            if not path.exists():
                cmd = ["ssh-keygen", "-t", key_type, "-f", str(path), "-N", ""] + extra_args
                if dry_run:
                    _LOG.info("DRY RUN — would generate", key_type=key_type, path=str(path))
                else:
                    subprocess.run(cmd, check=True)
                    _LOG.info("Generated host key", key_type=key_type, path=str(path))
            else:
                _LOG.debug("Host key exists, skipping", key_type=key_type)

    # ── moduli ───────────────────────────────────────────────────────────────

    def _harden_moduli(self, dry_run: bool) -> None:
        """Remove DH moduli < 3072 bits (recommended minimum per NIST SP 800-77r1)."""
        moduli_path = _SSH_DIR / "moduli"
        if not moduli_path.exists():
            return

        lines = moduli_path.read_text().splitlines()
        safe = [l for l in lines if l.startswith("#") or self._modulus_bits(l) >= 3072]
        removed = len(lines) - len(safe)

        if dry_run:
            _LOG.info("DRY RUN — would remove weak moduli", count=removed)
            return

        if removed > 0:
            backup = moduli_path.with_suffix(".fortress_backup")
            backup.write_text("\n".join(lines))
            moduli_path.write_text("\n".join(safe))
            _LOG.info("Weak DH moduli removed", removed=removed, kept=len(safe))

    @staticmethod
    def _modulus_bits(line: str) -> int:
        parts = line.split()
        try:
            return int(parts[4]) if len(parts) > 4 else 0
        except (ValueError, IndexError):
            return 0
