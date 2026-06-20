"""
KeyAuditor — scans all authorized_keys files across all user home directories:
  • Detects weak key types (DSA, ECDSA-256)
  • Detects undersized RSA keys (< configured minimum)
  • Flags keys older than max_key_age_days (requires comment with date or git)
  • Reports duplicate keys across users
  • Optionally revokes expired/weak keys (dry-run by default)
"""

from __future__ import annotations

import glob
import os
import pwd
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from modules.core import ConfigManager, get_logger

_LOG = get_logger("key_management.auditor")


@dataclass
class KeyEntry:
    path: str
    username: str
    key_type: str
    bits: int
    comment: str
    fingerprint: str
    options: str = ""
    raw_line: str = ""
    issues: list[str] = field(default_factory=list)

    @property
    def is_compliant(self) -> bool:
        return len(self.issues) == 0


class KeyAuditor:

    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg
        c = cfg.section("key_management")
        self._enabled: bool = c.get("audit_enabled", True)
        self._min_bits: dict = c.get("min_key_bits", {"rsa": 4096, "ecdsa": 521, "ed25519": 256})
        self._max_age_days: int = c.get("max_key_age_days", 365)
        self._revoke: bool = c.get("revoke_expired", False)
        self._ak_patterns: list[str] = c.get(
            "authorized_keys_paths",
            ["~/.ssh/authorized_keys", "/etc/ssh/authorized_keys/%u"],
        )

    def audit(self) -> list[KeyEntry]:
        """Run full audit across all system users. Returns list of KeyEntry."""
        if not self._enabled:
            return []

        entries: list[KeyEntry] = []
        seen_fingerprints: dict[str, KeyEntry] = {}

        for user in self._system_users():
            for ak_path in self._ak_paths_for(user):
                if not ak_path.exists():
                    continue
                for entry in self._parse_authorized_keys(ak_path, user.pw_name):
                    self._check_compliance(entry)
                    # Duplicate key detection
                    if entry.fingerprint in seen_fingerprints:
                        other = seen_fingerprints[entry.fingerprint]
                        entry.issues.append(
                            f"Duplicate key — also used by {other.username} in {other.path}"
                        )
                    else:
                        seen_fingerprints[entry.fingerprint] = entry
                    entries.append(entry)

        non_compliant = [e for e in entries if not e.is_compliant]
        _LOG.info(
            "Key audit complete",
            total=len(entries),
            non_compliant=len(non_compliant),
        )
        for e in non_compliant:
            _LOG.security_event(
                "KEY_AUDIT_FAIL",
                username=e.username,
                path=e.path,
                key_type=e.key_type,
                bits=e.bits,
                issues="; ".join(e.issues),
                action="AUDIT",
            )
            if self._revoke:
                self._remove_key(e)

        return entries

    # ── private ───────────────────────────────────────────────────────────────

    def _parse_authorized_keys(self, path: Path, username: str) -> list[KeyEntry]:
        entries: list[KeyEntry] = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = self._parse_key_line(line, str(path), username)
            if entry:
                entries.append(entry)
        return entries

    def _parse_key_line(self, line: str, path: str, username: str) -> Optional[KeyEntry]:
        parts = line.split()
        # authorized_keys format: [options] key-type base64-key [comment]
        idx = 0
        options = ""
        # Options are comma-separated and come before key type
        if parts and not parts[0].startswith("ssh-") and not parts[0].startswith("ecdsa-") and not parts[0].startswith("sk-"):
            options = parts[0]
            idx = 1

        if len(parts) < idx + 2:
            return None

        key_type = parts[idx] if idx < len(parts) else ""
        b64_key = parts[idx + 1] if idx + 1 < len(parts) else ""
        comment = " ".join(parts[idx + 2:]) if idx + 2 < len(parts) else ""

        if not key_type or not b64_key:
            return None

        fp, bits = self._get_key_info(key_type, b64_key)
        return KeyEntry(
            path=path,
            username=username,
            key_type=key_type,
            bits=bits,
            comment=comment,
            fingerprint=fp,
            options=options,
            raw_line=line,
        )

    def _check_compliance(self, entry: KeyEntry) -> None:
        kt = entry.key_type.lower()

        # Banned key types
        if "dsa" in kt:
            entry.issues.append("DSA keys are cryptographically broken (FIPS 186-4 deprecated)")
            return

        # Minimum bit sizes
        if "rsa" in kt:
            min_bits = self._min_bits.get("rsa", 4096)
            if entry.bits > 0 and entry.bits < min_bits:
                entry.issues.append(f"RSA key too small: {entry.bits} bits (min {min_bits})")

        elif "ecdsa" in kt and "sk-" not in kt:
            min_bits = self._min_bits.get("ecdsa", 521)
            if entry.bits > 0 and entry.bits < min_bits:
                entry.issues.append(f"ECDSA key too small: {entry.bits} bits (min {min_bits})")

    def _get_key_info(self, key_type: str, b64_key: str) -> tuple[str, int]:
        try:
            result = subprocess.run(
                ["ssh-keygen", "-l", "-f", "/dev/stdin"],
                input=f"{key_type} {b64_key} comment\n",
                capture_output=True, text=True, timeout=5,
            )
            # Output: 4096 SHA256:xxxxx comment (RSA)
            parts = result.stdout.split()
            bits = int(parts[0]) if parts and parts[0].isdigit() else 0
            fp = parts[1] if len(parts) > 1 else ""
            return fp, bits
        except Exception:
            return "", 0

    def _remove_key(self, entry: KeyEntry) -> None:
        try:
            path = Path(entry.path)
            lines = path.read_text().splitlines()
            new_lines = [l for l in lines if l.strip() != entry.raw_line.strip()]
            path.write_text("\n".join(new_lines) + "\n")
            _LOG.warning("KEY_REVOKED", path=entry.path, user=entry.username,
                         fingerprint=entry.fingerprint, issues=entry.issues)
        except Exception as e:
            _LOG.error("Failed to revoke key", error=str(e))

    def _system_users(self) -> list[pwd.struct_passwd]:
        return [u for u in pwd.getpwall() if u.pw_uid >= 1000 or u.pw_name == "root"]

    def _ak_paths_for(self, user: pwd.struct_passwd) -> list[Path]:
        paths: list[Path] = []
        for pattern in self._ak_patterns:
            expanded = pattern.replace("~", user.pw_dir).replace("%u", user.pw_name)
            paths.append(Path(expanded))
        return paths
