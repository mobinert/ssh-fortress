"""
PAMConfigurator — configures /etc/pam.d/sshd for:
  • pam_tally2 / pam_faillock account lockout
  • optional Google Authenticator TOTP (2FA)
  • pam_limits resource enforcement
"""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

from modules.core import ConfigManager, get_logger

_LOG = get_logger("hardening.pam")
_PAM_SSHD = Path("/etc/pam.d/sshd")


class PAMConfigurator:

    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg
        self._two_factor = cfg.get("two_factor", "enabled", default=False)

    def apply(self, dry_run: bool = False) -> bool:
        if not _PAM_SSHD.exists():
            _LOG.warning("PAM sshd file not found", path=str(_PAM_SSHD))
            return False

        content = self._build_pam_config()

        if dry_run:
            _LOG.info("DRY RUN — PAM config (not written)")
            print(content)
            return True

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy2(_PAM_SSHD, _PAM_SSHD.with_suffix(f".fortress_backup_{ts}"))
        _PAM_SSHD.write_text(content)
        _LOG.info("PAM sshd config applied", two_factor=self._two_factor)
        return True

    def _build_pam_config(self) -> str:
        totp_line = ""
        if self._two_factor:
            totp_line = (
                "# SSH Fortress: TOTP 2FA\n"
                "auth required pam_google_authenticator.so nullok\n"
            )

        return f"""# ============================================================
# SSH Fortress — PAM sshd configuration
# Generated: {datetime.now().isoformat()}
# ============================================================

# Account lockout (pam_faillock — RHEL 8+/Fedora; falls back to pam_tally2)
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth        include       password-auth
auth        [default=die] pam_faillock.so authfail audit deny=5

{totp_line}
# Standard auth stack
auth        include       password-auth

account     required      pam_nologin.so
account     required      pam_faillock.so
account     include       password-auth

# Resource limits
session     required      pam_limits.so
session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open env_params
session     optional      pam_keyinit.so force revoke
session     include       password-auth
"""
