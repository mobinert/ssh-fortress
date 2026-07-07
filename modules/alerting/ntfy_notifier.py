"""
NtfyNotifier — push alerts to an ntfy.sh topic (or a self-hosted ntfy server).

ntfy is the simplest possible pub/sub push channel: an HTTP POST to
`<server>/<topic>` shows up instantly on your phone via the ntfy app, with no
bot to register and no account required. Great for homelab / small-fleet
operators who don't want to run Telegram or SMTP.

Zero dependencies — plain urllib. `build_request()` is separated out so the
exact payload/headers can be unit-tested without touching the network.
"""

from __future__ import annotations

import urllib.request
from typing import Any

from modules.core import ConfigManager, get_logger

_LOG = get_logger("alerting.ntfy")

# alert_type -> (ntfy priority 1..5, emoji tags)
_STYLE = {
    "AUTH_SUCCESS":    (3, ["white_check_mark"]),
    "AUTH_FAILURE":    (2, ["warning"]),
    "BRUTE_FORCE_BAN": (5, ["no_entry", "hammer"]),
    "ROOT_ATTEMPT":    (5, ["rotating_light", "skull"]),
    "THREAT_BAN":      (5, ["no_entry", "brain"]),
    "ANOMALY":         (4, ["mag", "warning"]),
}


class NtfyNotifier:
    def __init__(self, cfg: ConfigManager) -> None:
        c = cfg.section("alerting").get("ntfy", {})
        self.enabled: bool = c.get("enabled", False)
        self._server: str = str(c.get("server", "https://ntfy.sh")).rstrip("/")
        self._topic: str = c.get("topic", "")
        self._token: str = c.get("token", "")
        self._default_priority: int = c.get("priority", 3)
        self._timeout: int = c.get("timeout", 10)

    # ── public ─────────────────────────────────────────────────────────────────

    def send_event(self, alert_type: str, details: dict[str, Any]) -> None:
        """Format and push a security event to the configured topic."""
        if not self.enabled or not self._topic:
            return
        priority, tags = _STYLE.get(alert_type, (self._default_priority, ["shield"]))
        ip = details.get("src_ip", "")
        user = details.get("username", "")
        title = f"SSH Fortress — {alert_type.replace('_', ' ').title()}"
        body_parts = [p for p in (
            f"IP {ip}" if ip else "",
            f"user {user}" if user else "",
        ) if p]
        for k, v in details.items():
            if k not in ("src_ip", "username") and v not in ("", None):
                body_parts.append(f"{k}={v}")
        message = " · ".join(body_parts) or "event"
        self._post(title, message, priority, tags)

    def test(self) -> None:
        self._post("SSH Fortress — test", "ntfy channel is working ✅", 3, ["shield"])

    # ── internals ──────────────────────────────────────────────────────────────

    def build_request(
        self, title: str, message: str, priority: int, tags: list[str]
    ) -> urllib.request.Request:
        """Build (but do not send) the ntfy HTTP request — unit-test seam."""
        headers = {
            "Title": title,
            "Priority": str(priority),
            "Tags": ",".join(tags),
            "Content-Type": "text/plain; charset=utf-8",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        url = f"{self._server}/{self._topic}"
        return urllib.request.Request(url, data=message.encode("utf-8"), headers=headers, method="POST")

    def _post(self, title: str, message: str, priority: int, tags: list[str]) -> None:
        try:
            req = self.build_request(title, message, priority, tags)
            with urllib.request.urlopen(req, timeout=self._timeout):
                pass
            _LOG.info("ntfy alert sent", title=title)
        except Exception as exc:
            _LOG.error("ntfy alert failed", error=str(exc))
