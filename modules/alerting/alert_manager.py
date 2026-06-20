"""
AlertManager — de-duplicates, rate-limits, and routes security alerts
to Email, Slack, PagerDuty, and generic webhooks.

Design:
  • Per-alert-type cooldown prevents alert storms
  • Each channel runs in its own thread — no channel blocks another
  • Configurable severity mapping per channel
"""

from __future__ import annotations

import json
import smtplib
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from modules.core import ConfigManager, get_logger

_LOG = get_logger("alerting.manager")


class AlertManager:

    def __init__(self, cfg: ConfigManager) -> None:
        self._enabled: bool = cfg.get("alerting", "enabled", default=True)
        self._cooldown: int = cfg.get("alerting", "cooldown", default=300)
        self._triggers: dict = cfg.section("alerting").get("triggers", {})
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()

        a = cfg.section("alerting")
        self._email_cfg = a.get("email", {})
        self._slack_cfg = a.get("slack", {})
        self._pd_cfg = a.get("pagerduty", {})
        self._wh_cfg = a.get("webhook", {})

    def send(self, alert_type: str, details: dict[str, Any]) -> None:
        if not self._enabled:
            return
        if not self._triggers.get(alert_type.lower(), True):
            return

        with self._lock:
            last = self._last_alert.get(alert_type, 0)
            if time.monotonic() - last < self._cooldown:
                return
            self._last_alert[alert_type] = time.monotonic()

        payload = self._build_payload(alert_type, details)
        threads = []

        if self._email_cfg.get("enabled"):
            t = threading.Thread(target=self._send_email, args=(payload,), daemon=True)
            t.start(); threads.append(t)

        if self._slack_cfg.get("enabled"):
            t = threading.Thread(target=self._send_slack, args=(payload,), daemon=True)
            t.start(); threads.append(t)

        if self._pd_cfg.get("enabled"):
            t = threading.Thread(target=self._send_pagerduty, args=(alert_type, payload,), daemon=True)
            t.start(); threads.append(t)

        if self._wh_cfg.get("enabled"):
            t = threading.Thread(target=self._send_webhook, args=(payload,), daemon=True)
            t.start(); threads.append(t)

        _LOG.info("Alert dispatched", type=alert_type, channels=len(threads))

    # ── channel implementations ───────────────────────────────────────────────

    def _send_email(self, payload: dict) -> None:
        c = self._email_cfg
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SSH Fortress] {payload['alert_type']} on {payload['host']}"
            msg["From"] = c["from_addr"]
            msg["To"] = ", ".join(c["to_addrs"])

            text_body = self._format_text(payload)
            html_body = self._format_html(payload)
            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            ctx = ssl.create_default_context() if c.get("use_tls") else None
            with smtplib.SMTP(c["smtp_host"], c.get("smtp_port", 587)) as server:
                if ctx:
                    server.starttls(context=ctx)
                if c.get("username"):
                    server.login(c["username"], c["password"])
                server.sendmail(c["from_addr"], c["to_addrs"], msg.as_string())
            _LOG.info("Alert email sent", type=payload["alert_type"])
        except Exception as e:
            _LOG.error("Email alert failed", error=str(e))

    def _send_slack(self, payload: dict) -> None:
        c = self._slack_cfg
        icon = ":rotating_light:" if "CRITICAL" in payload.get("severity", "") else ":warning:"
        message = {
            "channel": c.get("channel", "#security-alerts"),
            "username": c.get("username", "SSH Fortress"),
            "icon_emoji": icon,
            "attachments": [{
                "color": "danger",
                "title": f"{payload['alert_type']} on {payload['host']}",
                "text": self._format_text(payload),
                "footer": "SSH Fortress",
                "ts": int(time.time()),
            }],
        }
        try:
            self._http_post(c["webhook_url"], message)
            _LOG.info("Slack alert sent", type=payload["alert_type"])
        except Exception as e:
            _LOG.error("Slack alert failed", error=str(e))

    def _send_pagerduty(self, alert_type: str, payload: dict) -> None:
        c = self._pd_cfg
        event = {
            "routing_key": c["routing_key"],
            "event_action": "trigger",
            "payload": {
                "summary": f"SSH Fortress: {alert_type} on {payload['host']}",
                "severity": c.get("severity", "warning"),
                "source": payload["host"],
                "custom_details": payload,
            },
            "dedup_key": f"ssh-fortress-{alert_type}-{payload['host']}",
        }
        try:
            self._http_post("https://events.pagerduty.com/v2/enqueue", event)
            _LOG.info("PagerDuty alert sent", type=alert_type)
        except Exception as e:
            _LOG.error("PagerDuty alert failed", error=str(e))

    def _send_webhook(self, payload: dict) -> None:
        c = self._wh_cfg
        try:
            self._http_post(c["url"], payload, headers=c.get("headers", {}))
            _LOG.info("Webhook alert sent", type=payload["alert_type"])
        except Exception as e:
            _LOG.error("Webhook alert failed", error=str(e))

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(alert_type: str, details: dict) -> dict:
        import socket
        return {
            "alert_type": alert_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": socket.gethostname(),
            "severity": "HIGH" if alert_type in {
                "BRUTE_FORCE_BAN", "ROOT_LOGIN_ATTEMPT", "IMPOSSIBLE_TRAVEL"
            } else "MEDIUM",
            **details,
        }

    @staticmethod
    def _format_text(payload: dict) -> str:
        lines = [
            f"SSH Fortress Alert — {payload['alert_type']}",
            f"Host      : {payload.get('host', '-')}",
            f"Timestamp : {payload.get('timestamp', '-')}",
            f"Severity  : {payload.get('severity', '-')}",
            "",
        ]
        for k, v in payload.items():
            if k not in ("alert_type", "host", "timestamp", "severity"):
                lines.append(f"{k:<20}: {v}")
        return "\n".join(lines)

    @staticmethod
    def _format_html(payload: dict) -> str:
        rows = "".join(
            f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
            for k, v in payload.items()
        )
        return (
            f"<html><body>"
            f"<h2 style='color:red'>SSH Fortress Alert — {payload['alert_type']}</h2>"
            f"<table border='1' cellpadding='4'>{rows}</table>"
            f"</body></html>"
        )

    @staticmethod
    def _http_post(url: str, data: dict, headers: dict | None = None) -> None:
        body = json.dumps(data).encode()
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
