"""
Discord webhook alerts for SSH Fortress.
Uses Discord's embed format for clean, coloured notifications.
"""

import json
import time
import urllib.request
import threading
import queue
from datetime import datetime
import socket

HOSTNAME = socket.gethostname()

# Discord embed colors (decimal)
COLOR_GREEN  = 3066993
COLOR_RED    = 15158332
COLOR_ORANGE = 15105570
COLOR_PURPLE = 10181046
COLOR_BLUE   = 3447003


class DiscordNotifier:

    def __init__(self, cfg):
        dc = cfg.section("alerting").get("discord", {})
        self.enabled = dc.get("enabled", False)
        self.webhook_url = dc.get("webhook_url", "")
        self.username = dc.get("username", "SSH Fortress")
        self.notify_on = dc.get("notify_on", [
            "AUTH_SUCCESS", "BRUTE_FORCE_BAN", "ROOT_ATTEMPT"
        ])

        self._q = queue.Queue(maxsize=300)
        self._worker = threading.Thread(target=self._loop, daemon=True, name="discord-notifier")
        if self.enabled and self.webhook_url:
            self._worker.start()

    def notify_login_success(self, username, ip, method, country="N/A"):
        if not self.enabled or "AUTH_SUCCESS" not in self.notify_on:
            return
        self._enqueue({
            "username": self.username,
            "embeds": [{
                "title": "✅ Successful SSH Login",
                "color": COLOR_GREEN,
                "fields": [
                    {"name": "Server", "value": f"`{HOSTNAME}`", "inline": True},
                    {"name": "User", "value": f"`{username}`", "inline": True},
                    {"name": "Source IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Method", "value": f"`{method}`", "inline": True},
                    {"name": "Country", "value": f"`{country}`", "inline": True},
                ],
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "SSH Fortress Security Monitor"}
            }]
        })

    def notify_brute_force(self, ip, attempts, duration_s, username="unknown"):
        if not self.enabled or "BRUTE_FORCE_BAN" not in self.notify_on:
            return
        ban_str = f"{duration_s // 3600}h {(duration_s % 3600) // 60}m" if duration_s >= 3600 else f"{duration_s // 60}m"
        self._enqueue({
            "username": self.username,
            "embeds": [{
                "title": "🚫 Brute Force Attack Blocked",
                "color": COLOR_RED,
                "description": f"IP `{ip}` has been banned for `{ban_str}`",
                "fields": [
                    {"name": "Server", "value": f"`{HOSTNAME}`", "inline": True},
                    {"name": "Attacker IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Target User", "value": f"`{username}`", "inline": True},
                    {"name": "Attempts", "value": f"`{attempts}`", "inline": True},
                    {"name": "Ban Duration", "value": f"`{ban_str}`", "inline": True},
                ],
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "SSH Fortress Security Monitor"}
            }]
        })

    def notify_root_attempt(self, ip, country="N/A"):
        if not self.enabled or "ROOT_ATTEMPT" not in self.notify_on:
            return
        self._enqueue({
            "username": self.username,
            "embeds": [{
                "title": "🚨 Root Login Attempt!",
                "color": COLOR_RED,
                "description": "Someone tried to login as **root**. This is serious.",
                "fields": [
                    {"name": "Server", "value": f"`{HOSTNAME}`", "inline": True},
                    {"name": "Attacker IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Country", "value": f"`{country}`", "inline": True},
                ],
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "SSH Fortress Security Monitor"}
            }]
        })

    def notify_anomaly(self, alert_type, details):
        if not self.enabled or "ANOMALY" not in self.notify_on:
            return
        fields = [{"name": k, "value": f"`{v}`", "inline": True} for k, v in details.items()]
        self._enqueue({
            "username": self.username,
            "embeds": [{
                "title": f"🔴 Anomaly: {alert_type.replace('_', ' ').title()}",
                "color": COLOR_PURPLE,
                "fields": fields[:25],  # discord limit
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "SSH Fortress Security Monitor"}
            }]
        })

    def _enqueue(self, payload):
        try:
            self._q.put_nowait(payload)
        except queue.Full:
            pass

    def _loop(self):
        while True:
            try:
                payload = self._q.get(timeout=5)
                self._post(payload)
                time.sleep(0.5)  # discord rate limit: ~2 req/sec per webhook
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Discord] Error: {e}")
                time.sleep(3)

    def _post(self, payload, retries=3):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.webhook_url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    if r.status == 204:
                        return
            except Exception as e:
                if attempt == retries - 1:
                    print(f"[Discord] Failed after {retries} attempts: {e}")
                time.sleep(2 ** attempt)
