"""
Telegram alerts for SSH Fortress.
Sends messages on login success, brute force bans, and anomalies.

Setup:
  1. Talk to @BotFather on Telegram, create a bot, get token
  2. Get your chat_id from @userinfobot
  3. Put both in settings.yaml under alerting.telegram
"""

import json
import time
import urllib.request
import urllib.error
import threading
import queue
from datetime import datetime


class TelegramNotifier:

    def __init__(self, cfg):
        tg = cfg.section("alerting").get("telegram", {})
        self.enabled = tg.get("enabled", False)
        self.token = tg.get("bot_token", "")
        self.chat_id = tg.get("chat_id", "")
        self.notify_on = tg.get("notify_on", [
            "AUTH_SUCCESS", "BRUTE_FORCE_BAN", "ROOT_ATTEMPT", "IMPOSSIBLE_TRAVEL"
        ])
        self.silent_hours = tg.get("silent_hours", [])  # e.g. ["02:00-06:00"]
        self._base_url = f"https://api.telegram.org/bot{self.token}"

        # queue so we never block the main thread
        self._q = queue.Queue(maxsize=500)
        self._worker = threading.Thread(target=self._send_loop, daemon=True, name="tg-notifier")
        if self.enabled:
            self._worker.start()

    def send_login_success(self, username, src_ip, method, country="unknown"):
        if not self.enabled or "AUTH_SUCCESS" not in self.notify_on:
            return
        msg = (
            "✅ *SSH Login Successful*\n"
            f"👤 User: `{username}`\n"
            f"🌐 IP: `{src_ip}`\n"
            f"🔑 Method: `{method}`\n"
            f"🌍 Country: `{country}`\n"
            f"🕐 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        self._enqueue(msg)

    def send_brute_force_ban(self, ip, attempt_count, duration_s, username="unknown"):
        if not self.enabled or "BRUTE_FORCE_BAN" not in self.notify_on:
            return
        hours = duration_s // 3600
        mins = (duration_s % 3600) // 60
        ban_str = f"{hours}h {mins}m" if hours else f"{mins}m"
        msg = (
            "🚫 *Brute Force Detected — IP Banned*\n"
            f"🌐 IP: `{ip}`\n"
            f"👤 Target user: `{username}`\n"
            f"💥 Attempts: `{attempt_count}`\n"
            f"⏱️ Ban duration: `{ban_str}`\n"
            f"🕐 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        self._enqueue(msg)

    def send_login_failed(self, ip, username, attempt_num, max_attempts):
        if not self.enabled or "AUTH_FAILURE" not in self.notify_on:
            return
        msg = (
            "⚠️ *Failed SSH Login*\n"
            f"🌐 IP: `{ip}`\n"
            f"👤 User: `{username}`\n"
            f"🔢 Attempt: `{attempt_num}/{max_attempts}`\n"
            f"🕐 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        self._enqueue(msg)

    def send_root_attempt(self, ip):
        if not self.enabled or "ROOT_ATTEMPT" not in self.notify_on:
            return
        msg = (
            "🚨 *ROOT Login Attempt!*\n"
            f"🌐 IP: `{ip}`\n"
            f"🕐 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
            "_Someone tried to login as root — check your server_"
        )
        self._enqueue(msg)

    def send_anomaly(self, alert_type, details):
        if not self.enabled or "ANOMALY" not in self.notify_on:
            return
        lines = [f"🔴 *Security Anomaly: {alert_type}*"]
        for k, v in details.items():
            lines.append(f"• {k}: `{v}`")
        lines.append(f"🕐 `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")
        self._enqueue("\n".join(lines))

    def send_raw(self, text):
        if not self.enabled:
            return
        self._enqueue(text)

    def _enqueue(self, msg):
        if self._is_silent_hours():
            return
        try:
            self._q.put_nowait(msg)
        except queue.Full:
            pass  # drop if queue is full, no big deal

    def _send_loop(self):
        while True:
            try:
                msg = self._q.get(timeout=5)
                self._do_send(msg)
                time.sleep(0.3)  # rate limit: ~3 msgs/sec max
            except queue.Empty:
                continue
            except Exception:
                time.sleep(2)

    def _do_send(self, text, retries=3):
        url = f"{self._base_url}/sendMessage"
        payload = json.dumps({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }).encode()

        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url, data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=10):
                    return
            except urllib.error.HTTPError as e:
                if e.code == 429:  # rate limited
                    time.sleep(5)
                elif attempt == retries - 1:
                    print(f"[Telegram] Failed to send: {e}")
                    return
            except Exception as e:
                if attempt == retries - 1:
                    print(f"[Telegram] Error: {e}")
                time.sleep(2 ** attempt)

    def _is_silent_hours(self):
        if not self.silent_hours:
            return False
        now = datetime.now()
        current = now.hour * 60 + now.minute
        for range_str in self.silent_hours:
            try:
                start_s, end_s = range_str.split("-")
                sh, sm = map(int, start_s.split(":"))
                eh, em = map(int, end_s.split(":"))
                start = sh * 60 + sm
                end = eh * 60 + em
                if start <= current <= end:
                    return True
            except Exception:
                pass
        return False

    def test(self):
        """Send a test message to verify the bot is working."""
        self._do_send(
            "🛡️ *SSH Fortress — Test Message*\n"
            "Your Telegram alerts are working correctly!\n"
            f"🕐 `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        return True
