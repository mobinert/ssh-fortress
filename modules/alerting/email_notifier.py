"""
Email notifications for SSH Fortress.
Sends nice HTML emails for: login success, brute force bans, anomalies, daily reports.

Uses standard smtplib — no extra dependencies.
"""

import smtplib
import ssl
import threading
import time
import queue
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
import socket


HOSTNAME = socket.gethostname()


class EmailNotifier:

    def __init__(self, cfg):
        em = cfg.section("alerting").get("email", {})
        self.enabled = em.get("enabled", False)
        self.smtp_host = em.get("smtp_host", "localhost")
        self.smtp_port = em.get("smtp_port", 587)
        self.use_tls = em.get("use_tls", True)
        self.username = em.get("username", "")
        self.password = em.get("password", "")
        self.from_addr = em.get("from_addr", "ssh-fortress@localhost")
        self.to_addrs = em.get("to_addrs", [])
        self.notify_on = em.get("notify_on", [
            "AUTH_SUCCESS", "BRUTE_FORCE_BAN", "ROOT_ATTEMPT"
        ])

        # rate limit per type — don't spam the inbox
        self._last_sent = {}
        self._cooldown = em.get("cooldown_minutes", 5) * 60
        self._lock = threading.Lock()

        # async queue so email never blocks log processing
        self._q = queue.Queue(maxsize=200)
        self._worker = threading.Thread(target=self._mail_loop, daemon=True, name="email-notifier")
        if self.enabled and self.to_addrs:
            self._worker.start()

    def notify_login_success(self, username, src_ip, method, port, country="N/A"):
        if not self._should_send("AUTH_SUCCESS"):
            return
        subject = f"[SSH Fortress] Successful login on {HOSTNAME}"
        html = self._template(
            title="Successful SSH Login",
            color="#27ae60",
            icon="✅",
            rows={
                "Server": HOSTNAME,
                "Username": username,
                "Source IP": src_ip,
                "Port": port,
                "Auth Method": method,
                "Country": country,
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            note="This is an informational alert. If you did not perform this login, investigate immediately."
        )
        self._enqueue(subject, html)

    def notify_brute_force_ban(self, ip, attempts, duration_s, username="unknown", country="N/A"):
        if not self._should_send("BRUTE_FORCE_BAN"):
            return
        subject = f"[SSH Fortress] ALERT: Brute force attack blocked on {HOSTNAME}"
        ban_str = f"{duration_s // 3600}h {(duration_s % 3600) // 60}m" if duration_s >= 3600 else f"{duration_s // 60}m"
        html = self._template(
            title="Brute Force Attack Blocked",
            color="#e74c3c",
            icon="🚫",
            rows={
                "Server": HOSTNAME,
                "Attacker IP": ip,
                "Target User": username,
                "Failed Attempts": attempts,
                "Ban Duration": ban_str,
                "Country": country,
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            note="The attacker IP has been banned. Review the logs for further activity from this IP."
        )
        self._enqueue(subject, html)

    def notify_login_failed(self, ip, username, attempt_num, max_attempts):
        if not self._should_send("AUTH_FAILURE"):
            return
        subject = f"[SSH Fortress] Failed login attempt on {HOSTNAME}"
        html = self._template(
            title="Failed SSH Login Attempt",
            color="#e67e22",
            icon="⚠️",
            rows={
                "Server": HOSTNAME,
                "Source IP": ip,
                "Username": username,
                "Attempt Number": f"{attempt_num} of {max_attempts}",
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            note=f"After {max_attempts} failed attempts the IP will be banned automatically."
        )
        self._enqueue(subject, html)

    def notify_root_attempt(self, ip, country="N/A"):
        if not self._should_send("ROOT_ATTEMPT"):
            return
        subject = f"[SSH Fortress] CRITICAL: Root login attempt on {HOSTNAME}"
        html = self._template(
            title="Root Login Attempt Detected",
            color="#c0392b",
            icon="🚨",
            rows={
                "Server": HOSTNAME,
                "Attacker IP": ip,
                "Country": country,
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            note="Someone attempted to log in as root. This is a critical security event."
        )
        self._enqueue(subject, html)

    def notify_anomaly(self, alert_type, details):
        if not self._should_send("ANOMALY"):
            return
        subject = f"[SSH Fortress] Security anomaly detected: {alert_type}"
        html = self._template(
            title=f"Anomaly: {alert_type.replace('_', ' ').title()}",
            color="#8e44ad",
            icon="🔴",
            rows={k: str(v) for k, v in details.items()},
            note="Automatic anomaly detection flagged this event. Review your logs."
        )
        self._enqueue(subject, html)

    def send_daily_report(self, stats):
        """Daily summary email — called by a scheduler."""
        if not self.enabled or not self.to_addrs:
            return
        subject = f"[SSH Fortress] Daily security report — {HOSTNAME} — {datetime.now().strftime('%Y-%m-%d')}"
        html = self._template(
            title="Daily Security Report",
            color="#2980b9",
            icon="📊",
            rows={
                "Server": HOSTNAME,
                "Date": datetime.now().strftime("%Y-%m-%d"),
                "Total Auth Attempts": stats.get("total_attempts", 0),
                "Successful Logins": stats.get("successes", 0),
                "Failed Logins": stats.get("failures", 0),
                "IPs Banned": stats.get("bans", 0),
                "Root Attempts": stats.get("root_attempts", 0),
                "Active Sessions": stats.get("active_sessions", 0),
            },
            note="This is your automated daily SSH security digest."
        )
        self._enqueue(subject, html)

    # ── internals ─────────────────────────────────────────────────────────────

    def _enqueue(self, subject, html):
        try:
            self._q.put_nowait((subject, html))
        except queue.Full:
            pass

    def _mail_loop(self):
        while True:
            try:
                subject, html = self._q.get(timeout=10)
                self._send(subject, html)
                time.sleep(1)  # don't hammer the smtp server
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[EmailNotifier] Worker error: {e}")
                time.sleep(5)

    def _send(self, subject, html, retries=3):
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg.attach(MIMEText(html, "html", "utf-8"))

        for attempt in range(retries):
            try:
                ctx = ssl.create_default_context() if self.use_tls else None
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                    server.ehlo()
                    if self.use_tls and ctx:
                        server.starttls(context=ctx)
                        server.ehlo()
                    if self.username:
                        server.login(self.username, self.password)
                    server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
                return
            except Exception as e:
                if attempt == retries - 1:
                    print(f"[EmailNotifier] Failed to send '{subject}': {e}")
                time.sleep(3)

    def _should_send(self, event_type):
        if not self.enabled or not self.to_addrs:
            return False
        if event_type not in self.notify_on:
            return False
        with self._lock:
            last = self._last_sent.get(event_type, 0)
            if time.time() - last < self._cooldown:
                return False
            self._last_sent[event_type] = time.time()
        return True

    @staticmethod
    def _template(title, color, icon, rows, note=""):
        rows_html = "".join(
            f"""
            <tr>
                <td style="padding:8px 12px;background:#f8f9fa;border-bottom:1px solid #dee2e6;
                            font-weight:600;color:#495057;width:40%">{k}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #dee2e6;
                            font-family:monospace;color:#212529">{v}</td>
            </tr>"""
            for k, v in rows.items()
        )

        note_html = f"""
        <p style="margin:16px 0 0;padding:12px;background:#fff3cd;border-left:4px solid #ffc107;
                   color:#856404;border-radius:4px;font-size:13px">{note}</p>
        """ if note else ""

        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
             background:#f1f3f4;margin:0;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;
               box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden">

    <div style="background:{color};padding:24px;text-align:center">
      <div style="font-size:40px;margin-bottom:8px">{icon}</div>
      <h1 style="margin:0;color:#fff;font-size:20px;font-weight:600">{title}</h1>
    </div>

    <div style="padding:24px">
      <table style="width:100%;border-collapse:collapse;border:1px solid #dee2e6;border-radius:6px;overflow:hidden">
        {rows_html}
      </table>
      {note_html}
    </div>

    <div style="padding:16px 24px;background:#f8f9fa;border-top:1px solid #dee2e6;
                 text-align:center;color:#6c757d;font-size:12px">
      <strong>SSH Fortress</strong> — Advanced SSH Security &nbsp;|&nbsp;
      Server: <code>{HOSTNAME}</code>
    </div>
  </div>
</body>
</html>"""
