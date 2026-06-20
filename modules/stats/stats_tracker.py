"""
Simple stats tracker. Counts events so we can show a dashboard
and send daily email reports.

No database needed — just in-memory counters + periodic JSON dump.
"""

import json
import threading
import time
from datetime import datetime, date
from pathlib import Path


class StatsTracker:

    def __init__(self, cfg):
        self._lock = threading.Lock()
        stats_dir = Path(cfg.get("general", "data_dir", default="/var/lib/ssh-fortress"))
        self._file = stats_dir / "stats.json"
        stats_dir.mkdir(parents=True, exist_ok=True)

        # load existing stats if any
        self._data = self._load()

        # save every 30 seconds
        self._saver = threading.Thread(target=self._save_loop, daemon=True, name="stats-saver")
        self._saver.start()

    # ── event recording ────────────────────────────────────────────────────────

    def record_login_success(self, username, ip, method):
        with self._lock:
            self._inc("total_attempts")
            self._inc("successes")
            self._inc(f"users.{username}.successes")
            self._inc(f"methods.{method}")
            self._update_ip_stats(ip, "success")

    def record_login_failed(self, username, ip):
        with self._lock:
            self._inc("total_attempts")
            self._inc("failures")
            self._inc(f"users.{username}.failures")
            self._update_ip_stats(ip, "failure")

    def record_ban(self, ip):
        with self._lock:
            self._inc("bans")
            self._update_ip_stats(ip, "ban")

    def record_root_attempt(self, ip):
        with self._lock:
            self._inc("root_attempts")

    def record_anomaly(self, alert_type):
        with self._lock:
            self._inc(f"anomalies.{alert_type}")
            self._inc("total_anomalies")

    def set_active_sessions(self, count):
        with self._lock:
            self._data["active_sessions"] = count
            self._data["peak_sessions"] = max(
                self._data.get("peak_sessions", 0), count
            )

    # ── reading ────────────────────────────────────────────────────────────────

    def get_summary(self):
        with self._lock:
            return {
                "total_attempts": self._data.get("total_attempts", 0),
                "successes": self._data.get("successes", 0),
                "failures": self._data.get("failures", 0),
                "bans": self._data.get("bans", 0),
                "root_attempts": self._data.get("root_attempts", 0),
                "total_anomalies": self._data.get("total_anomalies", 0),
                "active_sessions": self._data.get("active_sessions", 0),
                "peak_sessions": self._data.get("peak_sessions", 0),
                "uptime_since": self._data.get("uptime_since", "unknown"),
            }

    def get_top_attackers(self, n=10):
        with self._lock:
            ips = self._data.get("ips", {})
            # sort by failure count
            sorted_ips = sorted(
                ips.items(),
                key=lambda x: x[1].get("failures", 0),
                reverse=True
            )
            return sorted_ips[:n]

    def reset_daily(self):
        """Called once a day to reset daily counters (keep total counters)."""
        with self._lock:
            self._data["daily_successes"] = 0
            self._data["daily_failures"] = 0
            self._data["daily_bans"] = 0
            self._data["daily_date"] = str(date.today())

    # ── internals ─────────────────────────────────────────────────────────────

    def _inc(self, key, by=1):
        """Increment a dot-path key like 'users.alice.successes'."""
        parts = key.split(".")
        d = self._data
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = d.get(parts[-1], 0) + by

    def _update_ip_stats(self, ip, event):
        ips = self._data.setdefault("ips", {})
        entry = ips.setdefault(ip, {"failures": 0, "successes": 0, "bans": 0, "first_seen": str(datetime.now())})
        entry[event + "s" if not event.endswith("s") else event] = entry.get(event + "s" if not event.endswith("s") else event, 0) + 1
        entry["last_seen"] = str(datetime.now())

    def _load(self):
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text())
                data["uptime_since"] = str(datetime.now())
                return data
            except Exception:
                pass
        return {"uptime_since": str(datetime.now())}

    def _save(self):
        try:
            with self._lock:
                snapshot = dict(self._data)
            tmp = self._file.with_suffix(".tmp")
            tmp.write_text(json.dumps(snapshot, indent=2, default=str))
            tmp.replace(self._file)
        except Exception as e:
            print(f"[Stats] Save failed: {e}")

    def _save_loop(self):
        while True:
            time.sleep(30)
            self._save()
