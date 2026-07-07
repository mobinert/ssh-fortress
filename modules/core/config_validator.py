"""
ConfigValidator — pre-flight sanity checks for settings.yaml.

Catches the foot-guns that otherwise only surface at 3am: a channel switched
on with no credentials, a SIEM backend enabled with no endpoint, a ban window
that can never trigger, a threshold outside its legal range. Returns a flat
list of typed findings so both the `doctor` CLI and unit tests can consume it.

Pure logic — takes a ConfigManager, touches nothing on disk.
"""

from __future__ import annotations

from dataclasses import dataclass

from modules.core.config_manager import ConfigManager

ERROR = "ERROR"
WARN = "WARN"
OK = "OK"


@dataclass
class Finding:
    level: str          # ERROR | WARN | OK
    section: str
    message: str


class ConfigValidator:
    def __init__(self, cfg: ConfigManager) -> None:
        self._cfg = cfg

    def validate(self) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._check_general()
        findings += self._check_brute_force()
        findings += self._check_threat_scoring()
        findings += self._check_alerting()
        findings += self._check_siem()
        findings += self._check_ip_reputation()
        findings += self._check_geo()
        findings += self._check_metrics()
        if not any(f.level == ERROR for f in findings):
            findings.append(Finding(OK, "config", "No blocking configuration errors found."))
        return findings

    # ── helpers ────────────────────────────────────────────────────────────────

    def _g(self, *keys, default=None):
        return self._cfg.get(*keys, default=default)

    def _missing(self, value) -> bool:
        return value is None or value == "" or value == [] or value == {}

    # ── checks ─────────────────────────────────────────────────────────────────

    def _check_general(self) -> list[Finding]:
        out = []
        lvl = str(self._g("general", "log_level", default="INFO")).upper()
        if lvl not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            out.append(Finding(WARN, "general", f"log_level '{lvl}' is not a standard level."))
        return out

    def _check_brute_force(self) -> list[Finding]:
        out = []
        if not self._g("brute_force", "enabled", default=True):
            return out
        max_attempts = self._g("brute_force", "max_attempts", default=5)
        if not isinstance(max_attempts, int) or max_attempts < 1:
            out.append(Finding(ERROR, "brute_force", "max_attempts must be a positive integer."))
        base = self._g("brute_force", "block_duration", default=3600)
        cap = self._g("brute_force", "max_ban_duration", default=86400)
        if isinstance(base, int) and isinstance(cap, int) and cap < base:
            out.append(Finding(WARN, "brute_force",
                               "max_ban_duration is below block_duration — the cap will shorten first bans."))
        return out

    def _check_threat_scoring(self) -> list[Finding]:
        out = []
        if not self._g("threat_scoring", "enabled", default=True):
            return out
        thr = self._g("threat_scoring", "ban_threshold", default=70)
        if not isinstance(thr, (int, float)) or not (0 < thr <= 100):
            out.append(Finding(ERROR, "threat_scoring", "ban_threshold must be between 1 and 100."))
        return out

    def _check_alerting(self) -> list[Finding]:
        out = []
        a = self._cfg.section("alerting")

        def enabled(name):
            return a.get(name, {}).get("enabled", False)

        if enabled("telegram"):
            tg = a["telegram"]
            if self._missing(tg.get("bot_token")) or self._missing(tg.get("chat_id")):
                out.append(Finding(ERROR, "alerting.telegram",
                                   "Telegram is enabled but bot_token / chat_id is empty."))
        if enabled("email"):
            em = a["email"]
            if self._missing(em.get("username")) or self._missing(em.get("password")):
                out.append(Finding(ERROR, "alerting.email",
                                   "Email is enabled but SMTP username / password is empty."))
            if self._missing(em.get("to_addrs")):
                out.append(Finding(ERROR, "alerting.email", "Email is enabled but to_addrs is empty."))
        if enabled("discord") and self._missing(a["discord"].get("webhook_url")):
            out.append(Finding(ERROR, "alerting.discord", "Discord is enabled but webhook_url is empty."))
        if enabled("slack") and self._missing(a["slack"].get("webhook_url")):
            out.append(Finding(ERROR, "alerting.slack", "Slack is enabled but webhook_url is empty."))
        if enabled("pagerduty") and self._missing(a["pagerduty"].get("routing_key")):
            out.append(Finding(ERROR, "alerting.pagerduty", "PagerDuty is enabled but routing_key is empty."))
        if enabled("ntfy") and self._missing(a["ntfy"].get("topic")):
            out.append(Finding(ERROR, "alerting.ntfy", "ntfy is enabled but topic is empty."))
        if enabled("webhook") and self._missing(a["webhook"].get("url")):
            out.append(Finding(ERROR, "alerting.webhook", "Webhook is enabled but url is empty."))

        channels = [n for n in ("telegram", "email", "discord", "slack", "pagerduty", "ntfy", "webhook")
                    if enabled(n)]
        if a.get("enabled", True) and not channels:
            out.append(Finding(WARN, "alerting", "Alerting is on but no channel is enabled — you won't be notified."))
        return out

    def _check_siem(self) -> list[Finding]:
        out = []
        if not self._g("siem", "enabled", default=True):
            return out
        b = self._cfg.section("siem").get("backends", {})
        es = b.get("elasticsearch", {})
        if es.get("enabled") and self._missing(es.get("hosts")):
            out.append(Finding(ERROR, "siem.elasticsearch", "Elasticsearch enabled but no hosts configured."))
        sp = b.get("splunk", {})
        if sp.get("enabled") and (self._missing(sp.get("hec_url")) or self._missing(sp.get("hec_token"))):
            out.append(Finding(ERROR, "siem.splunk", "Splunk enabled but hec_url / hec_token missing."))
        wh = b.get("webhook", {})
        if wh.get("enabled") and self._missing(wh.get("url")):
            out.append(Finding(ERROR, "siem.webhook", "SIEM webhook enabled but url missing."))
        if not any(b.get(k, {}).get("enabled") for k in b):
            out.append(Finding(WARN, "siem", "SIEM is on but every backend is disabled."))
        return out

    def _check_ip_reputation(self) -> list[Finding]:
        out = []
        if self._g("ip_reputation", "enabled", default=False):
            if self._missing(self._g("ip_reputation", "abuseipdb_api_key")):
                out.append(Finding(ERROR, "ip_reputation",
                                   "IP reputation enabled but abuseipdb_api_key is empty."))
        return out

    def _check_geo(self) -> list[Finding]:
        out = []
        if self._g("geo_blocker", "enabled", default=False):
            if self._missing(self._g("geo_blocker", "mmdb_path")):
                out.append(Finding(ERROR, "geo_blocker", "Geo blocking enabled but mmdb_path is empty."))
            if self._missing(self._g("geo_blocker", "countries")):
                out.append(Finding(WARN, "geo_blocker", "Geo blocking enabled but the countries list is empty."))
        return out

    def _check_metrics(self) -> list[Finding]:
        out = []
        if self._g("metrics", "enabled", default=False):
            port = self._g("metrics", "port", default=9822)
            if not isinstance(port, int) or not (1 <= port <= 65535):
                out.append(Finding(ERROR, "metrics", "metrics.port must be a valid TCP port (1-65535)."))
        return out
