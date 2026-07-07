#!/usr/bin/env python3
"""
SSH Fortress — main CLI

Usage:
  sudo python main.py harden       [--dry-run]
  sudo python main.py run                         # daemon
  sudo python main.py audit
  sudo python main.py doctor                       # validate settings.yaml
  sudo python main.py status
  sudo python main.py stats
  sudo python main.py report [--html | --json] [-o file]
  sudo python main.py metrics                      # Prometheus exporter
  sudo python main.py ban   <ip>   [--duration 3600]
  sudo python main.py unban <ip>
  sudo python main.py keys  audit
  sudo python main.py test  telegram | email | ntfy
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from modules.core import ConfigManager, ConfigValidator, get_logger, __version__
from modules.hardening import SSHConfigHardener, CryptoPolicy, PAMConfigurator
from modules.protection import BruteForceProtector, RateLimiter, GeoBlocker, PortKnocker, ThreatScorer
from modules.protection.ip_reputation import IPReputationChecker
from modules.logging import LogAggregator, SIEMForwarder
from modules.monitoring import SessionMonitor, AnomalyDetector, HealthChecker, MetricsExporter, render_metrics
from modules.alerting import AlertManager, NtfyNotifier
from modules.alerting.telegram_notifier import TelegramNotifier
from modules.alerting.email_notifier import EmailNotifier
from modules.alerting.discord_notifier import DiscordNotifier
from modules.key_management import KeyAuditor
from modules.stats import StatsTracker
from modules.reporting import build_html_report, build_json_report

console = Console()


@click.group()
@click.version_option(__version__, "-V", "--version", prog_name="ssh-fortress")
@click.option("--config", "-c", default=None, help="Path to settings.yaml")
@click.pass_context
def cli(ctx, config):
    """SSH Fortress — SSH hardening, brute-force protection, SIEM + multi-channel alerts."""
    ctx.ensure_object(dict)
    try:
        ctx.obj["cfg"] = ConfigManager(config)
    except FileNotFoundError as e:
        console.print(f"[red]Config error: {e}[/red]")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# harden
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--dry-run", is_flag=True)
@click.pass_context
def harden(ctx, dry_run):
    """Apply SSH hardening — sshd_config, crypto policy, PAM, nftables rules."""
    _need_root()
    cfg = ctx.obj["cfg"]

    console.rule("[bold blue]SSH Fortress — Hardening[/bold blue]")

    with console.status("Hardening sshd_config..."):
        ok = SSHConfigHardener(cfg).apply(dry_run=dry_run)
    console.print(f"  sshd_config      {'[green]OK[/green]' if ok else '[red]FAIL[/red]'}")

    with console.status("Crypto policy (keys + moduli)..."):
        CryptoPolicy(cfg).harden(dry_run=dry_run)
    console.print("  Crypto policy    [green]OK[/green]")

    with console.status("PAM configuration..."):
        PAMConfigurator(cfg).apply(dry_run=dry_run)
    console.print("  PAM              [green]OK[/green]")

    with console.status("nftables rate-limit rules..."):
        ok = RateLimiter(cfg).apply(dry_run=dry_run)
    console.print(f"  nftables         {'[green]OK[/green]' if ok else '[red]FAIL[/red]'}")

    note = " [yellow](dry-run — nothing written)[/yellow]" if dry_run else ""
    console.print(f"\n[bold green]Hardening complete.{note}[/bold green]")


# ─────────────────────────────────────────────────────────────────────────────
# run  (daemon mode)
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def run(ctx):
    """Start daemon: log tailing, brute-force protection, SIEM + all alert channels."""
    _need_root()
    cfg = ctx.obj["cfg"]
    log = get_logger(
        "main",
        log_path=cfg.get("logging", "fortress_log_path",
                          default="/var/log/ssh-fortress/fortress.log"),
    )

    log.info("SSH Fortress starting", version=__version__)
    console.print(f"[bold blue]SSH Fortress[/bold blue] v{__version__} starting...\n")

    # stats tracker
    stats = StatsTracker(cfg)

    # behavioural threat scorer (adaptive banning)
    threat = ThreatScorer(cfg)

    # notification channels
    telegram = TelegramNotifier(cfg)
    email    = EmailNotifier(cfg)
    discord  = DiscordNotifier(cfg)
    ntfy     = NtfyNotifier(cfg)

    # ip reputation (optional AbuseIPDB check)
    ip_rep = IPReputationChecker(cfg)

    # existing alert manager (Slack / PagerDuty / generic webhook)
    alert_mgr = AlertManager(cfg)

    def fire_alerts(event_type, details):
        """Route to all channels based on event type."""
        alert_mgr.send(event_type, details)
        ntfy.send_event("ANOMALY" if event_type.startswith("ANOMALY_") else event_type, details)
        ip = details.get("src_ip", "")
        user = details.get("username", "unknown")

        if event_type == "AUTH_SUCCESS":
            telegram.send_login_success(user, ip, details.get("method", "?"), details.get("country", "N/A"))
            email.notify_login_success(user, ip, details.get("method", "?"), details.get("src_port", 0), details.get("country", "N/A"))
            discord.notify_login_success(user, ip, details.get("method", "?"), details.get("country", "N/A"))

        elif event_type == "BRUTE_FORCE_BAN":
            attempts = details.get("attempt_count", "?")
            dur = details.get("duration", 3600)
            telegram.send_brute_force_ban(ip, attempts, dur, user)
            email.notify_brute_force_ban(ip, attempts, dur, user)
            discord.notify_brute_force_ban(ip, attempts, dur, user)

        elif event_type == "AUTH_FAILURE":
            telegram.send_login_failed(ip, user, details.get("attempt_num", 1), details.get("max_attempts", 5))
            email.notify_login_failed(ip, user, details.get("attempt_num", 1), details.get("max_attempts", 5))

        elif event_type == "ROOT_ATTEMPT":
            telegram.send_root_attempt(ip)
            email.notify_root_attempt(ip)
            discord.notify_root_attempt(ip)

        elif event_type.startswith("ANOMALY_"):
            short = event_type.replace("ANOMALY_", "")
            telegram.send_anomaly(short, details)
            email.notify_anomaly(short, details)
            discord.notify_anomaly(short, details)
            stats.record_anomaly(short)

    # brute force protector
    def on_ban(ip, duration):
        stats.record_ban(ip)
        fire_alerts("BRUTE_FORCE_BAN", {
            "src_ip": ip,
            "duration": duration,
            "attempt_count": bf.banned_ips(),  # just pass through
        })

    bf = BruteForceProtector(cfg, on_ban=on_ban)

    # geo blocker
    geo = GeoBlocker(cfg)
    geo.start()

    # port knocker
    knocker = PortKnocker(cfg)
    knocker.start()

    # SIEM
    siem = SIEMForwarder(cfg)

    # monitoring
    sessions = SessionMonitor(cfg)
    sessions.start()

    anomaly = AnomalyDetector(cfg, alert_cb=lambda t, d: fire_alerts(f"ANOMALY_{t}", d))

    health = HealthChecker(cfg, on_fail=lambda c, ok, msg: log.warning("HEALTH_FAIL", check=c))
    health.start()

    # Prometheus metrics endpoint (optional — scrape /metrics)
    metrics = MetricsExporter(cfg, collector=lambda: render_metrics(
        stats.get_summary(),
        banned_count=len(bf.banned_ips()),
        top_attackers=stats.get_top_attackers(10),
        top_threats=threat.top(10),
    ))
    metrics.start()

    # daily report scheduler (simple thread)
    if cfg.get("alerting", "email", "daily_report", default=False):
        _start_daily_report(email, stats, cfg)

    # log aggregator — ties everything together
    from modules.logging.log_parser import EventType

    aggregator = LogAggregator(cfg)

    def handle_event(event):
        # pre-ban check: is this IP already known bad?
        if event.src_ip and ip_rep.enabled:
            is_bad, score, country = ip_rep.check(event.src_ip)
            if is_bad:
                threat.record(event.src_ip, "failure", event.username,
                              reputation_flagged=True, when=event.timestamp)
                log.security_event("IP_REPUTATION_BAN", src_ip=event.src_ip,
                                   score=score, country=country, action="BAN")
                bf.ban(event.src_ip, reason=f"AbuseIPDB score={score}")
                return

        if event.event_type in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            kind = "invalid" if event.event_type == EventType.INVALID_USER else "failure"
            attempts = _get_attempt_count(bf, event.src_ip)
            banned = bf.record_failure(event.src_ip, event.username)
            risk = threat.record(event.src_ip, kind, event.username, when=event.timestamp)
            stats.record_login_failed(event.username, event.src_ip)

            # adaptive banning: behaviour looks malicious even below the raw
            # failure threshold (username spraying, invalid-user probing, …)
            if not banned and threat.should_ban(event.src_ip):
                bf.ban(event.src_ip, reason=f"threat-score={risk:.0f}")
                banned = True
                fire_alerts("THREAT_BAN", {
                    "src_ip": event.src_ip,
                    "username": event.username,
                    "threat_score": round(risk, 1),
                    "verdict": threat.classify(risk),
                })

            if not banned:
                fire_alerts("AUTH_FAILURE", {
                    "src_ip": event.src_ip,
                    "username": event.username,
                    "attempt_num": attempts + 1,
                    "max_attempts": cfg.get("brute_force", "max_attempts", default=5),
                    "threat_score": round(risk, 1),
                })
            log.security_event("AUTH_FAILURE", src_ip=event.src_ip,
                               username=event.username, threat_score=round(risk, 1))

        elif event.event_type in (EventType.AUTH_SUCCESS, EventType.PUBKEY_ACCEPTED):
            bf.record_success(event.src_ip)
            threat.record(event.src_ip, "success", event.username, when=event.timestamp)
            stats.record_login_success(event.username, event.src_ip, event.method)
            fire_alerts("AUTH_SUCCESS", {
                "src_ip": event.src_ip,
                "src_port": event.src_port,
                "username": event.username,
                "method": event.method,
            })

        elif event.event_type == EventType.ROOT_ATTEMPT:
            risk = threat.record(event.src_ip, "root", "root", when=event.timestamp)
            stats.record_root_attempt(event.src_ip)
            fire_alerts("ROOT_ATTEMPT", {"src_ip": event.src_ip, "threat_score": round(risk, 1)})

        # update session count in stats
        stats.set_active_sessions(sessions.session_count())

    aggregator.add_handler(handle_event)
    aggregator.add_handler(siem)
    aggregator.add_handler(sessions)
    aggregator.add_handler(anomaly)
    aggregator.start()

    console.print("[bold green]SSH Fortress is running.[/bold green]")
    console.print("  Channels active: " + ", ".join(filter(None, [
        "Telegram" if telegram.enabled else "",
        "Email"    if email.enabled    else "",
        "Discord"  if discord.enabled  else "",
        "ntfy"     if ntfy.enabled     else "",
        "Slack"    if cfg.get("alerting", "slack", "enabled") else "",
        "SIEM"     if cfg.get("siem", "enabled") else "",
    ])) or "none configured")
    if threat.enabled:
        console.print("  Adaptive banning: [green]on[/green] "
                      f"(threat ban threshold {cfg.get('threat_scoring', 'ban_threshold', default=70)})")
    if metrics.enabled:
        console.print(f"  Metrics: [green]http://{cfg.get('metrics', 'bind', default='127.0.0.1')}"
                      f":{cfg.get('metrics', 'port', default=9822)}"
                      f"{cfg.get('metrics', 'path', default='/metrics')}[/green]")
    console.print("  Press Ctrl+C to stop.\n")

    log.info("All modules running")

    def _stop(sig, frame):
        log.info("Shutting down")
        aggregator.stop()
        knocker.stop()
        health.stop()
        metrics.stop()
        console.print("[yellow]SSH Fortress stopped.[/yellow]")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.pause()


def _get_attempt_count(bf, ip):
    # peek at the attempt deque without triggering a ban
    with bf._lock:
        dq = bf._attempts.get(ip)
        return len(dq) if dq else 0


def _start_daily_report(email, stats, cfg):
    import threading
    import datetime as dt

    target_hour = cfg.get("alerting", "email", "daily_report_hour", default=8)

    def loop():
        while True:
            now = dt.datetime.now()
            next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
            if now >= next_run:
                next_run = next_run + dt.timedelta(days=1)
            time.sleep((next_run - now).total_seconds())
            try:
                email.send_daily_report(stats.get_summary())
                stats.reset_daily()
            except Exception as e:
                print(f"[DailyReport] Error: {e}")

    threading.Thread(target=loop, daemon=True, name="daily-report").start()


# ─────────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def audit(ctx):
    """Check sshd_config against CIS/NSA hardening baseline."""
    cfg = ctx.obj["cfg"]
    findings = SSHConfigHardener(cfg).audit()
    if not findings:
        console.print("[yellow]Could not read sshd_config.[/yellow]")
        return

    t = Table(title="SSH Config Audit — CIS Level 2", show_lines=True)
    t.add_column("Setting", style="cyan")
    t.add_column("Required")
    t.add_column("Current")
    t.add_column("Status")

    for f in sorted(findings, key=lambda x: not x["compliant"]):
        status = "[green]PASS[/green]" if f["compliant"] else "[red]FAIL[/red]"
        t.add_row(f["key"], str(f["required"]), str(f["current"]), status)

    console.print(t)
    failed = sum(1 for f in findings if not f["compliant"])
    console.print(f"\n{len(findings)} checks — [green]{len(findings)-failed} passed[/green]  [red]{failed} failed[/red]")


# ─────────────────────────────────────────────────────────────────────────────
# doctor
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def doctor(ctx):
    """Validate settings.yaml — catch mis-configured channels, SIEM, thresholds."""
    findings = ConfigValidator(ctx.obj["cfg"]).validate()

    t = Table(title="SSH Fortress — Configuration Doctor", show_lines=False)
    t.add_column("Level")
    t.add_column("Section", style="cyan")
    t.add_column("Finding")
    style = {"ERROR": "[red]ERROR[/red]", "WARN": "[yellow]WARN[/yellow]", "OK": "[green]OK[/green]"}
    for f in sorted(findings, key=lambda x: {"ERROR": 0, "WARN": 1, "OK": 2}.get(x.level, 3)):
        t.add_row(style.get(f.level, f.level), f.section, f.message)
    console.print(t)

    errors = sum(1 for f in findings if f.level == "ERROR")
    warns = sum(1 for f in findings if f.level == "WARN")
    console.print(f"\n[red]{errors} error(s)[/red]  [yellow]{warns} warning(s)[/yellow]")
    if errors:
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# status
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def status(ctx):
    """Show health, active bans, and live sessions."""
    cfg = ctx.obj["cfg"]

    # health
    health_results = HealthChecker(cfg).run_once()
    t = Table(title="Health Status")
    t.add_column("Check")
    t.add_column("Status")
    for check, ok in health_results.items():
        t.add_row(check, "[green]OK[/green]" if ok else "[red]FAIL[/red]")
    console.print(t)

    # sessions
    import json
    sf = Path(cfg.get("monitoring", "active_session_log",
                       default="/var/lib/ssh-fortress/sessions.json"))
    if sf.exists():
        data = json.loads(sf.read_text())
        console.print(f"\n[bold]Active sessions:[/bold] {data.get('active_count', 0)}")
        for s in data.get("sessions", []):
            if s.get("is_active"):
                console.print(
                    f"  [cyan]{s['username']}[/cyan]@{s['src_ip']}:{s['src_port']}"
                    f"  method=[green]{s['method']}[/green]  since={s['started_at']}"
                )


# ─────────────────────────────────────────────────────────────────────────────
# stats
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def stats(ctx):
    """Show event statistics and top attackers."""
    cfg = ctx.obj["cfg"]
    tracker = StatsTracker(cfg)
    summary = tracker.get_summary()

    t = Table(title="SSH Fortress Statistics")
    t.add_column("Metric")
    t.add_column("Value", style="cyan")
    for k, v in summary.items():
        t.add_row(k.replace("_", " ").title(), str(v))
    console.print(t)

    top = tracker.get_top_attackers(10)
    if top:
        t2 = Table(title="Top Attackers")
        t2.add_column("IP")
        t2.add_column("Failures", style="red")
        t2.add_column("Bans", style="red")
        t2.add_column("Last Seen")
        for ip, data in top:
            t2.add_row(
                ip,
                str(data.get("failures", 0)),
                str(data.get("bans", 0)),
                data.get("last_seen", "N/A"),
            )
        console.print(t2)


# ─────────────────────────────────────────────────────────────────────────────
# report
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--html", "as_html", is_flag=True, help="Write a self-contained HTML report")
@click.option("--json", "as_json", is_flag=True, help="Write a JSON report")
@click.option("--output", "-o", default=None, help="Output file path")
@click.pass_context
def report(ctx, as_html, as_json, output):
    """Generate a security report (text to console, or --html / --json to a file)."""
    cfg = ctx.obj["cfg"]
    tracker = StatsTracker(cfg)
    summary = tracker.get_summary()
    top = tracker.get_top_attackers(15)

    if as_json:
        _emit_report(build_json_report(summary, top), output, "ssh-fortress-report.json")
    elif as_html:
        _emit_report(build_html_report(summary, top), output, "ssh-fortress-report.html")
    else:
        t = Table(title="SSH Fortress — Security Report")
        t.add_column("Metric")
        t.add_column("Value", style="cyan")
        for k, v in summary.items():
            t.add_row(k.replace("_", " ").title(), str(v))
        console.print(t)
        console.print("\n[dim]Tip: add --html or --json to export a full report.[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# metrics
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def metrics(ctx):
    """Run the Prometheus metrics exporter in the foreground (scrape /metrics)."""
    cfg = ctx.obj["cfg"]
    if not cfg.get("metrics", "enabled", default=False):
        console.print("[yellow]metrics.enabled is false in settings.yaml — enable it first.[/yellow]")
        return
    tracker = StatsTracker(cfg)
    exporter = MetricsExporter(cfg, collector=lambda: render_metrics(
        tracker.get_summary(), top_attackers=tracker.get_top_attackers(10)))
    exporter.start()
    bind = cfg.get("metrics", "bind", default="127.0.0.1")
    port = cfg.get("metrics", "port", default=9822)
    path = cfg.get("metrics", "path", default="/metrics")
    console.print(f"[green]Metrics exporter running:[/green] http://{bind}:{port}{path}  (Ctrl+C to stop)")
    try:
        signal.pause()
    except KeyboardInterrupt:
        exporter.stop()
        console.print("[yellow]Exporter stopped.[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
# ban / unban
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("ip")
@click.option("--duration", default=3600, help="Seconds")
@click.pass_context
def ban(ctx, ip, duration):
    """Manually ban an IP."""
    _need_root()
    BruteForceProtector(ctx.obj["cfg"]).ban(ip, duration=duration, reason="manual-cli")
    console.print(f"[green]Banned {ip} for {duration}s[/green]")


@cli.command()
@click.argument("ip")
@click.pass_context
def unban(ctx, ip):
    """Manually unban an IP."""
    _need_root()
    ok = BruteForceProtector(ctx.obj["cfg"]).unban(ip)
    console.print(f"[green]Unbanned {ip}[/green]" if ok else f"[yellow]{ip} was not banned[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
# keys
# ─────────────────────────────────────────────────────────────────────────────

@cli.group()
def keys():
    """SSH key management."""


@keys.command("audit")
@click.pass_context
def keys_audit(ctx):
    """Audit all authorized_keys across the system."""
    _need_root()
    entries = KeyAuditor(ctx.obj["cfg"]).audit()
    if not entries:
        console.print("[yellow]No keys found or audit disabled.[/yellow]")
        return
    t = Table(title="SSH Key Audit", show_lines=True)
    t.add_column("User")
    t.add_column("Type")
    t.add_column("Bits")
    t.add_column("Fingerprint")
    t.add_column("Issues")
    for e in sorted(entries, key=lambda x: not x.is_compliant):
        color = "red" if e.issues else "green"
        t.add_row(
            e.username, e.key_type, str(e.bits),
            (e.fingerprint[:30] + "…") if e.fingerprint else "-",
            f"[{color}]{'; '.join(e.issues) or 'OK'}[/{color}]",
        )
    console.print(t)


# ─────────────────────────────────────────────────────────────────────────────
# test
# ─────────────────────────────────────────────────────────────────────────────

@cli.group()
def test():
    """Test notification channels."""


@test.command("telegram")
@click.pass_context
def test_telegram(ctx):
    """Send a test Telegram message."""
    cfg = ctx.obj["cfg"]
    tg = TelegramNotifier(cfg)
    if not tg.enabled:
        console.print("[yellow]Telegram is disabled in settings.yaml[/yellow]")
        return
    tg.test()
    console.print("[green]Test message sent — check your Telegram.[/green]")


@test.command("email")
@click.pass_context
def test_email(ctx):
    """Send a test email."""
    cfg = ctx.obj["cfg"]
    em = EmailNotifier(cfg)
    if not em.enabled:
        console.print("[yellow]Email is disabled in settings.yaml[/yellow]")
        return
    em.send_daily_report({"note": "This is a test email from SSH Fortress"})
    time.sleep(2)
    console.print("[green]Test email sent — check your inbox.[/green]")


@test.command("ntfy")
@click.pass_context
def test_ntfy(ctx):
    """Send a test ntfy.sh push notification."""
    n = NtfyNotifier(ctx.obj["cfg"])
    if not n.enabled:
        console.print("[yellow]ntfy is disabled in settings.yaml[/yellow]")
        return
    n.test()
    console.print("[green]Test push sent — check the ntfy app / your topic.[/green]")


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def _need_root():
    if os.geteuid() != 0:
        console.print("[red]Must run as root (sudo python main.py ...)[/red]")
        sys.exit(1)


def _emit_report(content: str, output: str | None, default_name: str) -> None:
    path = Path(output) if output else Path.cwd() / default_name
    path.write_text(content)
    console.print(f"[green]Report written:[/green] {path}")


if __name__ == "__main__":
    cli()
