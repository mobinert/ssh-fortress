"""
Security report builder — turns the persisted stats + live threat scores
into a self-contained, styled HTML report (and a machine-readable JSON one).

Both builders are pure functions of their inputs, so the `report` CLI command
stays a thin wrapper and the output is fully unit-testable. The HTML is a
single file with inline CSS — no assets, no JS required — so it can be emailed,
committed, or served as-is.
"""

from __future__ import annotations

import html
import json
import socket
from datetime import datetime, timezone
from typing import Any, Optional

__all__ = ["build_html_report", "build_json_report"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_json_report(
    summary: dict[str, Any],
    top_attackers: Optional[list] = None,
    top_threats: Optional[list[dict]] = None,
    *,
    host: Optional[str] = None,
) -> str:
    """Return a machine-readable JSON report string."""
    doc = {
        "tool": "ssh-fortress",
        "report": "security-summary",
        "host": host or socket.gethostname(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "top_attackers": [
            {"ip": ip, **(data or {})} for ip, data in (top_attackers or [])
        ],
        "top_threats": top_threats or [],
    }
    return json.dumps(doc, indent=2, default=str)


def build_html_report(
    summary: dict[str, Any],
    top_attackers: Optional[list] = None,
    top_threats: Optional[list[dict]] = None,
    *,
    host: Optional[str] = None,
) -> str:
    """Return a self-contained HTML security report."""
    host = host or socket.gethostname()
    attempts = int(summary.get("total_attempts", 0) or 0)
    successes = int(summary.get("successes", 0) or 0)
    failures = int(summary.get("failures", 0) or 0)
    bans = int(summary.get("bans", 0) or 0)
    roots = int(summary.get("root_attempts", 0) or 0)
    anomalies = int(summary.get("total_anomalies", 0) or 0)
    active = int(summary.get("active_sessions", 0) or 0)

    fail_rate = (failures / attempts * 100) if attempts else 0.0

    cards = [
        ("Total attempts", attempts, "cy"),
        ("Successful", successes, "gr"),
        ("Failed", failures, "am"),
        ("Bans", bans, "rd"),
        ("Root attempts", roots, "rd"),
        ("Anomalies", anomalies, "am"),
        ("Active sessions", active, "cy"),
        ("Failure rate", f"{fail_rate:.0f}%", "am"),
    ]
    card_html = "\n".join(
        f'<div class="card {cls}"><div class="v">{html.escape(str(v))}</div>'
        f'<div class="k">{html.escape(k)}</div></div>'
        for k, v, cls in cards
    )

    # Top attackers table
    if top_attackers:
        rows = "\n".join(
            f"<tr><td class=ip>{html.escape(str(ip))}</td>"
            f"<td>{int((d or {}).get('failures', 0))}</td>"
            f"<td>{int((d or {}).get('bans', 0))}</td>"
            f"<td>{html.escape(str((d or {}).get('last_seen', '-')))}</td></tr>"
            for ip, d in top_attackers[:15]
        )
        attackers_html = (
            "<table><thead><tr><th>Source IP</th><th>Failures</th>"
            "<th>Bans</th><th>Last seen</th></tr></thead><tbody>"
            f"{rows}</tbody></table>"
        )
    else:
        attackers_html = '<div class="empty">No attacker activity recorded.</div>'

    # Threat scores
    if top_threats:
        trows = "\n".join(
            f"<tr><td class=ip>{html.escape(str(t.get('ip', '')))}</td>"
            f"<td><span class='pill {_band_class(t.get('score', 0))}'>"
            f"{_band(t.get('score', 0))}</span></td>"
            f"<td class=score>{t.get('score', 0)}</td>"
            f"<td>{int(t.get('distinct_usernames', 0))}</td>"
            f"<td>{int(t.get('root_attempts', 0))}</td></tr>"
            for t in top_threats[:15]
        )
        threats_html = (
            "<table><thead><tr><th>Source IP</th><th>Verdict</th>"
            "<th>Score</th><th>Usernames</th><th>Root</th></tr></thead><tbody>"
            f"{trows}</tbody></table>"
        )
    else:
        threats_html = '<div class="empty">No behavioural threat scores yet (only available while the daemon is running).</div>'

    return _TEMPLATE.format(
        host=html.escape(host),
        generated=_now_iso(),
        cards=card_html,
        attackers=attackers_html,
        threats=threats_html,
    )


def _band(score: float) -> str:
    score = float(score or 0)
    if score >= 70:
        return "CRITICAL"
    if score >= 42:
        return "HIGH"
    if score >= 21:
        return "SUSPICIOUS"
    return "LOW"


def _band_class(score: float) -> str:
    return {"CRITICAL": "crit", "HIGH": "high", "SUSPICIOUS": "susp", "LOW": "low"}[_band(score)]


_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Fortress — Security Report</title>
<style>
  :root{{--bg:#0a0e14;--panel:#111823;--panel2:#0c121b;--line:#1c2635;--txt:#e6edf3;
        --mut:#9aa7b8;--cy:#38bdf8;--gr:#22c55e;--am:#f59e0b;--rd:#ef4444;--accent:#8b5cf6;}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--txt);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    background-image:radial-gradient(900px 500px at 85% -10%,rgba(139,92,246,.14),transparent 60%);}}
  .wrap{{max-width:960px;margin:0 auto;padding:34px 20px 60px}}
  header{{border:1px solid var(--line);border-radius:16px;padding:24px 26px;margin-bottom:26px;
    background:linear-gradient(180deg,var(--panel),var(--panel2))}}
  .brand{{font-weight:800;letter-spacing:.12em;color:var(--accent);font-size:12px}}
  h1{{margin:.25em 0 .1em;font-size:25px}}
  .meta{{color:var(--mut);font-size:13px}}
  h2{{font-size:16px;margin:28px 0 12px;color:var(--txt)}}
  .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
  @media(max-width:720px){{.grid{{grid-template-columns:1fr 1fr}}}}
  .card{{border:1px solid var(--line);border-radius:12px;padding:16px;background:var(--panel);border-top-width:3px}}
  .card .v{{font-size:26px;font-weight:800}}
  .card .k{{color:var(--mut);font-size:12.5px;margin-top:3px}}
  .card.cy{{border-top-color:var(--cy)}} .card.gr{{border-top-color:var(--gr)}}
  .card.am{{border-top-color:var(--am)}} .card.rd{{border-top-color:var(--rd)}}
  table{{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:12px;overflow:hidden}}
  th,td{{text-align:left;padding:10px 14px;font-size:13.5px;border-bottom:1px solid var(--line)}}
  th{{background:var(--panel2);color:var(--mut);font-weight:600}}
  tr:last-child td{{border-bottom:0}}
  td.ip{{font-family:ui-monospace,monospace;color:var(--cy)}}
  td.score{{font-family:ui-monospace,monospace;font-weight:700}}
  .pill{{font-size:11px;font-weight:800;padding:2px 8px;border-radius:6px;color:#0a0e14}}
  .pill.crit{{background:var(--rd)}} .pill.high{{background:var(--am)}}
  .pill.susp{{background:#eab308}} .pill.low{{background:var(--gr)}}
  .empty{{border:1px dashed var(--line);border-radius:12px;padding:20px;color:var(--mut);text-align:center}}
  footer{{margin-top:30px;color:#5f6e82;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<header>
  <div class="brand">🛡️ SSH FORTRESS · SECURITY REPORT</div>
  <h1>Compromise &amp; access summary</h1>
  <div class="meta">Host <b>{host}</b> &middot; generated {generated}</div>
</header>
<div class="grid">
{cards}
</div>
<h2>🎯 Top attackers</h2>
{attackers}
<h2>🧠 Behavioural threat scores</h2>
{threats}
<footer>Generated by SSH Fortress — figures are for review, not a verdict. Pair with your SIEM and alert history.</footer>
</div></body></html>
"""
