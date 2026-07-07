"""Unit tests for the Prometheus metrics renderer."""

from modules.monitoring.metrics_exporter import render_metrics

SUMMARY = {
    "total_attempts": 120,
    "successes": 30,
    "failures": 90,
    "bans": 5,
    "root_attempts": 4,
    "total_anomalies": 2,
    "active_sessions": 3,
    "peak_sessions": 7,
}


def test_counters_and_gauges_present():
    out = render_metrics(SUMMARY, banned_count=5)
    assert "ssh_fortress_attempts_total 120" in out
    assert "ssh_fortress_failures_total 90" in out
    assert "ssh_fortress_active_sessions 3" in out
    assert "ssh_fortress_banned_ips 5" in out
    assert "# TYPE ssh_fortress_attempts_total counter" in out
    assert "# TYPE ssh_fortress_active_sessions gauge" in out
    assert out.strip().endswith("ssh_fortress_up 1")


def test_top_attackers_labelled():
    out = render_metrics(
        SUMMARY,
        top_attackers=[("203.0.113.9", {"failures": 42})],
    )
    assert 'ssh_fortress_attacker_failures{ip="203.0.113.9"} 42' in out


def test_threat_scores_labelled():
    out = render_metrics(
        SUMMARY,
        top_threats=[{"ip": "198.51.100.2", "score": 88.0}],
    )
    assert 'ssh_fortress_threat_score{ip="198.51.100.2"} 88.0' in out


def test_label_values_escaped():
    out = render_metrics(SUMMARY, top_attackers=[('a"b\\c', {"failures": 1})])
    assert 'ip="a\\"b\\\\c"' in out


def test_empty_summary_is_safe():
    out = render_metrics({})
    assert "ssh_fortress_attempts_total 0" in out
    assert "ssh_fortress_up 1" in out
