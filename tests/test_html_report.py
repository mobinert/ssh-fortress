"""Unit tests for the security report builders."""

import json

from modules.reporting import build_html_report, build_json_report

SUMMARY = {
    "total_attempts": 100,
    "successes": 40,
    "failures": 60,
    "bans": 3,
    "root_attempts": 2,
    "total_anomalies": 1,
    "active_sessions": 2,
}
ATTACKERS = [("203.0.113.5", {"failures": 50, "bans": 1, "last_seen": "2026-07-08"})]
THREATS = [{"ip": "198.51.100.9", "score": 82.0, "distinct_usernames": 9, "root_attempts": 1}]


def test_html_contains_core_content():
    html = build_html_report(SUMMARY, ATTACKERS, THREATS, host="fortress-1")
    assert "<!DOCTYPE html>" in html
    assert "fortress-1" in html
    assert "203.0.113.5" in html
    assert "60" in html                       # failures card
    assert "CRITICAL" in html                 # threat band for score 82
    assert "SSH Fortress" in html


def test_html_handles_empty_inputs():
    html = build_html_report({}, [], [], host="h")
    assert "No attacker activity recorded." in html
    assert "No behavioural threat scores yet" in html


def test_html_escapes_untrusted_ip():
    html = build_html_report(SUMMARY, [("<script>", {"failures": 1})], host="h")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_json_report_is_valid_and_structured():
    doc = json.loads(build_json_report(SUMMARY, ATTACKERS, THREATS, host="fortress-1"))
    assert doc["tool"] == "ssh-fortress"
    assert doc["host"] == "fortress-1"
    assert doc["summary"]["failures"] == 60
    assert doc["top_attackers"][0]["ip"] == "203.0.113.5"
    assert doc["top_threats"][0]["score"] == 82.0
