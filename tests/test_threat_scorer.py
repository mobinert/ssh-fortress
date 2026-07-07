"""Unit tests for the behavioural ThreatScorer."""

from datetime import datetime

from modules.protection.threat_scorer import ThreatScorer

# A fixed business-hours timestamp so the off-hours signal never perturbs asserts.
NOON = datetime(2026, 1, 2, 12, 0, 0)


def _scorer():
    # No ConfigManager -> defaults, and crucially no background reaper thread.
    return ThreatScorer(None)


def test_single_failure_is_low_risk():
    s = _scorer()
    score = s.record("10.0.0.1", "failure", "alice", when=NOON)
    assert score == 8            # one failure * weight 8
    assert s.classify(score) == "LOW"
    assert s.should_ban("10.0.0.1") is False


def test_username_spray_crosses_ban_threshold():
    s = _scorer()
    ip = "203.0.113.5"
    score = 0.0
    for i in range(6):
        score = s.record(ip, "failure", f"user{i}", when=NOON)
    # 6 failures -> capped 40; 6 distinct usernames -> capped 30; total 70
    assert score >= 70
    assert s.should_ban(ip) is True
    assert s.classify(score) == "CRITICAL"


def test_root_attempt_weighs_heavily():
    s = _scorer()
    score = s.record("198.51.100.9", "root", "root", when=NOON)
    # failure(8) + spray(0, single username) + root flat(30) = 38
    assert score == 38
    assert s.classify(score) == "SUSPICIOUS"
    # a second distinct root-ish probe should push it into HIGH territory
    score2 = s.record("198.51.100.9", "root", "admin", when=NOON)
    assert score2 > score


def test_reputation_flag_adds_large_penalty():
    s = _scorer()
    score = s.record("192.0.2.7", "failure", "bob", reputation_flagged=True, when=NOON)
    assert score >= 50           # reputation weight alone is 50
    prof = s.profile("192.0.2.7")
    assert prof["reputation_flagged"] is True


def test_successful_auth_discounts_score():
    s = _scorer()
    ip = "10.0.0.42"
    before = s.record(ip, "failure", "carol", when=NOON)
    after = s.record(ip, "success", "carol", when=NOON)
    assert after < before
    assert s.profile(ip)["had_success"] is True


def test_off_hours_adds_signal():
    s = _scorer()
    midnight = datetime(2026, 1, 2, 3, 0, 0)
    day = s.record("10.0.0.100", "failure", "x", when=NOON)
    night = s.record("10.0.0.101", "failure", "x", when=midnight)
    assert night > day           # off-hours contributes extra weight


def test_top_orders_by_score():
    s = _scorer()
    s.record("1.1.1.1", "failure", "a", when=NOON)
    for i in range(6):
        s.record("2.2.2.2", "failure", f"u{i}", when=NOON)
    top = s.top(5)
    assert top[0]["ip"] == "2.2.2.2"
    assert top[0]["score"] >= top[-1]["score"]


def test_disabled_scorer_never_bans():
    s = ThreatScorer(None)
    s.enabled = False
    for i in range(10):
        s.record("9.9.9.9", "root", f"u{i}", when=NOON)
    assert s.should_ban("9.9.9.9") is False


def test_unknown_ip_scores_zero():
    s = _scorer()
    assert s.score("172.16.0.1") == 0.0
    assert s.profile("172.16.0.1") == {}
