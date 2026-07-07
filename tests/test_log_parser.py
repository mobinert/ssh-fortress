"""Unit tests for the auth.log parser (regression coverage for existing code)."""

from modules.logging.log_parser import EventType, LogParser

P = LogParser()


def test_failed_password_parsed():
    line = ("Jan  2 12:00:00 host sshd[123]: "
            "Failed password for invalid user admin from 10.0.0.9 port 51000 ssh2")
    ev = P.parse(line)
    assert ev is not None
    assert ev.event_type == EventType.AUTH_FAILURE
    assert ev.username == "admin"
    assert ev.src_ip == "10.0.0.9"
    assert ev.src_port == 51000
    assert ev.method == "password"


def test_accepted_login_parsed():
    line = ("Jan  2 12:00:01 host sshd[124]: "
            "Accepted password for deploy from 10.0.0.5 port 4022 ssh2")
    ev = P.parse(line)
    assert ev.event_type == EventType.AUTH_SUCCESS
    assert ev.username == "deploy"
    assert ev.src_ip == "10.0.0.5"


def test_invalid_user_parsed():
    line = "Jan  2 12:00:02 host sshd[125]: Invalid user oracle from 203.0.113.7 port 2222"
    ev = P.parse(line)
    assert ev.event_type == EventType.INVALID_USER
    assert ev.username == "oracle"
    assert ev.src_ip == "203.0.113.7"


def test_iso_timestamp_header_parsed():
    line = ("2026-07-08T12:00:03.123456+00:00 host sshd[126]: "
            "Failed password for root from 198.51.100.4 port 40000 ssh2")
    ev = P.parse(line)
    assert ev is not None
    assert ev.src_ip == "198.51.100.4"
    assert ev.timestamp is not None


def test_non_ssh_line_ignored():
    assert P.parse("Jan  2 12:00:04 host CRON[999]: pam_unix(cron:session): session opened") is None
    assert P.parse("") is None
