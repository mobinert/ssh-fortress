"""Unit tests for the settings.yaml validator."""

from modules.core import ConfigValidator


def _levels(findings):
    return {(f.section, f.level) for f in findings}


def test_clean_config_has_no_errors(cfg_factory):
    cfg = cfg_factory({
        "brute_force": {"enabled": True, "max_attempts": 5,
                        "block_duration": 3600, "max_ban_duration": 86400},
        "threat_scoring": {"enabled": True, "ban_threshold": 70},
        "alerting": {"enabled": True, "telegram": {"enabled": False}},
        "siem": {"enabled": False},
    })
    findings = ConfigValidator(cfg).validate()
    assert not any(f.level == "ERROR" for f in findings)
    assert any(f.level == "OK" for f in findings)


def test_telegram_enabled_without_token_is_error(cfg_factory):
    cfg = cfg_factory({"alerting": {"enabled": True,
                                    "telegram": {"enabled": True, "bot_token": "", "chat_id": ""}}})
    findings = ConfigValidator(cfg).validate()
    assert ("alerting.telegram", "ERROR") in _levels(findings)


def test_bad_ban_threshold_is_error(cfg_factory):
    cfg = cfg_factory({"threat_scoring": {"enabled": True, "ban_threshold": 150}})
    findings = ConfigValidator(cfg).validate()
    assert ("threat_scoring", "ERROR") in _levels(findings)


def test_invalid_max_attempts_is_error(cfg_factory):
    cfg = cfg_factory({"brute_force": {"enabled": True, "max_attempts": 0}})
    findings = ConfigValidator(cfg).validate()
    assert ("brute_force", "ERROR") in _levels(findings)


def test_reputation_without_key_is_error(cfg_factory):
    cfg = cfg_factory({"ip_reputation": {"enabled": True, "abuseipdb_api_key": ""}})
    findings = ConfigValidator(cfg).validate()
    assert ("ip_reputation", "ERROR") in _levels(findings)


def test_alerting_on_but_no_channels_warns(cfg_factory):
    cfg = cfg_factory({"alerting": {"enabled": True}})
    findings = ConfigValidator(cfg).validate()
    assert ("alerting", "WARN") in _levels(findings)


def test_bad_metrics_port_is_error(cfg_factory):
    cfg = cfg_factory({"metrics": {"enabled": True, "port": 99999}})
    findings = ConfigValidator(cfg).validate()
    assert ("metrics", "ERROR") in _levels(findings)
