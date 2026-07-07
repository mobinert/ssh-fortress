"""Unit tests for the ntfy notifier request builder."""

from modules.alerting import NtfyNotifier


def _cfg(cfg_factory, **ntfy):
    base = {"enabled": True, "server": "https://ntfy.sh", "topic": "fortress"}
    base.update(ntfy)
    return cfg_factory({"alerting": {"ntfy": base}})


def test_disabled_when_topic_missing(cfg_factory):
    cfg = cfg_factory({"alerting": {"ntfy": {"enabled": True, "topic": ""}}})
    n = NtfyNotifier(cfg)
    # send_event must be a no-op (must not raise) when topic is empty
    n.send_event("ROOT_ATTEMPT", {"src_ip": "1.2.3.4"})


def test_build_request_url_and_headers(cfg_factory):
    n = NtfyNotifier(_cfg(cfg_factory))
    req = n.build_request("Title here", "hello", 5, ["skull", "warning"])
    assert req.full_url == "https://ntfy.sh/fortress"
    assert req.get_method() == "POST"
    assert req.headers["Title"] == "Title here"
    assert req.headers["Priority"] == "5"
    assert req.headers["Tags"] == "skull,warning"
    assert req.data == b"hello"
    assert "Authorization" not in req.headers


def test_build_request_includes_bearer_token(cfg_factory):
    n = NtfyNotifier(_cfg(cfg_factory, token="tk_secret"))
    req = n.build_request("t", "m", 3, [])
    assert req.headers["Authorization"] == "Bearer tk_secret"


def test_self_hosted_server_trailing_slash_stripped(cfg_factory):
    n = NtfyNotifier(_cfg(cfg_factory, server="https://push.example.com/"))
    req = n.build_request("t", "m", 3, [])
    assert req.full_url == "https://push.example.com/fortress"
