"""Smoke test: the whole package (and the CLI) imports cleanly off-target."""

import importlib


def test_import_main_and_cli():
    main = importlib.import_module("main")
    assert main.cli is not None


def test_all_modules_import():
    for mod in [
        "modules.core",
        "modules.core.config_validator",
        "modules.protection.threat_scorer",
        "modules.monitoring.metrics_exporter",
        "modules.reporting.html_report",
        "modules.alerting.ntfy_notifier",
        "modules.logging.log_parser",
    ]:
        importlib.import_module(mod)


def test_version_exposed():
    from modules.core import __version__
    assert __version__ == "2.0.0"
