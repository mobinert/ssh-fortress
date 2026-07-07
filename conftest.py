"""Pytest bootstrap: make the project importable and provide a config factory."""

import sys
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from modules.core import ConfigManager  # noqa: E402


@pytest.fixture
def cfg_factory(tmp_path):
    """Return a helper that writes a settings dict to YAML and loads it."""
    def _make(data: dict) -> ConfigManager:
        path = tmp_path / "settings.yaml"
        path.write_text(yaml.safe_dump(data))
        return ConfigManager(path)
    return _make
