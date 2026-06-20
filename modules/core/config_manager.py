"""Central configuration manager — single source of truth for all modules."""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

import yaml


class ConfigManager:
    """
    Loads settings.yaml once, resolves template variables, and exposes
    typed accessors so modules never touch raw YAML directly.
    """

    DEFAULT_CONFIG_PATH = Path(__file__).parents[2] / "config" / "settings.yaml"

    def __init__(self, config_path: str | Path | None = None) -> None:
        path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with path.open() as fh:
            raw = yaml.safe_load(fh)
        self._cfg: dict[str, Any] = self._resolve_templates(raw)

    # ── public ──────────────────────────────────────────────────────────────

    def get(self, *keys: str, default: Any = None) -> Any:
        """Dotted-key access: get('siem', 'backends', 'elasticsearch', 'enabled')."""
        node: Any = self._cfg
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key, default)
            if node is default:
                return default
        return node

    def section(self, *keys: str) -> dict[str, Any]:
        """Return a config section as a dict (empty dict if missing)."""
        result = self.get(*keys)
        return result if isinstance(result, dict) else {}

    def require(self, *keys: str) -> Any:
        """Like get() but raises KeyError when the value is missing/None."""
        value = self.get(*keys)
        if value is None:
            raise KeyError(f"Required config key missing: {'.'.join(keys)}")
        return value

    @property
    def raw(self) -> dict[str, Any]:
        return self._cfg

    # ── private ─────────────────────────────────────────────────────────────

    def _resolve_templates(self, obj: Any) -> Any:
        """Replace {{ hostname }} and {{ env.VAR }} placeholders."""
        if isinstance(obj, str):
            obj = obj.replace("{{ ansible_hostname | default(hostname) }}", socket.gethostname())
            if "{{ env." in obj:
                import re
                for match in re.findall(r"\{\{ env\.(\w+) \}\}", obj):
                    obj = obj.replace(f"{{{{ env.{match} }}}}", os.environ.get(match, ""))
            return obj
        if isinstance(obj, dict):
            return {k: self._resolve_templates(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._resolve_templates(i) for i in obj]
        return obj
