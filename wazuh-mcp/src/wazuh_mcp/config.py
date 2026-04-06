"""
Configuration loader.

Non-sensitive settings come from config.toml (versioned).
Credentials come exclusively from environment variables / .env file (not versioned).
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from dotenv import load_dotenv

# Load .env if present (dev convenience - no-op in Docker)
load_dotenv()


def _find_config_toml() -> Path:
    """
    Locate config.toml by checking in order:
    1. WAZUH_CONFIG_PATH env var (explicit override)
    2. Current working directory (works in Docker: WORKDIR /app)
    3. Three levels up from this file (works for local editable install: src/wazuh_mcp/)
    """
    env_path = os.getenv("WAZUH_CONFIG_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"config.toml not found at WAZUH_CONFIG_PATH={env_path}")

    candidates = [
        Path.cwd() / "config.toml",
        Path(__file__).parent.parent.parent / "config.toml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "config.toml not found. Looked in:\n"
        + "\n".join(f"  {p}" for p in candidates)
        + "\nSet WAZUH_CONFIG_PATH or place config.toml in the working directory."
    )


def _load_toml() -> dict:
    with open(_find_config_toml(), "rb") as f:
        return tomllib.load(f)


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(
            f"Required environment variable '{name}' is not set. "
            "Set it in your .env file or environment."
        )
    return value


class Config:
    """Single source of truth for all runtime configuration."""

    def __init__(self) -> None:
        data = _load_toml()

        manager = data.get("manager", {})
        indexer = data.get("indexer", {})
        limits = data.get("limits", {})

        # Manager
        self.manager_url: str = manager.get("url", "https://localhost:55000").rstrip("/")
        self.manager_verify_ssl: bool | str = self._ssl(
            manager.get("verify_ssl", True), manager.get("ca_bundle", "")
        )

        # Indexer
        self.indexer_url: str = indexer.get("url", "https://localhost:9200").rstrip("/")
        self.indexer_verify_ssl: bool | str = self._ssl(
            indexer.get("verify_ssl", True), indexer.get("ca_bundle", "")
        )
        self.alert_index: str = indexer.get("alert_index", "wazuh-alerts-*")

        # Limits
        self.default_limit: int = int(limits.get("default_limit", 100))
        self.max_limit: int = int(limits.get("max_limit", 1000))
        self.token_ttl_seconds: int = int(limits.get("token_ttl_seconds", 800))

        # Credentials — must come from env
        self.manager_username: str = _require_env("WAZUH_MANAGER_USERNAME")
        self.manager_password: str = _require_env("WAZUH_MANAGER_PASSWORD")
        self.indexer_username: str = _require_env("WAZUH_INDEXER_USERNAME")
        self.indexer_password: str = _require_env("WAZUH_INDEXER_PASSWORD")

    @staticmethod
    def _ssl(verify: bool, ca_bundle: str) -> bool | str:
        """Return the value to pass as httpx verify=."""
        if not verify:
            return False
        if ca_bundle:
            return ca_bundle
        return True
