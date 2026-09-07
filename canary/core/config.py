"""Canary configuration management."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from canary.core.errors import ConfigError

DEFAULT_CONFIG_DIR = Path(os.environ.get("CANARY_HOME", "~/.canary")).expanduser()


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    api_token: str | None = None


class DbConfig(BaseModel):
    path: str = "canary.db"
    echo: bool = False


class CorrelationConfig(BaseModel):
    score_initial: int = 10
    score_auth_failure: int = 5
    score_command: int = 8
    score_technique: int = 15
    score_new_honeypot: int = 7
    score_protocol: int = 3
    score_tool: int = 12


class Config(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    db: DbConfig = Field(default_factory=DbConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        cfg_path = path or (DEFAULT_CONFIG_DIR / "config.yaml")
        if not cfg_path.exists():
            return cls()
        try:
            data = yaml.safe_load(cfg_path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid config YAML at {cfg_path}: {exc}") from exc
        return cls.model_validate(data)

    def ensure_default(self, path: Path | None = None) -> Path:
        cfg_path = path or (DEFAULT_CONFIG_DIR / "config.yaml")
        if not cfg_path.exists():
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            cfg_path.write_text(yaml.safe_dump(self.model_dump(), sort_keys=False))
        return cfg_path
