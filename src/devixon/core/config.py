"""
Configuration management for DEVIXON.
"""

from pathlib import Path
from typing import Optional, Dict, Any
import os
import json
from pydantic import BaseModel, Field

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "devixon"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "devixon"
DEFAULT_DB_FILE = DEFAULT_DATA_DIR / "devixon.db"
DEFAULT_REPORTS_DIR = Path.home() / "devixon_reports"


class AIConfig(BaseModel):
    enabled: bool = False
    provider: str = "openai"  # openai, ollama, local, disabled
    base_url: Optional[str] = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key_env_var: str = "DEVIXON_AI_API_KEY"
    temperature: float = 0.2
    max_tokens: int = 2048


class RateLimits(BaseModel):
    requests_per_second: int = 10
    max_concurrency: int = 5
    timeout_seconds: int = 15
    max_scan_duration_minutes: int = 60


class OutputConfig(BaseModel):
    no_color: bool = False
    quiet: bool = False
    verbose: bool = False
    log_level: str = "INFO"
    reports_dir: str = str(DEFAULT_REPORTS_DIR)


class AppConfig(BaseModel):
    database_path: str = str(DEFAULT_DB_FILE)
    default_profile: str = "QUICK"
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    custom_tool_paths: Dict[str, str] = Field(default_factory=dict)


def ensure_directories():
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    ensure_directories()
    if DEFAULT_CONFIG_FILE.exists():
        try:
            with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return AppConfig.model_validate(data)
        except Exception:
            return AppConfig()
    return AppConfig()


def save_config(config: AppConfig) -> None:
    ensure_directories()
    with open(DEFAULT_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config.model_dump(), f, indent=2)
