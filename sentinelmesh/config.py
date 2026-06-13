"""Configuration loading for SentinelMesh AI."""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


@dataclass(frozen=True)
class Settings:
    """Runtime settings for LLM enrichment."""

    openrouter_api_key: str | None
    openrouter_base_url: str
    openrouter_model: str
    request_timeout: int


def load_settings() -> Settings:
    """Load settings from environment variables."""
    if load_dotenv is not None:
        load_dotenv()

    return Settings(
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY"),
        openrouter_base_url=os.getenv(
            "OPENROUTER_BASE_URL",
            "https://openrouter.ai/api/v1",
        ),
        openrouter_model=os.getenv("OPENROUTER_MODEL", "openai/gpt-5-mini"),
        request_timeout=int(os.getenv("OPENROUTER_TIMEOUT", "20")),
    )
