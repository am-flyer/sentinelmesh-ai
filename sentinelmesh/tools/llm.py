"""OpenRouter enrichment helpers with deterministic fallback behavior."""

from __future__ import annotations

import json
from typing import Any

import requests

from sentinelmesh.config import Settings
from sentinelmesh.models.events import ThreatScenario


def build_fallback_summary(
    scenario: ThreatScenario,
    findings: list[str],
) -> str:
    """Create a deterministic executive summary when no LLM is used."""
    return (
        f"{scenario.title} was detected across {len(scenario.events)} events. "
        f"The strongest indicators were {findings[0].lower()} "
        f"Operators should contain affected identities, rotate exposed secrets, "
        f"preserve evidence, and validate recovery before closure."
    )


def enrich_summary_with_openrouter(
    settings: Settings,
    scenario: ThreatScenario,
    findings: list[str],
) -> str:
    """Ask OpenRouter to improve the incident summary."""
    if not settings.openrouter_api_key:
        return build_fallback_summary(scenario, findings)

    payload = _build_payload(settings, scenario, findings)
    headers = {
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8501",
        "X-Title": "SentinelMesh AI",
    }

    try:
        response = requests.post(
            f"{settings.openrouter_base_url.rstrip('/')}/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=settings.request_timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        content = data["choices"][0]["message"]["content"]
        return str(content).strip()
    except (KeyError, requests.RequestException, ValueError):
        return build_fallback_summary(scenario, findings)


def _build_payload(
    settings: Settings,
    scenario: ThreatScenario,
    findings: list[str],
) -> dict[str, Any]:
    """Build an OpenRouter chat-completions payload."""
    prompt = (
        "Write a concise SOC executive summary for this incident. "
        "Use clear security language, avoid speculation, and mention "
        "containment priorities.\n\n"
        f"Scenario: {scenario.title}\n"
        f"Description: {scenario.description}\n"
        f"Findings: {'; '.join(findings[:5])}"
    )
    return {
        "model": settings.openrouter_model,
        "messages": [
            {
                "role": "system",
                "content": "You are a senior SOC incident commander.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 220,
    }
