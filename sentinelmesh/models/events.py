"""Pydantic models for simulated cybersecurity events."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

EventKind = Literal["auth", "network", "api", "endpoint", "cloud"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AssetInfo(BaseModel):
    """Describe an asset involved in a security scenario."""

    asset_id: str
    name: str
    asset_type: str
    owner: str
    criticality: Severity = "MEDIUM"


class SecurityEvent(BaseModel):
    """Represent one normalized security event."""

    event_id: str
    timestamp: datetime
    kind: EventKind
    actor: str
    source_ip: str
    asset_id: str
    action: str
    outcome: str
    severity: Severity
    message: str
    indicators: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class ThreatScenario(BaseModel):
    """Bundle scenario metadata, assets, and generated events."""

    name: str
    title: str
    description: str
    category: str
    assets: list[AssetInfo]
    events: list[SecurityEvent]
