"""Parse browser-provided evidence into normalized security events."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

from sentinelmesh.models.events import AssetInfo, SecurityEvent, ThreatScenario

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
VALID_KINDS = {"auth", "network", "api", "endpoint", "cloud"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def parse_json_evidence(payload: str, source_name: str) -> ThreatScenario:
    """Parse JSON security evidence into a threat scenario."""
    _reject_empty(payload)
    loaded = json.loads(payload)
    records = loaded if isinstance(loaded, list) else [loaded]
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("JSON evidence must contain objects.")
    return _build_scenario(records, source_name)


def parse_csv_evidence(payload: str, source_name: str) -> ThreatScenario:
    """Parse CSV security evidence into a threat scenario."""
    _reject_empty(payload)
    reader = csv.DictReader(io.StringIO(payload))
    records = list(reader)
    if not records:
        raise ValueError("No evidence rows found in CSV input.")
    return _build_scenario(records, source_name)


def parse_text_evidence(payload: str, source_name: str) -> ThreatScenario:
    """Parse plain text or log lines into a threat scenario."""
    _reject_empty(payload)
    records = [_infer_record(line) for line in payload.splitlines() if line.strip()]
    if not records:
        raise ValueError("No evidence lines found in text input.")
    return _build_scenario(records, source_name)


def parse_uploaded_evidence(
    payload: str,
    source_name: str,
    file_type: str,
) -> ThreatScenario:
    """Route uploaded evidence to the right parser."""
    normalized_type = file_type.lower().lstrip(".")
    if normalized_type == "json":
        return parse_json_evidence(payload, source_name)
    if normalized_type == "csv":
        return parse_csv_evidence(payload, source_name)
    if normalized_type in {"txt", "log"}:
        return parse_text_evidence(payload, source_name)
    raise ValueError(f"Unsupported evidence type: {file_type}")


def _build_scenario(
    records: list[dict[str, Any]],
    source_name: str,
) -> ThreatScenario:
    """Build a threat scenario from normalized records."""
    events = [
        _record_to_event(index, record) for index, record in enumerate(records, start=1)
    ]
    assets = _assets_from_events(events)
    return ThreatScenario(
        name="uploaded_evidence",
        title=f"Uploaded Evidence Analysis: {source_name}",
        description="Read-only analysis of browser-provided security evidence.",
        category=_infer_category(events),
        assets=assets,
        events=events,
    )


def _record_to_event(index: int, record: dict[str, Any]) -> SecurityEvent:
    """Convert one record into a security event."""
    message = str(record.get("message") or record.get("raw") or "Uploaded event")
    indicators = _coerce_indicators(record.get("indicators"), message)
    return SecurityEvent(
        event_id=str(record.get("event_id") or f"upload-{index:03d}"),
        timestamp=_parse_timestamp(record.get("timestamp")),
        kind=_normalize_kind(str(record.get("kind") or ""), message),
        actor=str(record.get("actor") or record.get("user") or "unknown"),
        source_ip=str(record.get("source_ip") or _first_ip(message) or "0.0.0.0"),
        asset_id=str(record.get("asset_id") or record.get("asset") or "uploaded-asset"),
        action=str(record.get("action") or _infer_action(message)),
        outcome=str(record.get("outcome") or _infer_outcome(message)),
        severity=_normalize_severity(str(record.get("severity") or ""), message),
        message=message,
        indicators=indicators,
        metadata={"source": "uploaded"},
    )


def _infer_record(line: str) -> dict[str, Any]:
    """Infer a minimal event record from one log line."""
    return {
        "raw": line.strip(),
        "message": line.strip(),
        "kind": _normalize_kind("", line),
        "action": _infer_action(line),
        "outcome": _infer_outcome(line),
        "severity": _normalize_severity("", line),
        "source_ip": _first_ip(line) or "0.0.0.0",
        "indicators": _coerce_indicators(None, line),
    }


def _assets_from_events(events: list[SecurityEvent]) -> list[AssetInfo]:
    """Create asset records from event asset IDs."""
    seen: set[str] = set()
    assets: list[AssetInfo] = []
    for event in events:
        if event.asset_id in seen:
            continue
        seen.add(event.asset_id)
        assets.append(
            AssetInfo(
                asset_id=event.asset_id,
                name=event.asset_id,
                asset_type=event.kind,
                owner="Uploaded Evidence",
                criticality=event.severity,
            )
        )
    return assets


def _parse_timestamp(value: Any) -> datetime:
    """Parse a timestamp or return current UTC time."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    return datetime.now(timezone.utc)


def _normalize_kind(raw_kind: str, text: str) -> str:
    """Normalize or infer an event kind."""
    kind = raw_kind.strip().lower()
    if kind in VALID_KINDS:
        return kind
    lowered = text.lower()
    if any(word in lowered for word in ("login", "mfa", "password", "account")):
        return "auth"
    if any(word in lowered for word in ("api", "token", "key", "endpoint")):
        return "api"
    if any(word in lowered for word in ("bucket", "s3", "security group", "cloud")):
        return "cloud"
    if any(word in lowered for word in ("process", "malware", "mimikatz", "psexec")):
        return "endpoint"
    return "network"


def _normalize_severity(raw_severity: str, text: str) -> str:
    """Normalize or infer an event severity."""
    severity = raw_severity.strip().upper()
    if severity in VALID_SEVERITIES:
        return severity
    lowered = text.lower()
    if any(word in lowered for word in ("critical", "exfil", "malware", "mimikatz")):
        return "CRITICAL"
    if any(word in lowered for word in ("brute", "failed", "mass", "public")):
        return "HIGH"
    if any(word in lowered for word in ("warning", "unusual", "suspicious")):
        return "MEDIUM"
    return "LOW"


def _infer_action(text: str) -> str:
    """Infer an event action from free text."""
    lowered = text.lower()
    if "login" in lowered:
        return "login"
    if "bulk" in lowered or "mass" in lowered:
        return "bulk_read"
    if "exfil" in lowered:
        return "exfiltration"
    if "public" in lowered:
        return "public_access"
    if "mimikatz" in lowered or "credential" in lowered:
        return "credential_dump"
    return "observed_activity"


def _infer_outcome(text: str) -> str:
    """Infer event outcome from free text."""
    lowered = text.lower()
    if "failed" in lowered or "denied" in lowered:
        return "failed"
    return "success"


def _coerce_indicators(value: Any, text: str) -> list[str]:
    """Coerce indicators into a list and append IP indicators from text."""
    indicators: list[str] = []
    if isinstance(value, str) and value.strip():
        indicators.extend(item.strip() for item in value.split(",") if item.strip())
    elif isinstance(value, list):
        indicators.extend(str(item) for item in value if str(item).strip())
    indicators.extend(ip for ip in IP_PATTERN.findall(text) if ip not in indicators)
    return indicators


def _first_ip(text: str) -> str | None:
    """Return the first IPv4 address in text."""
    match = IP_PATTERN.search(text)
    return match.group(0) if match else None


def _infer_category(events: list[SecurityEvent]) -> str:
    """Infer report category from event types."""
    kinds = {event.kind for event in events}
    if "api" in kinds:
        return "api"
    if "auth" in kinds:
        return "identity"
    if "cloud" in kinds:
        return "cloud"
    if "endpoint" in kinds:
        return "malware"
    return "network"


def _reject_empty(payload: str) -> None:
    """Reject empty browser evidence."""
    if not payload.strip():
        raise ValueError("No evidence was provided.")
