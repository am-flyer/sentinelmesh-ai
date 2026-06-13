"""Tests for browser-provided security evidence ingestion."""

from sentinelmesh.ingestion.evidence_parser import (
    parse_csv_evidence,
    parse_json_evidence,
    parse_text_evidence,
)


def test_parse_json_evidence_list() -> None:
    """Verify JSON uploads normalize into a threat scenario."""
    payload = """
    [
      {
        "timestamp": "2026-06-13T10:00:00Z",
        "kind": "auth",
        "actor": "admin",
        "source_ip": "185.220.101.34",
        "asset_id": "iam-prod",
        "action": "login",
        "outcome": "failed",
        "severity": "HIGH",
        "message": "Repeated failed login attempts"
      }
    ]
    """

    scenario = parse_json_evidence(payload, source_name="browser.json")

    assert scenario.name == "uploaded_evidence"
    assert scenario.title == "Uploaded Evidence Analysis: browser.json"
    assert scenario.events[0].kind == "auth"
    assert scenario.events[0].source_ip == "185.220.101.34"


def test_parse_csv_evidence() -> None:
    """Verify CSV uploads normalize into security events."""
    payload = (
        "timestamp,kind,actor,source_ip,asset_id,action,outcome,severity,message\n"
        "2026-06-13T10:00:00Z,api,prod-key,45.83.64.12,api-prod,"
        "bulk_read,success,CRITICAL,Mass data extraction\n"
    )

    scenario = parse_csv_evidence(payload, source_name="evidence.csv")

    assert len(scenario.events) == 1
    assert scenario.events[0].action == "bulk_read"
    assert scenario.assets[0].asset_id == "api-prod"


def test_parse_text_evidence_infers_security_event() -> None:
    """Verify pasted or log text can be inferred into events."""
    payload = "admin login failed from 185.220.101.34 after brute force attempts"

    scenario = parse_text_evidence(payload, source_name="pasted text")

    assert scenario.events[0].kind == "auth"
    assert scenario.events[0].severity == "HIGH"
    assert "185.220.101.34" in scenario.events[0].indicators


def test_empty_text_evidence_is_rejected() -> None:
    """Verify empty browser input returns a clear validation error."""
    try:
        parse_text_evidence("   ", source_name="empty")
    except ValueError as exc:
        assert "No evidence" in str(exc)
    else:
        raise AssertionError("Expected ValueError for empty evidence")
