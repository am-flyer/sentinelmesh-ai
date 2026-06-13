"""Tests for the SentinelMesh agent pipeline."""

from sentinelmesh.agents.pipeline import run_pipeline
from sentinelmesh.ingestion.evidence_parser import parse_text_evidence


def test_pipeline_generates_soc_report_without_llm() -> None:
    """Verify the full pipeline works without an API key."""
    report = run_pipeline("api_key_compromise", use_llm=False)

    assert report.title.startswith("API Key")
    assert report.status == "CONTAINING"
    assert report.threat_score.value >= 80
    assert report.findings
    assert report.containment_actions
    assert "SOC INCIDENT REPORT" in report.to_text()


def test_pipeline_includes_policy_and_mitre_context() -> None:
    """Verify the report contains policy and MITRE enrichment."""
    report = run_pipeline("insider_threat", use_llm=False)

    assert report.mitre_techniques
    assert report.policy_gaps
    assert any(
        action.owner == "Security Operations" for action in report.containment_actions
    )


def test_pipeline_analyzes_uploaded_evidence_without_llm() -> None:
    """Verify uploaded browser evidence can drive the full report pipeline."""
    from sentinelmesh.agents.pipeline import run_evidence_pipeline

    scenario = parse_text_evidence(
        "prod-api-key bulk read from 45.83.64.12 caused mass extraction",
        source_name="browser paste",
    )
    report = run_evidence_pipeline(scenario, use_llm=False)

    assert report.scenario_name == "uploaded_evidence"
    assert report.title == "Uploaded Evidence Analysis: browser paste"
    assert report.findings
    assert report.containment_actions
