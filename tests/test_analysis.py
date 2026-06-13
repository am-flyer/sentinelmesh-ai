"""Tests for deterministic security analysis."""

from sentinelmesh.simulators.scenario_engine import build_scenario
from sentinelmesh.tools.analysis import (
    analyze_events,
    map_mitre_techniques,
    recommend_policy_gaps,
    score_threat,
)


def test_brute_force_analysis_finds_identity_attack() -> None:
    """Verify brute force scenarios produce identity findings."""
    scenario = build_scenario("brute_force_attack")
    findings = analyze_events(scenario)

    assert any("brute force" in finding.lower() for finding in findings)
    assert any("lateral movement" in finding.lower() for finding in findings)


def test_threat_score_reflects_critical_scenario() -> None:
    """Verify severe scenarios receive a critical threat score."""
    scenario = build_scenario("malware_lateral_movement")
    score = score_threat(scenario, analyze_events(scenario))

    assert score.value >= 85
    assert score.severity == "CRITICAL"


def test_mitre_and_policy_context_are_returned() -> None:
    """Verify analysis maps security context to known frameworks."""
    scenario = build_scenario("cloud_misconfiguration")

    mitre = map_mitre_techniques(scenario)
    gaps = recommend_policy_gaps(scenario)

    assert any(item.technique_id == "T1530" for item in mitre)
    assert any("NIST" in gap.framework for gap in gaps)
