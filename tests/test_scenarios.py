"""Tests for deterministic threat scenarios."""

from sentinelmesh.simulators.scenario_engine import SCENARIOS, build_scenario


def test_all_five_scenarios_are_available() -> None:
    """Verify the demo exposes the requested pre-built scenarios."""
    assert set(SCENARIOS) == {
        "brute_force_attack",
        "insider_threat",
        "api_key_compromise",
        "malware_lateral_movement",
        "cloud_misconfiguration",
    }


def test_build_scenario_contains_events_and_assets() -> None:
    """Verify a scenario includes usable event and asset data."""
    scenario = build_scenario("brute_force_attack")

    assert scenario.name == "brute_force_attack"
    assert scenario.events
    assert scenario.assets
    assert scenario.description.startswith("Brute force")


def test_unknown_scenario_raises_clear_error() -> None:
    """Verify unknown scenarios fail with a useful message."""
    try:
        build_scenario("missing")
    except ValueError as exc:
        assert "Unknown scenario" in str(exc)
    else:
        raise AssertionError("Expected ValueError for an unknown scenario")
