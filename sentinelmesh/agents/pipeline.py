"""Agent pipeline orchestration for SentinelMesh AI."""

from __future__ import annotations

from typing import TypedDict

from sentinelmesh.config import Settings, load_settings
from sentinelmesh.models.events import ThreatScenario
from sentinelmesh.models.response import ContainmentAction, SOCIncidentReport
from sentinelmesh.simulators.scenario_engine import build_scenario
from sentinelmesh.tools.analysis import (
    analyze_events,
    build_timeline,
    find_vulnerabilities,
    map_mitre_techniques,
    recommend_policy_gaps,
    score_threat,
)
from sentinelmesh.tools.llm import (
    build_fallback_summary,
    enrich_summary_with_openrouter,
)

try:
    from langgraph.graph import END, StateGraph
except ImportError:
    END = None
    StateGraph = None


class PipelineState(TypedDict, total=False):
    """Represent mutable state passed between agent steps."""

    scenario: ThreatScenario
    findings: list[str]
    timeline: list[str]
    summary: str
    settings: Settings
    use_llm: bool
    report: SOCIncidentReport


def run_pipeline(scenario_name: str, use_llm: bool = True) -> SOCIncidentReport:
    """Run the complete agent pipeline for a scenario."""
    return run_evidence_pipeline(build_scenario(scenario_name), use_llm=use_llm)


def run_evidence_pipeline(
    scenario: ThreatScenario,
    use_llm: bool = True,
) -> SOCIncidentReport:
    """Run the complete agent pipeline for normalized evidence."""
    initial_state: PipelineState = {
        "scenario": scenario,
        "settings": load_settings(),
        "use_llm": use_llm,
    }
    final_state = _run_langgraph(initial_state) or _run_local_pipeline(initial_state)
    return final_state["report"]


def _run_langgraph(state: PipelineState) -> PipelineState | None:
    """Run the pipeline through LangGraph when installed."""
    if StateGraph is None or END is None:
        return None

    graph = StateGraph(PipelineState)
    graph.add_node("log_monitor", _log_monitor_agent)
    graph.add_node("threat_intel", _threat_intel_agent)
    graph.add_node("incident_response", _incident_response_agent)
    graph.set_entry_point("log_monitor")
    graph.add_edge("log_monitor", "threat_intel")
    graph.add_edge("threat_intel", "incident_response")
    graph.add_edge("incident_response", END)
    compiled = graph.compile()
    result = compiled.invoke(state)
    return PipelineState(**result)


def _run_local_pipeline(state: PipelineState) -> PipelineState:
    """Run the same agent steps without LangGraph."""
    for step in (_log_monitor_agent, _threat_intel_agent, _incident_response_agent):
        state = step(state)
    return state


def _log_monitor_agent(state: PipelineState) -> PipelineState:
    """Detect suspicious events and build the incident timeline."""
    scenario = state["scenario"]
    state["findings"] = analyze_events(scenario)
    state["timeline"] = build_timeline(scenario)
    return state


def _threat_intel_agent(state: PipelineState) -> PipelineState:
    """Enrich findings with LLM or deterministic summary text."""
    scenario = state["scenario"]
    findings = state["findings"]
    settings = state["settings"]

    if state.get("use_llm", True):
        state["summary"] = enrich_summary_with_openrouter(
            settings=settings,
            scenario=scenario,
            findings=findings,
        )
    else:
        state["summary"] = build_fallback_summary(scenario, findings)

    return state


def _incident_response_agent(state: PipelineState) -> PipelineState:
    """Create final SOC report and safe containment plan."""
    scenario = state["scenario"]
    findings = state["findings"]
    threat_score = score_threat(scenario, findings)
    state["report"] = SOCIncidentReport(
        title=scenario.title,
        scenario_name=scenario.name,
        status="CONTAINING",
        executive_summary=state["summary"],
        threat_score=threat_score,
        findings=findings,
        mitre_techniques=map_mitre_techniques(scenario),
        vulnerabilities=find_vulnerabilities(scenario),
        policy_gaps=recommend_policy_gaps(scenario),
        containment_actions=_containment_actions(scenario),
        timeline=state["timeline"],
    )
    return state


def _containment_actions(scenario: ThreatScenario) -> list[ContainmentAction]:
    """Return safe operator actions for a scenario."""
    if scenario.name == "uploaded_evidence":
        return [
            ContainmentAction(
                action="Preserve uploaded evidence and validate original log source",
                owner="Security Operations",
                priority="P0",
                safe_to_automate=False,
            ),
            ContainmentAction(
                action="Review affected accounts, IPs, and assets from evidence",
                owner="Security Operations",
                priority="P1",
                safe_to_automate=False,
            ),
            ContainmentAction(
                action="Create investigation ticket with report and timeline",
                owner="SOC Lead",
                priority="P1",
                safe_to_automate=True,
            ),
        ]

    playbooks: dict[str, list[tuple[str, str, str, bool]]] = {
        "brute_force_attack": [
            (
                "Block malicious external IPs at firewall",
                "Network Security",
                "P0",
                True,
            ),
            (
                "Disable compromised accounts pending review",
                "Security Operations",
                "P0",
                False,
            ),
            ("Collect endpoint forensic images", "IT Operations", "P1", False),
        ],
        "insider_threat": [
            (
                "Suspend elevated access for the insider account",
                "Security Operations",
                "P0",
                False,
            ),
            ("Preserve API and storage audit logs", "Cloud Team", "P0", True),
            ("Start HR and legal evidence workflow", "GRC Team", "P1", False),
        ],
        "api_key_compromise": [
            ("Revoke and rotate exposed API key", "Security Operations", "P0", False),
            ("Apply rate limits to affected endpoints", "Platform Team", "P0", True),
            ("Identify downstream data exposure", "Data Team", "P1", False),
        ],
        "malware_lateral_movement": [
            ("Isolate affected endpoints", "Security Operations", "P0", False),
            ("Block command-and-control destinations", "Network Security", "P0", True),
            ("Reset credentials observed on host", "Identity Team", "P1", False),
        ],
        "cloud_misconfiguration": [
            ("Block public access on sensitive bucket", "Cloud Team", "P0", True),
            ("Restrict security group source ranges", "Cloud Team", "P0", True),
            (
                "Review object access logs for exposure",
                "Security Operations",
                "P1",
                False,
            ),
        ],
    }
    return [
        ContainmentAction(
            action=action,
            owner=owner,
            priority=priority,
            safe_to_automate=safe,
        )
        for action, owner, priority, safe in playbooks[scenario.name]
    ]
