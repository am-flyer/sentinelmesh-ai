"""Streamlit SOC console for SentinelMesh AI."""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinelmesh.agents.pipeline import run_evidence_pipeline, run_pipeline
from sentinelmesh.ingestion.evidence_parser import (
    parse_text_evidence,
    parse_uploaded_evidence,
)
from sentinelmesh.simulators.scenario_engine import SCENARIOS, build_scenario


def main() -> None:
    """Render the SentinelMesh AI Streamlit application."""
    st.set_page_config(
        page_title="SentinelMesh AI",
        layout="wide",
    )
    st.title("SentinelMesh AI")
    st.caption("Multi-agent cybersecurity incident analysis")

    input_mode = st.sidebar.radio(
        "Input mode",
        options=[
            "Demo scenario",
            "Upload evidence",
            "Paste evidence",
        ],
    )
    use_llm = st.sidebar.toggle(
        "Use OpenRouter enrichment",
        value=True,
        help="Requires OPENROUTER_API_KEY. Falls back safely if unavailable.",
    )

    scenario, report = _load_report(input_mode, use_llm)
    if scenario is None or report is None:
        _render_scenario_table()
        return

    _render_overview(report)
    _render_scenario_table()
    _render_timeline(scenario.events)
    _render_agent_findings(report)
    _render_report(report.to_text())


def _load_report(input_mode: str, use_llm: bool) -> tuple[Any | None, Any | None]:
    """Load a report from the selected browser input mode."""
    if input_mode == "Demo scenario":
        scenario_name = st.sidebar.selectbox(
            "Threat scenario",
            options=sorted(SCENARIOS),
            format_func=_format_scenario_name,
        )
        return build_scenario(scenario_name), run_pipeline(
            scenario_name, use_llm=use_llm
        )

    if input_mode == "Upload evidence":
        uploaded_file = st.sidebar.file_uploader(
            "Upload security evidence",
            type=["json", "csv", "txt", "log"],
        )
        if uploaded_file is None:
            st.info("Upload a JSON, CSV, TXT, or LOG file to analyze evidence.")
            return None, None
        try:
            content = uploaded_file.getvalue().decode("utf-8")
            file_type = uploaded_file.name.rsplit(".", maxsplit=1)[-1]
            scenario = parse_uploaded_evidence(
                content,
                source_name=uploaded_file.name,
                file_type=file_type,
            )
            return scenario, run_evidence_pipeline(scenario, use_llm=use_llm)
        except (UnicodeDecodeError, ValueError) as exc:
            st.error(f"Evidence validation failed: {exc}")
            return None, None

    pasted = st.sidebar.text_area(
        "Paste security logs",
        height=180,
        placeholder=(
            "Example: admin login failed from 185.220.101.34 "
            "after brute force attempts"
        ),
    )
    if not pasted.strip():
        st.info("Paste one or more security log lines to analyze evidence.")
        return None, None
    try:
        scenario = parse_text_evidence(pasted, source_name="browser paste")
        return scenario, run_evidence_pipeline(scenario, use_llm=use_llm)
    except ValueError as exc:
        st.error(f"Evidence validation failed: {exc}")
        return None, None


def _render_overview(report: Any) -> None:
    """Render top-level incident metrics."""
    score_color = "inverse" if report.threat_score.value >= 85 else "normal"
    columns = st.columns(4)
    columns[0].metric("Severity", report.threat_score.severity)
    columns[1].metric("Threat score", f"{report.threat_score.value}/100")
    columns[2].metric("Status", report.status)
    columns[3].metric(
        "Actions", len(report.containment_actions), delta_color=score_color
    )

    st.subheader(report.title)
    source_label = (
        "Uploaded Evidence"
        if report.scenario_name == "uploaded_evidence"
        else "Demo Scenario"
    )
    st.caption(f"Source: {source_label}")
    st.write(report.executive_summary)


def _render_scenario_table() -> None:
    """Render the pre-built scenario reference table."""
    st.divider()
    st.subheader("Pre-Built Threat Scenarios")
    rows = [
        {"Scenario": name, "Description": description}
        for name, description in SCENARIOS.items()
    ]
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def _render_timeline(events: list[Any]) -> None:
    """Render event timeline and severity distribution."""
    st.divider()
    st.subheader("Threat Timeline")
    frame = pd.DataFrame(
        [
            {
                "Time": event.timestamp,
                "Kind": event.kind,
                "Actor": event.actor,
                "Asset": event.asset_id,
                "Severity": event.severity,
                "Message": event.message,
            }
            for event in events
        ]
    )
    chart = px.scatter(
        frame,
        x="Time",
        y="Kind",
        color="Severity",
        hover_data=["Actor", "Asset", "Message"],
        title="Event timeline by signal type",
    )
    st.plotly_chart(chart, width="stretch")
    st.dataframe(frame, width="stretch", hide_index=True)


def _render_agent_findings(report: Any) -> None:
    """Render agent findings and response recommendations."""
    st.divider()
    st.subheader("Agent Findings")

    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown("**Log Monitor Agent**")
        for finding in report.findings:
            st.write(f"- {finding}")

        st.markdown("**Threat Intelligence Agent**")
        for item in report.mitre_techniques:
            st.write(f"- {item.technique_id}: {item.name} ({item.tactic})")

    with col_right:
        st.markdown("**Vulnerability Scanner Agent**")
        for item in report.vulnerabilities:
            st.write(f"- {item.component}: {item.finding}")

        st.markdown("**Policy Checker Agent**")
        for gap in report.policy_gaps:
            st.write(f"- {gap.framework} {gap.control}: {gap.gap}")

    st.markdown("**Incident Response Agent**")
    for action in report.containment_actions:
        safe_label = "safe automation" if action.safe_to_automate else "approval needed"
        st.write(
            f"- {action.priority}: {action.action} " f"({action.owner}, {safe_label})"
        )


def _render_report(text_report: str) -> None:
    """Render the final SOC report."""
    st.divider()
    st.subheader("SOC Incident Report")
    st.code(text_report, language="text")


def _format_scenario_name(name: str) -> str:
    """Convert a scenario key to a readable label."""
    return name.replace("_", " ").title()


if __name__ == "__main__":
    main()
