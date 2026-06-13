"""Pydantic models for analysis results and incident response reports."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatScore(BaseModel):
    """Represent a normalized threat score."""

    value: int
    severity: str
    rationale: str


class MitreTechnique(BaseModel):
    """Represent a MITRE ATT&CK mapping."""

    technique_id: str
    name: str
    tactic: str


class PolicyGap(BaseModel):
    """Represent a compliance or control gap."""

    framework: str
    control: str
    gap: str
    recommendation: str


class VulnerabilityFinding(BaseModel):
    """Represent a simulated vulnerability or weakness."""

    component: str
    severity: str
    finding: str
    fix: str


class ContainmentAction(BaseModel):
    """Represent a safe response action for operators."""

    action: str
    owner: str
    priority: str
    safe_to_automate: bool = False


class SOCIncidentReport(BaseModel):
    """Represent the final incident response report."""

    title: str
    scenario_name: str
    status: str
    executive_summary: str
    threat_score: ThreatScore
    findings: list[str] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    policy_gaps: list[PolicyGap] = Field(default_factory=list)
    containment_actions: list[ContainmentAction] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)

    def to_text(self) -> str:
        """Render a plain-text SOC report."""
        mitre = ", ".join(
            f"{item.technique_id} ({item.name})" for item in self.mitre_techniques
        )
        actions = "\n".join(
            f"{index}) {item.action} [{item.owner}]"
            for index, item in enumerate(self.containment_actions, start=1)
        )
        findings = "\n".join(f"- {finding}" for finding in self.findings)
        vulnerabilities = "\n".join(
            f"- {item.component}: {item.finding} Fix: {item.fix}"
            for item in self.vulnerabilities
        )
        policy_gaps = "\n".join(
            f"- {item.framework} {item.control}: {item.gap}"
            for item in self.policy_gaps
        )

        return (
            "============================================================\n"
            "SOC INCIDENT REPORT\n"
            "============================================================\n\n"
            f"TITLE: {self.title}\n"
            f"SEVERITY: {self.threat_score.severity}\n"
            f"THREAT SCORE: {self.threat_score.value}/100\n"
            f"STATUS: {self.status}\n\n"
            "EXECUTIVE SUMMARY\n"
            f"{self.executive_summary}\n\n"
            "KEY FINDINGS\n"
            f"{findings}\n\n"
            "MITRE ATT&CK MAPPING\n"
            f"{mitre}\n\n"
            "VULNERABILITY CONTEXT\n"
            f"{vulnerabilities}\n\n"
            "POLICY GAPS\n"
            f"{policy_gaps}\n\n"
            "CONTAINMENT ACTIONS\n"
            f"{actions}\n"
            "============================================================\n"
            "END OF REPORT\n"
            "============================================================"
        )
