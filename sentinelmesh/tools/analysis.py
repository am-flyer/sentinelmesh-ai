"""Deterministic detection and enrichment helpers."""

from __future__ import annotations

from sentinelmesh.models.events import SecurityEvent, ThreatScenario
from sentinelmesh.models.response import (
    MitreTechnique,
    PolicyGap,
    ThreatScore,
    VulnerabilityFinding,
)

SEVERITY_WEIGHTS: dict[str, int] = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 45,
    "CRITICAL": 65,
}


def analyze_events(scenario: ThreatScenario) -> list[str]:
    """Create human-readable findings from scenario events."""
    findings = [_finding_for_event(event) for event in scenario.events]
    scenario_findings = {
        "brute_force_attack": [
            "Coordinated brute force activity led to privileged access.",
            "Successful login enabled lateral movement to user workstations.",
        ],
        "insider_threat": [
            "Privileged insider activity combined access escalation and export.",
            "Sensitive API data was staged to unsanctioned cloud storage.",
        ],
        "api_key_compromise": [
            "Production API key was used from an untrusted foreign IP address.",
            "Mass data extraction followed abnormal token use.",
        ],
        "malware_lateral_movement": [
            "Malware behavior included beaconing and credential dumping.",
            "PsExec-like lateral movement targeted a critical database host.",
        ],
        "cloud_misconfiguration": [
            "Cloud storage was exposed publicly.",
            "A broad network rule allowed external access to sensitive assets.",
        ],
    }
    return (
        _uploaded_evidence_findings(scenario)
        + scenario_findings.get(scenario.name, [])
        + findings
    )


def score_threat(scenario: ThreatScenario, findings: list[str]) -> ThreatScore:
    """Score scenario severity using event severity and finding volume."""
    raw_score = 20 + len(findings) * 4
    raw_score += max(SEVERITY_WEIGHTS[event.severity] for event in scenario.events)
    raw_score += _category_boost(scenario.category)
    value = min(100, raw_score)
    severity = _severity_label(value)

    return ThreatScore(
        value=value,
        severity=severity,
        rationale=(
            f"{scenario.title} scored {value}/100 from {len(scenario.events)} "
            f"events and {len(findings)} findings."
        ),
    )


def map_mitre_techniques(scenario: ThreatScenario) -> list[MitreTechnique]:
    """Map a scenario to MITRE ATT&CK techniques."""
    mappings = {
        "brute_force_attack": [
            ("T1110", "Brute Force", "Credential Access"),
            ("T1078", "Valid Accounts", "Defense Evasion"),
            ("T1021", "Remote Services", "Lateral Movement"),
        ],
        "insider_threat": [
            ("T1078", "Valid Accounts", "Defense Evasion"),
            ("T1136", "Create Account", "Persistence"),
            ("T1567", "Exfiltration Over Web Service", "Exfiltration"),
        ],
        "api_key_compromise": [
            ("T1552", "Unsecured Credentials", "Credential Access"),
            ("T1078", "Valid Accounts", "Defense Evasion"),
            ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        ],
        "malware_lateral_movement": [
            ("T1059", "Command and Scripting Interpreter", "Execution"),
            ("T1003", "OS Credential Dumping", "Credential Access"),
            ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        ],
        "cloud_misconfiguration": [
            ("T1530", "Data from Cloud Storage", "Collection"),
            ("T1611", "Escape to Host", "Privilege Escalation"),
            ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        ],
    }
    if scenario.name not in mappings:
        return _generic_mitre_mapping(scenario)

    return [
        MitreTechnique(technique_id=item[0], name=item[1], tactic=item[2])
        for item in mappings[scenario.name]
    ]


def find_vulnerabilities(scenario: ThreatScenario) -> list[VulnerabilityFinding]:
    """Return simulated vulnerabilities relevant to a scenario."""
    findings = {
        "brute_force_attack": [
            (
                "Identity provider",
                "CRITICAL",
                "Privileged account allowed repeated failed login attempts.",
                "Enable adaptive MFA, lockout, and bot protection.",
            ),
            (
                "Endpoint access",
                "HIGH",
                "Admin account had broad remote access rights.",
                "Restrict admin sessions through privileged access workstations.",
            ),
        ],
        "insider_threat": [
            (
                "IAM groups",
                "HIGH",
                "Contractor could self-escalate into data-admin access.",
                "Require approval workflows for privileged group changes.",
            )
        ],
        "api_key_compromise": [
            (
                "API credentials",
                "CRITICAL",
                "Production API key lacked origin and rate controls.",
                "Rotate key, enforce scoped tokens, and bind use to workloads.",
            )
        ],
        "malware_lateral_movement": [
            (
                "Endpoint controls",
                "CRITICAL",
                "Credential dumping and PsExec patterns were not blocked.",
                "Enable EDR prevention rules and disable legacy admin shares.",
            )
        ],
        "cloud_misconfiguration": [
            (
                "Cloud storage",
                "CRITICAL",
                "Sensitive bucket allowed public object reads.",
                "Block public access and apply least-privilege bucket policy.",
            )
        ],
    }
    if scenario.name not in findings:
        return [
            VulnerabilityFinding(
                component="Uploaded evidence source",
                severity=scenario.events[0].severity if scenario.events else "MEDIUM",
                finding="Uploaded logs indicate suspicious activity needing review.",
                fix="Validate source system controls and preserve original evidence.",
            )
        ]

    return [
        VulnerabilityFinding(
            component=item[0],
            severity=item[1],
            finding=item[2],
            fix=item[3],
        )
        for item in findings[scenario.name]
    ]


def recommend_policy_gaps(scenario: ThreatScenario) -> list[PolicyGap]:
    """Map scenario weaknesses to NIST, ISO, and SOC 2 controls."""
    common = [
        PolicyGap(
            framework="NIST CSF",
            control="DE.CM-1",
            gap="Monitoring detected the issue after risky activity occurred.",
            recommendation="Add preventive controls and higher-fidelity alerts.",
        ),
        PolicyGap(
            framework="SOC 2",
            control="CC7.2",
            gap="Response procedures need faster evidence collection.",
            recommendation="Automate incident timeline and escalation workflow.",
        ),
    ]
    scenario_gap = PolicyGap(
        framework="ISO 27001",
        control="A.8.15",
        gap=f"{scenario.category.title()} monitoring needs stronger coverage.",
        recommendation="Review control ownership and detection thresholds.",
    )
    return [scenario_gap] + common


def _uploaded_evidence_findings(scenario: ThreatScenario) -> list[str]:
    """Create uploaded-evidence-specific findings."""
    if scenario.name != "uploaded_evidence":
        return []
    return [
        "Browser-provided evidence was normalized and analyzed in read-only mode.",
        f"Uploaded evidence contains {len(scenario.events)} security event(s).",
    ]


def _generic_mitre_mapping(scenario: ThreatScenario) -> list[MitreTechnique]:
    """Infer MITRE mappings for uploaded evidence."""
    kinds = {event.kind for event in scenario.events}
    mappings: list[tuple[str, str, str]] = []
    if "auth" in kinds:
        mappings.append(("T1110", "Brute Force", "Credential Access"))
    if "api" in kinds:
        mappings.append(("T1552", "Unsecured Credentials", "Credential Access"))
    if "cloud" in kinds:
        mappings.append(("T1530", "Data from Cloud Storage", "Collection"))
    if "endpoint" in kinds:
        mappings.append(("T1003", "OS Credential Dumping", "Credential Access"))
    if not mappings:
        mappings.append(("T1041", "Exfiltration Over C2 Channel", "Exfiltration"))
    return [
        MitreTechnique(technique_id=item[0], name=item[1], tactic=item[2])
        for item in mappings
    ]


def build_timeline(scenario: ThreatScenario) -> list[str]:
    """Build a compact human-readable event timeline."""
    return [
        f"{event.timestamp.isoformat()} | {event.kind.upper()} | {event.message}"
        for event in scenario.events
    ]


def _finding_for_event(event: SecurityEvent) -> str:
    """Create a finding line from a single event."""
    return (
        f"{event.kind.title()} event on {event.asset_id}: {event.action} "
        f"{event.outcome} from {event.source_ip}. {event.message}"
    )


def _category_boost(category: str) -> int:
    """Return category-specific scoring boost."""
    boosts = {
        "identity": 8,
        "insider": 10,
        "api": 12,
        "malware": 14,
        "cloud": 11,
    }
    return boosts.get(category, 5)


def _severity_label(score: int) -> str:
    """Convert a numeric score to a severity label."""
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
