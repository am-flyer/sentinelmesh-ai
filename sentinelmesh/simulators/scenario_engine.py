"""Deterministic pre-built threat scenarios for the hackathon demo."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinelmesh.models.events import AssetInfo, SecurityEvent, ThreatScenario

SCENARIOS: dict[str, str] = {
    "brute_force_attack": (
        "Brute force against admin accounts from botnet IPs, account "
        "compromise, lateral movement"
    ),
    "insider_threat": (
        "Employee escalates privileges, accesses sensitive APIs, exfiltrates "
        "data via cloud storage"
    ),
    "api_key_compromise": (
        "Leaked production API key used from foreign IP for mass data " "extraction"
    ),
    "malware_lateral_movement": (
        "Phishing leads to beaconing, credential dumping, PsExec lateral "
        "movement, and C2 traffic"
    ),
    "cloud_misconfiguration": (
        "Storage bucket made public and security group opened to 0.0.0.0/0"
    ),
}


def _event(
    index: int,
    kind: str,
    actor: str,
    source_ip: str,
    asset_id: str,
    action: str,
    outcome: str,
    severity: str,
    message: str,
    indicators: list[str] | None = None,
    metadata: dict[str, str] | None = None,
) -> SecurityEvent:
    """Create a timestamped event with stable IDs."""
    base_time = datetime(2026, 6, 13, 10, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        event_id=f"evt-{index:03d}",
        timestamp=base_time + timedelta(minutes=index * 3),
        kind=kind,
        actor=actor,
        source_ip=source_ip,
        asset_id=asset_id,
        action=action,
        outcome=outcome,
        severity=severity,
        message=message,
        indicators=indicators or [],
        metadata=metadata or {},
    )


def _base_assets() -> list[AssetInfo]:
    """Return shared demo assets."""
    return [
        AssetInfo(
            asset_id="iam-prod",
            name="Production IAM",
            asset_type="identity",
            owner="Identity Team",
            criticality="CRITICAL",
        ),
        AssetInfo(
            asset_id="api-prod",
            name="Customer API",
            asset_type="api",
            owner="Platform Team",
            criticality="CRITICAL",
        ),
        AssetInfo(
            asset_id="db-prod",
            name="Customer Database",
            asset_type="database",
            owner="Data Team",
            criticality="CRITICAL",
        ),
        AssetInfo(
            asset_id="s3-sensitive",
            name="Sensitive Data Bucket",
            asset_type="cloud_storage",
            owner="Cloud Team",
            criticality="HIGH",
        ),
        AssetInfo(
            asset_id="workstation-77",
            name="Finance Workstation",
            asset_type="endpoint",
            owner="IT Operations",
            criticality="HIGH",
        ),
    ]


def build_scenario(name: str) -> ThreatScenario:
    """Build a named deterministic threat scenario."""
    builders = {
        "brute_force_attack": _brute_force_attack,
        "insider_threat": _insider_threat,
        "api_key_compromise": _api_key_compromise,
        "malware_lateral_movement": _malware_lateral_movement,
        "cloud_misconfiguration": _cloud_misconfiguration,
    }
    try:
        return builders[name]()
    except KeyError as exc:
        valid = ", ".join(sorted(builders))
        raise ValueError(
            f"Unknown scenario '{name}'. Valid scenarios: {valid}"
        ) from exc


def _brute_force_attack() -> ThreatScenario:
    """Build the brute force attack scenario."""
    events = [
        _event(
            1,
            "auth",
            "admin",
            "185.220.101.34",
            "iam-prod",
            "login",
            "failed",
            "HIGH",
            "Botnet IP generated repeated failed admin login attempts.",
            ["185.220.101.34"],
            {"attempts": "48"},
        ),
        _event(
            2,
            "auth",
            "admin",
            "185.220.101.34",
            "iam-prod",
            "login",
            "success",
            "CRITICAL",
            "Admin login succeeded from known malicious IP.",
            ["185.220.101.34", "admin"],
        ),
        _event(
            3,
            "endpoint",
            "admin",
            "10.0.8.15",
            "workstation-77",
            "remote_session",
            "success",
            "CRITICAL",
            "Admin opened remote sessions to jsmith and mchen endpoints.",
            ["jsmith", "mchen"],
        ),
    ]
    return ThreatScenario(
        name="brute_force_attack",
        title="Brute Force Compromise of 'admin' with Lateral Movement",
        description=SCENARIOS["brute_force_attack"],
        category="identity",
        assets=_base_assets(),
        events=events,
    )


def _insider_threat() -> ThreatScenario:
    """Build the insider threat scenario."""
    events = [
        _event(
            1,
            "auth",
            "alex.contractor",
            "10.0.4.22",
            "iam-prod",
            "privilege_escalation",
            "success",
            "HIGH",
            "Contractor added self to privileged data-admin group.",
            ["alex.contractor"],
        ),
        _event(
            2,
            "api",
            "alex.contractor",
            "10.0.4.22",
            "api-prod",
            "bulk_export",
            "success",
            "CRITICAL",
            "Sensitive customer records exported through internal API.",
            ["customer-records"],
            {"records": "24000"},
        ),
        _event(
            3,
            "cloud",
            "alex.contractor",
            "10.0.4.22",
            "s3-sensitive",
            "object_upload",
            "success",
            "HIGH",
            "Export archive uploaded to unsanctioned cloud storage path.",
            ["s3://external-dropbox"],
        ),
    ]
    return ThreatScenario(
        name="insider_threat",
        title="Privileged Insider Data Exfiltration",
        description=SCENARIOS["insider_threat"],
        category="insider",
        assets=_base_assets(),
        events=events,
    )


def _api_key_compromise() -> ThreatScenario:
    """Build the API key compromise scenario."""
    events = [
        _event(
            1,
            "api",
            "prod-api-key",
            "45.83.64.12",
            "api-prod",
            "token_use",
            "success",
            "HIGH",
            "Production API key used from never-seen foreign IP.",
            ["45.83.64.12", "prod-api-key"],
        ),
        _event(
            2,
            "api",
            "prod-api-key",
            "45.83.64.12",
            "api-prod",
            "bulk_read",
            "success",
            "CRITICAL",
            "API key performed high-volume customer data extraction.",
            ["customer-data"],
            {"requests": "18800"},
        ),
        _event(
            3,
            "network",
            "prod-api-key",
            "45.83.64.12",
            "db-prod",
            "egress",
            "success",
            "HIGH",
            "Unusual outbound data volume observed after API activity.",
            ["45.83.64.12"],
        ),
    ]
    return ThreatScenario(
        name="api_key_compromise",
        title="API Key Compromise with Mass Data Extraction",
        description=SCENARIOS["api_key_compromise"],
        category="api",
        assets=_base_assets(),
        events=events,
    )


def _malware_lateral_movement() -> ThreatScenario:
    """Build the malware lateral movement scenario."""
    events = [
        _event(
            1,
            "endpoint",
            "mchen",
            "10.0.9.44",
            "workstation-77",
            "process_start",
            "success",
            "HIGH",
            "Suspicious beacon process spawned after phishing email.",
            ["beacon.exe"],
        ),
        _event(
            2,
            "endpoint",
            "mchen",
            "10.0.9.44",
            "workstation-77",
            "credential_dump",
            "success",
            "CRITICAL",
            "Mimikatz-like credential dumping behavior detected.",
            ["mimikatz"],
        ),
        _event(
            3,
            "network",
            "mchen",
            "198.51.100.44",
            "workstation-77",
            "c2_beacon",
            "success",
            "CRITICAL",
            "Periodic command-and-control beaconing detected.",
            ["198.51.100.44"],
        ),
        _event(
            4,
            "endpoint",
            "mchen",
            "10.0.9.44",
            "db-prod",
            "psexec_lateral_movement",
            "success",
            "CRITICAL",
            "PsExec-style lateral movement attempted against database host.",
            ["psexec"],
        ),
    ]
    return ThreatScenario(
        name="malware_lateral_movement",
        title="Malware Beacon with Credential Dumping and Lateral Movement",
        description=SCENARIOS["malware_lateral_movement"],
        category="malware",
        assets=_base_assets(),
        events=events,
    )


def _cloud_misconfiguration() -> ThreatScenario:
    """Build the cloud misconfiguration scenario."""
    events = [
        _event(
            1,
            "cloud",
            "cloud-admin",
            "10.0.2.9",
            "s3-sensitive",
            "bucket_policy_change",
            "success",
            "HIGH",
            "Sensitive storage bucket policy changed to public read.",
            ["public-read"],
        ),
        _event(
            2,
            "cloud",
            "cloud-admin",
            "10.0.2.9",
            "api-prod",
            "security_group_change",
            "success",
            "HIGH",
            "Security group opened administrative port to 0.0.0.0/0.",
            ["0.0.0.0/0"],
        ),
        _event(
            3,
            "network",
            "unknown",
            "203.0.113.77",
            "s3-sensitive",
            "public_object_read",
            "success",
            "CRITICAL",
            "External actor accessed sensitive objects from public bucket.",
            ["203.0.113.77"],
        ),
    ]
    return ThreatScenario(
        name="cloud_misconfiguration",
        title="Public Cloud Exposure of Sensitive Data",
        description=SCENARIOS["cloud_misconfiguration"],
        category="cloud",
        assets=_base_assets(),
        events=events,
    )
