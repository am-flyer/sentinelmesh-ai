# SentinelMesh AI Design

## Goal

Build a first-version hackathon demo of a cybersecurity AI agent system named
SentinelMesh AI under the hackathon workspace. The demo must show multiple
agents analyzing simulated security events, enriching findings with threat and
policy context, and producing an incident response report.

## Scope

Version 1 is a working local demo, not a production security platform. It uses
pre-built scenarios and deterministic detection logic so the demo remains stable.
OpenRouter is used when an API key is configured to improve the written incident
summary and remediation language. Without a key, the demo still runs with local
fallback summaries.

Production-leaning integrations are deferred to the roadmap: real log
collectors, CVE feeds, vulnerability scanners, container image scans, SIEM
exports, persistent evidence storage, and approval-gated containment actions.

## Name

Primary name: SentinelMesh AI.

The name signals a mesh of collaborating security agents watching identity,
network, API, endpoint, cloud, vulnerability, policy, and response signals.

## Architecture

The app is a Python Streamlit project with a small package named
`sentinelmesh`. It uses Pydantic models for security events and incident
reports, a scenario engine for deterministic sample data, LangGraph for the
agent pipeline shape, and LangChain/OpenRouter for optional LLM enrichment.

The v1 pipeline is:

1. Scenario engine generates events for a selected threat scenario.
2. Log Monitor Agent detects suspicious activity in auth, network, API,
   endpoint, and cloud events.
3. Threat Intelligence Agent maps indicators and behaviors to MITRE ATT&CK,
   reputation, and CVE-style context.
4. Vulnerability Scanner Agent reports simulated code, API, cloud, and image
   weaknesses relevant to the incident.
5. Policy Checker Agent maps gaps to NIST, ISO 27001, and SOC 2 controls.
6. Incident Response Agent creates containment steps, recovery actions, and a
   SOC incident report.
7. Streamlit presents scenarios, metrics, timeline, findings, controls, and the
   final report.

## Components

- `sentinelmesh/config.py`: environment loading and OpenRouter settings.
- `sentinelmesh/models/events.py`: event, alert, scenario, and asset models.
- `sentinelmesh/models/response.py`: response, control, and report models.
- `sentinelmesh/simulators/scenario_engine.py`: five pre-built scenarios.
- `sentinelmesh/tools/analysis.py`: deterministic detection and scoring helpers.
- `sentinelmesh/tools/llm.py`: OpenRouter client with safe fallback behavior.
- `sentinelmesh/agents/pipeline.py`: LangGraph-compatible pipeline orchestration.
- `streamlit_app.py`: local SOC console.
- `tests/`: behavior tests for scenario generation, analysis, and reports.

## Scenarios

The first build includes these scenarios:

- `brute_force_attack`: botnet brute force against admin accounts with lateral
  movement.
- `insider_threat`: privilege escalation, sensitive API access, and cloud data
  exfiltration.
- `api_key_compromise`: leaked production API key used from foreign IPs for mass
  extraction.
- `malware_lateral_movement`: phishing, beaconing, credential dumping, PsExec,
  and command-and-control traffic.
- `cloud_misconfiguration`: public storage and broad network exposure leading to
  sensitive data access.

## Constraints

- Python 3.11 or 3.12.
- Type hints on all functions.
- Concise docstrings for modules, classes, and functions.
- PEP 8 conventions.
- Streamlit UI with pandas and Plotly.
- Tests with pytest.
- Linting support with black and flake8.
- No real destructive containment actions in v1.
- OpenRouter key read from `OPENROUTER_API_KEY`; no key is committed.

## Done When

- The repo contains a runnable SentinelMesh AI Streamlit app.
- All five scenarios produce incident reports.
- The pipeline works without an OpenRouter key and enriches output when one is
  present.
- Tests cover scenario generation, scoring, and report generation.
- Documentation explains setup, environment variables, and the production
  roadmap.
