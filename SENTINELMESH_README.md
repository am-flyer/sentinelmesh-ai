# SentinelMesh AI

SentinelMesh AI is a clean, runnable cybersecurity multi-agent demo. It shows how specialized agents can monitor logs, enrich findings with threat intelligence, scan vulnerable assets, check compliance posture, and generate incident-response playbooks.

The project is designed to work offline by default, so it is reliable for demos, interviews, and labs. Real NVD, Trivy, Bandit, SIEM, or LLM integrations can be added behind the same agent interfaces.

## What It Demonstrates

- Log Monitor Agent: detects brute force, SQL injection, RCE, exfiltration, and scanning patterns from system, network, and API logs.
- Threat Intelligence Agent: matches CVEs, IOCs, CISA KEV-like exploitation signals, and MITRE ATT&CK mappings from a local RAG-style knowledge base.
- Vulnerability Scanner Agent: scans code, dependency manifests, Dockerfiles, and API definitions for common security weaknesses.
- Policy Checker Agent: checks security configuration against NIST CSF, ISO 27001, and SOC 2 style controls.
- Incident Response Agent: creates a prioritized, step-by-step action plan with containment, eradication, recovery, owners, and evidence.
- Orchestrator: runs all agents together and produces a single SOC-ready assessment.

## Project Structure

```text
sentinelmesh-ai/
├── sentinelmesh_ai/
│   ├── agents/
│   │   ├── base.py
│   │   ├── incident_response.py
│   │   ├── log_monitor.py
│   │   ├── policy_checker.py
│   │   ├── threat_intel.py
│   │   └── vulnerability_scanner.py
│   ├── api/
│   │   └── app.py
│   ├── data/
│   │   └── samples.py
│   ├── knowledge/
│   │   ├── compliance_controls.py
│   │   └── threat_catalog.py
│   ├── cli.py
│   ├── models.py
│   └── orchestrator.py
├── tests/
├── pyproject.toml
└── README.md
```

## Quick Start

```bash
cd /Users/vijay.kumar.grandhi/Documents/outskill/sentinelmesh-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[api,test]"
python -m sentinelmesh_ai.cli --scenario brute_force
```

Run all tests:

```bash
pytest
```

Start the API:

```bash
uvicorn sentinelmesh_ai.api.app:app --reload
```

Then call:

```bash
curl http://127.0.0.1:8000/scenarios
curl -X POST http://127.0.0.1:8000/analyze/brute_force
```

## Available Scenarios

- `brute_force`: failed SSH logins followed by a successful admin login.
- `web_attack`: SQL injection and command execution indicators against an API.
- `container_risk`: insecure Dockerfile, leaked secret, vulnerable package, and weak config.
- `compliance_gap`: weak cloud and identity configuration mapped to audit controls.

## Why This Name

`SentinelMesh AI` fits the project because the system acts like a mesh of specialist sentinels: each agent watches one part of the environment, shares evidence, and contributes to one coordinated security decision.

## Extension Ideas

- Replace local CVE data with NVD API ingestion and cached vector retrieval.
- Add Bandit, Semgrep, Safety, Grype, or Trivy adapters to the scanner agent.
- Add a real SIEM connector for Splunk, Elastic, Wazuh, or CloudWatch logs.
- Add an LLM summarizer for executive reports while keeping deterministic findings as source-of-truth.
- Add a React SOC dashboard with agent timeline, risk score, compliance gauges, and action approvals.
