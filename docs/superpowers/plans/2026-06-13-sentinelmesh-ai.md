# SentinelMesh AI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable Streamlit hackathon demo for SentinelMesh AI with simulated cybersecurity events, agent orchestration, optional OpenRouter enrichment, and tests.

**Architecture:** Create a focused Python package named `sentinelmesh`. Keep detection deterministic and local, then layer optional LLM enrichment through OpenRouter so the demo remains reliable.

**Tech Stack:** Python 3.11/3.12, Pydantic, LangGraph, LangChain/OpenRouter, Streamlit, pandas, Plotly, pytest, black, flake8.

---

## File Structure

- `README.md`: setup, run commands, scenario list, environment variables, roadmap.
- `.env.example`: OpenRouter settings without secrets.
- `requirements.txt`: requested runtime, UI, RAG, test, and lint packages.
- `pyproject.toml`: black, pytest, and package configuration.
- `.flake8`: lint configuration.
- `streamlit_app.py`: Streamlit SOC console.
- `sentinelmesh/config.py`: settings loader.
- `sentinelmesh/models/events.py`: event, scenario, alert, and asset models.
- `sentinelmesh/models/response.py`: response action, policy gap, and report models.
- `sentinelmesh/simulators/scenario_engine.py`: five deterministic scenarios.
- `sentinelmesh/tools/analysis.py`: detection, scoring, MITRE, vulnerability, and policy helpers.
- `sentinelmesh/tools/llm.py`: OpenRouter client and fallback text generator.
- `sentinelmesh/agents/pipeline.py`: LangGraph pipeline and report orchestration.
- `tests/test_scenarios.py`: scenario behavior tests.
- `tests/test_analysis.py`: scoring and finding tests.
- `tests/test_pipeline.py`: end-to-end report tests.

### Task 1: Project Skeleton and Tests

**Files:**
- Create: `tests/test_scenarios.py`
- Create: `tests/test_analysis.py`
- Create: `tests/test_pipeline.py`
- Create: package directories and `__init__.py` files

- [ ] **Step 1: Write failing tests**

```python
from sentinelmesh.simulators.scenario_engine import (
    SCENARIOS,
    build_scenario,
)


def test_all_five_scenarios_are_available() -> None:
    assert set(SCENARIOS) == {
        "brute_force_attack",
        "insider_threat",
        "api_key_compromise",
        "malware_lateral_movement",
        "cloud_misconfiguration",
    }


def test_build_scenario_contains_events_and_assets() -> None:
    scenario = build_scenario("brute_force_attack")

    assert scenario.name == "brute_force_attack"
    assert scenario.events
    assert scenario.assets
```

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_scenarios.py -v`
Expected: fail because `sentinelmesh` does not exist.

### Task 2: Models and Scenario Engine

**Files:**
- Create: `sentinelmesh/models/events.py`
- Create: `sentinelmesh/models/response.py`
- Create: `sentinelmesh/simulators/scenario_engine.py`

- [ ] **Step 1: Implement Pydantic models and five scenarios**
- [ ] **Step 2: Run scenario tests and verify pass**

Run: `pytest tests/test_scenarios.py -v`
Expected: pass.

### Task 3: Analysis Helpers

**Files:**
- Create: `sentinelmesh/tools/analysis.py`
- Test: `tests/test_analysis.py`

- [ ] **Step 1: Add tests for severity, findings, MITRE, and policy gaps**
- [ ] **Step 2: Verify tests fail before implementation**
- [ ] **Step 3: Implement deterministic analysis helpers**
- [ ] **Step 4: Verify tests pass**

### Task 4: Agent Pipeline and OpenRouter Fallback

**Files:**
- Create: `sentinelmesh/config.py`
- Create: `sentinelmesh/tools/llm.py`
- Create: `sentinelmesh/agents/pipeline.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Add end-to-end report tests**
- [ ] **Step 2: Verify tests fail before implementation**
- [ ] **Step 3: Implement pipeline with optional LangGraph usage**
- [ ] **Step 4: Verify tests pass**

### Task 5: Streamlit App and Docs

**Files:**
- Create: `streamlit_app.py`
- Create: `README.md`
- Create: `.env.example`
- Create: `requirements.txt`
- Create: `pyproject.toml`
- Create: `.flake8`

- [ ] **Step 1: Implement SOC console**
- [ ] **Step 2: Document setup and usage**
- [ ] **Step 3: Run full verification**

Run: `pytest -v`
Run: `python -m compileall sentinelmesh streamlit_app.py`
Run: `black --check .`
Run: `flake8 .`
