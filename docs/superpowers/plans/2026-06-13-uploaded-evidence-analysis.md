# Uploaded Evidence Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only uploaded and pasted security evidence analysis to SentinelMesh AI.

**Architecture:** Introduce an ingestion module that normalizes JSON, CSV, text, and log content into `ThreatScenario`. Reuse the existing pipeline through a new `run_evidence_pipeline` entry point and update Streamlit with input modes.

**Tech Stack:** Python 3.12, Pydantic, Streamlit, pandas, pytest, black, flake8.

---

## Task 1: Evidence Parser Tests

**Files:**
- Create: `tests/test_ingestion.py`
- Create: `sentinelmesh/ingestion/evidence_parser.py`

- [ ] Write tests for JSON list parsing, CSV parsing, plain text parsing, and empty input validation.
- [ ] Run tests and verify they fail because ingestion does not exist.
- [ ] Implement parser functions with type hints and docstrings.
- [ ] Run parser tests and verify pass.

## Task 2: Evidence Pipeline Tests

**Files:**
- Modify: `tests/test_pipeline.py`
- Modify: `sentinelmesh/agents/pipeline.py`

- [ ] Write tests for `run_evidence_pipeline`.
- [ ] Run tests and verify they fail because the entry point does not exist.
- [ ] Implement `run_evidence_pipeline`.
- [ ] Run pipeline tests and verify pass.

## Task 3: Streamlit Input Modes

**Files:**
- Modify: `streamlit_app.py`

- [ ] Add sidebar input mode selector.
- [ ] Add file uploader for `.json`, `.csv`, `.txt`, and `.log`.
- [ ] Add pasted text area mode.
- [ ] Render validation errors without crashing.
- [ ] Preserve demo scenario mode.

## Task 4: Documentation and Verification

**Files:**
- Modify: `README.md`

- [ ] Document upload and paste modes.
- [ ] Run `pytest -v`.
- [ ] Run `python -m compileall sentinelmesh main.py streamlit_app.py`.
- [ ] Run `black --check .`.
- [ ] Run `flake8 .`.
