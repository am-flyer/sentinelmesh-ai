# Uploaded Evidence Analysis Design

## Goal

Extend SentinelMesh AI from scenario-only demo mode to production-leaning,
read-only security evidence analysis. Users can upload or paste logs in the
browser, normalize them into security events, and run the same agent pipeline.

## Scope

Version 2 accepts security evidence only:

- `.json` files containing one event object or a list of event objects.
- `.csv` files with event columns.
- `.txt` and `.log` files with plain log lines.
- Pasted browser text using the same plain-line parser.

Source code, Dockerfiles, IaC files, API specs, and dependency manifests are out
of scope for this slice. Those require a different scanner pipeline and risk
model.

## Safety Constraints

- Uploaded data is analyzed locally in memory.
- No uploaded file is written to disk.
- No real containment action is executed.
- Reports must label source as `Uploaded Evidence`.
- The app must preserve scenario mode as a fallback demo path.
- Parser failures must return user-readable validation errors.

## Architecture

Add an ingestion layer under `sentinelmesh/ingestion/` that converts browser
uploads or pasted text into the existing `ThreatScenario` model. The pipeline
gets a second public entry point, `run_evidence_pipeline`, that receives a
normalized `ThreatScenario` instead of a scenario key.

The UI adds an input mode selector:

- Demo scenario.
- Upload evidence.
- Paste evidence.

Uploaded or pasted evidence then flows through the existing analysis, scoring,
MITRE, policy, LLM enrichment, and report rendering paths.

## Supported Input Fields

Structured JSON/CSV records may include:

- `timestamp`
- `kind`
- `actor`
- `source_ip`
- `asset_id`
- `action`
- `outcome`
- `severity`
- `message`
- `indicators`

Missing fields use safe defaults. Plain text lines infer kind, action, severity,
and indicators from keywords.

## Done When

- Tests cover JSON, CSV, plain text parsing, and evidence pipeline reports.
- Streamlit supports browser upload and pasted text analysis.
- Reports identify uploaded evidence as the source.
- Existing five demo scenarios continue to work.
- Tests, compile, Black, and flake8 pass.
