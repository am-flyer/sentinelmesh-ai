# Gradio Visual Integration Analysis for CyberSecurity Multi-Agent System

## Overview

This document analyzes the **Gradio** web UI integration for `main.py`, providing users with an interactive visual interface to run security analyses and view agent results.

---

## Current Entry Points (from `main.py`)

| Entry Point | Description |
|---|---|
| `run_analysis(user_input, save_report=True)` | Main function — accepts text, returns full `CyberAgentState` dict |
| `check_vector_store_exists()` | Pre-check if ChromaDB has data — avoids unnecessary initialization |
| `EXAMPLE_INPUTS` dict | 4 built-in scenarios: `ssh_brute_force`, `vulnerable_code`, `docker_misconfig`, `policy_audit` |
| CLI `__main__` | Runs a named scenario from sys.argv |

The `run_analysis` function returns a dict containing:
- `input_type` — classified type (log/code/config/policy)
- `log_findings` — dict with severity, findings, IoCs
- `threat_intel` — dict with CVEs, MITRE TTPs, threat actors
- `vuln_scan` — dict with risk_score, vulnerabilities list
- `incident_plan` — dict with priority, timeline, containment steps
- `policy_gaps` — dict with framework scores, gaps, quick wins
- `final_report` — full text report string
- `agent_trace` — execution log list

---

## Vector Store Persistence Check

Before any heavy initialization, the system calls `check_vector_store_exists()`:

```python
def check_vector_store_exists() -> bool:
    """Check if ChromaDB persistent vector store already exists with data."""
    if not os.path.exists(Config.CHROMA_PERSIST_DIR):
        return False
    client = chromadb.PersistentClient(path=Config.CHROMA_PERSIST_DIR)
    collection = client.get_or_create_collection(name=Config.CHROMA_COLLECTION)
    return collection.count() > 0
```

**Behavior:**
- If `data/chroma_cybersec_db/` exists and has vectors → loads existing index (no re-indexing)
- If not → indexes the `CYBERSEC_KNOWLEDGE_BASE` documents into ChromaDB (first run only)
- `VectorKnowledgeBase.loaded_existing` flag tracks which path was taken

---

## Gradio UI Layout

### Tab-Based Interface with Status Panel

```
┌─────────────────────────────────────────────────────────────────────────┐
│  🛡️ CyberSecurity Multi-Agent Analyzer                                  │
├───────────────────────────────────────────┬─────────────────────────────┤
│ [Scenario Dropdown] [🚀 Run] [🔍 Status] │  🟢 System Status           │
│                                           │  ✅ OpenRouter LLM          │
│ [Input Textbox]                           │  ✅ HuggingFace Embeddings  │
│                                           │  ✅ ChromaDB Vector Store    │
│                                           │  ✅ LangGraph Pipeline      │
├───────────────────────────────────────────┴─────────────────────────────┤
│ [Report] [Log Findings] [Threat Intel] [Vulns] [Compliance] [Trace]     │
├─────────────────────────────────────────────────────────────────────────┤
│  Tab content area                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Status Indicators

The right panel shows green ✅ checkboxes after initialization:

| State | Display |
|---|---|
| Not yet initialized | ⏳ Pipeline not yet initialized |
| Vector store found on disk | ✅ + "loaded from existing persistent data" |
| Freshly indexed | ✅ + "freshly initialized (knowledge base indexed)" |
| Component ready | ✅ Component Name |
| Component pending | ⬜ Component Name |

---

## Integration Architecture

```
┌──────────────┐       ┌───────────────────────┐       ┌──────────────────┐
│  Gradio UI   │──────▶│  main   │──────▶│  LangGraph       │
│  (Browser)   │◀──────│  (pipeline singleton)  │◀──────│  Pipeline        │
└──────────────┘       └───────────────────────┘       └──────────────────┘
                                     │
                              ┌──────┴──────┐
                              │  @tool utils  │
                              │ query_kb      │
                              │ lookup_cve    │
                              │ check_control │
                              └─────────────┘
```

### Hybrid Architecture: Nodes + Tools

The pipeline uses **deterministic node-based flow** (LangGraph edges define execution order),
but agent nodes internally call **@tool utilities** for enriched analysis:

| Tool | Used By | Purpose |
|------|---------|--------|
| `@tool query_knowledge_base` | RAG Retriever | Search ChromaDB for relevant context |
| `@tool lookup_cve` | Threat Intel Agent | Enrich with CVE-specific knowledge |
| `@tool check_compliance_control` | Policy Checker Agent | Lookup specific framework controls |

This hybrid gives you:
- Deterministic, predictable pipeline flow (no missed agents)
- Richer context via tool calls inside nodes
- Proper `@tool` annotations for LangGraph/LangChain compatibility

### Startup Flow

```
1. User opens Gradio UI
2. check_vector_store_exists() → shows pre-check status
3. User clicks "Run Analysis"
4. get_pipeline() called (singleton):
   a. check_vector_store_exists() → determines if re-indexing needed
   b. build_llm() → connect to OpenRouter
   c. build_embeddings() → load HuggingFace model
   d. VectorKnowledgeBase() → load or index ChromaDB
   e. build_cybersec_graph() → compile LangGraph
5. Status panel updates with all ✅ green checkboxes
6. Analysis runs, results populate tabs
```

---

## Key Implementation Details

### Singleton Pipeline (avoids re-init per request)

```python
_graph = None
_kb = None
_init_status = {}

def get_pipeline():
    global _graph, _kb, _init_status
    if _graph is None:
        store_exists = check_vector_store_exists()
        _init_status["vector_store_preexisted"] = store_exists
        # ... initialize once ...
    return _graph
```

### .env for Credentials

```
OPENROUTER_API_KEY=<your_key_here>
GRADIO_USER=admin
GRADIO_PASSWORD=CyberSec@2026!
LANGSMITH_API_KEY=<your_langsmith_key_here>
LANGSMITH_PROJECT=cybersec-multi-agent
LANGSMITH_TRACING=true
LANGSMITH_ENDPOINT=https://api.smith.langchain.com
```

Loaded via `python-dotenv` at module import time — no hardcoded keys in source.

### LangSmith Observability

When `LANGSMITH_TRACING=true` is set in .env, the system auto-traces:

| What | Visibility |
|------|------------|
| Every `ChatOpenAI.invoke()` | Prompt, response, tokens, latency |
| `@tool` calls (lookup_cve, check_compliance_control) | Tool name, input, output, duration |
| LangGraph node transitions | State flow, conditional edge decisions |
| Full pipeline runs | End-to-end trace per analysis request |

To disable: set `LANGSMITH_TRACING=false` — no code changes needed.

### Security Layers

| Layer | Implementation |
|-------|---------------|
| Authentication | `demo.launch(auth=authenticate)` — credentials from .env |
| Rate Limiting | 30s cooldown between requests per session |
| Input Validation | Max 10,000 chars — rejects oversized prompts |
| Network Binding | `server_name="127.0.0.1"` — localhost only |
| Concurrency | `max_threads=2` — prevents resource exhaustion |
| Share Disabled | `share=False` — no public Gradio links |

---

## Gradio Components Used

| Component | Purpose |
|---|---|
| `gr.Textbox` | Input area for logs/code/config/policy |
| `gr.Dropdown` | Select built-in example scenarios |
| `gr.Button` | Trigger analysis / check status |
| `gr.Markdown` | Render final report + status panel with ✅ checkboxes |
| `gr.JSON` | Display structured agent outputs |
| `gr.Textbox` (readonly) | Agent execution trace |
| `gr.Tab` | Organize output sections |
| `gr.Row` / `gr.Column` | Layout with status sidebar |

---

## Dependency

Added to `requirements.txt`:
```
gradio>=4.0.0
```

---

## Summary

| Aspect | Approach |
|---|---|
| Wrapper | Gradio Blocks wrapping singleton pipeline from `main.py` |
| Layout | Tabbed output + status sidebar with green ✅ checkboxes |
| Persistence | `check_vector_store_exists()` before init; skip re-indexing if data exists |
| Secrets | API keys in `.env`, loaded via python-dotenv |
| Status | Real-time ✅/⬜ indicators for LLM, Embeddings, Vector Store, Graph |
| Performance | Singleton initialization, fast subsequent requests |
| Deployment | `python api/gradio_app.py` → launches local browser UI |
