import gradio as gr
from cybersecurityAgents import (
    run_analysis,
    EXAMPLE_INPUTS,
    build_llm,
    build_embeddings,
    build_cybersec_graph,
    VectorKnowledgeBase,
    CyberAgentState,
    Config,
    check_vector_store_exists,
)
from datetime import datetime
import json
import time
import os
from dotenv import load_dotenv

load_dotenv("cs.env")

# ── Security Configuration ─────────────────────────────────────────────
GRADIO_USER = os.getenv("GRADIO_USER", "admin")
GRADIO_PASSWORD = os.getenv("GRADIO_PASSWORD", "CyberSec@2026!")
MAX_INPUT_LENGTH = 10000
REQUEST_COOLDOWN_SECONDS = 30
MAX_CONCURRENT_THREADS = 2

_last_request_time: float = 0.0

# ── Singleton pipeline ─────────────────────────────────────────────────
_graph = None
_kb = None
_init_status = {}


def get_pipeline():
    global _graph, _kb, _init_status
    if _graph is None:
        store_exists = check_vector_store_exists()
        _init_status["vector_store_preexisted"] = store_exists

        llm = build_llm()
        _init_status["llm"] = True

        embeddings = build_embeddings()
        _init_status["embeddings"] = True

        _kb = VectorKnowledgeBase(embeddings)
        _init_status["vector_store"] = True
        _init_status["vector_store_loaded_existing"] = _kb.loaded_existing

        _graph = build_cybersec_graph(llm, _kb)
        _init_status["graph"] = True

    return _graph


def get_status_markdown():
    if not _init_status:
        return (
            "### ⏳ Not Initialized\n\n"
            "Click **Run Analysis** to initialize.\n\n"
            "---\n"
            "#### Components\n"
            "- ⬜ OpenRouter LLM\n"
            "- ⬜ HuggingFace Embeddings\n"
            "- ⬜ ChromaDB Vector Store\n"
            "- ⬜ LangGraph Pipeline"
        )

    lines = ["### 🟢 Initialized\n"]
    checks = [
        ("llm", "OpenRouter LLM"),
        ("embeddings", "HuggingFace Embeddings"),
        ("vector_store", "ChromaDB Vector Store"),
        ("graph", "LangGraph Pipeline"),
    ]
    for key, label in checks:
        if _init_status.get(key):
            lines.append(f"- ✅ {label}")
        else:
            lines.append(f"- ⬜ {label}")

    lines.append("\n---")
    if _init_status.get("vector_store_loaded_existing"):
        lines.append("📂 **Loaded from disk**\n(no re-indexing)")
    elif _init_status.get("vector_store"):
        lines.append("🆕 **Freshly indexed**\n(knowledge base built)")

    lines.append(f"\n---\n**Model:** `{Config.LLM_MODEL}`")
    lines.append(f"\n**Embeddings:** `{Config.EMBEDDING_MODEL.split('/')[-1]}`")
    lines.append(f"\n**Vector DB:** `{Config.CHROMA_PERSIST_DIR}`")

    return "\n".join(lines)


LANGGRAPH_PIPELINE_MD = """### 🔗 LangGraph Pipeline

```
START
  │
  ▼
🏷️ classify_input
  │
  ▼
📚 rag_retrieve
  │
  ▼
📡 log_monitor
  │
  ▼
🕵️ threat_intel
  │
  ▼
🔍 vuln_scanner
  │
  ▼
🔧 code_fixer ◄──┐
  │    (loop max 3x)
  │ fixed?         │
  ├── No ──────────┘
  ▼ Yes
🚨 incident_response
  │
  ▼
📋 policy_checker
  │
  ▼
📝 synthesize_report
  │
  ▼
 END
```

---

### 🤖 Agents

| # | Agent | Role |
|---|-------|------|
| 1 | Log Monitor | Detect attacks in logs |
| 2 | Threat Intel | CVE & MITRE mapping |
| 3 | Vuln Scanner | OWASP/CWE scan |
| 4 | Code Fixer | Iterative bug fix |
| 5 | Incident Response | NIST 800-61 plan |
| 6 | Policy Checker | ISO/NIST/SOC2 gaps |
"""


SCENARIO_MAP = {
    "Log Monitor Agent": "ssh_brute_force",
    "Threat Intelligence Agent": "ssh_brute_force",
    "Vulnerability Scanner Agent": "vulnerable_code",
    "Code Fixer Agent": "vulnerable_code",
    "Incident Response Agent": "docker_misconfig",
    "Policy Checker Agent": "policy_audit",
}

SCENARIO_DESCRIPTIONS = {
    "custom": "> **Paste your own logs, code, config, or policy text below.**",
    "Log Monitor Agent": "> **Reads system and network logs to detect unusual activity or attacks.**",
    "Threat Intelligence Agent": "> **Looks up known security threats (CVE data, reports) and checks if your system is affected.**",
    "Vulnerability Scanner Agent": "> **Scans code, APIs, or Docker images to find security weaknesses.**",
    "Code Fixer Agent": "> **Iteratively fixes security vulnerabilities and bugs in your code (up to 3 passes).**",
    "Incident Response Agent": "> **Creates step-by-step action plans when an issue is found.**",
    "Policy Checker Agent": "> **Checks your setup against standards like ISO, NIST, or SOC2 and shows where you need fixes.**",
}


def authenticate(username, password):
    """Validate login credentials against cs.env values."""
    return username == GRADIO_USER and password == GRADIO_PASSWORD


def analyze(text, scenario):
    global _last_request_time

    # Rate limiting: enforce cooldown between requests
    now = time.time()
    elapsed_since_last = now - _last_request_time
    if elapsed_since_last < REQUEST_COOLDOWN_SECONDS and _last_request_time > 0:
        wait = int(REQUEST_COOLDOWN_SECONDS - elapsed_since_last)
        return f"⏳ Rate limited. Please wait {wait}s before next request.", {}, {}, {}, {}, {}, "", get_status_markdown(), ""
    _last_request_time = now

    # Input validation: enforce max length
    input_text = text
    if not input_text or not input_text.strip():
        return "⚠️ Please provide input or select a scenario.", {}, {}, {}, {}, {}, "", get_status_markdown(), ""
    if len(input_text) > MAX_INPUT_LENGTH:
        return f"❌ Input too long ({len(input_text)} chars). Maximum is {MAX_INPUT_LENGTH} characters.", {}, {}, {}, {}, {}, "", get_status_markdown(), ""

    try:
        app = get_pipeline()
    except Exception as e:
        return f"❌ Pipeline initialization failed: {e}", {}, {}, {}, {}, {}, "", get_status_markdown(), ""

    initial_state: CyberAgentState = {
        "raw_input": input_text,
        "input_type": "general",
        "log_findings": None,
        "threat_intel": None,
        "vuln_scan": None,
        "code_fix": None,
        "incident_plan": None,
        "policy_gaps": None,
        "agent_trace": [],
        "errors": [],
        "rag_context": None,
        "final_report": None,
        "started_at": datetime.now().isoformat(),
    }

    t0 = time.time()
    state = app.invoke(initial_state)
    elapsed = time.time() - t0

    report = state.get("final_report", "No report generated.")
    report += f"\n\n⏱ Analysis completed in {elapsed:.1f}s"

    # Extract fixed code for display
    code_fix = state.get("code_fix") or {}
    fixed_code = code_fix.get("fixed_code", "")
    if not fixed_code or code_fix.get("skipped"):
        fixed_code = "# No code fix generated (input was not code or code fixer was skipped)"

    return (
        report,
        state.get("log_findings") or {},
        state.get("threat_intel") or {},
        state.get("vuln_scan") or {},
        code_fix,
        state.get("policy_gaps") or {},
        "\n".join(state.get("agent_trace", [])),
        get_status_markdown(),
        fixed_code,
    )


def load_scenario(scenario):
    if scenario == "custom":
        return "", SCENARIO_DESCRIPTIONS["custom"]
    key = SCENARIO_MAP.get(scenario, "ssh_brute_force")
    return EXAMPLE_INPUTS.get(key, ""), SCENARIO_DESCRIPTIONS.get(scenario, "")


def check_init_status():
    store_exists = check_vector_store_exists()
    if store_exists:
        return get_status_markdown() if _init_status else (
            "### 🟢 Ready\n\n"
            "- ✅ ChromaDB vector store found on disk\n\n"
            "---\n"
            "Pipeline will load existing data on first run.\n\n"
            f"**Path:** `{Config.CHROMA_PERSIST_DIR}`"
        )
    else:
        return (
            "### 🟡 First Run\n\n"
            "- ⬜ No vector store found\n\n"
            "---\n"
            "Knowledge base will be indexed on first analysis run."
        )


# ── Gradio UI ──────────────────────────────────────────────────────────
with gr.Blocks(title="CyberSec Multi-Agent Analyzer", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ CyberSecurity Multi-Agent Analyzer")

    with gr.Row():
        # ── LEFT: LangGraph Pipeline ───────────────────────────────────
        with gr.Column(scale=1, min_width=250):
            gr.Markdown(LANGGRAPH_PIPELINE_MD)

        # ── CENTER: Main Playground ────────────────────────────────────
        with gr.Column(scale=3):
            scenario = gr.Dropdown(
                choices=[
                    "custom",
                    "Log Monitor Agent",
                    "Threat Intelligence Agent",
                    "Vulnerability Scanner Agent",
                    "Code Fixer Agent",
                    "Incident Response Agent",
                    "Policy Checker Agent",
                ],
                value="Log Monitor Agent",
                label="Select Agent Scenario",
            )

            scenario_desc = gr.Markdown(value=SCENARIO_DESCRIPTIONS["Log Monitor Agent"])

            input_box = gr.Textbox(
                lines=8,
                label="Input (logs, code, config, or policy)",
                placeholder="Paste your input here or select a scenario above...",
                value=EXAMPLE_INPUTS["ssh_brute_force"],
            )

            with gr.Row():
                run_btn = gr.Button("🚀 Run Analysis", variant="primary", scale=2)
                status_btn = gr.Button("🔍 Check Status", scale=1)

            with gr.Tabs():
                with gr.Tab("📄 Report"):
                    report_out = gr.Markdown()
                with gr.Tab("🔍 Log Findings"):
                    log_out = gr.JSON()
                with gr.Tab("🕵️ Threat Intel"):
                    threat_out = gr.JSON()
                with gr.Tab("⚠️ Vulnerabilities"):
                    vuln_out = gr.JSON()
                with gr.Tab("🔧 Code Fix"):
                    codefix_out = gr.JSON()
                with gr.Tab("📋 Compliance"):
                    policy_out = gr.JSON()
                with gr.Tab("📝 Trace"):
                    trace_out = gr.Textbox(lines=12, label="Agent Execution Trace")

        # ── RIGHT: Storage & Initialization ────────────────────────────
        with gr.Column(scale=1, min_width=250):
            gr.Markdown("### 📦 Storage & Init")
            status_out = gr.Markdown(value=check_init_status())
            gr.Markdown("---")
            gr.Markdown("### 🔧 Fixed Code Output")
            fixed_code_out = gr.Code(
                label="Fixed Code (read-only)",
                language="python",
                interactive=False,
                lines=15,
            )

    # ── Event Handlers ─────────────────────────────────────────────────
    scenario.change(fn=load_scenario, inputs=[scenario], outputs=[input_box, scenario_desc])
    run_btn.click(
        fn=analyze,
        inputs=[input_box, scenario],
        outputs=[report_out, log_out, threat_out, vuln_out, codefix_out, policy_out, trace_out, status_out, fixed_code_out],
    )
    status_btn.click(fn=check_init_status, inputs=[], outputs=[status_out])

if __name__ == "__main__":
    demo.launch(
        auth=authenticate,
        auth_message="🔐 CyberSecurity Multi-Agent System — Login Required",
        server_name="127.0.0.1",
        max_threads=MAX_CONCURRENT_THREADS,
        share=False,
    )
