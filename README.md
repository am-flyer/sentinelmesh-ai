╔══════════════════════════════════════════════════════════════════════╗
║  CyberSecurity Multi-Agent System                                     ║
║  LangGraph · Ollama · HuggingFace · LlamaIndex · ChromaDB · @tool    ║
║  Gradio Web UI                                                        ║
╚══════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 STACK OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Component          Role
 ─────────────────  ─────────────────────────────────────────────────
 LangGraph          Orchestrates agents as a compiled state machine
 Ollama             Local LLM runtime (gpt-oss:120b-cloud)
 LangChain @tool    Utility tools callable inside agent nodes
 HuggingFace        Local sentence-transformer embeddings (no API key)
 LlamaIndex         RAG framework — document indexing + retrieval
 ChromaDB           Persistent vector store (local disk)
 Gradio             Interactive web UI for analysis & visualization

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Install dependencies:
   pip install -r requirements.txt

2. Set your credentials in cs.env:
   OPENROUTER_API_KEY=sk-or-...  (if using OpenRouter)
   GRADIO_USER=admin
   GRADIO_PASSWORD=CyberSec@2026!
   LANGSMITH_API_KEY=lsv2_pt_...  (optional, for tracing)
   LANGSMITH_TRACING=true          (set false to disable)

   (Change the default password before deploying)

3. Run the Gradio web UI:
   python cybersecurityGradio.py

   This opens a browser-based interface with:
   - Scenario selector (4 built-in examples + custom input)
   - Tabbed results: Report, Log Findings, Threat Intel, Vulnerabilities, Compliance, Trace
   - Green ✅ status indicators showing initialization state

4. Run via CLI (headless):
   python cybersecurityAgents.py ssh_brute_force
   python cybersecurityAgents.py vulnerable_code
   python cybersecurityAgents.py docker_misconfig
   python cybersecurityAgents.py policy_audit

5. Run programmatically:
   from cybersecurityAgents import run_analysis
   results = run_analysis("your logs or code here")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PROJECT FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 File                       Purpose
 ────────────────────────   ──────────────────────────────────────────
 cybersecurityAgents.py     Core multi-agent system (LangGraph pipeline)
 cybersecurityGradio.py     Gradio web UI wrapper
 cs.env                     API keys (OPENROUTER_API_KEY)
 requirements.txt           Python dependencies
 README.md                  This file
 claude.md                  Gradio integration analysis & architecture
 skill.md                   Team skills & technology breakdown

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 VECTOR STORE PERSISTENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 The system checks if ChromaDB already has indexed data on startup:

 - If ./chroma_cybersec_db/ exists with data → loads existing index (fast)
 - If not → indexes the knowledge base into ChromaDB (first run only)

 The Gradio UI displays green ✅ checkboxes showing:
   ✅ OpenRouter LLM Connected
   ✅ HuggingFace Embeddings Loaded
   ✅ ChromaDB + LlamaIndex Vector Store (loaded existing / freshly indexed)
   ✅ LangGraph Pipeline Compiled

 Use the "🔍 Check Status" button to inspect without running analysis.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 AGENTS & LANGGRAPH FLOW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [Input]
     │
     ▼
  classify_input       ← Detects if input is log/code/config/policy
     │
     ▼
  rag_retrieve         ← LlamaIndex retrieves relevant KB chunks from ChromaDB
     │
     ▼
  log_monitor          ← Detects attacks, anomalies, IoCs
     │
     ▼
  threat_intel         ← Maps to CVEs, MITRE ATT&CK, threat actors
     │
     ▼
  vuln_scanner         ← OWASP/CWE vulnerability assessment
     │
     ▼
  incident_response    ← NIST 800-61 playbook with 3-phase timeline
     │
     ▼
  policy_checker       ← NIST CSF / ISO 27001 / SOC 2 gap analysis
     │
     ▼
  synthesize_report    ← Combines all outputs into final report
     │
     ▼
  [Report + JSON saved to disk]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 GRADIO WEB UI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Launch:
   python cybersecurityGradio.py

 Features:
   - Login gate (username/password from cs.env)
   - Dropdown to select built-in scenarios or paste custom input
   - Tabbed output panels (Report, Findings, Threat Intel, Vulns, Compliance, Trace)
   - Real-time system status panel with green ✅ checkboxes
   - Singleton pipeline — initializes once, reuses across requests
   - Vector store persistence check — skips re-indexing if data exists
   - Rate limiting (30s cooldown between requests)
   - Input validation (max 10,000 characters)
   - Localhost-only binding (no external network access)

 Architecture:
   ┌──────────────┐       ┌───────────────────────┐       ┌──────────────────┐
   │  Gradio UI   │──────▶│  cybersecurityAgents   │──────▶│  LangGraph       │
   │  (Browser)   │◀──────│  (pipeline singleton)  │◀──────│  Pipeline        │
   └──────────────┘       └───────────────────────┘       └──────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 MODEL OPTIONS (OpenRouter)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Free tier (no billing required):
   mistralai/mistral-7b-instruct              ← Default
   meta-llama/llama-3.1-8b-instruct:free
   google/gemma-2-9b-it:free

 Paid (higher quality):
   openai/gpt-4o
   anthropic/claude-3-5-sonnet
   mistralai/mixtral-8x7b-instruct

 Change in Config.LLM_MODEL in cybersecurityAgents.py

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EMBEDDING OPTIONS (HuggingFace, all local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 sentence-transformers/all-MiniLM-L6-v2   ← Default (~90MB, fast)
 BAAI/bge-base-en-v1.5                    ← Better quality (~440MB)
 sentence-transformers/all-mpnet-base-v2  ← Balanced (~420MB)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 OUTPUT FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 cybersec_report_YYYYMMDD_HHMMSS.txt   ← Human-readable report
 cybersec_results_YYYYMMDD_HHMMSS.json ← Structured JSON for all agents
 ./chroma_cybersec_db/                 ← Persistent ChromaDB vector store

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXTENDING THE SYSTEM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Add knowledge to the RAG database:
   kb.add_document("Your threat intel text...", {"category": "threat_intel"})

 Add a new agent:
   1. Write a node function: def node_my_agent(state) → state
   2. graph.add_node("my_agent", node_my_agent)
   3. graph.add_edge("policy_checker", "my_agent")
   4. Add result key to CyberAgentState TypedDict

 Add conditional routing (e.g., only run incident response for CRITICAL):
   graph.add_conditional_edges(
       "vuln_scanner",
       lambda s: "incident_response" if s["vuln_scan"]["risk_score"] > 70 else "policy_checker",
       {"incident_response": "incident_response", "policy_checker": "policy_checker"}
   )
