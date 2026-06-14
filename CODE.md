# Skills & Technology Breakdown

## Core Technologies Used

| Technology | Skill Area | Usage |
|---|---|---|
| Python 3.10+ | Backend development | Core language for all components |
| LangGraph | AI orchestration | Multi-agent state machine pipeline (nodes + conditional edges) |
| LangChain (langchain-openai) | LLM client | ChatOpenAI + @tool definitions |
| LangSmith | Observability | Auto-traces LLM calls, tool invocations, node transitions |
| Ollama | Local LLM runtime | Serves gpt-oss:120b-cloud at localhost:11434/v1 |
| HuggingFace | ML embeddings | Local sentence-transformer models (no API key) |
| LlamaIndex | RAG framework | Document indexing, retrieval, query engine |
| ChromaDB | Vector database | Persistent local vector store with cosine similarity |
| Gradio | Web UI | Interactive browser-based interface |
| python-dotenv | Config management | Secure API key loading from .env |

## Architecture Skills

| Skill | Application |
|---|---|
| Multi-agent systems | 6 specialized agents orchestrated via LangGraph state machine |
| RAG (Retrieval Augmented Generation) | Knowledge base retrieval before LLM analysis |
| LangChain @tool decorator | 3 utility tools (query_knowledge_base, lookup_cve, check_compliance_control) callable inside agent nodes |
| Vector embeddings | HuggingFace local embeddings → ChromaDB persistence |
| State machine design | Sequential agent pipeline with shared typed state |
| Conditional edges | Code Fixer iterative loop (max 3x) |
| Singleton patterns | Pipeline pre-initialization for Gradio performance |
| Persistence management | ChromaDB check-before-init to avoid re-indexing |

## Cybersecurity Domain Skills

| Domain | Implementation |
|---|---|
| Log analysis | SSH brute force, SQL injection, port scan detection |
| Threat intelligence | CVE mapping, MITRE ATT&CK TTPs, threat actor identification |
| Vulnerability assessment | OWASP Top 10, CWE mapping, risk scoring |
| Incident response | NIST SP 800-61 playbook, 3-phase timeline |
| Compliance auditing | NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II gap analysis |
| Docker security | Container misconfiguration detection |

## UI/UX Skills (Gradio)

| Feature | Implementation |
|---|---|
| Authentication | Login gate with credentials from .env |
| Rate limiting | 30s cooldown between analysis requests |
| Input validation | Max 10,000 character limit on input |
| Network security | Localhost-only binding, share=False |
| Concurrency control | max_threads=2 prevents resource exhaustion |
| Tabbed interface | Report, Findings, Threat Intel, Vulnerabilities, Compliance, Trace |
| Status indicators | Green ✅ checkboxes for each initialized component |
| Persistence awareness | UI shows whether vector store loaded from disk or freshly indexed |
| Scenario selector | Dropdown with 6 agent scenarios + custom input |
| Singleton pipeline | One-time initialization, fast subsequent requests |

## Key Design Decisions

1. **.env for secrets** — API keys stored externally, loaded via python-dotenv
2. **Vector store persistence check** — `check_vector_store_exists()` runs before heavy initialization; skips re-indexing if ChromaDB already has data
3. **Gradio status panel** — Real-time green checkboxes show initialization state to the user
4. **Singleton pattern** — LLM, embeddings, KB, and graph initialized once per session, not per request
5. **Hybrid Tool architecture** — Pipeline uses deterministic node flow, but agents internally call `@tool` utilities (query_knowledge_base, lookup_cve, check_compliance_control) for enrichment
6. **Ollama local LLM** — Uses OpenAI-compatible endpoint at localhost:11434/v1 with gpt-oss:120b-cloud
7. **Iterative Code Fixer** — Conditional edge loops up to 3x until code is fully fixed
8. **LangSmith tracing** — Auto-enabled when LANGSMITH_TRACING=true in .env; traces all LLM calls, @tool invocations, and node transitions to LangSmith dashboard
