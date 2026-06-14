"""
╔══════════════════════════════════════════════════════════════════════╗
║   CyberSecurity Multi-Agent System                                    ║
║   Stack: LangGraph · HuggingFace Embeddings · OpenRouter LLM         ║
║          LlamaIndex RAG · ChromaDB Vector Store                       ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import TypedDict, List, Optional, Any
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

# ── LangSmith Tracing (auto-enabled if env vars are set) ─────────────
if os.getenv("LANGSMITH_TRACING", "false").lower() == "true":
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
    os.environ.setdefault("LANGCHAIN_API_KEY", os.getenv("LANGSMITH_API_KEY", ""))
    os.environ.setdefault("LANGCHAIN_PROJECT", os.getenv("LANGSMITH_PROJECT", "cybersec-multi-agent"))
    os.environ.setdefault("LANGCHAIN_ENDPOINT", os.getenv("LANGSMITH_ENDPOINT", "https://api.smith.langchain.com"))
    print("  [LangSmith] Tracing enabled → project:", os.getenv("LANGSMITH_PROJECT"))

# ── LangGraph ──────────────────────────────────────────────────────────
from langgraph.graph import StateGraph, END

# ── LangChain ─────────────────────────────────────────────────────────
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_huggingface import HuggingFaceEmbeddings

# ── LlamaIndex ─────────────────────────────────────────────────────────
from llama_index.core import (
    VectorStoreIndex,
    Document,
    Settings,
    StorageContext,
)
from llama_index.core.retrievers import VectorIndexRetriever
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.vector_stores.chroma import ChromaVectorStore

# ── ChromaDB ───────────────────────────────────────────────────────────
import chromadb
from chromadb.config import Settings as ChromaSettings


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════

class Config:
    # ── LLM Configuration ──────────────────────────────────────────────
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "ollama")
    OPENROUTER_BASE_URL: str = os.getenv("OPENROUTER_BASE_URL", "http://localhost:11434/v1")
    

    # ── Model (local Ollama) ───────────────────────────────────────────
    LLM_MODEL: str = "gpt-oss:120b-cloud"
    # LLM_MODEL = "openai/gpt-4o"                             # Premium option
    # LLM_MODEL = "qwen/qwen-2.5-72b-instruct"                  # Alternative
    # LLM_MODEL = "meta-llama/llama-3.1-8b-instruct:free"    # Llama free
    # ── HuggingFace Embeddings (runs locally, no API key needed) ───────
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    # EMBEDDING_MODEL = "BAAI/bge-base-en-v1.5"              # Higher quality
    # EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"

    # ── ChromaDB (persistent local vector store) ────────────────────────
    PROJECT_DIR: Path = Path(__file__).resolve().parent
    CHROMA_PERSIST_DIR: str = str(PROJECT_DIR / "data" / "chroma_cybersec_db")
    CHROMA_COLLECTION: str = "cybersecurity_knowledge"

    # ── RAG settings ────────────────────────────────────────────────────
    TOP_K_RETRIEVAL: int = 3
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2048


# ══════════════════════════════════════════════════════════════════════
# LANGGRAPH STATE DEFINITION
# ══════════════════════════════════════════════════════════════════════

class CyberAgentState(TypedDict):
    """Shared state flowing through all LangGraph nodes."""
    # Input
    raw_input: str
    input_type: str                    # "log", "code", "config", "policy"

    # Per-agent results
    log_findings: Optional[dict]
    threat_intel: Optional[dict]
    vuln_scan: Optional[dict]
    code_fix: Optional[dict]           # Iterative code fixer results
    incident_plan: Optional[dict]
    policy_gaps: Optional[dict]

    # Orchestration metadata
    agent_trace: List[str]             # Execution log
    errors: List[str]                  # Any errors encountered
    rag_context: Optional[str]         # Retrieved knowledge base context
    final_report: Optional[str]        # Synthesized final report
    started_at: str


# ══════════════════════════════════════════════════════════════════════
# LLM CLIENT — OpenRouter
# ══════════════════════════════════════════════════════════════════════

def build_llm(model: str = None) -> ChatOpenAI:
    """
    Build LangChain ChatOpenAI client pointed at OpenRouter.
    OpenRouter is OpenAI-API-compatible, so no custom wrapper needed.
    """
    if not Config.OPENROUTER_API_KEY:
        Config.OPENROUTER_API_KEY = "ollama"

    return ChatOpenAI(
        model=model or Config.LLM_MODEL,
        openai_api_key=Config.OPENROUTER_API_KEY,
        openai_api_base=Config.OPENROUTER_BASE_URL,
        temperature=Config.LLM_TEMPERATURE,
        max_tokens=Config.LLM_MAX_TOKENS,
    )


# ══════════════════════════════════════════════════════════════════════
# HUGGINGFACE EMBEDDINGS
# ══════════════════════════════════════════════════════════════════════

def build_embeddings() -> HuggingFaceEmbeddings:
    """
    Local HuggingFace sentence-transformer embeddings.
    Downloads model on first run (~90MB), cached locally after that.
    """
    print(f"  [HuggingFace] Loading embedding model: {Config.EMBEDDING_MODEL}")
    return HuggingFaceEmbeddings(
        model_name=Config.EMBEDDING_MODEL,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


# ══════════════════════════════════════════════════════════════════════
# VECTOR STORE — ChromaDB + LlamaIndex
# ══════════════════════════════════════════════════════════════════════

CYBERSEC_KNOWLEDGE_BASE = [
    # Log Analysis
    Document(
        text="SSH brute force attack pattern: multiple failed authentication attempts "
             "from the same IP within a short timeframe. Typical threshold: >5 failures "
             "in 60 seconds. Common source IPs often belong to Tor exit nodes or VPS providers. "
             "Mitigation: fail2ban, rate limiting, disable password auth, use key-based auth only.",
        metadata={"category": "log_analysis", "threat": "brute_force", "severity": "HIGH"},
    ),
    Document(
        text="SQL Injection in web logs appears as unusual characters in URL parameters: "
             "UNION, SELECT, OR 1=1, --, '; DROP TABLE. WAF bypass techniques include "
             "URL encoding (%27 for '), case variation (SeLeCt), comments (/*!SELECT*/). "
             "CVE references: multiple CVEs exist per application. OWASP A03:2021.",
        metadata={"category": "log_analysis", "threat": "sql_injection", "severity": "CRITICAL"},
    ),
    Document(
        text="Port scanning indicators in network logs: sequential port access, RST responses, "
             "SYN packets to multiple ports in rapid succession. Tools: nmap, masscan, zmap. "
             "Nmap default scan leaves fingerprint in IDS logs as SYN to common ports.",
        metadata={"category": "log_analysis", "threat": "reconnaissance", "severity": "MEDIUM"},
    ),
    # Threat Intel
    Document(
        text="CVE-2021-44228 Log4Shell: Critical RCE in Apache Log4j 2.x. CVSS 10.0. "
             "Exploited by JNDI lookup injection via user-controlled log data. "
             "Affected versions: log4j-core 2.0-beta9 to 2.14.1. "
             "Patch: upgrade to 2.15.0+. Widely exploited in the wild by nation-state actors.",
        metadata={"category": "threat_intel", "cve": "CVE-2021-44228", "cvss": "10.0"},
    ),
    Document(
        text="CVE-2023-44487 HTTP/2 Rapid Reset: DDoS vulnerability in HTTP/2 protocol. "
             "CVSS 7.5. Allows attackers to send RST_STREAM frames to reset connections rapidly. "
             "Affected: nginx, Apache, Go HTTP/2 servers. Patch available in nginx 1.25.3+. "
             "Exploited by botnet in record-breaking DDoS campaigns (October 2023).",
        metadata={"category": "threat_intel", "cve": "CVE-2023-44487", "cvss": "7.5"},
    ),
    Document(
        text="MITRE ATT&CK T1110 Brute Force: Adversaries may use brute force techniques "
             "to gain access to accounts. Sub-techniques: T1110.001 Password Guessing, "
             "T1110.003 Password Spraying, T1110.004 Credential Stuffing. "
             "Relevant threat groups: APT28, Lazarus Group, FIN7.",
        metadata={"category": "threat_intel", "mitre": "T1110"},
    ),
    # Vulnerability Patterns
    Document(
        text="SQL Injection (CWE-89, OWASP A03:2021): Occurs when user input is concatenated "
             "directly into SQL queries without parameterization. Fix: use prepared statements "
             "with parameterized queries. Example vulnerable: query = 'SELECT * FROM users WHERE id=' + id. "
             "Secure: cursor.execute('SELECT * FROM users WHERE id = %s', (id,))",
        metadata={"category": "vulnerability", "cwe": "CWE-89", "owasp": "A03:2021"},
    ),
    Document(
        text="Hardcoded credentials (CWE-798): Embedding passwords, API keys, or tokens "
             "in source code is a critical vulnerability. Secret scanning tools: truffleHog, "
             "git-secrets, GitHub Secret Scanning. Remediation: use environment variables, "
             "AWS Secrets Manager, HashiCorp Vault, or similar secret management systems.",
        metadata={"category": "vulnerability", "cwe": "CWE-798", "severity": "CRITICAL"},
    ),
    Document(
        text="Docker security misconfigurations: Running as root increases attack surface. "
             "Privileged containers can escape to host. Exposed Docker socket (/var/run/docker.sock) "
             "allows full host compromise. Mounting /etc exposes sensitive host files. "
             "Best practices: non-root USER, read-only filesystem, drop capabilities, "
             "network policies, scan images with Trivy or Snyk.",
        metadata={"category": "vulnerability", "topic": "docker", "severity": "HIGH"},
    ),
    # Incident Response
    Document(
        text="NIST SP 800-61 Incident Response phases: Preparation (policies, tools, training), "
             "Detection & Analysis (identify, classify, prioritize), Containment (short/long term), "
             "Eradication (remove threat artifacts), Recovery (restore operations), "
             "Post-Incident Activity (lessons learned, evidence retention). "
             "Severity P1: respond within 15 minutes. P2: 1 hour. P3: 4 hours. P4: 24 hours.",
        metadata={"category": "incident_response", "framework": "NIST_800-61"},
    ),
    Document(
        text="Digital forensics evidence preservation: Capture volatile memory first (RAM) "
             "using tools like LiME or WinPmem. Disk imaging with dd or FTK Imager. "
             "Preserve network logs (PCAP), system logs (/var/log/), "
             "process list, open connections (netstat), scheduled tasks (cron, at). "
             "Chain of custody must be documented for legal proceedings.",
        metadata={"category": "incident_response", "topic": "forensics"},
    ),
    # Compliance
    Document(
        text="NIST CSF 2.0 Core Functions: Govern (GV), Identify (ID), Protect (PR), "
             "Detect (DE), Respond (RS), Recover (RC). "
             "Critical controls: asset inventory (ID.AM), risk assessment (ID.RA), "
             "access control (PR.AA), awareness training (PR.AT), "
             "anomaly detection (DE.AE), incident management (RS.MA).",
        metadata={"category": "compliance", "framework": "NIST_CSF"},
    ),
    Document(
        text="SOC 2 Trust Service Criteria: Security (CC), Availability (A), "
             "Processing Integrity (PI), Confidentiality (C), Privacy (P). "
             "Common CC controls: CC6.1 logical access, CC6.3 MFA, CC7.2 monitoring, "
             "CC8.1 change management, CC9.1 risk management. "
             "Annual penetration testing and vulnerability scans typically required.",
        metadata={"category": "compliance", "framework": "SOC2"},
    ),
    Document(
        text="ISO 27001:2022 Annex A controls include: A.5 Organizational controls, "
             "A.6 People controls (background checks, training), "
             "A.7 Physical controls (clean desk, screen lock), "
             "A.8 Technological controls (endpoint protection, SIEM, vulnerability management, "
             "backup, encryption, MFA, logging). 93 controls total in 2022 version.",
        metadata={"category": "compliance", "framework": "ISO_27001"},
    ),
]


def check_vector_store_exists() -> bool:
    """Check if ChromaDB persistent vector store already exists with data."""
    if not os.path.exists(Config.CHROMA_PERSIST_DIR):
        return False
    try:
        client = chromadb.PersistentClient(
            path=Config.CHROMA_PERSIST_DIR,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        collection = client.get_or_create_collection(name=Config.CHROMA_COLLECTION)
        return collection.count() > 0
    except Exception:
        return False


class VectorKnowledgeBase:
    """
    LlamaIndex + ChromaDB persistent vector store with HuggingFace embeddings.
    Provides RAG retrieval for all agents.
    """

    def __init__(self, hf_embeddings: HuggingFaceEmbeddings):
        self.hf_embeddings = hf_embeddings
        self._index: Optional[VectorStoreIndex] = None
        self._query_engine: Optional[RetrieverQueryEngine] = None
        self.loaded_existing: bool = False
        self._setup()

    def _setup(self):
        print(f"  [ChromaDB] Initializing persistent store: {Config.CHROMA_PERSIST_DIR}")

        # ChromaDB persistent client
        chroma_client = chromadb.PersistentClient(
            path=Config.CHROMA_PERSIST_DIR,
            settings=ChromaSettings(anonymized_telemetry=False),
        )

        # Get or create collection
        chroma_collection = chroma_client.get_or_create_collection(
            name=Config.CHROMA_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )

        # LlamaIndex ChromaVectorStore wrapper
        vector_store = ChromaVectorStore(chroma_collection=chroma_collection)

        # Custom LlamaIndex-compatible embedding wrapper around HuggingFace
        from llama_index.core.embeddings import BaseEmbedding
        from typing import List as TList

        hf_emb = self.hf_embeddings

        class HFEmbeddingAdapter(BaseEmbedding):
            """Adapts LangChain HuggingFaceEmbeddings → LlamaIndex BaseEmbedding."""

            def _get_query_embedding(self, query: str) -> TList[float]:
                return hf_emb.embed_query(query)

            def _get_text_embedding(self, text: str) -> TList[float]:
                return hf_emb.embed_documents([text])[0]

            def _get_text_embeddings(self, texts: TList[str]) -> TList[TList[float]]:
                return hf_emb.embed_documents(texts)

            async def _aget_query_embedding(self, query: str) -> TList[float]:
                return self._get_query_embedding(query)

            async def _aget_text_embedding(self, text: str) -> TList[float]:
                return self._get_text_embedding(text)

        # Configure LlamaIndex global settings
        Settings.embed_model = HFEmbeddingAdapter()
        Settings.llm = None    # We use LangChain LLM directly

        storage_context = StorageContext.from_defaults(vector_store=vector_store)

        # Check if collection already has data — skip indexing if so
        existing_count = chroma_collection.count()
        if existing_count == 0:
            print(f"  [LlamaIndex] Indexing {len(CYBERSEC_KNOWLEDGE_BASE)} knowledge documents...")
            self._index = VectorStoreIndex.from_documents(
                CYBERSEC_KNOWLEDGE_BASE,
                storage_context=storage_context,
                show_progress=True,
            )
            self.loaded_existing = False
        else:
            print(f"  [LlamaIndex] Loaded existing index ({existing_count} vectors from ChromaDB)")
            self._index = VectorStoreIndex.from_vector_store(
                vector_store=vector_store,
                storage_context=storage_context,
            )
            self.loaded_existing = True

        # Build retriever
        retriever = VectorIndexRetriever(
            index=self._index,
            similarity_top_k=Config.TOP_K_RETRIEVAL,
        )
        self._query_engine = RetrieverQueryEngine(retriever=retriever)

    def retrieve(self, query: str) -> str:
        """Retrieve top-K relevant documents for a query."""
        try:
            retriever = self._index.as_retriever(similarity_top_k=Config.TOP_K_RETRIEVAL)
            nodes = retriever.retrieve(query)
            if not nodes:
                return "No relevant context found in knowledge base."
            parts = []
            for i, node in enumerate(nodes, 1):
                score = getattr(node, "score", 0.0) or 0.0
                category = node.metadata.get("category", "general")
                parts.append(
                    f"[Context {i} | category={category} | relevance={score:.2f}]\n"
                    f"{node.text}"
                )
            return "\n\n".join(parts)
        except Exception as e:
            return f"RAG retrieval error: {e}"

    def add_document(self, text: str, metadata: dict = None):
        """Dynamically add new knowledge to the vector store."""
        doc = Document(text=text, metadata=metadata or {})
        self._index.insert(doc)
        print(f"  [VectorDB] Added new document (category={metadata.get('category','?')})")


# ══════════════════════════════════════════════════════════════════════
# LANGCHAIN TOOLS (@tool utilities for agent nodes)
# ══════════════════════════════════════════════════════════════════════

# These tools are callable utilities used INSIDE agent nodes.
# They provide structured access to the knowledge base and external lookups.
# The pipeline flow remains node-based (deterministic), but agents can
# invoke these tools internally for enriched analysis.

_kb_instance: Optional[Any] = None  # Set during pipeline build


@tool
def query_knowledge_base(query: str) -> str:
    """Search the cybersecurity knowledge base (ChromaDB) for relevant context on threats, vulnerabilities, compliance, or incident response."""
    if _kb_instance is None:
        return "Knowledge base not initialized."
    return _kb_instance.retrieve(query)


@tool
def lookup_cve(cve_id: str) -> str:
    """Look up a specific CVE identifier in the knowledge base and return relevant threat intelligence."""
    if _kb_instance is None:
        return "Knowledge base not initialized."
    return _kb_instance.retrieve(f"CVE vulnerability {cve_id} exploit patch")


@tool
def check_compliance_control(framework: str, control: str) -> str:
    """Check a specific compliance control (e.g., framework='NIST CSF', control='PR.AT-1') against the knowledge base."""
    if _kb_instance is None:
        return "Knowledge base not initialized."
    return _kb_instance.retrieve(f"{framework} {control} compliance requirement")


# List of all available tools for agent nodes
AGENT_TOOLS = [query_knowledge_base, lookup_cve, check_compliance_control]


# ══════════════════════════════════════════════════════════════════════
# AGENT NODE FACTORY
# ══════════════════════════════════════════════════════════════════════

def _call_llm(llm: ChatOpenAI, system_prompt: str, user_prompt: str) -> str:
    """Call LLM via OpenRouter with system + user messages."""
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]
    response = llm.invoke(messages)
    return response.content


def _parse_json_safe(text: str) -> dict:
    """Safely parse JSON from LLM response, stripping markdown fences."""
    clean = text.strip()
    for fence in ["```json", "```JSON", "```"]:
        if clean.startswith(fence):
            clean = clean[len(fence):]
    if clean.endswith("```"):
        clean = clean[:-3]
    clean = clean.strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        # Return structured error fallback
        return {"raw_output": text, "parse_error": "JSON decode failed"}


# ══════════════════════════════════════════════════════════════════════
# NODE 1 — INPUT CLASSIFIER
# ══════════════════════════════════════════════════════════════════════

def node_input_classifier(state: CyberAgentState) -> CyberAgentState:
    """Classify input type and route accordingly."""
    text = state["raw_input"].lower()
    input_type = "general"

    log_keywords = ["failed password", "sshd", "auth", "nov ", "dec ", "timestamp", "kernel", "iptables"]
    code_keywords = ["def ", "function", "import ", "require(", "const ", "class ", "SELECT", "query"]
    config_keywords = ["docker", "privileged", "volume", "--", "env", "container", "nginx", "aws_"]
    policy_keywords = ["mfa", "policy", "compliance", "training", "audit", "siem", "retention", "encryption at rest"]

    scores = {
        "log":    sum(k in text for k in log_keywords),
        "code":   sum(k in text for k in code_keywords),
        "config": sum(k in text for k in config_keywords),
        "policy": sum(k in text for k in policy_keywords),
    }
    input_type = max(scores, key=scores.get) if max(scores.values()) > 0 else "general"

    trace = state.get("agent_trace", [])
    trace.append(f"[{_ts()}] InputClassifier → detected input_type='{input_type}' | scores={scores}")

    return {**state, "input_type": input_type, "agent_trace": trace}


# ══════════════════════════════════════════════════════════════════════
# NODE 2 — RAG CONTEXT RETRIEVER
# ══════════════════════════════════════════════════════════════════════

def build_rag_node(kb: VectorKnowledgeBase):
    def node_rag_retriever(state: CyberAgentState) -> CyberAgentState:
        """Retrieve relevant knowledge base context before agent analysis."""
        query = f"cybersecurity {state['input_type']} analysis: {state['raw_input'][:300]}"
        print(f"  [RAG] Retrieving context for: {query[:80]}...")
        context = kb.retrieve(query)

        trace = state.get("agent_trace", [])
        trace.append(f"[{_ts()}] RAGRetriever → retrieved {len(context)} chars of context")
        return {**state, "rag_context": context, "agent_trace": trace}
    return node_rag_retriever


# ══════════════════════════════════════════════════════════════════════
# NODE 3 — LOG MONITOR AGENT
# ══════════════════════════════════════════════════════════════════════

LOG_MONITOR_SYSTEM = """You are an expert Security Log Analysis Agent.
Analyze the provided input for security threats, anomalies, and indicators of compromise.
Use the RAG knowledge context to enrich your analysis.

Return ONLY valid JSON (no markdown fences) with this exact structure:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "one-line overview",
  "findings": [
    {"type": "attack type", "detail": "specific detail", "severity": "HIGH", "source_ip": "if present"}
  ],
  "indicators_of_compromise": ["ioc1", "ioc2"],
  "attack_timeline": "reconstructed sequence if possible",
  "recommended_next_step": "immediate action"
}"""

def build_log_monitor_node(llm: ChatOpenAI):
    def node_log_monitor(state: CyberAgentState) -> CyberAgentState:
        print("  [Agent] Log Monitor Agent running...")
        user_prompt = (
            f"RAG CONTEXT:\n{state.get('rag_context', 'None')}\n\n"
            f"INPUT TO ANALYZE:\n{state['raw_input']}"
        )
        try:
            raw = _call_llm(llm, LOG_MONITOR_SYSTEM, user_prompt)
            result = _parse_json_safe(raw)
        except Exception as e:
            result = {"error": str(e), "severity": "UNKNOWN"}

        trace = state.get("agent_trace", [])
        trace.append(f"[{_ts()}] LogMonitorAgent → severity={result.get('severity','?')} | {len(result.get('findings',[]))} findings")
        return {**state, "log_findings": result, "agent_trace": trace}
    return node_log_monitor


# ══════════════════════════════════════════════════════════════════════
# NODE 4 — THREAT INTELLIGENCE AGENT
# ══════════════════════════════════════════════════════════════════════

THREAT_INTEL_SYSTEM = """You are a Cyber Threat Intelligence Agent with expertise in CVEs,
threat actors, and MITRE ATT&CK framework.
Use RAG context to identify real CVEs and known threats related to the input.

Return ONLY valid JSON (no markdown fences):
{
  "exposure_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "threat landscape summary",
  "cves": [
    {"id": "CVE-XXXX-XXXXX", "cvss_score": 9.8, "description": "brief", "exploited_in_wild": true}
  ],
  "mitre_ttps": [
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
  ],
  "threat_actors": ["APT28", "FIN7"],
  "intelligence_assessment": "detailed assessment paragraph"
}"""

def build_threat_intel_node(llm: ChatOpenAI):
    def node_threat_intel(state: CyberAgentState) -> CyberAgentState:
        print("  [Agent] Threat Intelligence Agent running...")
        # Use @tool: lookup_cve for enrichment
        extra_context = ""
        rag_text = state.get("rag_context", "")
        if "cve" in state["raw_input"].lower() or "cve" in rag_text.lower():
            cve_result = lookup_cve.invoke("known CVEs related to detected attack patterns")
            extra_context = f"\nTOOL(lookup_cve) RESULT:\n{cve_result}\n"

        prior_context = ""
        if state.get("log_findings"):
            prior_context = f"\nLOG MONITOR FINDINGS:\n{json.dumps(state['log_findings'], indent=2)}\n"

        user_prompt = (
            f"RAG CONTEXT:\n{state.get('rag_context', 'None')}\n"
            f"{extra_context}"
            f"{prior_context}"
            f"\nINPUT TO ANALYZE:\n{state['raw_input']}"
        )
        try:
            raw = _call_llm(llm, THREAT_INTEL_SYSTEM, user_prompt)
            result = _parse_json_safe(raw)
        except Exception as e:
            result = {"error": str(e), "exposure_level": "UNKNOWN"}

        trace = state.get("agent_trace", [])
        trace.append(f"[{_ts()}] ThreatIntelAgent → {len(result.get('cves',[]))} CVEs | {len(result.get('mitre_ttps',[]))} TTPs")
        return {**state, "threat_intel": result, "agent_trace": trace}
    return node_threat_intel


# ══════════════════════════════════════════════════════════════════════
# NODE 5 — VULNERABILITY SCANNER AGENT
# ══════════════════════════════════════════════════════════════════════

VULN_SCANNER_SYSTEM = """You are an expert Vulnerability Assessment Agent.
Analyze the input for security vulnerabilities, misconfigurations, and coding flaws.
Map findings to OWASP Top 10, CWE, and CVE identifiers where applicable.

Return ONLY valid JSON (no markdown fences):
{
  "risk_score": 85,
  "summary": "scan overview",
  "total_findings": 5,
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "SQL Injection",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "severity": "CRITICAL",
      "exploitable": true,
      "location": "file.py line 42",
      "description": "detailed description",
      "remediation": "how to fix it"
    }
  ],
  "secure_coding_recommendations": ["recommendation 1", "recommendation 2"]
}"""

def build_vuln_scanner_node(llm: ChatOpenAI):
    def node_vuln_scanner(state: CyberAgentState) -> CyberAgentState:
        print("  [Agent] Vulnerability Scanner Agent running...")
        user_prompt = (
            f"RAG CONTEXT:\n{state.get('rag_context', 'None')}\n\n"
            f"INPUT TO SCAN:\n{state['raw_input']}"
        )
        try:
            raw = _call_llm(llm, VULN_SCANNER_SYSTEM, user_prompt)
            result = _parse_json_safe(raw)
        except Exception as e:
            result = {"error": str(e), "risk_score": 0}

        trace = state.get("agent_trace", [])
        trace.append(f"[{_ts()}] VulnScannerAgent → risk_score={result.get('risk_score','?')} | {result.get('total_findings','?')} findings")
        return {**state, "vuln_scan": result, "agent_trace": trace}
    return node_vuln_scanner


# ══════════════════════════════════════════════════════════════════════
# NODE 5B — ITERATIVE CODE FIXER AGENT
# ══════════════════════════════════════════════════════════════════════

CODE_FIXER_SYSTEM = """You are an expert Secure Code Fixer Agent.
You receive buggy/vulnerable code along with vulnerability findings.
Your job is to fix ALL security vulnerabilities and bugs in the provided code.

IMPORTANT RULES:
- You MUST return the SAME code that was given to you, but with security fixes applied.
- Do NOT generate new/different code. Only modify the vulnerable lines.
- Keep the same imports, structure, function names, and logic.
- Only change what is necessary to fix the vulnerabilities.

After fixing, verify:
1. Path traversal: Is user input sanitized before file access?
2. SQL injection: Are parameterized queries used?
3. Hardcoded credentials: Are they removed/externalized?
4. Input validation: Is it added where needed?

Return ONLY valid JSON (no markdown fences):
{
  "iteration": 1,
  "fixed_code": "the complete fixed source code preserving original structure",
  "changes_made": [
    {"issue": "Path Traversal", "fix": "Added os.path.realpath check", "line": "10"}
  ],
  "remaining_issues": [],
  "is_fully_fixed": true,
  "confidence": 95,
  "explanation": "Summary of all fixes applied"
}

If there are still remaining issues, set is_fully_fixed to false and list them.
"""

MAX_CODE_FIX_ITERATIONS = 3


def build_code_fixer_node(llm: ChatOpenAI):
    def node_code_fixer(state: CyberAgentState) -> CyberAgentState:
        # Skip if input is not code
        if state.get("input_type") not in ("code", "general"):
            trace = state.get("agent_trace", [])
            trace.append(f"[{_ts()}] CodeFixerAgent → skipped (input_type={state.get('input_type')})")
            return {**state, "code_fix": {"skipped": True, "reason": "not code input"}, "agent_trace": trace}

        existing_fix = state.get("code_fix") or {}
        iteration = existing_fix.get("iteration", 0) + 1

        print(f"  [Agent] Code Fixer Agent running (iteration {iteration}/{MAX_CODE_FIX_ITERATIONS})...")

        # Build prompt with vuln findings and previous fix attempt
        vuln_context = json.dumps(state.get("vuln_scan") or {}, indent=2)
        code_to_fix = existing_fix.get("fixed_code", state["raw_input"])
        previous_issues = existing_fix.get("remaining_issues", [])

        user_prompt = (
            f"VULNERABILITY SCAN FINDINGS:\n{vuln_context}\n\n"
        )
        if iteration > 1:
            user_prompt += (
                f"PREVIOUS FIX ATTEMPT (iteration {iteration - 1}) STILL HAD ISSUES:\n"
                f"{json.dumps(previous_issues, indent=2)}\n\n"
            )
        user_prompt += f"CODE TO FIX:\n{code_to_fix}"

        try:
            raw = _call_llm(llm, CODE_FIXER_SYSTEM, user_prompt)
            result = _parse_json_safe(raw)
            result["iteration"] = iteration
        except Exception as e:
            result = {"error": str(e), "iteration": iteration, "is_fully_fixed": True}

        trace = state.get("agent_trace", [])
        is_fixed = result.get("is_fully_fixed", True)
        n_changes = len(result.get("changes_made", []))
        n_remaining = len(result.get("remaining_issues", []))
        trace.append(
            f"[{_ts()}] CodeFixerAgent → iteration={iteration} | "
            f"{n_changes} fixes | {n_remaining} remaining | fully_fixed={is_fixed}"
        )

        return {**state, "code_fix": result, "agent_trace": trace}
    return node_code_fixer


def code_fixer_should_loop(state: CyberAgentState) -> str:
    """Conditional edge: loop back to code_fixer if not fully fixed and under max iterations."""
    code_fix = state.get("code_fix") or {}
    if code_fix.get("skipped"):
        return "incident_response"
    iteration = code_fix.get("iteration", 0)
    is_fixed = code_fix.get("is_fully_fixed", True)
    if not is_fixed and iteration < MAX_CODE_FIX_ITERATIONS:
        return "code_fixer"
    return "incident_response"


# ══════════════════════════════════════════════════════════════════════
# NODE 6 — INCIDENT RESPONSE AGENT
# ══════════════════════════════════════════════════════════════════════

INCIDENT_RESPONSE_SYSTEM = """You are an Incident Response Commander following NIST SP 800-61.
Based on all prior agent findings, create a comprehensive incident response plan.

Return ONLY valid JSON (no markdown fences):
{
  "incident_classification": "Credential Attack / Data Breach / etc",
  "priority": "P1|P2|P3|P4",
  "timeline": {
    "immediate_0_1h": ["isolate affected systems", "preserve logs"],
    "short_term_1_24h": ["forensic analysis", "patch systems"],
    "long_term_1_7d": ["root cause analysis", "policy updates"]
  },
  "containment_steps": ["step 1", "step 2"],
  "eradication_steps": ["step 1", "step 2"],
  "recovery_steps": ["step 1", "step 2"],
  "evidence_to_preserve": ["/var/log/auth.log", "memory dump"],
  "stakeholders": ["CISO", "Legal", "PR"],
  "communications_template": "Brief incident notification text",
  "lessons_learned_items": ["item 1", "item 2"]
}"""

def build_incident_response_node(llm: ChatOpenAI):
    def node_incident_response(state: CyberAgentState) -> CyberAgentState:
        print("  [Agent] Incident Response Agent running...")
        aggregated = json.dumps({
            "log_findings": state.get("log_findings"),
            "threat_intel": state.get("threat_intel"),
            "vuln_scan": state.get("vuln_scan"),
        }, indent=2)

        user_prompt = (
            f"RAG CONTEXT:\n{state.get('rag_context', 'None')}\n\n"
            f"ALL PRIOR AGENT FINDINGS:\n{aggregated}\n\n"
            f"ORIGINAL INPUT:\n{state['raw_input']}"
        )
        try:
            raw = _call_llm(llm, INCIDENT_RESPONSE_SYSTEM, user_prompt)
            result = _parse_json_safe(raw)
        except Exception as e:
            result = {"error": str(e), "priority": "UNKNOWN"}

        trace = state.get("agent_trace", [])
        trace.append(f"[{_ts()}] IncidentResponseAgent → priority={result.get('priority','?')}")
        return {**state, "incident_plan": result, "agent_trace": trace}
    return node_incident_response


# ══════════════════════════════════════════════════════════════════════
# NODE 7 — POLICY CHECKER AGENT
# ══════════════════════════════════════════════════════════════════════

POLICY_CHECKER_SYSTEM = """You are a Security Compliance and Policy Expert.
Evaluate the provided information against NIST CSF 2.0, ISO 27001:2022, and SOC 2 Type II.
Use RAG context for specific control requirements.

Return ONLY valid JSON (no markdown fences):
{
  "overall_score": 45,
  "summary": "compliance overview",
  "frameworks": {
    "nist_csf": {
      "score": 50,
      "passing": ["ID.AM-1: Asset inventory exists"],
      "failing": ["PR.AT-1: No security training"],
      "partial": ["DE.AE-1: Partial anomaly detection"]
    },
    "iso_27001": {
      "score": 40,
      "passing": [],
      "failing": ["A.8.5: Secure authentication not enforced"],
      "partial": []
    },
    "soc2": {
      "score": 35,
      "passing": [],
      "failing": ["CC6.3: MFA not required"],
      "partial": []
    }
  },
  "gaps": [
    {
      "control": "CC6.3",
      "framework": "SOC2",
      "gap": "MFA not enforced",
      "risk": "HIGH",
      "remediation": "Implement MFA for all user accounts"
    }
  ],
  "quick_wins": ["Enable MFA", "Set 90-day log retention"],
  "compliance_roadmap": "Step-by-step prioritized path to compliance"
}"""

def build_policy_checker_node(llm: ChatOpenAI):
    def node_policy_checker(state: CyberAgentState) -> CyberAgentState:
        print("  [Agent] Policy Checker Agent running...")
        # Use @tool: check_compliance_control for enrichment
        compliance_context = ""
        input_lower = state["raw_input"].lower()
        if "mfa" in input_lower or "encryption" in input_lower or "training" in input_lower:
            compliance_context = check_compliance_control.invoke({"framework": "NIST CSF", "control": "access control MFA encryption"})
            compliance_context = f"\nTOOL(check_compliance_control) RESULT:\n{compliance_context}\n"

        user_prompt = (
            f"RAG CONTEXT:\n{state.get('rag_context', 'None')}\n"
            f"{compliance_context}\n"
            f"CONFIGURATION/POLICY TO EVALUATE:\n{state['raw_input']}\n\n"
            f"VULNERABILITY FINDINGS:\n{json.dumps(state.get('vuln_scan', {}), indent=2)}"
        )
        try:
            raw = _call_llm(llm, POLICY_CHECKER_SYSTEM, user_prompt)
            result = _parse_json_safe(raw)
        except Exception as e:
            result = {"error": str(e), "overall_score": 0}

        trace = state.get("agent_trace", [])
        trace.append(f"[{_ts()}] PolicyCheckerAgent → overall_score={result.get('overall_score','?')}")
        return {**state, "policy_gaps": result, "agent_trace": trace}
    return node_policy_checker


# ══════════════════════════════════════════════════════════════════════
# NODE 8 — REPORT SYNTHESIZER
# ══════════════════════════════════════════════════════════════════════

def node_synthesize_report(state: CyberAgentState) -> CyberAgentState:
    """Combine all agent outputs into a Markdown-formatted final report."""
    lf = state.get("log_findings") or {}
    ti = state.get("threat_intel") or {}
    vs = state.get("vuln_scan") or {}
    cf = state.get("code_fix") or {}
    ir = state.get("incident_plan") or {}
    pc = state.get("policy_gaps") or {}

    code_fix_metric = "Skipped" if cf.get("skipped") else "Iter {}/3".format(cf.get("iteration", 0))
    code_fix_detail = "—" if cf.get("skipped") else ("✅ Fixed" if cf.get("is_fully_fixed") else "❌ Remaining issues")

    lines = [
        f"📋 **Analysis Report** | Generated: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}` | Input: `{state.get('input_type', 'unknown').upper()}`",
        "",
        "---",
        "",
        "#### Agent Summary",
        "",
        "| Agent | Key Metric | Details |",
        "|-------|-----------|---------|" ,
        f"| 📡 Log Monitor | Severity: **{lf.get('severity','N/A')}** | {len(lf.get('findings',[]))} findings |",
        f"| 🕵️ Threat Intel | Exposure: **{ti.get('exposure_level','N/A')}** | {len(ti.get('cves',[]))} CVEs, {len(ti.get('mitre_ttps',[]))} TTPs |",
        f"| 🔍 Vuln Scanner | Risk: **{vs.get('risk_score','N/A')}/100** | {vs.get('total_findings',0)} findings |",
        f"| 🔧 Code Fixer | {code_fix_metric} | {code_fix_detail} |",
        f"| 🚨 Incident Response | Priority: **{ir.get('priority','N/A')}** | {ir.get('incident_classification','N/A')} |",
        f"| 📋 Policy Checker | Score: **{pc.get('overall_score','N/A')}/100** | {len(pc.get('gaps',[]))} gaps |",
    ]

    # Detailed findings (only show sections with data)
    if lf.get("findings"):
        lines += ["", "---", "", "#### 📡 Log Findings", "",
                  f"> {lf.get('summary','')}", "",
                  "| Severity | Type | Detail | Source IP |",
                  "|----------|------|--------|-----------|"]
        for f in lf.get("findings", []):
            lines.append(f"| {f.get('severity','?')} | {f.get('type','?')} | {f.get('detail','?')} | `{f.get('source_ip','—')}` |")
        iocs = lf.get("indicators_of_compromise", [])
        if iocs:
            lines += ["", f"**IoCs:** `{'`, `'.join(iocs)}`"]

    if ti.get("cves") or ti.get("mitre_ttps"):
        lines += ["", "---", "", "#### 🕵️ Threat Intelligence", ""]
        if ti.get("summary"):
            lines.append(f"> {ti['summary']}")
            lines.append("")
        if ti.get("cves"):
            lines += ["| CVE | CVSS | Description | In Wild |", "|-----|------|-------------|---------|"]
            for cve in ti["cves"]:
                wild = "🔴 Yes" if cve.get("exploited_in_wild") else "—"
                lines.append(f"| `{cve.get('id','?')}` | {cve.get('cvss_score','?')} | {cve.get('description','?')} | {wild} |")
        if ti.get("mitre_ttps"):
            lines += ["", "**MITRE ATT&CK:**"]
            for ttp in ti["mitre_ttps"]:
                lines.append(f"- `{ttp.get('id','?')}` {ttp.get('name','?')} ({ttp.get('tactic','?')})")

    if vs.get("vulnerabilities"):
        lines += ["", "---", "", "#### 🔍 Vulnerabilities", "",
                  "| ID | Severity | Title | CWE | Fix |",
                  "|----|----------|-------|-----|-----|"]
        for v in vs.get("vulnerabilities", []):
            lines.append(f"| {v.get('id','?')} | {v.get('severity','?')} | {v.get('title','?')} | `{v.get('cwe','?')}` | {v.get('remediation','—')} |")

    if not cf.get("skipped") and cf.get("changes_made"):
        lines += ["", "---", "", f"#### 🔧 Code Fixer (Iteration {cf.get('iteration',0)}/3)", "",
                  "| Issue | Fix | Line |", "|-------|-----|------|"]
        for c in cf.get("changes_made", []):
            lines.append(f"| {c.get('issue','?')} | {c.get('fix','?')} | {c.get('line','?')} |")
        if cf.get("explanation"):
            lines += ["", f"> {cf['explanation']}"]

    if ir.get("timeline"):
        lines += ["", "---", "", "#### 🚨 Incident Response", "",
                  f"> **{ir.get('incident_classification','N/A')}**", "",
                  "| Phase | Actions |", "|-------|---------|"]
        tl = ir["timeline"]
        for phase, label in [("immediate_0_1h","🔴 0-1h"),("short_term_1_24h","🟡 1-24h"),("long_term_1_7d","🟢 1-7d")]:
            actions = tl.get(phase, [])
            if actions:
                lines.append(f"| {label} | {'; '.join(actions)} |")
        evidence = ir.get("evidence_to_preserve", [])
        if evidence:
            lines += ["", f"**Preserve:** `{'`, `'.join(evidence)}`"]

    if pc.get("frameworks"):
        lines += ["", "---", "", "#### 📋 Compliance", "",
                  "| Framework | Score | Gaps |", "|-----------|------:|-----:|"]
        fw = pc["frameworks"]
        for fk, fl in [("nist_csf","NIST CSF"),("iso_27001","ISO 27001"),("soc2","SOC 2")]:
            if fk in fw:
                lines.append(f"| {fl} | {fw[fk].get('score','?')}/100 | {len(fw[fk].get('failing',[]))} |")
        qw = pc.get("quick_wins", [])
        if qw:
            lines += ["", "**Quick Wins:** " + ", ".join(qw[:5])]

    # Execution Trace (collapsible)
    lines += ["", "---", "",
              "<details><summary>📝 <b>Execution Trace</b></summary>", "", "```"]
    for t in state.get("agent_trace", []):
        lines.append(t)
    lines += ["```", "", "</details>"]

    report = "\n".join(lines)
    trace = state.get("agent_trace", [])
    trace.append(f"[{_ts()}] ReportSynthesizer → report generated ({len(report)} chars)")
    return {**state, "final_report": report, "agent_trace": trace}


# ══════════════════════════════════════════════════════════════════════
# LANGGRAPH ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════

def build_cybersec_graph(llm: ChatOpenAI, kb: VectorKnowledgeBase) -> Any:
    """
    Build and compile the LangGraph state machine.

    Flow:
        classify_input → rag_retrieve → log_monitor → threat_intel
                                     → vuln_scanner → incident_response
                                                    → policy_checker
                                                    → synthesize_report → END
    """
    graph = StateGraph(CyberAgentState)

    # Set global kb reference for @tool functions
    global _kb_instance
    _kb_instance = kb

    # Register nodes
    graph.add_node("classify_input",      node_input_classifier)
    graph.add_node("rag_retrieve",        build_rag_node(kb))
    graph.add_node("log_monitor",         build_log_monitor_node(llm))
    graph.add_node("threat_intel",        build_threat_intel_node(llm))
    graph.add_node("vuln_scanner",        build_vuln_scanner_node(llm))
    graph.add_node("code_fixer",          build_code_fixer_node(llm))
    graph.add_node("incident_response",   build_incident_response_node(llm))
    graph.add_node("policy_checker",      build_policy_checker_node(llm))
    graph.add_node("synthesize_report",   node_synthesize_report)

    # Define edges
    graph.set_entry_point("classify_input")
    graph.add_edge("classify_input",    "rag_retrieve")
    graph.add_edge("rag_retrieve",      "log_monitor")
    graph.add_edge("log_monitor",       "threat_intel")
    graph.add_edge("threat_intel",      "vuln_scanner")
    graph.add_edge("vuln_scanner",      "code_fixer")
    # Conditional loop: code_fixer → code_fixer (if not fixed) OR → incident_response
    graph.add_conditional_edges(
        "code_fixer",
        code_fixer_should_loop,
        {"code_fixer": "code_fixer", "incident_response": "incident_response"},
    )
    graph.add_edge("incident_response", "policy_checker")
    graph.add_edge("policy_checker",    "synthesize_report")
    graph.add_edge("synthesize_report", END)

    return graph.compile()


# ══════════════════════════════════════════════════════════════════════
# HELPER
# ══════════════════════════════════════════════════════════════════════

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run_analysis(user_input: str, save_report: bool = True) -> dict:
    """
    Run the full multi-agent cybersecurity analysis pipeline.

    Args:
        user_input: Logs, code, config, or policy text to analyze
        save_report: Whether to save the final report to disk

    Returns:
        Final CyberAgentState dict with all agent results
    """
    print("\n" + "=" * 60)
    print("  CyberSecurity Multi-Agent System")
    print("  Stack: LangGraph · OpenRouter · HuggingFace · LlamaIndex · ChromaDB")
    print("=" * 60)

    # 1. Initialize LLM (OpenRouter)
    print("\n[1/4] Connecting to OpenRouter LLM...")
    llm = build_llm()
    print(f"  Model: {Config.LLM_MODEL}")

    # 2. Initialize HuggingFace embeddings
    print("\n[2/4] Loading HuggingFace embedding model...")
    embeddings = build_embeddings()

    # 3. Initialize vector knowledge base
    print("\n[3/4] Setting up LlamaIndex + ChromaDB vector store...")
    kb = VectorKnowledgeBase(embeddings)

    # 4. Build and run LangGraph
    print("\n[4/4] Building LangGraph pipeline and running agents...\n")
    app = build_cybersec_graph(llm, kb)

    initial_state: CyberAgentState = {
        "raw_input":     user_input,
        "input_type":    "general",
        "log_findings":  None,
        "threat_intel":  None,
        "vuln_scan":     None,
        "code_fix":      None,
        "incident_plan": None,
        "policy_gaps":   None,
        "agent_trace":   [],
        "errors":        [],
        "rag_context":   None,
        "final_report":  None,
        "started_at":    datetime.now().isoformat(),
    }

    t0 = time.time()
    final_state = app.invoke(initial_state)
    elapsed = time.time() - t0

    # Print report
    print("\n" + final_state.get("final_report", "No report generated"))
    print(f"\n⏱  Total analysis time: {elapsed:.1f}s")

    # Save report
    if save_report and final_state.get("final_report"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Config.PROJECT_DIR / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = output_dir / f"cybersec_report_{ts}.txt"        
        with open(fname, "w", encoding="utf-8") as f:
            f.write(final_state["final_report"])
        print(f"💾 Report saved: {fname}")

        # Also save JSON results
        json_fname = output_dir / f"cybersec_results_{ts}.json"
        json_data = {k: v for k, v in final_state.items() if k != "final_report"}        
        with open(json_fname, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)
        print(f"💾 JSON results saved: {json_fname}")

    return final_state


# ══════════════════════════════════════════════════════════════════════
# EXAMPLE SCENARIOS
# ══════════════════════════════════════════════════════════════════════

EXAMPLE_INPUTS = {
    "ssh_brute_force": """
Nov 12 03:14:22 web01 sshd[12345]: Failed password for root from 192.168.1.105 port 54321 ssh2
Nov 12 03:14:23 web01 sshd[12346]: Failed password for root from 192.168.1.105 port 54322 ssh2
Nov 12 03:14:24 web01 sshd[12347]: Failed password for admin from 192.168.1.105 port 54323 ssh2
Nov 12 03:14:25 web01 sshd[12348]: Failed password for ubuntu from 192.168.1.105 port 54324 ssh2
Nov 12 03:14:30 web01 sshd[12350]: Failed password for root from 185.220.101.45 port 12345 ssh2
Nov 12 03:14:50 web01 sshd[12360]: Accepted password for deploy from 185.220.101.45 port 12346 ssh2
""",

    "vulnerable_code": """
import sqlite3, flask
app = flask.Flask(__name__)
DB_PASSWORD = "supersecret123"

@app.route('/user')
def get_user():
    user_id = flask.request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection!
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchall())

@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form['username']
    password = flask.request.form['password']
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # No password hashing!
    conn = sqlite3.connect('users.db')
    result = conn.execute(query).fetchone()
    if result:
        return "Logged in!"
    return "Failed"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # debug=True in production!
""",

    "docker_misconfig": """
Docker Compose Configuration:
services:
  app:
    image: myapp:latest
    user: root
    privileged: true
    ports:
      - "0.0.0.0:22:22"
      - "0.0.0.0:3306:3306"
      - "0.0.0.0:6379:6379"
    volumes:
      - /etc:/etc:rw
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
      - DB_PASSWORD=admin123
      - NODE_ENV=development
    cap_add:
      - ALL
    security_opt:
      - no-new-privileges:false
    network_mode: host
""",

    "policy_audit": """
Company Security Policy Review:
- Password policy: minimum 6 characters, no complexity requirements, no rotation
- MFA: not enforced for any accounts (including admin)
- Security training: no formal program exists
- Log retention: 7 days only (on local servers, no SIEM)
- Vulnerability scanning: ad-hoc only, no scheduled scans
- Incident response: undocumented, informal process
- Data encryption: databases NOT encrypted at rest
- Backup testing: last tested 18 months ago
- Access reviews: never formally conducted
- Vendor risk: no third-party risk assessments
- Penetration testing: never performed
- Change management: informal, no approval process
- Endpoint protection: basic antivirus only, no EDR
"""
}


def cli():
    import sys

    # Force UTF-8 encoding for stdout to prevent UnicodeEncodeError on Windows terminals
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8')

    # Select input (pass scenario name as argument, or default to ssh_brute_force)
    scenario = sys.argv[1] if len(sys.argv) > 1 else "ssh_brute_force"
    user_input = EXAMPLE_INPUTS.get(scenario, EXAMPLE_INPUTS["ssh_brute_force"])

    print(f"\nRunning scenario: {scenario}")
    print(f"Input preview: {user_input.strip()[:120]}...")

    results = run_analysis(user_input, save_report=True)


if __name__ == "__main__":
    cli()
