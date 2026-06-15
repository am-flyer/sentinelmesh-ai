# SentinelMesh AI

Cybersecurity multi-agent analyzer built with LangGraph, HuggingFace embeddings, LlamaIndex, ChromaDB, and Gradio.

# Working Prototype for Demo

### 🚀 Live Demo
You can access the live web application here:
👉 [Launch Working Prototype](https://huggingface.co/spaces/bchoudha/C7HackathonGroup4)

### 📺 Video Demonstration
If the live environment is asleep or you'd prefer a quick walkthrough, you can watch the demonstration video here:
👉 [Watch Video Demo (Google Drive)](https://drive.google.com/file/d/125DG_nVNxIkB0j0YukBfr_cpfUIR1KcQ/view?usp=drive_link)

``` text
username: admin
password: change-me
```

## Structure

```text
CyberSecAiAgent/
└── sentinelmesh_ai/
    ├── .cursor/rules/
    │   └── agentic_design_patterns.mdc
    ├── .gitignore
    ├── dummy.env
    ├── pyproject.toml
    ├── requirements.txt
    ├── main.py
    ├── agents/
    ├── tools/
    ├── models/
    ├── simulators/
    ├── guardrails/
    ├── utils/
    │   └── generate_graph_image.py
    ├── api/
    │   ├── gradio_app.py
    │   ├── routers/
    │   └── schemas/
    ├── frontend/src/
    ├── data/chroma_cybersec_db/
    ├── assets/langgraph_pipeline.png
    ├── outputs/
    ├── ARCHITECTURE.md
    └── CODE.md
```

## Quick Start

```bash
cd /Downloads/CyberSecAiAgent/sentinelmesh_ai
cp dummy.env .env
pip install -e .
python main.py ssh_brute_force
python api/gradio_app.py
```

## Environment

Use `.env` for local credentials and `dummy.env` as the template. `.env` is ignored by Git.

## Notes

- The active UI is Gradio, so the runnable app is `api/gradio_app.py`.
- `frontend/`, `api/routers/`, and `api/schemas/` are placeholders until this project adds React or FastAPI.
- Generated analysis files belong in `outputs/`.
- Persistent ChromaDB data belongs in `data/chroma_cybersec_db/`.
