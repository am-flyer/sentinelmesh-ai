"""Generate a visual image of the LangGraph pipeline."""
from pathlib import Path
import sys

OUTPUT_PATH = Path(__file__).resolve().parents[1] / "assets" / "langgraph_pipeline.png"

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from main import (
        build_llm,
        build_embeddings,
        build_cybersec_graph,
        VectorKnowledgeBase,
    )
else:
    from ..main import (
        build_llm,
        build_embeddings,
        build_cybersec_graph,
        VectorKnowledgeBase,
    )

print("Initializing pipeline to generate graph image...")
llm = build_llm()
embeddings = build_embeddings()
kb = VectorKnowledgeBase(embeddings)
app = build_cybersec_graph(llm, kb)

# Method 1: LangGraph built-in (requires pygraphviz or grandalf)
try:
    png_data = app.get_graph().draw_png()
    with open(OUTPUT_PATH, "wb") as f:
        f.write(png_data)
    print(f"Graph saved as {OUTPUT_PATH} (using LangGraph draw_png)")
except Exception as e:
    print(f"draw_png not available ({e}), falling back to matplotlib...")

    # Method 2: Matplotlib fallback with code_fixer loop
    import matplotlib.pyplot as plt
    import matplotlib.patches as FancyArrowPatch

    nodes = [
        ("classify_input",    "🏷️  Classify Input"),
        ("rag_retrieve",      "📚  RAG Retrieve"),
        ("log_monitor",       "📡  Log Monitor Agent"),
        ("threat_intel",      "🕵️  Threat Intel Agent"),
        ("vuln_scanner",      "🔍  Vuln Scanner Agent"),
        ("code_fixer",        "🔧  Code Fixer Agent (iterative)"),
        ("incident_response", "🚨  Incident Response Agent"),
        ("policy_checker",    "📋  Policy Checker Agent"),
        ("synthesize_report", "📝  Synthesize Report"),
    ]

    fig, ax = plt.subplots(1, 1, figsize=(8, 14))
    ax.set_xlim(-2, 12)
    ax.set_ylim(-0.5, len(nodes) + 2.5)
    ax.axis("off")
    ax.set_title("CyberSecurity Multi-Agent LangGraph Pipeline\n(with iterative Code Fixer loop)",
                 fontsize=13, fontweight="bold", pad=20)

    center_x = 5
    node_positions = {}

    # Draw START
    start_y = len(nodes) + 1.5
    ax.annotate("START", xy=(center_x, start_y), fontsize=11, ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#4CAF50", edgecolor="black"),
                color="white", fontweight="bold")

    # Draw nodes
    for i, (key, label) in enumerate(nodes):
        y = len(nodes) - i
        node_positions[key] = (center_x, y)

        # Highlight code_fixer differently
        if key == "code_fixer":
            facecolor = "#FF9800"
            edgecolor = "#E65100"
        else:
            facecolor = "#2196F3"
            edgecolor = "#1565C0"

        ax.annotate(label, xy=(center_x, y), fontsize=9.5, ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.4", facecolor=facecolor, edgecolor=edgecolor, alpha=0.9),
                    color="white", fontweight="bold")

    # Draw END
    end_y = 0
    ax.annotate("END", xy=(center_x, end_y), fontsize=11, ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#f44336", edgecolor="black"),
                color="white", fontweight="bold")

    # Draw arrows between sequential nodes
    # START -> first node
    ax.annotate("", xy=(center_x, node_positions["classify_input"][1] + 0.3),
                xytext=(center_x, start_y - 0.25),
                arrowprops=dict(arrowstyle="->", color="black", lw=1.5))

    # Sequential edges
    sequential = [
        ("classify_input", "rag_retrieve"),
        ("rag_retrieve", "log_monitor"),
        ("log_monitor", "threat_intel"),
        ("threat_intel", "vuln_scanner"),
        ("vuln_scanner", "code_fixer"),
        # code_fixer -> incident_response is conditional (drawn separately)
        ("incident_response", "policy_checker"),
        ("policy_checker", "synthesize_report"),
    ]

    for src, dst in sequential:
        src_y = node_positions[src][1]
        dst_y = node_positions[dst][1]
        ax.annotate("", xy=(center_x, dst_y + 0.3),
                    xytext=(center_x, src_y - 0.3),
                    arrowprops=dict(arrowstyle="->", color="black", lw=1.5))

    # code_fixer -> incident_response (conditional: when fixed)
    cf_y = node_positions["code_fixer"][1]
    ir_y = node_positions["incident_response"][1]
    ax.annotate("", xy=(center_x, ir_y + 0.3),
                xytext=(center_x, cf_y - 0.3),
                arrowprops=dict(arrowstyle="->", color="green", lw=2))
    ax.text(center_x + 1.8, (cf_y + ir_y) / 2, "fixed ✅", fontsize=8, color="green", fontweight="bold")

    # code_fixer LOOP (conditional: when not fixed)
    loop_x = center_x + 4.2
    ax.annotate("",
                xy=(center_x + 2.5, cf_y + 0.15),
                xytext=(center_x + 2.5, cf_y - 0.15),
                arrowprops=dict(arrowstyle="->", color="#FF5722", lw=2,
                                connectionstyle="arc3,rad=-1.8"))
    # Loop label
    ax.text(loop_x - 0.5, cf_y, "loop\n(max 3x)", fontsize=8, color="#FF5722",
            fontweight="bold", ha="center", va="center",
            bbox=dict(boxstyle="round,pad=0.2", facecolor="#FFF3E0", edgecolor="#FF5722", alpha=0.8))

    # Last node -> END
    ax.annotate("", xy=(center_x, end_y + 0.25),
                xytext=(center_x, node_positions["synthesize_report"][1] - 0.3),
                arrowprops=dict(arrowstyle="->", color="black", lw=1.5))

    plt.tight_layout()
    plt.savefig(OUTPUT_PATH, dpi=150, bbox_inches="tight")
    print(f"Graph saved as {OUTPUT_PATH} (using matplotlib)")
