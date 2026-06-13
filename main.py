"""Command-line entry point for generating SentinelMesh reports."""

from __future__ import annotations

import argparse

from sentinelmesh.agents.pipeline import run_pipeline
from sentinelmesh.simulators.scenario_engine import SCENARIOS


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run a SentinelMesh AI scenario.")
    parser.add_argument(
        "scenario",
        choices=sorted(SCENARIOS),
        help="Threat scenario to analyze.",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable OpenRouter enrichment.",
    )
    return parser.parse_args()


def main() -> None:
    """Run the selected scenario and print the SOC report."""
    args = parse_args()
    report = run_pipeline(args.scenario, use_llm=not args.no_llm)
    print(report.to_text())


if __name__ == "__main__":
    main()
