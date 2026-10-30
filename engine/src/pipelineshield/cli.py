"""Command-line interface for PipelineShield Policy Engine."""

import argparse
import json
import sys
from pathlib import Path
from pipelineshield.config import load_policy
from pipelineshield.models import GateDecision
from pipelineshield.normalizer import Normalizer
from pipelineshield.policy_engine import PolicyEngine
from pipelineshield.reporter import Reporter


def parse_args(args=None):
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="pipelineshield",
        description="PipelineShield - Automated DevSecOps Policy Gatekeeper",
    )
    parser.add_argument(
        "--policy",
        "-p",
        default="config/policy.yaml",
        help="Path to security policy YAML file (default: config/policy.yaml)",
    )
    parser.add_argument(
        "--findings",
        "-f",
        help="Path to JSON findings file to evaluate",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="reports/security-summary.json",
        help="Path to write evaluation JSON report (default: reports/security-summary.json)",
    )
    parser.add_argument(
        "--summary-md",
        help="Path to write GitHub Step Summary markdown",
    )
    return parser.parse_args(args)


def main(args=None) -> int:
    """Run PipelineShield policy evaluation CLI."""
    parsed = parse_args(args)

    try:
        policy = load_policy(parsed.policy)
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 2

    raw_findings = []
    if parsed.findings:
        f_path = Path(parsed.findings)
        if not f_path.exists():
            print(f"Findings file not found: {f_path}", file=sys.stderr)
            return 2
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                raw_findings = json.load(f)
                if isinstance(raw_findings, dict) and "findings" in raw_findings:
                    raw_findings = raw_findings["findings"]
                elif not isinstance(raw_findings, list):
                    raw_findings = [raw_findings]
        except Exception as e:
            print(f"Error reading findings file: {e}", file=sys.stderr)
            return 2

    normalized = Normalizer.normalize_list(raw_findings)
    engine = PolicyEngine(policy)
    result = engine.evaluate(normalized)

    # Write JSON output
    Reporter.write_json(result, parsed.output)
    print(f"Evaluation report written to: {parsed.output}")

    # Write GitHub Markdown summary if requested
    if parsed.summary_md:
        md = Reporter.to_markdown(result)
        summary_path = Path(parsed.summary_md)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(md, encoding="utf-8")
        print(f"Markdown summary written to: {parsed.summary_md}")

    # Print summary to stdout
    print(f"Decision: {result.decision.value}")
    print(f"Total findings: {result.summary.total_findings} (Critical: {result.summary.critical}, High: {result.summary.high}, Medium: {result.summary.medium})")

    if result.decision == GateDecision.BLOCK:
        print("Security gate FAILED: Violations exceed policy thresholds.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
