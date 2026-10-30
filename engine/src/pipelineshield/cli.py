"""Command-line interface for PipelineShield Policy Engine.

Exit codes:
    0 — PASS or non-blocking WARN
    1 — BLOCK
    2 — ERROR (configuration failure, invalid input, engine failure)

Security requirements:
    - --findings is REQUIRED. Missing findings produce exit code 2, not PASS.
    - An explicit --findings file containing an empty list [] is valid (clean scan).
    - Unknown scanner format requires --scanner to be specified for native parsers.
    - JSON parse errors return exit code 2.
    - Policy load errors return exit code 2.
    - ERROR gate decisions return exit code 2.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipelineshield.config import load_policy
from pipelineshield.models import GateDecision
from pipelineshield.normalizer import (
    NormalizationError,
    Normalizer,
    normalize_finding_list,
)
from pipelineshield.policy_engine import PolicyEngine
from pipelineshield.reporter import Reporter

_EXIT_PASS = 0
_EXIT_BLOCK = 1
_EXIT_ERROR = 2


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="pipelineshield",
        description=(
            "PipelineShield — Automated DevSecOps Policy Gatekeeper.\n"
            "Evaluates security scanner findings against declarative policy rules."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  PASS or WARN (non-blocking)\n"
            "  1  BLOCK (findings violate policy)\n"
            "  2  ERROR (invalid input, policy load failure, or engine error)\n\n"
            "Examples:\n"
            "  pipelineshield --policy config/policy.yaml --findings trivy.json --scanner trivy\n"
            "  pipelineshield --policy config/policy.yaml --findings semgrep.json --scanner semgrep\n"
            "  pipelineshield --policy config/policy.yaml --findings findings.json\n"
        ),
    )

    parser.add_argument(
        "--policy", "-p",
        required=True,
        metavar="POLICY_YAML",
        help="Path to security policy YAML file.",
    )
    parser.add_argument(
        "--findings", "-f",
        default=None,
        metavar="FINDINGS_JSON",
        help=(
            "Path to JSON file containing scanner findings. "
            "An empty list [] in the file is valid and represents a clean scan."
        ),
    )
    parser.add_argument(
        "--trivy",
        default=None,
        metavar="TRIVY_JSON",
        help="Path to native Trivy JSON output file.",
    )
    parser.add_argument(
        "--semgrep",
        default=None,
        metavar="SEMGREP_JSON",
        help="Path to native Semgrep JSON output file.",
    )
    parser.add_argument(
        "--dependency-review",
        default=None,
        metavar="DEP_REVIEW_JSON",
        help="Path to native GitHub Dependency Review JSON output file.",
    )
    parser.add_argument(
        "--scanner",
        metavar="SCANNER",
        choices=["trivy", "semgrep", "dependency_review", "pipelineshield"],
        default="pipelineshield",
        help=(
            "Scanner format of the findings file when using --findings. "
            "Use 'trivy', 'semgrep', or 'dependency_review' for native formats. "
            "Use 'pipelineshield' (default) for the normalized intermediate format."
        ),
    )
    parser.add_argument(
        "--event-name",
        default=os.environ.get("GITHUB_EVENT_NAME"),
        metavar="EVENT_NAME",
        help="CI event name (e.g. 'pull_request', 'push', 'workflow_dispatch').",
    )
    parser.add_argument(
        "--scanner-status",
        nargs="*",
        default=None,
        metavar="SCANNER=STATUS",
        help="Explicit scanner status overrides (e.g. trivy=COMPLETED dependency_review=NOT_APPLICABLE).",
    )
    parser.add_argument(
        "--output", "-o",
        default="reports/security-summary.json",
        metavar="OUTPUT_JSON",
        help="Path to write evaluation JSON report (default: reports/security-summary.json).",
    )
    parser.add_argument(
        "--summary-md",
        metavar="SUMMARY_MD",
        default=None,
        help="Optional path to write GitHub Step Summary markdown.",
    )
    return parser


def parse_args(args: Optional[list] = None) -> argparse.Namespace:
    """Parse and return CLI arguments."""
    parser = create_parser()
    return parser.parse_args(args)


def _load_json_file(path: Path) -> Any:
    """Load and parse a JSON file.

    Returns:
        Parsed JSON object.

    Raises:
        FileNotFoundError, ValueError, OSError: On file access or JSON parsing errors.
    """
    if not path.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in findings file '{path}': {e}") from e
    except OSError as e:
        raise OSError(f"Cannot read findings file '{path}': {e}") from e


def _normalize_findings(scanner: str, raw_data: Any) -> list:
    """Dispatch to the appropriate scanner normalizer.

    Returns:
        List of normalized Finding objects.

    Raises:
        NormalizationError: On normalization failure or invalid structure.
    """
    if scanner == "trivy":
        return Normalizer.from_trivy(raw_data)
    if scanner == "semgrep":
        return Normalizer.from_semgrep(raw_data)
    if scanner == "dependency_review":
        return Normalizer.from_dependency_review(raw_data)
    # "pipelineshield" — generic normalized format
    if not isinstance(raw_data, list):
        # Support {"findings": [...]} wrapper
        if isinstance(raw_data, dict) and "findings" in raw_data:
            raw_data = raw_data["findings"]
            if not isinstance(raw_data, list):
                raise NormalizationError(
                    "'findings' key in JSON file must contain a list."
                )
        else:
            raise NormalizationError(
                "PipelineShield format expects a JSON list or "
                "an object with a 'findings' key."
            )
    return normalize_finding_list(raw_data)


def main(args: Optional[list] = None) -> int:
    """Run PipelineShield policy evaluation.

    Returns:
        Exit code: 0 (PASS/WARN), 1 (BLOCK), 2 (ERROR).
    """
    parser = create_parser()
    parsed = parser.parse_args(args)

    # --- Load policy ---
    try:
        policy = load_policy(parsed.policy)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return _EXIT_ERROR
    except (ValueError, TypeError) as e:
        print(f"[ERROR] Policy configuration error: {e}", file=sys.stderr)
        return _EXIT_ERROR
    except Exception as e:
        print(f"[ERROR] Unexpected error loading policy: {e}", file=sys.stderr)
        return _EXIT_ERROR

    # --- Check scanner input requirements ---
    all_scanners_disabled = (
        not policy.scanners.trivy.enabled
        and not policy.scanners.semgrep.enabled
        and not policy.scanners.dependency_review.enabled
    )

    has_input = bool(
        parsed.findings
        or parsed.trivy
        or parsed.semgrep
        or parsed.dependency_review
    )

    if not has_input:
        if not all_scanners_disabled:
            parser.error(
                "At least one findings file is required when security scanners are enabled in policy. "
                "Specify --findings (with optional --scanner), or one or more of "
                "--trivy, --semgrep, --dependency-review."
            )
        print(
            "[WARN] All security scanners are disabled by policy configuration. "
            "No security scanning was performed."
        )

    # --- Load findings ---
    normalized = []
    try:
        if parsed.findings:
            findings_path = Path(parsed.findings)
            raw_data = _load_json_file(findings_path)
            normalized.extend(_normalize_findings(parsed.scanner, raw_data))
        if parsed.trivy:
            trivy_path = Path(parsed.trivy)
            raw_data = _load_json_file(trivy_path)
            normalized.extend(Normalizer.from_trivy(raw_data))
        if parsed.semgrep:
            semgrep_path = Path(parsed.semgrep)
            raw_data = _load_json_file(semgrep_path)
            normalized.extend(Normalizer.from_semgrep(raw_data))
        if parsed.dependency_review:
            dep_path = Path(parsed.dependency_review)
            raw_data = _load_json_file(dep_path)
            normalized.extend(Normalizer.from_dependency_review(raw_data))
    except (FileNotFoundError, OSError, ValueError, NormalizationError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return _EXIT_ERROR
    except Exception as e:
        print(f"[ERROR] Unexpected error processing findings: {e}", file=sys.stderr)
        return _EXIT_ERROR

    # --- Resolve scanner execution statuses ---
    explicit_status: Dict[str, str] = {}
    if parsed.scanner_status:
        for item in parsed.scanner_status:
            if "=" in item:
                k, v = item.split("=", 1)
                explicit_status[k.strip().lower()] = v.strip().upper()

    resolved_status: Dict[str, str] = {}
    for sc in ("trivy", "semgrep", "dependency_review"):
        if sc in explicit_status:
            resolved_status[sc] = explicit_status[sc]
            continue

        sc_cfg = getattr(policy.scanners, sc)
        if not sc_cfg.enabled:
            resolved_status[sc] = "DISABLED"
        elif sc == "trivy":
            if parsed.trivy or (parsed.findings and parsed.scanner == "trivy"):
                resolved_status[sc] = "COMPLETED"
            elif parsed.findings and parsed.scanner == "pipelineshield":
                resolved_status[sc] = "COMPLETED"
            elif parsed.event_name:
                resolved_status[sc] = "FAILED"
            else:
                resolved_status[sc] = "NOT_APPLICABLE"
        elif sc == "semgrep":
            if parsed.semgrep or (parsed.findings and parsed.scanner == "semgrep"):
                resolved_status[sc] = "COMPLETED"
            elif parsed.findings and parsed.scanner == "pipelineshield":
                resolved_status[sc] = "COMPLETED"
            elif parsed.event_name:
                resolved_status[sc] = "FAILED"
            else:
                resolved_status[sc] = "NOT_APPLICABLE"
        elif sc == "dependency_review":
            if parsed.dependency_review or (parsed.findings and parsed.scanner == "dependency_review"):
                resolved_status[sc] = "COMPLETED"
            elif parsed.findings and parsed.scanner == "pipelineshield":
                resolved_status[sc] = "COMPLETED"
            else:
                # If event is non-PR, dependency review is not applicable
                if parsed.event_name and parsed.event_name != "pull_request":
                    resolved_status[sc] = "NOT_APPLICABLE"
                elif parsed.event_name:
                    resolved_status[sc] = "FAILED"
                else:
                    resolved_status[sc] = "NOT_APPLICABLE"

    # --- Evaluate ---
    engine = PolicyEngine(policy)
    result = engine.evaluate_with_error_guard(normalized, scanner_status=resolved_status)

    # --- Write JSON report ---
    try:
        Reporter.write_json(result, parsed.output)
        print(f"[INFO] Report written to: {parsed.output}")
    except OSError as e:
        print(f"[ERROR] Could not write report to '{parsed.output}': {e}", file=sys.stderr)
        return _EXIT_ERROR

    # --- Write Markdown summary ---
    if parsed.summary_md:
        summary_path = Path(parsed.summary_md)
        try:
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(Reporter.to_markdown(result), encoding="utf-8")
            print(f"[INFO] Markdown summary written to: {parsed.summary_md}")
        except OSError as e:
            print(f"[WARN] Could not write Markdown summary: {e}", file=sys.stderr)

    # --- Console summary ---
    s = result.summary
    print(
        f"[RESULT] Decision: {result.decision.value} | "
        f"Total: {s.total_findings} | "
        f"Critical: {s.critical} | High: {s.high} | "
        f"Medium: {s.medium} | Low: {s.low} | "
        f"Exempted: {s.exempted}"
    )
    for reason in result.reasons:
        print(f"[REASON] {reason}")

    # --- Exit code ---
    if result.decision == GateDecision.BLOCK:
        print("[GATE] FAILED — findings violate security policy.", file=sys.stderr)
        return _EXIT_BLOCK

    if result.decision == GateDecision.ERROR:
        if any("no security scanning was performed" in r.lower() for r in result.reasons):
            print(
                "[GATE] ERROR — security assessment not performed (all scanners disabled or unexecuted).",
                file=sys.stderr,
            )
        else:
            print("[GATE] ERROR — engine could not complete evaluation.", file=sys.stderr)
        for err in result.errors:
            print(f"[ENGINE ERROR] {err}", file=sys.stderr)
        return _EXIT_ERROR

    if result.decision == GateDecision.WARN:
        print("[GATE] PASSED WITH WARNINGS — review advisory findings.")
        return _EXIT_PASS

    print("[GATE] PASSED — all findings within policy thresholds.")
    return _EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
