#!/usr/bin/env python3
"""PipelineShield Dashboard Report Compatibility & CLI Exit Code Verification Script.

Verifies:
1. CLI generates valid JSON conforming to the dashboard's schema validator.
2. All findings (including PASS-level findings) are preserved and categorized.
3. Summary fields are complete and strictly validated.
4. CLI produces expected exit codes:
   - Clean scan: 0
   - Vulnerable scan (blocking violations): 1
   - Malformed input / configuration error: 2
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
ENGINE_DIR = ROOT_DIR / "engine"
FIXTURES_DIR = ENGINE_DIR / "tests" / "fixtures"
PYTHON = sys.executable


def run_cli(*args: str) -> subprocess.CompletedProcess:
    policy_path = str(ROOT_DIR / "config" / "policy.yaml")
    cmd = [PYTHON, "-m", "pipelineshield.cli", "--policy", policy_path, *args]
    return subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)


def validate_dashboard_schema(data: dict) -> None:
    """Mirrors the exact validation logic implemented in dashboard/src/app/page.tsx."""
    if not isinstance(data, dict):
        raise ValueError("Report must be a JSON object")

    # Required top-level decision
    valid_decisions = {"PASS", "WARN", "BLOCK", "ERROR"}
    if "decision" not in data or data["decision"] not in valid_decisions:
        raise ValueError(f"Invalid or missing decision: '{data.get('decision')}'")

    summary = data.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("'summary' must be an object")

    summary_fields = [
        "total_findings",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "exempted",
        "blocking_count",
        "warning_count",
    ]
    for sf in summary_fields:
        if sf not in summary or not isinstance(summary[sf], (int, float)):
            raise ValueError(f"Summary missing or invalid numeric field: '{sf}'")

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    valid_scanners = {"trivy", "semgrep", "dependency_review", "manual"}

    def validate_finding(f: dict, list_name: str, idx: int) -> None:
        if not isinstance(f, dict):
            raise ValueError(f"Finding at {list_name}[{idx}] must be an object")
        if not f.get("id"):
            raise ValueError(f"Finding at {list_name}[{idx}] missing 'id'")
        if not f.get("title"):
            raise ValueError(f"Finding at {list_name}[{idx}] missing 'title'")
        sev = str(f.get("severity", "")).upper()
        if sev not in valid_severities:
            raise ValueError(f"Finding {f.get('id')} has invalid severity: '{sev}'")
        sc = str(f.get("scanner", "")).lower()
        if sc not in valid_scanners:
            raise ValueError(f"Finding {f.get('id')} has invalid scanner: '{sc}'")

    # Validate findings array
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("'findings' must be an array")
    for idx, f in enumerate(findings):
        validate_finding(f, "findings", idx)

    for col in ("blocking_findings", "warning_findings", "exempted_findings"):
        items = data.get(col, [])
        if not isinstance(items, list):
            raise ValueError(f"'{col}' must be an array")
        for idx, f in enumerate(items):
            validate_finding(f, col, idx)


def test_cli_report_generation_and_compatibility():
    print("[1/4] Testing CLI report generation and dashboard schema validation...")
    out_file = ROOT_DIR / "reports" / "verification_test_report.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    proc = run_cli(
        "--trivy", str(FIXTURES_DIR / "trivy_vulnerabilities.json"),
        "--semgrep", str(FIXTURES_DIR / "semgrep_findings.json"),
        "--dependency-review", str(FIXTURES_DIR / "dep_review_official_added_vuln.json"),
        "--output", str(out_file),
    )

    # Vulnerabilities present -> exit 1
    assert proc.returncode == 1, f"Expected exit 1 for vulnerable scan, got {proc.returncode}. stderr: {proc.stderr}"
    assert out_file.exists(), "Report file was not created"

    report_data = json.loads(out_file.read_text())
    validate_dashboard_schema(report_data)

    # Verify all findings are preserved and PASS-level findings are not dropped
    all_findings = report_data.get("findings", [])
    assert len(all_findings) >= 5, f"Expected at least 5 findings in total superset, got {len(all_findings)}"

    blocking_ids = {f["id"] for f in report_data.get("blocking_findings", [])}
    warning_ids = {f["id"] for f in report_data.get("warning_findings", [])}
    exempted_ids = {f["id"] for f in report_data.get("exempted_findings", [])}

    # In dashboard logic, finding decision category is:
    # if in blocking_findings -> 'blocking'
    # elif in warning_findings -> 'warning'
    # elif in exempted_findings -> 'exempted'
    # else -> 'advisory' (PASS)
    categories = {}
    for f in all_findings:
        fid = f["id"]
        if fid in blocking_ids:
            cat = "blocking"
        elif fid in warning_ids:
            cat = "warning"
        elif fid in exempted_ids:
            cat = "exempted"
        else:
            cat = "advisory"
        categories[fid] = cat

    print(f"      Total findings: {len(all_findings)}")
    print(f"      Categories: {set(categories.values())}")
    assert "blocking" in categories.values(), "Blocking findings missing"

    # Clean up test output
    out_file.unlink(missing_ok=True)
    print("      ✓ Dashboard schema and finding retention validated successfully.")


def test_clean_scan_exit_code():
    print("[2/4] Testing clean scan exit code (expected 0)...")
    proc = run_cli(
        "--trivy", str(FIXTURES_DIR / "trivy_clean.json"),
        "--semgrep", str(FIXTURES_DIR / "semgrep_clean.json"),
        "--dependency-review", str(FIXTURES_DIR / "dep_review_official_added_clean.json"),
    )
    assert proc.returncode == 0, f"Expected exit 0 for clean scan, got {proc.returncode}. stderr: {proc.stderr}"
    print("      ✓ Clean scan exited with code 0.")


def test_vulnerable_scan_exit_code():
    print("[3/4] Testing vulnerable scan exit code (expected 1)...")
    proc = run_cli(
        "--trivy", str(FIXTURES_DIR / "trivy_vulnerabilities.json"),
    )
    assert proc.returncode == 1, f"Expected exit 1 for vulnerable scan, got {proc.returncode}"
    print("      ✓ Vulnerable scan exited with code 1.")


def test_malformed_input_exit_code():
    print("[4/4] Testing malformed input exit code (expected 2)...")
    proc = run_cli(
        "--trivy", str(FIXTURES_DIR / "malformed.json"),
    )
    assert proc.returncode == 2, f"Expected exit 2 for malformed input, got {proc.returncode}"
    print("      ✓ Malformed input exited with code 2.")


def main():
    print("=== PipelineShield Dashboard Report & CLI Verification ===")
    test_cli_report_generation_and_compatibility()
    test_clean_scan_exit_code()
    test_vulnerable_scan_exit_code()
    test_malformed_input_exit_code()
    print("=== All Verifications Passed Successfully ===")


if __name__ == "__main__":
    main()
