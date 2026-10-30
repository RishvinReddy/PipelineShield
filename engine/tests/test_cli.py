"""Tests for CLI exit codes, argument validation, and end-to-end invocation.

Tests use main() directly (not subprocess) for speed and proper coverage tracking.
CLI exit-code semantics:
    0 — PASS / non-blocking WARN
    1 — BLOCK
    2 — ERROR (bad args, bad policy, bad findings JSON, engine error)
"""

import json
import textwrap
from pathlib import Path

import pytest

from pipelineshield.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_json(tmp_path: Path, data, filename: str = "findings.json") -> Path:
    p = tmp_path / filename
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def write_policy(tmp_path: Path, content: str, filename: str = "policy.yaml") -> Path:
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# --findings is required
# ---------------------------------------------------------------------------

class TestFindingsRequired:
    def test_missing_findings_arg_causes_sysexit(self, tmp_path):
        """--findings is required; omitting it must not return 0."""
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        with pytest.raises(SystemExit) as exc_info:
            main(["--policy", str(policy_path)])
        # argparse exits with code 2 for missing required arguments
        assert exc_info.value.code != 0

    def test_nonexistent_findings_file_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--findings", str(tmp_path / "does_not_exist.json"),
        ])
        assert code == 2


# ---------------------------------------------------------------------------
# Clean scan (exit 0)
# ---------------------------------------------------------------------------

class TestCleanScan:
    def test_empty_findings_list_returns_0(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_report_written_for_clean_scan(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [])
        out_path = tmp_path / "report.json"
        main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(out_path),
        ])
        assert out_path.exists()
        report = json.loads(out_path.read_text())
        assert report["decision"] == "PASS"


# ---------------------------------------------------------------------------
# Critical vulnerability (exit 1)
# ---------------------------------------------------------------------------

class TestCriticalVulnerability:
    def test_critical_finding_returns_1(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [{
            "id": "CVE-2024-CRIT",
            "scanner": "trivy",
            "title": "Critical RCE",
            "severity": "CRITICAL",
        }])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 1

    def test_critical_report_contains_block_decision(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [{
            "id": "CVE-2024-CRIT",
            "scanner": "trivy",
            "title": "Critical RCE",
            "severity": "CRITICAL",
        }])
        out_path = tmp_path / "out.json"
        main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(out_path),
        ])
        report = json.loads(out_path.read_text())
        assert report["decision"] == "BLOCK"


# ---------------------------------------------------------------------------
# WARN (exit 0 with warnings)
# ---------------------------------------------------------------------------

class TestWarnScan:
    def test_medium_finding_returns_0(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [{
            "id": "WARN-001",
            "scanner": "semgrep",
            "title": "Medium Finding",
            "severity": "MEDIUM",
        }])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_medium_report_contains_warn_decision(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [{
            "id": "WARN-001",
            "scanner": "semgrep",
            "title": "Medium Finding",
            "severity": "MEDIUM",
        }])
        out_path = tmp_path / "out.json"
        main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(out_path),
        ])
        report = json.loads(out_path.read_text())
        assert report["decision"] == "WARN"


# ---------------------------------------------------------------------------
# Native scanner formats
# ---------------------------------------------------------------------------

class TestNativeScannerFormats:
    def test_trivy_scanner_format(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--findings", str(FIXTURES / "trivy_vulnerabilities.json"),
            "--scanner", "trivy",
            "--output", str(out_path),
        ])
        # Should BLOCK (has CRITICAL and HIGH findings)
        assert code == 1
        report = json.loads(out_path.read_text())
        assert report["decision"] == "BLOCK"

    def test_trivy_clean_scan(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--findings", str(FIXTURES / "trivy_clean.json"),
            "--scanner", "trivy",
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_semgrep_scanner_format(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--findings", str(FIXTURES / "semgrep_findings.json"),
            "--scanner", "semgrep",
            "--output", str(out_path),
        ])
        # ERROR severity → HIGH → BLOCK
        assert code == 1

    def test_semgrep_clean_scan(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--findings", str(FIXTURES / "semgrep_clean.json"),
            "--scanner", "semgrep",
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_dependency_review_format(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--findings", str(FIXTURES / "dep_review_findings.json"),
            "--scanner", "dependency_review",
            "--output", str(out_path),
        ])
        assert code == 1  # has CRITICAL finding


# ---------------------------------------------------------------------------
# Malformed input (exit 2)
# ---------------------------------------------------------------------------

class TestMalformedInput:
    def test_invalid_json_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not valid json", encoding="utf-8")
        code = main([
            "--policy", str(policy_path),
            "--findings", str(bad_json),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2

    def test_unknown_severity_in_pipelineshield_format_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [{
            "id": "CVE-001",
            "scanner": "trivy",
            "title": "Test",
            "severity": "EXTREME",  # not a valid severity
        }])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2

    def test_unknown_scanner_in_pipelineshield_format_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [{
            "id": "CVE-001",
            "scanner": "snyk",  # not a supported scanner
            "title": "Test",
            "severity": "HIGH",
        }])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2


# ---------------------------------------------------------------------------
# Invalid policy (exit 2)
# ---------------------------------------------------------------------------

class TestInvalidPolicy:
    def test_missing_policy_file_returns_2(self, tmp_path):
        findings_path = write_json(tmp_path, [])
        code = main([
            "--policy", str(tmp_path / "no_policy.yaml"),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2

    def test_invalid_policy_mode_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, """
            version: "1.0"
            enforcement:
              mode: aggressive
        """)
        findings_path = write_json(tmp_path, [])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2

    def test_unknown_policy_key_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, """
            version: "1.0"
            rogue_key: not_allowed
        """)
        findings_path = write_json(tmp_path, [])
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2


# ---------------------------------------------------------------------------
# Markdown summary output
# ---------------------------------------------------------------------------

class TestMarkdownOutput:
    def test_markdown_written_when_flag_given(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [])
        md_path = tmp_path / "summary.md"
        main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
            "--summary-md", str(md_path),
        ])
        assert md_path.exists()
        content = md_path.read_text()
        assert "PipelineShield" in content

    def test_markdown_not_written_without_flag(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = write_json(tmp_path, [])
        md_path = tmp_path / "summary.md"
        main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert not md_path.exists()


# ---------------------------------------------------------------------------
# Pipelineshield findings format wrapper
# ---------------------------------------------------------------------------

class TestFindingsWrapper:
    def test_findings_key_wrapper_accepted(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        findings_path = tmp_path / "wrapped.json"
        findings_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_invalid_wrapper_returns_2(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        # Non-list, non-wrapper dict
        findings_path = write_json(tmp_path, {"some_other_key": []})
        code = main([
            "--policy", str(policy_path),
            "--findings", str(findings_path),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 2


# ---------------------------------------------------------------------------
# Multi-scanner CLI arguments
# ---------------------------------------------------------------------------

class TestMultiScannerCLI:
    def test_trivy_flag_alone(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_clean.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_semgrep_flag_alone(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--semgrep", str(FIXTURES / "semgrep_clean.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_dependency_review_flag_alone(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--dependency-review", str(FIXTURES / "dependency_review_clean.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_combined_multi_scanner_all_clean(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_clean.json"),
            "--semgrep", str(FIXTURES / "semgrep_clean.json"),
            "--dependency-review", str(FIXTURES / "dependency_review_clean.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_combined_multi_scanner_with_violation_blocks(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_vulnerabilities.json"),
            "--semgrep", str(FIXTURES / "semgrep_clean.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 1

    def test_trivy_blocking_misconfiguration_exits_1(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_blocking_misconfig.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 1

    def test_trivy_clean_misconfiguration_exits_0(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_clean_misconfig.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_trivy_exposed_secret_exits_1(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_exposed_secret.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 1

    def test_trivy_clean_secrets_exits_0(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_clean_secrets.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 0

    def test_trivy_mixed_scan_blocks(self, tmp_path):
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_mixed_results.json"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert code == 1

    def test_cli_all_scanners_disabled_mode_exits_0(self, tmp_path):
        """When all scanners are disabled in policy, CLI does not require inputs and exits 0."""
        policy_yaml = """
        version: "1.0"
        scanners:
          trivy:
            enabled: false
          semgrep:
            enabled: false
          dependency_review:
            enabled: false
        """
        policy_path = write_policy(tmp_path, policy_yaml)
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--output", str(out_path),
        ])
        assert code == 0
        data = json.loads(out_path.read_text())
        assert data["decision"] == "PASS"
        assert data["scanner_status"] == {
            "trivy": "DISABLED",
            "semgrep": "DISABLED",
            "dependency_review": "DISABLED",
        }
        assert any("all security scanners are disabled" in r.lower() for r in data["reasons"])

    def test_cli_push_event_marks_dependency_review_not_applicable(self, tmp_path):
        """On a push event, omitted Dependency Review report records NOT_APPLICABLE."""
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_clean.json"),
            "--semgrep", str(FIXTURES / "semgrep_clean.json"),
            "--event-name", "push",
            "--output", str(out_path),
        ])
        assert code == 0
        data = json.loads(out_path.read_text())
        assert data["scanner_status"]["dependency_review"] == "NOT_APPLICABLE"
        assert data["scanner_status"]["trivy"] == "COMPLETED"
        assert data["scanner_status"]["semgrep"] == "COMPLETED"

    def test_cli_pr_event_missing_dependency_review_fails_closed(self, tmp_path):
        """On a PR event, if an enabled scanner output is missing, it is marked FAILED and fails closed."""
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--trivy", str(FIXTURES / "trivy_clean.json"),
            "--semgrep", str(FIXTURES / "semgrep_clean.json"),
            "--event-name", "pull_request",
            "--output", str(out_path),
        ])
        assert code == 2  # ERROR decision due to missing required scanner
        data = json.loads(out_path.read_text())
        assert data["decision"] == "ERROR"
        assert data["scanner_status"]["dependency_review"] == "FAILED"

    def test_cli_explicit_scanner_status_override(self, tmp_path):
        """Explicit --scanner-status flag overrides resolved scanner statuses."""
        policy_path = write_policy(tmp_path, 'version: "1.0"')
        out_path = tmp_path / "out.json"
        code = main([
            "--policy", str(policy_path),
            "--findings", str(FIXTURES / "clean_findings.json"),
            "--scanner-status", "trivy=COMPLETED", "semgrep=DISABLED", "dependency_review=NOT_APPLICABLE",
            "--output", str(out_path),
        ])
        assert code == 0
        data = json.loads(out_path.read_text())
        assert data["scanner_status"] == {
            "trivy": "COMPLETED",
            "semgrep": "DISABLED",
            "dependency_review": "NOT_APPLICABLE",
        }


