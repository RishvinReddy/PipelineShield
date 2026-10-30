"""Tests for Reporter — JSON and Markdown output."""

import json
from pathlib import Path

import pytest

from pipelineshield.models import (
    EvaluationResult,
    EvaluationSummary,
    EnforcementMode,
    Finding,
    GateDecision,
    PolicyConfig,
    ScannerType,
    Severity,
)
from pipelineshield.policy_engine import PolicyEngine
from pipelineshield.reporter import Reporter, _escape_md


def make_result(decision: GateDecision, **kwargs) -> EvaluationResult:
    summary = kwargs.pop("summary", EvaluationSummary())
    return EvaluationResult(
        decision=decision,
        summary=summary,
        **kwargs,
    )


def make_finding(severity: Severity, fid: str = "CVE-001") -> Finding:
    return Finding(
        id=fid, scanner=ScannerType.TRIVY,
        title="Test Vulnerability", severity=severity,
    )


# ---------------------------------------------------------------------------
# Markdown escaping
# ---------------------------------------------------------------------------

class TestMarkdownEscaping:
    def test_pipe_escaped(self):
        assert "&#124;" in _escape_md("a|b")

    def test_backtick_escaped(self):
        assert "&#96;" in _escape_md("a`b")

    def test_empty_string_returns_empty(self):
        assert _escape_md("") == ""

    def test_safe_text_unchanged(self):
        assert _escape_md("CVE-2024-0001") == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

class TestJSONReport:
    def test_to_json_is_valid_json(self):
        engine = PolicyEngine(PolicyConfig())
        result = engine.evaluate([])
        json_str = Reporter.to_json(result)
        parsed = json.loads(json_str)
        assert "decision" in parsed

    def test_json_contains_decision(self):
        result = make_result(GateDecision.PASS, reasons=["All clear"])
        j = json.loads(Reporter.to_json(result))
        assert j["decision"] == "PASS"

    def test_json_contains_timestamp(self):
        result = make_result(GateDecision.PASS)
        j = json.loads(Reporter.to_json(result))
        assert "evaluated_at" in j

    def test_json_contains_summary(self):
        result = make_result(GateDecision.BLOCK)
        j = json.loads(Reporter.to_json(result))
        assert "summary" in j

    def test_json_contains_errors(self):
        result = make_result(GateDecision.ERROR, errors=["Engine error"])
        j = json.loads(Reporter.to_json(result))
        assert "errors" in j
        assert "Engine error" in j["errors"]

    def test_write_json_creates_file(self, tmp_path):
        result = make_result(GateDecision.PASS)
        out_path = tmp_path / "reports" / "summary.json"
        Reporter.write_json(result, out_path)
        assert out_path.exists()
        parsed = json.loads(out_path.read_text())
        assert parsed["decision"] == "PASS"

    def test_write_json_creates_parent_dirs(self, tmp_path):
        result = make_result(GateDecision.WARN)
        out_path = tmp_path / "deep" / "nested" / "report.json"
        Reporter.write_json(result, out_path)
        assert out_path.exists()


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

class TestMarkdownReport:
    def test_pass_report_contains_pass(self):
        result = make_result(GateDecision.PASS, reasons=["All clear"])
        md = Reporter.to_markdown(result)
        assert "PASS" in md
        assert "✅" in md

    def test_warn_report_contains_warn(self):
        result = make_result(GateDecision.WARN)
        md = Reporter.to_markdown(result)
        assert "WARN" in md
        assert "⚠️" in md

    def test_block_report_contains_block(self):
        result = make_result(GateDecision.BLOCK)
        md = Reporter.to_markdown(result)
        assert "BLOCK" in md
        assert "🛑" in md

    def test_error_report_contains_error_icon(self):
        result = make_result(GateDecision.ERROR, errors=["Engine failure"])
        md = Reporter.to_markdown(result)
        assert "💥" in md
        assert "ERROR" in md

    def test_markdown_contains_timestamp(self):
        result = make_result(GateDecision.PASS)
        md = Reporter.to_markdown(result)
        assert "Evaluated at" in md

    def test_markdown_contains_policy_mode(self):
        result = make_result(GateDecision.PASS, policy_mode=EnforcementMode.STRICT)
        md = Reporter.to_markdown(result)
        assert "strict" in md

    def test_markdown_blocking_section(self):
        finding = make_finding(Severity.CRITICAL, "CVE-BLOCK-001")
        result = EvaluationResult(
            decision=GateDecision.BLOCK,
            summary=EvaluationSummary(total_findings=1, critical=1, blocking_count=1),
            findings=[finding],
            blocking_findings=[finding],
            reasons=["BLOCK: 1 finding"],
        )
        md = Reporter.to_markdown(result)
        assert "Blocking Findings" in md
        assert "CVE-BLOCK-001" in md

    def test_markdown_warning_section(self):
        finding = make_finding(Severity.MEDIUM, "WARN-001")
        result = EvaluationResult(
            decision=GateDecision.WARN,
            summary=EvaluationSummary(total_findings=1, medium=1, warning_count=1),
            findings=[finding],
            warning_findings=[finding],
            reasons=["WARN: 1 finding"],
        )
        md = Reporter.to_markdown(result)
        assert "Warning Findings" in md
        assert "WARN-001" in md

    def test_markdown_exempted_section(self):
        finding = make_finding(Severity.CRITICAL, "EXEMPT-001")
        result = EvaluationResult(
            decision=GateDecision.PASS,
            summary=EvaluationSummary(total_findings=1, critical=1, exempted=1),
            findings=[finding],
            exempted_findings=[finding],
            reasons=["All clear"],
        )
        md = Reporter.to_markdown(result)
        assert "Exempted Findings" in md
        assert "EXEMPT-001" in md

    def test_markdown_pipe_injection_escaped(self):
        """Scanner-supplied pipe chars in titles must not break markdown tables."""
        finding = Finding(
            id="CVE-PIPE-001",
            scanner=ScannerType.TRIVY,
            title="Vulnerability | with | pipes",
            severity=Severity.HIGH,
        )
        result = EvaluationResult(
            decision=GateDecision.BLOCK,
            summary=EvaluationSummary(total_findings=1, high=1, blocking_count=1),
            blocking_findings=[finding],
            findings=[finding],
            reasons=["BLOCK: 1 finding"],
        )
        md = Reporter.to_markdown(result)
        # Pipes in values must be escaped
        assert "&#124;" in md

    def test_markdown_engine_errors_shown(self):
        result = make_result(GateDecision.ERROR, errors=["Simulated engine crash"])
        md = Reporter.to_markdown(result)
        assert "Simulated engine crash" in md

    def test_markdown_no_blocking_section_if_none(self):
        result = make_result(GateDecision.PASS)
        md = Reporter.to_markdown(result)
        assert "Blocking Findings" not in md

    def test_markdown_summary_table_present(self):
        result = make_result(GateDecision.PASS, summary=EvaluationSummary(
            total_findings=5, critical=1, high=1
        ))
        md = Reporter.to_markdown(result)
        assert "Total findings" in md
        assert "5" in md
