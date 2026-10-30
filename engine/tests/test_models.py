"""Tests for PipelineShield data models and schema validation."""

import pytest
from pydantic import ValidationError

import pipelineshield
from pipelineshield.models import (
    EnforcementMode,
    EvaluationResult,
    EvaluationSummary,
    Finding,
    GateDecision,
    PolicyConfig,
    PolicyExemptions,
    PolicyThresholds,
    ScannerConfig,
    ScannerType,
    Severity,
)


# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------

class TestPackage:
    def test_version_exposed(self):
        assert pipelineshield.__version__ == "0.1.0"


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------

class TestSeverity:
    def test_all_values_exist(self):
        for val in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert Severity(val) is not None

    def test_case_sensitive(self):
        with pytest.raises(ValueError):
            Severity("critical")  # must be uppercase


# ---------------------------------------------------------------------------
# ScannerType enum
# ---------------------------------------------------------------------------

class TestScannerType:
    def test_all_supported_scanners(self):
        assert ScannerType("trivy") == ScannerType.TRIVY
        assert ScannerType("semgrep") == ScannerType.SEMGREP
        assert ScannerType("dependency_review") == ScannerType.DEPENDENCY_REVIEW

    def test_unknown_scanner_raises(self):
        with pytest.raises(ValueError):
            ScannerType("unknown_tool")


# ---------------------------------------------------------------------------
# GateDecision enum
# ---------------------------------------------------------------------------

class TestGateDecision:
    def test_all_decisions_exist(self):
        for val in ("PASS", "WARN", "BLOCK", "ERROR"):
            assert GateDecision(val) is not None


# ---------------------------------------------------------------------------
# EnforcementMode enum
# ---------------------------------------------------------------------------

class TestEnforcementMode:
    def test_all_modes_exist(self):
        assert EnforcementMode("strict") == EnforcementMode.STRICT
        assert EnforcementMode("permissive") == EnforcementMode.PERMISSIVE
        assert EnforcementMode("monitor") == EnforcementMode.MONITOR

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            EnforcementMode("aggressive")


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class TestFinding:
    def test_minimal_valid_finding(self):
        f = Finding(
            id="CVE-2024-0001",
            scanner=ScannerType.TRIVY,
            title="Test Vulnerability",
            severity=Severity.HIGH,
        )
        assert f.id == "CVE-2024-0001"
        assert f.scanner == ScannerType.TRIVY
        assert f.severity == Severity.HIGH
        assert f.description == ""
        assert f.cwe_ids == []
        assert f.metadata == {}

    def test_full_finding_fields(self):
        f = Finding(
            id="CVE-2024-9999",
            scanner=ScannerType.SEMGREP,
            title="SQL Injection",
            description="User input passed directly to SQL query",
            severity=Severity.CRITICAL,
            file_path="app/db.py",
            line_number=42,
            package_name="sqlalchemy",
            installed_version="1.3.0",
            fixed_version="1.4.0",
            cwe_ids=["CWE-89"],
            remediation="Use parameterized queries",
            metadata={"rule_set": "owasp"},
        )
        assert f.file_path == "app/db.py"
        assert f.line_number == 42
        assert f.cwe_ids == ["CWE-89"]

    def test_empty_id_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="",
                scanner=ScannerType.TRIVY,
                title="Test",
                severity=Severity.LOW,
            )

    def test_whitespace_only_id_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="   ",
                scanner=ScannerType.TRIVY,
                title="Test",
                severity=Severity.LOW,
            )

    def test_empty_title_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="CVE-001",
                scanner=ScannerType.TRIVY,
                title="",
                severity=Severity.LOW,
            )

    def test_negative_line_number_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="CVE-001",
                scanner=ScannerType.TRIVY,
                title="Test",
                severity=Severity.LOW,
                line_number=-1,
            )

    def test_zero_line_number_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="CVE-001",
                scanner=ScannerType.TRIVY,
                title="Test",
                severity=Severity.LOW,
                line_number=0,
            )

    def test_id_is_stripped(self):
        f = Finding(
            id="  CVE-2024-0001  ",
            scanner=ScannerType.TRIVY,
            title="Test",
            severity=Severity.LOW,
        )
        assert f.id == "CVE-2024-0001"

    def test_title_is_stripped(self):
        f = Finding(
            id="CVE-001",
            scanner=ScannerType.TRIVY,
            title="  Test Title  ",
            severity=Severity.LOW,
        )
        assert f.title == "Test Title"


# ---------------------------------------------------------------------------
# PolicyThresholds validation
# ---------------------------------------------------------------------------

class TestPolicyThresholds:
    def test_default_thresholds(self):
        t = PolicyThresholds()
        assert t.critical == GateDecision.BLOCK
        assert t.high == GateDecision.BLOCK
        assert t.medium == GateDecision.WARN
        assert t.low == GateDecision.PASS
        assert t.info == GateDecision.PASS

    def test_error_as_threshold_raises(self):
        with pytest.raises(ValidationError):
            PolicyThresholds(critical="ERROR")

    def test_valid_custom_thresholds(self):
        t = PolicyThresholds(
            critical=GateDecision.BLOCK,
            high=GateDecision.WARN,
            medium=GateDecision.PASS,
        )
        assert t.high == GateDecision.WARN


# ---------------------------------------------------------------------------
# PolicyConfig validation
# ---------------------------------------------------------------------------

class TestPolicyConfig:
    def test_default_config(self):
        config = PolicyConfig()
        assert config.mode == EnforcementMode.STRICT
        assert config.fail_on_block is True
        assert config.fail_on_warn is False

    def test_invalid_mode_raises(self):
        with pytest.raises(ValidationError):
            PolicyConfig(mode="aggressive")

    def test_inconsistent_fail_flags_raise(self):
        """fail_on_warn=True with fail_on_block=False is inconsistent."""
        with pytest.raises(ValidationError):
            PolicyConfig(fail_on_warn=True, fail_on_block=False)

    def test_valid_permissive_mode(self):
        config = PolicyConfig(mode=EnforcementMode.PERMISSIVE)
        assert config.mode == EnforcementMode.PERMISSIVE

    def test_valid_monitor_mode(self):
        config = PolicyConfig(mode=EnforcementMode.MONITOR)
        assert config.mode == EnforcementMode.MONITOR


# ---------------------------------------------------------------------------
# PolicyExemptions validation
# ---------------------------------------------------------------------------

class TestPolicyExemptions:
    def test_empty_by_default(self):
        e = PolicyExemptions()
        assert e.findings == []
        assert e.paths == []

    def test_valid_exemptions(self):
        e = PolicyExemptions(findings=["CVE-2024-001"], paths=["tests/**"])
        assert "CVE-2024-001" in e.findings

    def test_none_becomes_empty_list(self):
        e = PolicyExemptions(findings=None, paths=None)
        assert e.findings == []

    def test_non_list_raises(self):
        with pytest.raises(ValidationError):
            PolicyExemptions(findings="CVE-001")


# ---------------------------------------------------------------------------
# EvaluationResult
# ---------------------------------------------------------------------------

class TestEvaluationResult:
    def test_result_has_timestamp(self):
        result = EvaluationResult(
            decision=GateDecision.PASS,
            summary=EvaluationSummary(),
        )
        assert result.evaluated_at is not None
        assert "T" in result.evaluated_at  # ISO 8601 format

    def test_result_defaults(self):
        result = EvaluationResult(
            decision=GateDecision.ERROR,
            summary=EvaluationSummary(),
        )
        assert result.findings == []
        assert result.errors == []
        assert result.reasons == []
