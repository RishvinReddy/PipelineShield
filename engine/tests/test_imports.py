"""Basic import and sanity tests for PipelineShield engine modules."""

import pytest
import pipelineshield
from pipelineshield.models import (
    Finding,
    GateDecision,
    PolicyConfig,
    ScannerType,
    Severity,
)
from pipelineshield.config import load_policy
from pipelineshield.normalizer import Normalizer, normalize_severity
from pipelineshield.policy_engine import PolicyEngine
from pipelineshield.reporter import Reporter


def test_package_version():
    """Verify package version is exposed."""
    assert pipelineshield.__version__ == "0.1.0"


def test_models_instantiation():
    """Verify Finding model can be instantiated and validated."""
    finding = Finding(
        id="CVE-2024-0001",
        scanner=ScannerType.TRIVY,
        title="Test Critical Vulnerability",
        severity=Severity.CRITICAL,
        file_path="package-lock.json",
        line_number=42,
    )
    assert finding.id == "CVE-2024-0001"
    assert finding.scanner == ScannerType.TRIVY
    assert finding.severity == Severity.CRITICAL


def test_severity_normalization():
    """Verify arbitrary strings normalize to valid Severity enums."""
    assert normalize_severity("CRITICAL") == Severity.CRITICAL
    assert normalize_severity("error") == Severity.HIGH
    assert normalize_severity("warning") == Severity.MEDIUM
    assert normalize_severity("low") == Severity.LOW
    assert normalize_severity("unknown") == Severity.INFO


def test_policy_engine_evaluation_pass():
    """Verify empty or low-severity findings yield a PASS decision."""
    config = PolicyConfig()
    engine = PolicyEngine(config)
    result = engine.evaluate([])
    assert result.decision == GateDecision.PASS
    assert result.summary.total_findings == 0


def test_policy_engine_evaluation_block():
    """Verify a critical finding yields a BLOCK decision under default policy."""
    config = PolicyConfig()
    engine = PolicyEngine(config)
    finding = Finding(
        id="CVE-2024-9999",
        scanner=ScannerType.TRIVY,
        title="Remote Code Execution",
        severity=Severity.CRITICAL,
    )
    result = engine.evaluate([finding])
    assert result.decision == GateDecision.BLOCK
    assert len(result.blocking_findings) == 1
    assert result.summary.critical == 1


def test_reporter_markdown_generation():
    """Verify markdown report generation contains expected headers."""
    config = PolicyConfig()
    engine = PolicyEngine(config)
    result = engine.evaluate([])
    md = Reporter.to_markdown(result)
    assert "PipelineShield Security Gate" in md
    assert "PASS" in md
