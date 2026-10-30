"""Tests for PolicyEngine evaluation logic and enforcement mode semantics."""

import pytest

from pipelineshield.models import (
    EnforcementMode,
    EvaluationResult,
    Finding,
    GateDecision,
    PolicyConfig,
    PolicyExemptions,
    PolicyThresholds,
    ScannerType,
    Severity,
)
from pipelineshield.policy_engine import PolicyEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    severity: Severity,
    finding_id: str = "TEST-001",
    scanner: ScannerType = ScannerType.TRIVY,
    file_path: str | None = None,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        id=finding_id,
        scanner=scanner,
        title=title,
        severity=severity,
        file_path=file_path,
    )


def make_config(**kwargs) -> PolicyConfig:
    return PolicyConfig(**kwargs)


# ---------------------------------------------------------------------------
# Clean scan
# ---------------------------------------------------------------------------

class TestCleanScan:
    def test_empty_findings_produces_pass(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([])
        assert result.decision == GateDecision.PASS
        assert result.summary.total_findings == 0

    def test_pass_reason_present(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([])
        assert any("PASS" in r for r in result.reasons)

    def test_info_finding_produces_pass(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.INFO)])
        assert result.decision == GateDecision.PASS

    def test_low_finding_produces_pass(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.LOW)])
        assert result.decision == GateDecision.PASS


# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

class TestSeverityThresholds:
    def test_critical_blocks(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1

    def test_high_blocks(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.HIGH)])
        assert result.decision == GateDecision.BLOCK

    def test_medium_warns(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.MEDIUM)])
        assert result.decision == GateDecision.WARN
        assert len(result.warning_findings) == 1

    def test_severity_counts_correct(self):
        engine = PolicyEngine(make_config())
        findings = [
            make_finding(Severity.CRITICAL, "CVE-001"),
            make_finding(Severity.HIGH, "CVE-002"),
            make_finding(Severity.MEDIUM, "CVE-003"),
            make_finding(Severity.LOW, "CVE-004"),
            make_finding(Severity.INFO, "CVE-005"),
        ]
        result = engine.evaluate(findings)
        assert result.summary.critical == 1
        assert result.summary.high == 1
        assert result.summary.medium == 1
        assert result.summary.low == 1
        assert result.summary.info == 1
        assert result.summary.total_findings == 5

    def test_block_reason_present(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert any("BLOCK" in r for r in result.reasons)

    def test_warn_reason_present(self):
        engine = PolicyEngine(make_config())
        result = engine.evaluate([make_finding(Severity.MEDIUM)])
        assert any("WARN" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# fail_on_block semantics
# ---------------------------------------------------------------------------

class TestFailOnBlock:
    def test_fail_on_block_true_blocks_critical(self):
        """Default: fail_on_block=True → CRITICAL → BLOCK."""
        config = make_config(fail_on_block=True)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.BLOCK

    def test_fail_on_block_false_downgrades_block_to_warn(self):
        """fail_on_block=False → CRITICAL finding → WARN, never PASS."""
        config = make_config(fail_on_block=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.WARN
        # Must NOT be PASS — that would be fail-open
        assert result.decision != GateDecision.PASS

    def test_fail_on_block_false_medium_is_still_warn(self):
        config = make_config(fail_on_block=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.MEDIUM)])
        assert result.decision == GateDecision.WARN

    def test_fail_on_block_false_pass_for_clean(self):
        config = make_config(fail_on_block=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([])
        assert result.decision == GateDecision.PASS


# ---------------------------------------------------------------------------
# fail_on_warn semantics
# ---------------------------------------------------------------------------

class TestFailOnWarn:
    def test_fail_on_warn_false_medium_is_warn(self):
        config = make_config(fail_on_warn=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.MEDIUM)])
        assert result.decision == GateDecision.WARN

    def test_fail_on_warn_true_medium_becomes_block(self):
        config = make_config(fail_on_warn=True, fail_on_block=True)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.MEDIUM)])
        assert result.decision == GateDecision.BLOCK


# ---------------------------------------------------------------------------
# Enforcement mode semantics
# ---------------------------------------------------------------------------

class TestEnforcementModes:
    def test_strict_mode_blocks_critical(self):
        config = make_config(mode=EnforcementMode.STRICT)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.BLOCK

    def test_permissive_mode_downgrades_block_to_warn(self):
        """PERMISSIVE mode: BLOCK findings become WARN — never PASS."""
        config = make_config(mode=EnforcementMode.PERMISSIVE, fail_on_block=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.WARN
        assert result.decision != GateDecision.PASS

    def test_permissive_mode_keeps_warn(self):
        config = make_config(mode=EnforcementMode.PERMISSIVE, fail_on_block=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.MEDIUM)])
        assert result.decision == GateDecision.WARN

    def test_permissive_mode_keeps_pass_for_clean(self):
        config = make_config(mode=EnforcementMode.PERMISSIVE, fail_on_block=False)
        engine = PolicyEngine(config)
        result = engine.evaluate([])
        assert result.decision == GateDecision.PASS

    def test_monitor_mode_always_passes(self):
        """MONITOR mode: findings are recorded but never enforced."""
        config = make_config(mode=EnforcementMode.MONITOR)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.PASS

    def test_monitor_mode_reason_mentions_monitor(self):
        config = make_config(mode=EnforcementMode.MONITOR)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert any("monitor" in r.lower() for r in result.reasons)

    def test_monitor_mode_still_counts_findings(self):
        config = make_config(mode=EnforcementMode.MONITOR)
        engine = PolicyEngine(config)
        findings = [
            make_finding(Severity.CRITICAL, "CVE-001"),
            make_finding(Severity.HIGH, "CVE-002"),
        ]
        result = engine.evaluate(findings)
        assert result.summary.total_findings == 2
        assert result.summary.critical == 1
        assert result.summary.high == 1


# ---------------------------------------------------------------------------
# Exemption logic
# ---------------------------------------------------------------------------

class TestExemptions:
    def test_id_exemption_removes_from_blocking(self):
        config = PolicyConfig(
            exemptions=PolicyExemptions(findings=["CVE-EXEMPT-001"])
        )
        engine = PolicyEngine(config)
        finding = make_finding(Severity.CRITICAL, finding_id="CVE-EXEMPT-001")
        result = engine.evaluate([finding])
        assert result.decision == GateDecision.PASS
        assert len(result.exempted_findings) == 1
        assert len(result.blocking_findings) == 0

    def test_exempted_finding_still_counted_in_severity(self):
        """Exempted findings must be counted in severity totals."""
        config = PolicyConfig(
            exemptions=PolicyExemptions(findings=["CVE-EXEMPT-001"])
        )
        engine = PolicyEngine(config)
        finding = make_finding(Severity.CRITICAL, finding_id="CVE-EXEMPT-001")
        result = engine.evaluate([finding])
        # Still counted in critical total even though exempted
        assert result.summary.critical == 1
        assert result.summary.exempted == 1

    def test_exempted_finding_visible_in_report(self):
        """Exempted findings must appear in exempted_findings — not silently dropped."""
        config = PolicyConfig(
            exemptions=PolicyExemptions(findings=["CVE-EXEMPT-001"])
        )
        engine = PolicyEngine(config)
        finding = make_finding(Severity.CRITICAL, finding_id="CVE-EXEMPT-001")
        result = engine.evaluate([finding])
        assert finding in result.exempted_findings

    def test_path_exemption_works(self):
        config = PolicyConfig(
            exemptions=PolicyExemptions(paths=["tests/**"])
        )
        engine = PolicyEngine(config)
        finding = make_finding(
            Severity.CRITICAL, finding_id="CVE-001",
            file_path="tests/vulnerable_test.py"
        )
        result = engine.evaluate([finding])
        assert result.decision == GateDecision.PASS
        assert len(result.exempted_findings) == 1

    def test_path_exemption_no_match_still_blocks(self):
        config = PolicyConfig(
            exemptions=PolicyExemptions(paths=["tests/**"])
        )
        engine = PolicyEngine(config)
        finding = make_finding(
            Severity.CRITICAL, finding_id="CVE-001",
            file_path="src/production.py"
        )
        result = engine.evaluate([finding])
        assert result.decision == GateDecision.BLOCK

    def test_nonexempted_finding_still_blocks_alongside_exempted(self):
        """Non-exempt blocking findings must still block even when some findings are exempt."""
        config = PolicyConfig(
            exemptions=PolicyExemptions(findings=["CVE-EXEMPT-001"])
        )
        engine = PolicyEngine(config)
        findings = [
            make_finding(Severity.CRITICAL, finding_id="CVE-EXEMPT-001"),
            make_finding(Severity.CRITICAL, finding_id="CVE-NOT-EXEMPT"),
        ]
        result = engine.evaluate(findings)
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1
        assert len(result.exempted_findings) == 1

    def test_unknown_exemption_id_not_matched(self):
        """Unrelated exemption IDs do not exempt non-matching findings."""
        config = PolicyConfig(
            exemptions=PolicyExemptions(findings=["CVE-DIFFERENT-001"])
        )
        engine = PolicyEngine(config)
        finding = make_finding(Severity.CRITICAL, finding_id="CVE-ACTUAL-001")
        result = engine.evaluate([finding])
        assert result.decision == GateDecision.BLOCK


# ---------------------------------------------------------------------------
# evaluate_with_error_guard
# ---------------------------------------------------------------------------

class TestErrorGuard:
    def test_error_guard_catches_exceptions(self, monkeypatch):
        """Verify evaluate_with_error_guard returns ERROR, not an exception."""
        config = make_config()
        engine = PolicyEngine(config)

        def broken_evaluate(findings):
            raise RuntimeError("Simulated engine failure")

        monkeypatch.setattr(engine, "evaluate", broken_evaluate)
        result = engine.evaluate_with_error_guard([])
        assert result.decision == GateDecision.ERROR
        assert len(result.errors) > 0
        assert "Simulated engine failure" in result.errors[0]

    def test_error_guard_normal_operation(self):
        """In normal operation, evaluate_with_error_guard delegates correctly."""
        config = make_config()
        engine = PolicyEngine(config)
        result = engine.evaluate_with_error_guard([])
        assert result.decision == GateDecision.PASS


# ---------------------------------------------------------------------------
# Custom threshold configurations
# ---------------------------------------------------------------------------

class TestCustomThresholds:
    def test_all_thresholds_as_block(self):
        thresholds = PolicyThresholds(
            critical=GateDecision.BLOCK,
            high=GateDecision.BLOCK,
            medium=GateDecision.BLOCK,
            low=GateDecision.BLOCK,
            info=GateDecision.BLOCK,
        )
        config = PolicyConfig(thresholds=thresholds)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.INFO)])
        assert result.decision == GateDecision.BLOCK

    def test_all_thresholds_as_pass(self):
        thresholds = PolicyThresholds(
            critical=GateDecision.PASS,
            high=GateDecision.PASS,
            medium=GateDecision.PASS,
            low=GateDecision.PASS,
            info=GateDecision.PASS,
        )
        config = PolicyConfig(thresholds=thresholds)
        engine = PolicyEngine(config)
        result = engine.evaluate([make_finding(Severity.CRITICAL)])
        assert result.decision == GateDecision.PASS


# ---------------------------------------------------------------------------
# Multiple findings combinations
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    def test_mixed_severities_block_wins(self):
        engine = PolicyEngine(make_config())
        findings = [
            make_finding(Severity.LOW, "LOW-001"),
            make_finding(Severity.MEDIUM, "MED-001"),
            make_finding(Severity.CRITICAL, "CRIT-001"),
        ]
        result = engine.evaluate(findings)
        assert result.decision == GateDecision.BLOCK
        assert result.summary.blocking_count == 1
        assert result.summary.warning_count == 1

    def test_blocking_and_summary_counts_consistent(self):
        engine = PolicyEngine(make_config())
        findings = [
            make_finding(Severity.CRITICAL, "CRIT-001"),
            make_finding(Severity.HIGH, "HIGH-001"),
            make_finding(Severity.MEDIUM, "MED-001"),
        ]
        result = engine.evaluate(findings)
        assert result.summary.blocking_count == len(result.blocking_findings)
        assert result.summary.warning_count == len(result.warning_findings)

    def test_result_contains_all_findings(self):
        engine = PolicyEngine(make_config())
        findings = [
            make_finding(Severity.CRITICAL, "C001"),
            make_finding(Severity.MEDIUM, "M001"),
        ]
        result = engine.evaluate(findings)
        assert len(result.findings) == 2
