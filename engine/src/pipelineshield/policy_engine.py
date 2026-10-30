"""Policy evaluation engine enforcing security thresholds and exemptions."""

import fnmatch
from typing import List
from pipelineshield.models import (
    EvaluationResult,
    EvaluationSummary,
    Finding,
    GateDecision,
    PolicyConfig,
    Severity,
)


class PolicyEngine:
    """Evaluates findings against a PolicyConfig to determine gate pass/block decisions."""

    def __init__(self, config: PolicyConfig):
        self.config = config

    def is_exempted(self, finding: Finding) -> bool:
        """Check whether a finding matches exemption criteria (by ID or file path)."""
        if finding.id in self.config.exemptions.findings:
            return True

        if finding.file_path:
            for pattern in self.config.exemptions.paths:
                if fnmatch.fnmatch(finding.file_path, pattern):
                    return True
        return False

    def evaluate(self, findings: List[Finding]) -> EvaluationResult:
        """Evaluate a list of normalized findings against policy rules.

        Args:
            findings: List of normalized Finding objects.

        Returns:
            EvaluationResult detailing decision, summary, and classified findings.
        """
        summary = EvaluationSummary(total_findings=len(findings))
        blocking: List[Finding] = []
        warning: List[Finding] = []
        exempted: List[Finding] = []
        reasons: List[str] = []

        threshold_map = {
            Severity.CRITICAL: self.config.thresholds.critical,
            Severity.HIGH: self.config.thresholds.high,
            Severity.MEDIUM: self.config.thresholds.medium,
            Severity.LOW: self.config.thresholds.low,
            Severity.INFO: self.config.thresholds.info,
        }

        for finding in findings:
            # Count severity
            if finding.severity == Severity.CRITICAL:
                summary.critical += 1
            elif finding.severity == Severity.HIGH:
                summary.high += 1
            elif finding.severity == Severity.MEDIUM:
                summary.medium += 1
            elif finding.severity == Severity.LOW:
                summary.low += 1
            else:
                summary.info += 1

            # Exemption check
            if self.is_exempted(finding):
                summary.exempted += 1
                exempted.append(finding)
                continue

            decision_for_severity = threshold_map.get(finding.severity, GateDecision.PASS)
            if decision_for_severity == GateDecision.BLOCK:
                blocking.append(finding)
            elif decision_for_severity == GateDecision.WARN:
                warning.append(finding)

        # Determine overall decision
        if blocking and self.config.fail_on_block:
            decision = GateDecision.BLOCK
            reasons.append(f"Blocked by {len(blocking)} findings exceeding policy threshold.")
        elif warning and self.config.fail_on_warn:
            decision = GateDecision.BLOCK
            reasons.append(f"Blocked by {len(warning)} warning findings (fail_on_warn is enabled).")
        elif warning:
            decision = GateDecision.WARN
            reasons.append(f"Passed with {len(warning)} advisory warnings.")
        else:
            decision = GateDecision.PASS
            reasons.append("All findings satisfy the configured security policy.")

        return EvaluationResult(
            decision=decision,
            summary=summary,
            findings=findings,
            blocking_findings=blocking,
            warning_findings=warning,
            exempted_findings=exempted,
            reasons=reasons,
        )
