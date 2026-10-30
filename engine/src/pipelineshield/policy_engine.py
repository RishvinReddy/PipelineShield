"""Policy evaluation engine enforcing security thresholds and exemptions.

Design principles:
- Fail-closed: errors never produce PASS or WARN decisions.
- Explicit mode semantics: STRICT / PERMISSIVE / MONITOR behaviours are enforced separately.
- Exemptions are visible in reports — they are never silently discarded.
- Every decision has an auditable reason.
- Unknown severity or invalid findings produce an ERROR decision, not a pass.
"""

import fnmatch
from typing import List, Optional, Tuple

from pipelineshield.models import (
    EnforcementMode,
    EvaluationResult,
    EvaluationSummary,
    Finding,
    GateDecision,
    PolicyConfig,
    Severity,
)


class PolicyEngine:
    """Evaluates normalized findings against a PolicyConfig to produce a gate decision.

    The evaluation is deterministic given the same findings and config.
    """

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Exemption logic
    # ------------------------------------------------------------------

    def is_exempted(self, finding: Finding) -> bool:
        """Return True if the finding matches any exemption rule.

        Exempted findings are never silently dropped; they are tracked separately
        and remain visible in all reports.
        """
        # ID-based exemption (exact match)
        if finding.id in self.config.exemptions.findings:
            return True

        # Path-based exemption (glob match)
        if finding.file_path:
            for pattern in self.config.exemptions.paths:
                if fnmatch.fnmatch(finding.file_path, pattern):
                    return True

        return False

    # ------------------------------------------------------------------
    # Threshold resolution per enforcement mode
    # ------------------------------------------------------------------

    def _resolve_threshold(self, severity: Severity) -> GateDecision:
        """Return the configured threshold GateDecision for a given severity."""
        mapping = {
            Severity.CRITICAL: self.config.thresholds.critical,
            Severity.HIGH: self.config.thresholds.high,
            Severity.MEDIUM: self.config.thresholds.medium,
            Severity.LOW: self.config.thresholds.low,
            Severity.INFO: self.config.thresholds.info,
        }
        return mapping[severity]

    def _apply_mode(self, raw_decision: GateDecision) -> GateDecision:
        """Apply enforcement mode semantics to a raw threshold decision.

        - STRICT: preserve raw decision as-is.
        - PERMISSIVE: downgrade BLOCK to WARN, preserve everything else.
        - MONITOR: downgrade BLOCK and WARN to PASS, preserve PASS.

        ERROR is never affected by mode — it always propagates.
        """
        if raw_decision == GateDecision.ERROR:
            return GateDecision.ERROR

        mode = self.config.mode

        if mode == EnforcementMode.STRICT:
            return raw_decision
        if mode == EnforcementMode.PERMISSIVE:
            if raw_decision == GateDecision.BLOCK:
                return GateDecision.WARN
            return raw_decision
        if mode == EnforcementMode.MONITOR:
            return GateDecision.PASS

        # Defensive: unknown mode — fail closed
        return GateDecision.ERROR

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(self, findings: List[Finding]) -> EvaluationResult:
        """Evaluate a list of normalized findings against policy rules.

        Args:
            findings: List of normalized Finding objects.
                      An empty list is valid and produces PASS.
                      This method must only be called with an explicitly supplied
                      findings list — never with a default empty list from missing input.

        Returns:
            EvaluationResult with decision, summary, and classified findings.
        """
        summary = EvaluationSummary(total_findings=len(findings))
        blocking: List[Finding] = []
        warning: List[Finding] = []
        exempted: List[Finding] = []
        reasons: List[str] = []

        for finding in findings:
            # Count by severity (all findings, including exempted)
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

            raw_threshold = self._resolve_threshold(finding.severity)
            effective = self._apply_mode(raw_threshold)

            if effective == GateDecision.BLOCK:
                blocking.append(finding)
            elif effective == GateDecision.WARN:
                warning.append(finding)
            # PASS → no action required

        summary.blocking_count = len(blocking)
        summary.warning_count = len(warning)

        # ------------------------------------------------------------------
        # Determine overall decision
        # ------------------------------------------------------------------
        decision = self._determine_decision(blocking, warning, reasons)

        return EvaluationResult(
            decision=decision,
            policy_mode=self.config.mode,
            summary=summary,
            findings=findings,
            blocking_findings=blocking,
            warning_findings=warning,
            exempted_findings=exempted,
            reasons=reasons,
        )

    def _determine_decision(
        self,
        blocking: List[Finding],
        warning: List[Finding],
        reasons: List[str],
    ) -> GateDecision:
        """Determine the final gate decision from classified finding lists.

        Decision matrix (in evaluation order):
        1. Blocking findings exist AND (fail_on_block OR mode is STRICT) → BLOCK
        2. Warning findings exist AND fail_on_warn → BLOCK
        3. Warning findings exist → WARN
        4. No blocking or warning findings → PASS

        Monitor mode always produces PASS regardless of findings
        (enforcement-disabled observation mode).
        """
        mode = self.config.mode

        if mode == EnforcementMode.MONITOR:
            finding_note = f"{len(blocking)} blocking-threshold and {len(warning)} warning-threshold finding(s) observed"
            reasons.append(
                f"Monitor mode: {finding_note} — no enforcement action taken."
            )
            return GateDecision.PASS

        if blocking:
            if self.config.fail_on_block:
                reasons.append(
                    f"BLOCK: {len(blocking)} finding(s) exceed the configured blocking threshold."
                )
                return GateDecision.BLOCK
            else:
                # fail_on_block=False — blocking findings exist but enforcement is disabled.
                # Downgrade to WARN so the issue is visible but not blocking.
                reasons.append(
                    f"WARN: {len(blocking)} finding(s) exceed blocking thresholds, "
                    f"but fail_on_block is disabled. Review and enable enforcement."
                )
                return GateDecision.WARN

        if warning:
            if self.config.fail_on_warn:
                reasons.append(
                    f"BLOCK: {len(warning)} warning finding(s) present and fail_on_warn is enabled."
                )
                return GateDecision.BLOCK
            reasons.append(
                f"WARN: {len(warning)} advisory finding(s) present within acceptable thresholds."
            )
            return GateDecision.WARN

        reasons.append(
            "PASS: All findings satisfy the configured security policy thresholds."
        )
        return GateDecision.PASS

    def evaluate_with_error_guard(
        self, findings: List[Finding]
    ) -> EvaluationResult:
        """Run evaluate() wrapped in a defensive error guard.

        If any exception occurs during evaluation, returns an ERROR decision
        rather than propagating the exception. This ensures the gate always
        fails closed on unexpected engine failures.

        Args:
            findings: List of normalized Finding objects.

        Returns:
            EvaluationResult — always returns, never raises.
        """
        try:
            return self.evaluate(findings)
        except Exception as exc:
            error_msg = f"Policy engine encountered an unexpected error: {exc}"
            return EvaluationResult(
                decision=GateDecision.ERROR,
                policy_mode=self.config.mode,
                summary=EvaluationSummary(),
                reasons=["ERROR: Policy engine failed. Gate closed for safety."],
                errors=[error_msg],
            )
