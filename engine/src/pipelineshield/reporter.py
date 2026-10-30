"""Report generation for PipelineShield policy evaluation results.

Produces:
- Structured JSON reports for programmatic consumption and artifact storage.
- GitHub Actions Step Summary markdown for PR feedback.

Security considerations:
- Markdown tables escape pipe characters and backticks from untrusted scanner data
  to prevent markdown injection.
- JSON serialization uses model_dump_json for deterministic output.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from pipelineshield.models import EvaluationResult, GateDecision


def _escape_md(value: str) -> str:
    """Escape pipe characters and backticks in markdown table cells.

    Scanner-supplied values (CVE IDs, titles, file paths) must be escaped
    before inclusion in markdown tables to prevent cell breaking and injection.
    """
    if not value:
        return ""
    # Escape markdown table cell delimiters and backtick sequences
    return value.replace("|", "&#124;").replace("`", "&#96;")


_DECISION_ICONS: dict = {
    GateDecision.PASS: "✅",
    GateDecision.WARN: "⚠️",
    GateDecision.BLOCK: "🛑",
    GateDecision.ERROR: "💥",
}


class Reporter:
    """Formats EvaluationResult into JSON and GitHub Markdown summaries."""

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(result: EvaluationResult, indent: int = 2) -> str:
        """Serialize EvaluationResult to a deterministic, formatted JSON string."""
        return result.model_dump_json(indent=indent)

    @classmethod
    def write_json(cls, result: EvaluationResult, output_path: Union[str, Path]) -> None:
        """Write JSON report to disk, creating parent directories as needed."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.to_json(result), encoding="utf-8")

    # ------------------------------------------------------------------
    # Markdown (GitHub Step Summary)
    # ------------------------------------------------------------------

    @staticmethod
    def to_markdown(result: EvaluationResult) -> str:
        """Generate a GitHub Actions Step Summary markdown document.

        All scanner-supplied values are escaped before inclusion in table cells.
        The report accurately reflects engine state — no placeholder metrics.

        Returns:
            Markdown string suitable for writing to $GITHUB_STEP_SUMMARY.
        """
        icon = _DECISION_ICONS.get(result.decision, "❓")
        decision_val = result.decision.value

        md: list[str] = [
            f"# {icon} PipelineShield Security Gate: {decision_val}",
            "",
            f"**Evaluated at**: `{result.evaluated_at}`  ",
            f"**Policy mode**: `{result.policy_mode.value}`  ",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Total findings | {result.summary.total_findings} |",
            f"| 🔴 Critical | {result.summary.critical} |",
            f"| 🟠 High | {result.summary.high} |",
            f"| 🟡 Medium | {result.summary.medium} |",
            f"| 🔵 Low | {result.summary.low} |",
            f"| ⚪ Info | {result.summary.info} |",
            f"| 🔕 Exempted | {result.summary.exempted} |",
            f"| 🛑 Blocking | {result.summary.blocking_count} |",
            f"| ⚠️ Warnings | {result.summary.warning_count} |",
            "",
            "## Decision Reasons",
            "",
        ]

        for reason in result.reasons:
            md.append(f"- {_escape_md(reason)}")

        if result.errors:
            md.append("")
            md.append("### 💥 Engine Errors")
            md.append("")
            for err in result.errors:
                md.append(f"- `{_escape_md(err)}`")

        if result.blocking_findings:
            md.extend([
                "",
                "## 🛑 Blocking Findings",
                "",
                "| ID | Scanner | Severity | Title | Location |",
                "|---|---|---|---|---|",
            ])
            for f in result.blocking_findings:
                fid = _escape_md(f.id)
                title = _escape_md(f.title)
                scanner = _escape_md(f.scanner.value)
                sev = f.severity.value
                loc_parts = []
                if f.file_path:
                    loc_parts.append(_escape_md(f.file_path))
                if f.line_number:
                    loc_parts.append(f"L{f.line_number}")
                loc = ":".join(loc_parts) or "N/A"
                md.append(f"| `{fid}` | {scanner} | **{sev}** | {title} | `{loc}` |")

        if result.warning_findings:
            md.extend([
                "",
                "## ⚠️ Warning Findings",
                "",
                "| ID | Scanner | Severity | Title | Location |",
                "|---|---|---|---|---|",
            ])
            for f in result.warning_findings:
                fid = _escape_md(f.id)
                title = _escape_md(f.title)
                scanner = _escape_md(f.scanner.value)
                sev = f.severity.value
                loc_parts = []
                if f.file_path:
                    loc_parts.append(_escape_md(f.file_path))
                if f.line_number:
                    loc_parts.append(f"L{f.line_number}")
                loc = ":".join(loc_parts) or "N/A"
                md.append(f"| `{fid}` | {scanner} | {sev} | {title} | `{loc}` |")

        if result.exempted_findings:
            md.extend([
                "",
                "## 🔕 Exempted Findings (Visible, Not Enforced)",
                "",
                "| ID | Scanner | Severity | Title |",
                "|---|---|---|---|",
            ])
            for f in result.exempted_findings:
                fid = _escape_md(f.id)
                title = _escape_md(f.title)
                scanner = _escape_md(f.scanner.value)
                sev = f.severity.value
                md.append(f"| `{fid}` | {scanner} | {sev} | {title} |")

        return "\n".join(md)
