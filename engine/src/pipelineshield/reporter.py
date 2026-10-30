"""Report generation for policy evaluation results."""

import json
from pathlib import Path
from typing import Union
from pipelineshield.models import EvaluationResult, GateDecision


class Reporter:
    """Formats evaluation results into JSON and GitHub Markdown summaries."""

    @staticmethod
    def to_json(result: EvaluationResult, indent: int = 2) -> str:
        """Serialize EvaluationResult to formatted JSON string."""
        return result.model_dump_json(indent=indent)

    @classmethod
    def write_json(cls, result: EvaluationResult, output_path: Union[str, Path]) -> None:
        """Write JSON report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.to_json(result), encoding="utf-8")

    @staticmethod
    def to_markdown(result: EvaluationResult) -> str:
        """Generate a GitHub Step Summary markdown document."""
        icon = "✅" if result.decision == GateDecision.PASS else ("⚠️" if result.decision == GateDecision.WARN else "🛑")

        md = [
            f"# {icon} PipelineShield Security Gate: {result.decision.value}",
            "",
            f"**Total Findings**: {result.summary.total_findings} | "
            f"**Critical**: {result.summary.critical} | "
            f"**High**: {result.summary.high} | "
            f"**Medium**: {result.summary.medium} | "
            f"**Low**: {result.summary.low} | "
            f"**Exempted**: {result.summary.exempted}",
            "",
            "### Decision Reasons",
        ]

        for reason in result.reasons:
            md.append(f"- {reason}")

        if result.blocking_findings:
            md.append("")
            md.append("### 🛑 Blocking Findings")
            md.append("| ID | Scanner | Severity | Title | Location |")
            md.append("|---|---|---|---|---|")
            for f in result.blocking_findings:
                loc = f"{f.file_path or 'N/A'}:{f.line_number or ''}".rstrip(":")
                md.append(f"| `{f.id}` | {f.scanner.value} | **{f.severity.value}** | {f.title} | `{loc}` |")

        if result.warning_findings:
            md.append("")
            md.append("### ⚠️ Warning Findings")
            md.append("| ID | Scanner | Severity | Title | Location |")
            md.append("|---|---|---|---|---|")
            for f in result.warning_findings:
                loc = f"{f.file_path or 'N/A'}:{f.line_number or ''}".rstrip(":")
                md.append(f"| `{f.id}` | {f.scanner.value} | {f.severity.value} | {f.title} | `{loc}` |")

        return "\n".join(md)
