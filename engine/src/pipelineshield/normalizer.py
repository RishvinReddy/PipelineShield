"""Scanner output normalizer for Trivy, Semgrep, and Dependency Review."""

from typing import Any, Dict, List
from pipelineshield.models import Finding, ScannerType, Severity


def normalize_severity(raw_severity: str) -> Severity:
    """Map arbitrary tool severity strings to standard Severity enum."""
    val = (raw_severity or "").strip().upper()
    if val in ("CRITICAL", "BLOCKER"):
        return Severity.CRITICAL
    if val in ("HIGH", "ERROR"):
        return Severity.HIGH
    if val in ("MEDIUM", "MODERATE", "WARNING", "WARN"):
        return Severity.MEDIUM
    if val in ("LOW", "NOTICE"):
        return Severity.LOW
    return Severity.INFO


class Normalizer:
    """Normalizes heterogeneous scanner outputs into standard Finding objects."""

    @staticmethod
    def normalize_finding_dict(raw: Dict[str, Any]) -> Finding:
        """Create a Finding from an already normalized or partially-normalized dictionary."""
        severity = normalize_severity(str(raw.get("severity", "INFO")))
        scanner = raw.get("scanner", "trivy")
        try:
            scanner_type = ScannerType(scanner)
        except ValueError:
            scanner_type = ScannerType.TRIVY

        return Finding(
            id=str(raw.get("id", "UNKNOWN")),
            scanner=scanner_type,
            title=str(raw.get("title", "")),
            description=raw.get("description", ""),
            severity=severity,
            file_path=raw.get("file_path"),
            line_number=raw.get("line_number"),
            package_name=raw.get("package_name"),
            installed_version=raw.get("installed_version"),
            fixed_version=raw.get("fixed_version"),
            cwe_ids=raw.get("cwe_ids", []),
            remediation=raw.get("remediation"),
            metadata=raw.get("metadata", {}),
        )

    @classmethod
    def normalize_list(cls, items: List[Dict[str, Any]]) -> List[Finding]:
        """Normalize a list of finding dictionaries."""
        return [cls.normalize_finding_dict(item) for item in items]
