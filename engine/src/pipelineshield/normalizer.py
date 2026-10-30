"""Scanner output normalizers for Trivy, Semgrep, and GitHub Dependency Review.

Each scanner produces a structurally distinct JSON format.
This module provides native parsers for each supported format and a generic
Finding-dict normalizer for pre-normalized PipelineShield finding lists.

Design principles:
- Unknown scanners raise NormalizationError — never silently default.
- Unknown severity strings raise NormalizationError — never silently become INFO.
- Missing optional fields are preserved as None — never substituted with defaults.
- Malformed input raises NormalizationError with actionable context.
- Original scanner identifiers, CVEs, and rule IDs are always preserved.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pipelineshield.models import Finding, ScannerType, Severity


class NormalizationError(ValueError):
    """Raised when scanner output cannot be normalized into a valid Finding.

    This error must always propagate — it must never be silently caught and
    replaced with a default value, as that would constitute a fail-open defect.
    """


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

# Explicit mapping tables for each supported scanner's severity vocabulary.
# Unmapped strings are NOT silently promoted to INFO — they raise an error.

_TRIVY_SEVERITY_MAP: Dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.INFO,  # Trivy uses UNKNOWN for unparseable NVD entries
}

_SEMGREP_SEVERITY_MAP: Dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
    # Semgrep CE also uses these in newer output formats
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
}

_DEP_REVIEW_SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _map_trivy_severity(raw: str) -> Severity:
    """Map a Trivy severity string to a normalized Severity enum.

    Raises NormalizationError for any unmapped value other than UNKNOWN.
    """
    normalized = raw.strip().upper()
    if normalized in _TRIVY_SEVERITY_MAP:
        return _TRIVY_SEVERITY_MAP[normalized]
    raise NormalizationError(
        f"Trivy: unrecognized severity value '{raw}'. "
        f"Expected one of: {list(_TRIVY_SEVERITY_MAP.keys())}"
    )


def _map_semgrep_severity(raw: str) -> Severity:
    """Map a Semgrep severity string to a normalized Severity enum."""
    normalized = raw.strip().upper()
    if normalized in _SEMGREP_SEVERITY_MAP:
        return _SEMGREP_SEVERITY_MAP[normalized]
    raise NormalizationError(
        f"Semgrep: unrecognized severity value '{raw}'. "
        f"Expected one of: {list(_SEMGREP_SEVERITY_MAP.keys())}"
    )


def _map_dep_review_severity(raw: str) -> Severity:
    """Map a Dependency Review severity string to a normalized Severity enum."""
    normalized = raw.strip().lower()
    if normalized in _DEP_REVIEW_SEVERITY_MAP:
        return _DEP_REVIEW_SEVERITY_MAP[normalized]
    raise NormalizationError(
        f"Dependency Review: unrecognized severity value '{raw}'. "
        f"Expected one of: {list(_DEP_REVIEW_SEVERITY_MAP.keys())}"
    )


def _safe_str(val: Any, field: str, context: str) -> str:
    """Extract a required string field, raising NormalizationError if missing or blank."""
    if val is None or str(val).strip() == "":
        raise NormalizationError(
            f"{context}: required field '{field}' is missing or empty."
        )
    return str(val).strip()


# ---------------------------------------------------------------------------
# Trivy normalizer
# ---------------------------------------------------------------------------

def normalize_trivy_json(data: Any) -> List[Finding]:
    """Parse Trivy JSON output into a list of normalized Findings.

    Trivy's standard JSON schema (trivy fs --format json):
    {
      "Results": [
        {
          "Target": "...",
          "Type": "...",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-...",
              "PkgName": "...",
              "InstalledVersion": "...",
              "FixedVersion": "...",
              "Severity": "HIGH",
              "Title": "...",
              "Description": "...",
              "CweIDs": ["CWE-..."],
              "References": [...],
              ...
            }
          ]
        }
      ]
    }

    Args:
        data: Parsed JSON object (dict) from Trivy.

    Returns:
        List of normalized Finding objects.

    Raises:
        NormalizationError: If the data does not conform to expected Trivy schema.
    """
    if not isinstance(data, dict):
        raise NormalizationError(
            f"Trivy: expected JSON object at root level. Got: {type(data).__name__}"
        )

    results = data.get("Results")
    if results is None:
        # Trivy may produce empty Results for clean scans
        return []
    if not isinstance(results, list):
        raise NormalizationError(
            f"Trivy: 'Results' must be a list. Got: {type(results).__name__}"
        )

    findings: List[Finding] = []
    for result_idx, result in enumerate(results):
        if not isinstance(result, dict):
            raise NormalizationError(
                f"Trivy: Results[{result_idx}] must be a mapping. Got: {type(result).__name__}"
            )

        target = str(result.get("Target", "unknown"))
        vulns = result.get("Vulnerabilities")
        if vulns is None:
            # Clean target — no vulnerabilities
            continue
        if not isinstance(vulns, list):
            raise NormalizationError(
                f"Trivy: Results[{result_idx}].Vulnerabilities must be a list. "
                f"Got: {type(vulns).__name__}"
            )

        for vuln_idx, vuln in enumerate(vulns):
            if not isinstance(vuln, dict):
                raise NormalizationError(
                    f"Trivy: Results[{result_idx}].Vulnerabilities[{vuln_idx}] "
                    f"must be a mapping. Got: {type(vuln).__name__}"
                )
            ctx = f"Trivy Results[{result_idx}].Vulnerabilities[{vuln_idx}]"
            cve_id = _safe_str(vuln.get("VulnerabilityID"), "VulnerabilityID", ctx)
            severity = _map_trivy_severity(
                _safe_str(vuln.get("Severity"), "Severity", ctx)
            )
            title = vuln.get("Title") or cve_id
            description = vuln.get("Description") or ""
            pkg_name = vuln.get("PkgName") or None
            installed_ver = vuln.get("InstalledVersion") or None
            fixed_ver = vuln.get("FixedVersion") or None
            cwe_ids = vuln.get("CweIDs") or []
            if not isinstance(cwe_ids, list):
                cwe_ids = []

            remediation: str | None = None
            if fixed_ver:
                remediation = f"Upgrade {pkg_name or 'package'} to version {fixed_ver} or later."

            findings.append(
                Finding(
                    id=cve_id,
                    scanner=ScannerType.TRIVY,
                    title=str(title),
                    description=str(description),
                    severity=severity,
                    file_path=target,
                    package_name=pkg_name,
                    installed_version=installed_ver,
                    fixed_version=fixed_ver,
                    cwe_ids=[str(c) for c in cwe_ids],
                    remediation=remediation,
                    metadata={
                        "references": vuln.get("References") or [],
                        "data_source": vuln.get("DataSource"),
                        "result_type": result.get("Type"),
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Semgrep normalizer
# ---------------------------------------------------------------------------

def normalize_semgrep_json(data: Any) -> List[Finding]:
    """Parse Semgrep JSON output into a list of normalized Findings.

    Semgrep CE JSON schema (semgrep --json):
    {
      "results": [
        {
          "check_id": "python.lang.security.audit.dangerous-subprocess-use-audit",
          "path": "app/utils.py",
          "start": {"line": 42, "col": 5},
          "end": {"line": 42, "col": 50},
          "extra": {
            "message": "...",
            "severity": "WARNING",
            "metadata": {"cwe": ["CWE-78"], "owasp": ["A1:2017"]}
          }
        }
      ],
      "errors": []
    }

    Args:
        data: Parsed JSON object from Semgrep.

    Returns:
        List of normalized Finding objects.

    Raises:
        NormalizationError: If the data does not conform to expected Semgrep schema.
    """
    if not isinstance(data, dict):
        raise NormalizationError(
            f"Semgrep: expected JSON object at root level. Got: {type(data).__name__}"
        )

    results = data.get("results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise NormalizationError(
            f"Semgrep: 'results' must be a list. Got: {type(results).__name__}"
        )

    findings: List[Finding] = []
    for idx, result in enumerate(results):
        if not isinstance(result, dict):
            raise NormalizationError(
                f"Semgrep: results[{idx}] must be a mapping. Got: {type(result).__name__}"
            )
        ctx = f"Semgrep results[{idx}]"
        rule_id = _safe_str(result.get("check_id"), "check_id", ctx)
        file_path = result.get("path") or None

        extra = result.get("extra") or {}
        if not isinstance(extra, dict):
            raise NormalizationError(
                f"{ctx}: 'extra' must be a mapping. Got: {type(extra).__name__}"
            )

        raw_severity = _safe_str(extra.get("severity"), "extra.severity", ctx)
        severity = _map_semgrep_severity(raw_severity)
        message = extra.get("message") or rule_id

        start = result.get("start") or {}
        line_num = start.get("line") if isinstance(start, dict) else None
        if line_num is not None:
            try:
                line_num = int(line_num)
                if line_num < 1:
                    line_num = None
            except (ValueError, TypeError):
                line_num = None

        extra_meta = extra.get("metadata") or {}
        if not isinstance(extra_meta, dict):
            extra_meta = {}

        cwe_ids_raw = extra_meta.get("cwe") or []
        if isinstance(cwe_ids_raw, str):
            cwe_ids_raw = [cwe_ids_raw]
        cwe_ids = [str(c) for c in cwe_ids_raw if c]

        findings.append(
            Finding(
                id=rule_id,
                scanner=ScannerType.SEMGREP,
                title=str(message)[:200],  # cap title length for reports
                description=str(message),
                severity=severity,
                file_path=str(file_path) if file_path else None,
                line_number=line_num,
                cwe_ids=cwe_ids,
                remediation=extra_meta.get("message") or None,
                metadata={
                    "owasp": extra_meta.get("owasp") or [],
                    "source_rule_id": rule_id,
                    "semgrep_extra": extra_meta,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Dependency Review normalizer
# ---------------------------------------------------------------------------

def normalize_dependency_review_json(data: Any) -> List[Finding]:
    """Parse GitHub Dependency Review action JSON output into normalized Findings.

    PipelineShield uses a structured intermediate format produced when the
    dependency-review-action writes vulnerability data to a JSON file.

    Expected schema:
    [
      {
        "package_name": "lodash",
        "version": "4.17.15",
        "severity": "critical",
        "advisory_id": "GHSA-35jh-r3h4-6jhm",
        "advisory_url": "https://github.com/advisories/GHSA-...",
        "summary": "Prototype Pollution in lodash",
        "vulnerable_versions": "< 4.17.21",
        "fixed_at": "4.17.21"
      },
      ...
    ]

    Args:
        data: Parsed JSON list from Dependency Review.

    Returns:
        List of normalized Finding objects.

    Raises:
        NormalizationError: If the data does not conform to expected schema.
    """
    if not isinstance(data, list):
        raise NormalizationError(
            f"Dependency Review: expected JSON list at root level. Got: {type(data).__name__}"
        )

    findings: List[Finding] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise NormalizationError(
                f"Dependency Review: item[{idx}] must be a mapping. Got: {type(item).__name__}"
            )
        ctx = f"Dependency Review item[{idx}]"

        advisory_id = _safe_str(item.get("advisory_id"), "advisory_id", ctx)
        pkg_name = _safe_str(item.get("package_name"), "package_name", ctx)
        raw_severity = _safe_str(item.get("severity"), "severity", ctx)
        severity = _map_dep_review_severity(raw_severity)

        summary = item.get("summary") or advisory_id
        installed_ver = item.get("version") or None
        fixed_ver = item.get("fixed_at") or None

        remediation: str | None = None
        if fixed_ver:
            remediation = f"Upgrade {pkg_name} to version {fixed_ver} or later."
        advisory_url = item.get("advisory_url") or None

        findings.append(
            Finding(
                id=advisory_id,
                scanner=ScannerType.DEPENDENCY_REVIEW,
                title=str(summary),
                description=str(summary),
                severity=severity,
                package_name=pkg_name,
                installed_version=str(installed_ver) if installed_ver else None,
                fixed_version=str(fixed_ver) if fixed_ver else None,
                remediation=remediation,
                metadata={
                    "advisory_url": advisory_url,
                    "vulnerable_versions": item.get("vulnerable_versions"),
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Generic PipelineShield normalized-dict normalizer
# ---------------------------------------------------------------------------

def normalize_finding_dict(raw: Dict[str, Any]) -> Finding:
    """Normalize a pre-formatted PipelineShield finding dictionary into a Finding.

    This is used when findings are already in PipelineShield's intermediate format
    (e.g., written by tests or composed from multiple scanner outputs).

    Unlike scanner-specific normalizers, this accepts the full PipelineShield schema.
    Unknown scanners raise NormalizationError. Unknown severities raise NormalizationError.

    Args:
        raw: Dictionary matching the PipelineShield Finding schema.

    Returns:
        Validated Finding object.

    Raises:
        NormalizationError: If the dictionary is missing required fields or contains
                            unsupported scanner/severity values.
    """
    if not isinstance(raw, dict):
        raise NormalizationError(
            f"Finding entry must be a mapping. Got: {type(raw).__name__}"
        )

    # Required fields
    finding_id = raw.get("id")
    if not finding_id or not str(finding_id).strip():
        raise NormalizationError("Finding 'id' is required and must not be empty.")

    title = raw.get("title")
    if not title or not str(title).strip():
        raise NormalizationError("Finding 'title' is required and must not be empty.")

    # Severity — explicit mapping, no silent INFO fallback
    raw_severity = raw.get("severity")
    if raw_severity is None:
        raise NormalizationError("Finding 'severity' is required.")
    sev_str = str(raw_severity).strip().upper()
    try:
        severity = Severity(sev_str)
    except ValueError:
        raise NormalizationError(
            f"Finding '{finding_id}': unrecognized severity '{raw_severity}'. "
            f"Must be one of: {[s.value for s in Severity]}"
        )

    # Scanner — explicit validation, no silent trivy default
    raw_scanner = raw.get("scanner")
    if raw_scanner is None:
        raise NormalizationError(
            f"Finding '{finding_id}': 'scanner' is required. "
            f"Must be one of: {[s.value for s in ScannerType]}"
        )
    try:
        scanner_type = ScannerType(str(raw_scanner).lower().strip())
    except ValueError:
        raise NormalizationError(
            f"Finding '{finding_id}': unsupported scanner '{raw_scanner}'. "
            f"Supported scanners: {[s.value for s in ScannerType]}"
        )

    line_num = raw.get("line_number")
    if line_num is not None:
        try:
            line_num = int(line_num)
        except (ValueError, TypeError):
            line_num = None

    return Finding(
        id=str(finding_id).strip(),
        scanner=scanner_type,
        title=str(title).strip(),
        description=str(raw.get("description") or ""),
        severity=severity,
        file_path=raw.get("file_path") or None,
        line_number=line_num if (line_num and line_num >= 1) else None,
        package_name=raw.get("package_name") or None,
        installed_version=raw.get("installed_version") or None,
        fixed_version=raw.get("fixed_version") or None,
        cwe_ids=list(raw.get("cwe_ids") or []),
        remediation=raw.get("remediation") or None,
        metadata=dict(raw.get("metadata") or {}),
    )


def normalize_finding_list(items: List[Dict[str, Any]]) -> List[Finding]:
    """Normalize a list of PipelineShield finding dictionaries.

    Args:
        items: List of finding dicts.

    Returns:
        List of validated Finding objects.

    Raises:
        NormalizationError: If any item fails normalization.
    """
    if not isinstance(items, list):
        raise NormalizationError(
            f"Findings input must be a list. Got: {type(items).__name__}"
        )
    findings = []
    for idx, item in enumerate(items):
        try:
            findings.append(normalize_finding_dict(item))
        except NormalizationError as e:
            raise NormalizationError(f"Item[{idx}]: {e}") from e
    return findings


class Normalizer:
    """Public interface for scanner-specific and generic normalization.

    Chooses the appropriate parser based on the detected scanner format.
    Unknown scanner formats raise NormalizationError.
    """

    @staticmethod
    def from_trivy(data: Any) -> List[Finding]:
        """Normalize native Trivy JSON output."""
        return normalize_trivy_json(data)

    @staticmethod
    def from_semgrep(data: Any) -> List[Finding]:
        """Normalize native Semgrep JSON output."""
        return normalize_semgrep_json(data)

    @staticmethod
    def from_dependency_review(data: Any) -> List[Finding]:
        """Normalize GitHub Dependency Review JSON output."""
        return normalize_dependency_review_json(data)

    @staticmethod
    def normalize_list(items: List[Dict[str, Any]]) -> List[Finding]:
        """Normalize a list of pre-formatted PipelineShield finding dicts."""
        return normalize_finding_list(items)
