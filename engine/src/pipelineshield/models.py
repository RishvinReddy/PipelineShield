"""Data models and schemas for PipelineShield.

All models use Pydantic v2 with strict validation.
Unknown or unsupported values are rejected explicitly — never silently defaulted.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(str, Enum):
    """Normalized vulnerability severity levels.

    Order from most to least severe: CRITICAL > HIGH > MEDIUM > LOW > INFO.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    """Supported security scanner identifiers.

    Only explicitly supported scanners are permitted.
    Unknown scanner sources must raise a ValueError rather than silently default.
    """
    TRIVY = "trivy"
    SEMGREP = "semgrep"
    DEPENDENCY_REVIEW = "dependency_review"


class EnforcementMode(str, Enum):
    """Policy enforcement mode controlling how violations are acted upon.

    - STRICT: Apply blocking and warning thresholds as configured.
    - PERMISSIVE: Downgrade all BLOCK decisions to WARN — never block.
    - MONITOR: Record all findings and observations without any enforcement.
    """
    STRICT = "strict"
    PERMISSIVE = "permissive"
    MONITOR = "monitor"


class GateDecision(str, Enum):
    """Security gate evaluation decision.

    Exit codes:
    - PASS:  0  (All findings within policy thresholds)
    - WARN:  0  (Advisory findings only — no blocking violations)
    - BLOCK: 1  (At least one non-exempt finding violates a blocking rule)
    - ERROR: 2  (Engine cannot reliably complete evaluation)
    """
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


class Finding(BaseModel):
    """Normalized security finding representation.

    Produced by scanner-specific normalizers and consumed by the policy engine.
    All required fields must be present. Optional fields default to None.
    """
    id: str = Field(description="Unique finding identifier (e.g. CVE-2023-1234 or Semgrep rule ID)")
    scanner: ScannerType = Field(description="Scanner that detected this finding")
    title: str = Field(description="Short human-readable finding summary")
    description: str = Field(default="", description="Detailed explanation of the vulnerability")
    severity: Severity = Field(description="Standardized severity level")
    file_path: Optional[str] = Field(default=None, description="Path to file where finding was detected")
    line_number: Optional[int] = Field(default=None, description="Line number if available", ge=1)
    package_name: Optional[str] = Field(default=None, description="Affected dependency package name")
    installed_version: Optional[str] = Field(default=None, description="Currently installed package version")
    fixed_version: Optional[str] = Field(default=None, description="Minimum safe package version if available")
    cwe_ids: List[str] = Field(default_factory=list, description="Associated CWE identifiers (e.g. CWE-89)")
    license: Optional[str] = Field(default=None, description="Software license identifier (e.g. MIT, GPL-3.0)")
    remediation: Optional[str] = Field(default=None, description="Suggested action to resolve this finding")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw scanner-specific metadata (read-only)")

    @field_validator("id")
    @classmethod
    def id_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Finding 'id' must not be empty")
        return v.strip()

    @field_validator("title")
    @classmethod
    def title_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Finding 'title' must not be empty")
        return v.strip()


class PolicyThresholds(BaseModel):
    """Security gate decision thresholds mapped by severity level.

    Each severity maps to a GateDecision (BLOCK, WARN, or PASS).
    ERR is not a valid threshold value — it is reserved for engine failures.
    """
    model_config = ConfigDict(extra="forbid")

    critical: GateDecision = GateDecision.BLOCK
    high: GateDecision = GateDecision.BLOCK
    medium: GateDecision = GateDecision.WARN
    low: GateDecision = GateDecision.PASS
    info: GateDecision = GateDecision.PASS

    @field_validator("critical", "high", "medium", "low", "info", mode="before")
    @classmethod
    def threshold_must_not_be_error(cls, v: Any) -> Any:
        """Reject ERROR as a threshold value — it is reserved for engine failures."""
        if str(v).upper() == "ERROR":
            raise ValueError(
                "GateDecision.ERROR is not a valid severity threshold. "
                "Use BLOCK, WARN, or PASS."
            )
        return v


class ScannerConfig(BaseModel):
    """Base scanner configuration."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class TrivyScannerConfig(ScannerConfig):
    """Typed configuration options for Trivy vulnerability scanner."""
    fail_on_cve_severity: Optional[List[Severity]] = None
    scan_types: List[str] = Field(
        default_factory=lambda: ["vuln", "misconfig", "secret"]
    )
    ignore_unfixed: bool = False

    @field_validator("fail_on_cve_severity", mode="before")
    @classmethod
    def validate_trivy_severities(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, Severity):
                    res.append(item)
                else:
                    try:
                        res.append(Severity(str(item).strip().upper()))
                    except ValueError:
                        raise ValueError(f"Trivy: unrecognized severity '{item}' in fail_on_cve_severity")
            return res
        raise ValueError("fail_on_cve_severity must be a list")

    @field_validator("scan_types")
    @classmethod
    def validate_scan_types(cls, v: List[str]) -> List[str]:
        valid_types = {"vuln", "misconfig", "secret", "license"}
        for item in v:
            if item not in valid_types:
                raise ValueError(
                    f"Trivy: unsupported scan_type '{item}'. Expected one of: {sorted(valid_types)}"
                )
        return v


class SemgrepScannerConfig(ScannerConfig):
    """Typed configuration options for Semgrep SAST scanner."""
    rulesets: List[str] = Field(
        default_factory=lambda: ["p/security-audit", "p/secrets", "p/owasp-top-ten"]
    )
    fail_on_severity: Optional[List[Severity]] = None

    @field_validator("fail_on_severity", mode="before")
    @classmethod
    def validate_semgrep_severities(cls, v: Any) -> Any:
        if v is None:
            return None
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, Severity):
                    res.append(item)
                else:
                    norm = str(item).strip().upper()
                    if norm in mapping:
                        res.append(mapping[norm])
                    else:
                        raise ValueError(f"Semgrep: unrecognized severity '{item}' in fail_on_severity")
            return res
        raise ValueError("fail_on_severity must be a list")


class DependencyReviewScannerConfig(ScannerConfig):
    """Typed configuration options for GitHub Dependency Review scanner."""
    allow_licenses: List[str] = Field(default_factory=list)
    deny_licenses: List[str] = Field(default_factory=list)
    deny_severities: Optional[List[Severity]] = None
    fail_on_severity: Optional[List[Severity]] = None

    @field_validator("deny_severities", "fail_on_severity", mode="before")
    @classmethod
    def validate_dep_severities(cls, v: Any) -> Any:
        if v is None:
            return None
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, Severity):
                    res.append(item)
                else:
                    norm = str(item).strip().lower()
                    if norm in mapping:
                        res.append(mapping[norm])
                    else:
                        raise ValueError(f"Dependency Review: unrecognized severity '{item}' in deny_severities")
            return res
        raise ValueError("deny_severities must be a list")


class ScannersConfig(BaseModel):
    """Typed scanner configuration container."""
    model_config = ConfigDict(extra="forbid")

    trivy: TrivyScannerConfig = Field(default_factory=TrivyScannerConfig)
    semgrep: SemgrepScannerConfig = Field(default_factory=SemgrepScannerConfig)
    dependency_review: DependencyReviewScannerConfig = Field(
        default_factory=DependencyReviewScannerConfig
    )

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(f"Unknown scanner '{item}'. Supported: trivy, semgrep, dependency_review")

    def __contains__(self, item: object) -> bool:
        return isinstance(item, str) and hasattr(self, item) and not item.startswith("_")

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)


class PolicyExemptions(BaseModel):
    """Allowlist of finding IDs or path glob patterns that are exempt from enforcement.

    Exempted findings are still recorded in reports — they are never silently dropped.
    """
    model_config = ConfigDict(extra="forbid")

    findings: List[str] = Field(default_factory=list, description="Exact finding IDs to exempt")
    paths: List[str] = Field(default_factory=list, description="Glob patterns for exempt file paths")

    @field_validator("findings", "paths", mode="before")
    @classmethod
    def must_be_list(cls, v: Any) -> Any:
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("Exemptions 'findings' and 'paths' must be lists")
        return v


class PolicyConfig(BaseModel):
    """Parsed and validated security policy configuration.

    Loaded from config/policy.yaml and validated before use.
    Invalid configurations raise ValueError — they never silently default to unsafe states.
    """
    model_config = ConfigDict(extra="forbid")

    version: str = Field(default="1.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    mode: EnforcementMode = Field(default=EnforcementMode.STRICT)
    fail_on_block: bool = Field(default=True)
    fail_on_warn: bool = Field(default=False)
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    exemptions: PolicyExemptions = Field(default_factory=PolicyExemptions)

    @field_validator("mode", mode="before")
    @classmethod
    def validate_mode(cls, v: Any) -> Any:
        """Reject invalid enforcement modes explicitly."""
        if isinstance(v, str) and v.lower() not in {m.value for m in EnforcementMode}:
            valid = ", ".join(m.value for m in EnforcementMode)
            raise ValueError(
                f"Invalid enforcement mode '{v}'. Must be one of: {valid}"
            )
        return v

    @model_validator(mode="after")
    def validate_fail_flags_consistency(self) -> "PolicyConfig":
        """Warn if fail_on_warn=True but fail_on_block=False — that is likely misconfigured."""
        if self.fail_on_warn and not self.fail_on_block:
            raise ValueError(
                "Inconsistent policy: fail_on_warn=true with fail_on_block=false would "
                "block on warnings but not on explicit BLOCK findings. "
                "Set fail_on_block=true or fail_on_warn=false."
            )
        return self


class EvaluationSummary(BaseModel):
    """Aggregated finding counts by severity and status."""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    exempted: int = 0
    blocking_count: int = 0
    warning_count: int = 0


class EvaluationResult(BaseModel):
    """Complete output of a policy evaluation run.

    Produced by PolicyEngine.evaluate() and consumed by Reporter.
    The decision field is authoritative — all other fields provide supporting evidence.
    """
    decision: GateDecision
    policy_mode: EnforcementMode = EnforcementMode.STRICT
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    summary: EvaluationSummary
    findings: List[Finding] = Field(default_factory=list)
    blocking_findings: List[Finding] = Field(default_factory=list)
    warning_findings: List[Finding] = Field(default_factory=list)
    exempted_findings: List[Finding] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list, description="Engine errors that caused ERROR decisions")
    scanner_status: Dict[str, str] = Field(
        default_factory=dict, description="Execution status per scanner ('enabled' or 'disabled')"
    )

