"""Data models and schemas for PipelineShield."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    """Supported security scanner identifiers."""
    TRIVY = "trivy"
    SEMGREP = "semgrep"
    DEPENDENCY_REVIEW = "dependency_review"


class GateDecision(str, Enum):
    """Security gate evaluation decision."""
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


class Finding(BaseModel):
    """Normalized security finding representation."""
    id: str = Field(description="Unique finding identifier (e.g. CVE-2023-1234 or rule ID)")
    scanner: ScannerType = Field(description="Scanner that detected the finding")
    title: str = Field(description="Short human-readable finding summary")
    description: Optional[str] = Field(default="", description="Detailed explanation of the vulnerability")
    severity: Severity = Field(description="Standardized severity level")
    file_path: Optional[str] = Field(default=None, description="Path to file where finding was detected")
    line_number: Optional[int] = Field(default=None, description="Line number if available")
    package_name: Optional[str] = Field(default=None, description="Affected dependency package")
    installed_version: Optional[str] = Field(default=None, description="Currently installed package version")
    fixed_version: Optional[str] = Field(default=None, description="Fixed package version if available")
    cwe_ids: List[str] = Field(default_factory=list, description="Associated Common Weakness Enumeration IDs")
    remediation: Optional[str] = Field(default=None, description="Suggested action to resolve finding")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw scanner-specific metadata")


class PolicyThresholds(BaseModel):
    """Decision thresholds mapped by severity."""
    critical: GateDecision = GateDecision.BLOCK
    high: GateDecision = GateDecision.BLOCK
    medium: GateDecision = GateDecision.WARN
    low: GateDecision = GateDecision.PASS
    info: GateDecision = GateDecision.PASS


class ScannerConfig(BaseModel):
    """Scanner-specific enablement and configuration."""
    enabled: bool = True
    fail_on_severity: List[str] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)


class PolicyExemptions(BaseModel):
    """Allowed finding IDs or file paths."""
    findings: List[str] = Field(default_factory=list)
    paths: List[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    """Parsed and validated policy configuration."""
    version: str = "1.0"
    mode: str = "strict"
    fail_on_block: bool = True
    fail_on_warn: bool = False
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)
    scanners: Dict[str, ScannerConfig] = Field(default_factory=dict)
    exemptions: PolicyExemptions = Field(default_factory=PolicyExemptions)


class EvaluationSummary(BaseModel):
    """Aggregated finding counts by severity."""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    exempted: int = 0


class EvaluationResult(BaseModel):
    """Complete output of a policy evaluation run."""
    decision: GateDecision
    summary: EvaluationSummary
    findings: List[Finding] = Field(default_factory=list)
    blocking_findings: List[Finding] = Field(default_factory=list)
    warning_findings: List[Finding] = Field(default_factory=list)
    exempted_findings: List[Finding] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
