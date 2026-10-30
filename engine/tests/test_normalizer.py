"""Tests for scanner output normalizers (Trivy, Semgrep, Dependency Review, generic)."""

import json
from pathlib import Path

import pytest

from pipelineshield.models import ScannerType, Severity
from pipelineshield.normalizer import (
    NormalizationError,
    Normalizer,
    normalize_finding_dict,
    normalize_finding_list,
    normalize_trivy_json,
    normalize_semgrep_json,
    normalize_dependency_review_json,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Trivy normalizer
# ---------------------------------------------------------------------------

class TestTrivyNormalizer:
    def test_parse_real_fixture(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        assert len(findings) == 3  # 2 from requirements.txt + 1 from package-lock.json
        ids = [f.id for f in findings]
        assert "CVE-2022-42966" in ids
        assert "CVE-2023-49083" in ids
        assert "CVE-2023-26115" in ids

    def test_critical_severity_mapped(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        crit = next(f for f in findings if f.id == "CVE-2022-42966")
        assert crit.severity == Severity.CRITICAL
        assert crit.scanner == ScannerType.TRIVY

    def test_high_severity_mapped(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        high = next(f for f in findings if f.id == "CVE-2023-49083")
        assert high.severity == Severity.HIGH

    def test_medium_severity_mapped(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        med = next(f for f in findings if f.id == "CVE-2023-26115")
        assert med.severity == Severity.MEDIUM

    def test_package_info_preserved(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        crit = next(f for f in findings if f.id == "CVE-2022-42966")
        assert crit.package_name == "cryptography"
        assert crit.installed_version == "3.4.8"
        assert crit.fixed_version == "38.0.3"

    def test_cwe_ids_preserved(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        crit = next(f for f in findings if f.id == "CVE-2022-42966")
        assert "CWE-208" in crit.cwe_ids

    def test_clean_scan_returns_empty(self):
        data = json.loads((FIXTURES / "trivy_clean.json").read_text())
        findings = normalize_trivy_json(data)
        assert findings == []

    def test_null_vulnerabilities_skipped(self):
        """Results entries with null Vulnerabilities are valid (clean target)."""
        data = {
            "Results": [
                {"Target": "go.sum", "Type": "gomod", "Vulnerabilities": None}
            ]
        }
        findings = normalize_trivy_json(data)
        assert findings == []

    def test_no_results_key_returns_empty(self):
        findings = normalize_trivy_json({"SchemaVersion": 2})
        assert findings == []

    def test_non_dict_root_raises(self):
        with pytest.raises(NormalizationError, match="expected JSON object"):
            normalize_trivy_json([{"VulnerabilityID": "CVE-001"}])

    def test_non_list_results_raises(self):
        with pytest.raises(NormalizationError, match="'Results' must be a list"):
            normalize_trivy_json({"Results": "invalid"})

    def test_missing_vulnerability_id_raises(self):
        data = {
            "Results": [{
                "Target": "req.txt",
                "Vulnerabilities": [{"Severity": "HIGH", "Title": "Test"}]
            }]
        }
        with pytest.raises(NormalizationError, match="VulnerabilityID"):
            normalize_trivy_json(data)

    def test_missing_severity_raises(self):
        data = {
            "Results": [{
                "Target": "req.txt",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-001", "Title": "Test"}]
            }]
        }
        with pytest.raises(NormalizationError, match="Severity"):
            normalize_trivy_json(data)

    def test_unknown_trivy_severity_raises(self):
        data = {
            "Results": [{
                "Target": "req.txt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-001",
                    "Severity": "EXTREME",
                    "Title": "Test"
                }]
            }]
        }
        with pytest.raises(NormalizationError, match="unrecognized severity"):
            normalize_trivy_json(data)

    def test_remediation_auto_generated(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = normalize_trivy_json(data)
        crit = next(f for f in findings if f.id == "CVE-2022-42966")
        assert "38.0.3" in crit.remediation

    def test_normalizer_class_from_trivy(self):
        data = json.loads((FIXTURES / "trivy_vulnerabilities.json").read_text())
        findings = Normalizer.from_trivy(data)
        assert len(findings) == 3

    def test_clean_misconfig_returns_empty(self):
        data = json.loads((FIXTURES / "trivy_clean_misconfig.json").read_text())
        findings = normalize_trivy_json(data)
        assert findings == []

    def test_blocking_misconfig_parsed(self):
        data = json.loads((FIXTURES / "trivy_blocking_misconfig.json").read_text())
        findings = normalize_trivy_json(data)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "DS002"
        assert f.severity == Severity.HIGH
        assert f.scanner == ScannerType.TRIVY
        assert f.file_path == "Dockerfile"
        assert f.line_number == 1
        assert "USER" in f.remediation
        assert f.metadata.get("finding_type") == "misconfiguration"

    def test_clean_secrets_returns_empty(self):
        data = json.loads((FIXTURES / "trivy_clean_secrets.json").read_text())
        findings = normalize_trivy_json(data)
        assert findings == []

    def test_exposed_secret_parsed(self):
        data = json.loads((FIXTURES / "trivy_exposed_secret.json").read_text())
        findings = normalize_trivy_json(data)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "aws-access-key-id"
        assert f.severity == Severity.CRITICAL
        assert f.scanner == ScannerType.TRIVY
        assert f.file_path == "config/settings.py"
        assert f.line_number == 14
        assert "Revoke" in f.remediation
        assert f.metadata.get("category") == "AWS"
        assert f.metadata.get("finding_type") == "secret"

    def test_mixed_results_parsed(self):
        data = json.loads((FIXTURES / "trivy_mixed_results.json").read_text())
        findings = normalize_trivy_json(data)
        assert len(findings) == 3
        ids = {f.id for f in findings}
        assert "CVE-2022-42966" in ids
        assert "DS002" in ids
        assert "github-pat" in ids
        types = {f.metadata.get("finding_type") for f in findings}
        assert types == {"vulnerability", "misconfiguration", "secret"}

    def test_non_list_misconfigurations_raises(self):
        data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": "invalid"}]}
        with pytest.raises(NormalizationError, match="Misconfigurations must be a list"):
            normalize_trivy_json(data)

    def test_non_dict_misconfiguration_item_raises(self):
        data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": ["not-a-dict"]}]}
        with pytest.raises(NormalizationError, match="must be a mapping"):
            normalize_trivy_json(data)

    def test_missing_misconfiguration_id_raises(self):
        data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [{"Severity": "HIGH"}]}]}
        with pytest.raises(NormalizationError, match="required field 'ID'"):
            normalize_trivy_json(data)

    def test_non_list_secrets_raises(self):
        data = {"Results": [{"Target": ".env", "Secrets": "invalid"}]}
        with pytest.raises(NormalizationError, match="Secrets must be a list"):
            normalize_trivy_json(data)

    def test_non_dict_secret_item_raises(self):
        data = {"Results": [{"Target": ".env", "Secrets": ["not-a-dict"]}]}
        with pytest.raises(NormalizationError, match="must be a mapping"):
            normalize_trivy_json(data)

    def test_missing_secret_rule_id_raises(self):
        data = {"Results": [{"Target": ".env", "Secrets": [{"Severity": "CRITICAL"}]}]}
        with pytest.raises(NormalizationError, match="required field 'RuleID'"):
            normalize_trivy_json(data)




# ---------------------------------------------------------------------------
# Semgrep normalizer
# ---------------------------------------------------------------------------

class TestSemgrepNormalizer:
    def test_parse_real_fixture(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        assert len(findings) == 2
        ids = [f.id for f in findings]
        assert "python.lang.security.audit.dangerous-subprocess-use-audit" in ids
        assert "python.lang.security.audit.hardcoded-password-string" in ids

    def test_error_severity_maps_to_high(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        subprocess_f = next(f for f in findings if "subprocess" in f.id)
        assert subprocess_f.severity == Severity.HIGH

    def test_warning_severity_maps_to_medium(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        password_f = next(f for f in findings if "hardcoded" in f.id)
        assert password_f.severity == Severity.MEDIUM

    def test_file_path_preserved(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        subprocess_f = next(f for f in findings if "subprocess" in f.id)
        assert subprocess_f.file_path == "app/shell_runner.py"

    def test_line_number_preserved(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        subprocess_f = next(f for f in findings if "subprocess" in f.id)
        assert subprocess_f.line_number == 42

    def test_cwe_ids_preserved(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        subprocess_f = next(f for f in findings if "subprocess" in f.id)
        assert "CWE-78" in subprocess_f.cwe_ids

    def test_scanner_is_semgrep(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = normalize_semgrep_json(data)
        for f in findings:
            assert f.scanner == ScannerType.SEMGREP

    def test_clean_scan_returns_empty(self):
        data = json.loads((FIXTURES / "semgrep_clean.json").read_text())
        findings = normalize_semgrep_json(data)
        assert findings == []

    def test_no_results_key_returns_empty(self):
        findings = normalize_semgrep_json({})
        assert findings == []

    def test_non_dict_root_raises(self):
        with pytest.raises(NormalizationError, match="expected JSON object"):
            normalize_semgrep_json([])

    def test_missing_check_id_raises(self):
        data = {"results": [{"path": "app.py", "extra": {"severity": "ERROR", "message": "test"}}]}
        with pytest.raises(NormalizationError, match="check_id"):
            normalize_semgrep_json(data)

    def test_missing_severity_raises(self):
        data = {"results": [{"check_id": "rule.id", "path": "app.py", "extra": {"message": "test"}}]}
        with pytest.raises(NormalizationError, match="extra.severity"):
            normalize_semgrep_json(data)

    def test_unknown_semgrep_severity_raises(self):
        data = {"results": [{
            "check_id": "rule.id",
            "path": "app.py",
            "extra": {"severity": "BLOCKER", "message": "test"}
        }]}
        with pytest.raises(NormalizationError, match="unrecognized severity"):
            normalize_semgrep_json(data)

    def test_normalizer_class_from_semgrep(self):
        data = json.loads((FIXTURES / "semgrep_findings.json").read_text())
        findings = Normalizer.from_semgrep(data)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Dependency Review normalizer
# ---------------------------------------------------------------------------

class TestDepReviewNormalizer:
    def test_parse_real_fixture(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = normalize_dependency_review_json(data)
        assert len(findings) == 2

    def test_critical_severity_mapped(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = normalize_dependency_review_json(data)
        lodash = next(f for f in findings if f.id == "GHSA-35jh-r3h4-6jhm")
        assert lodash.severity == Severity.CRITICAL

    def test_high_severity_mapped(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = normalize_dependency_review_json(data)
        minimist = next(f for f in findings if f.id == "GHSA-xvch-5gv4-984h")
        assert minimist.severity == Severity.HIGH

    def test_package_info_preserved(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = normalize_dependency_review_json(data)
        lodash = next(f for f in findings if "lodash" in f.package_name)
        assert lodash.package_name == "lodash"
        assert lodash.installed_version == "4.17.15"
        assert lodash.fixed_version == "4.17.21"

    def test_scanner_is_dependency_review(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = normalize_dependency_review_json(data)
        for f in findings:
            assert f.scanner == ScannerType.DEPENDENCY_REVIEW

    def test_remediation_auto_generated(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = normalize_dependency_review_json(data)
        lodash = next(f for f in findings if "lodash" in f.package_name)
        assert "4.17.21" in lodash.remediation

    def test_empty_list_returns_empty(self):
        findings = normalize_dependency_review_json([])
        assert findings == []

    def test_non_list_root_raises(self):
        with pytest.raises(NormalizationError, match="expected JSON list"):
            normalize_dependency_review_json({"key": "value"})

    def test_missing_advisory_id_raises(self):
        data = [{"package_name": "pkg", "severity": "high"}]
        with pytest.raises(NormalizationError, match="advisory_id"):
            normalize_dependency_review_json(data)

    def test_unknown_dep_severity_raises(self):
        data = [{
            "advisory_id": "GHSA-xxxx",
            "package_name": "test",
            "severity": "extreme",
            "summary": "test"
        }]
        with pytest.raises(NormalizationError, match="unrecognized severity"):
            normalize_dependency_review_json(data)

    def test_normalizer_class_from_dep_review(self):
        data = json.loads((FIXTURES / "dep_review_findings.json").read_text())
        findings = Normalizer.from_dependency_review(data)
        assert len(findings) == 2

    def test_github_dependency_review_action_format(self):
        data = [
            {
                "change_type": "added",
                "manifest": "package.json",
                "name": "example-pkg",
                "version": "1.0.0",
                "license": "MIT",
                "vulnerabilities": [
                    {
                        "severity": "critical",
                        "advisory_ghsa_id": "GHSA-abcd-1234",
                        "advisory_summary": "Critical vuln in example-pkg",
                        "safe_version": "1.0.1",
                    }
                ]
            }
        ]
        findings = normalize_dependency_review_json(data)
        assert len(findings) == 1
        assert findings[0].id == "GHSA-abcd-1234"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].package_name == "example-pkg"
        assert findings[0].license == "MIT"
        assert findings[0].fixed_version == "1.0.1"

    def test_github_dependency_review_action_format_license_only(self):
        data = [
            {
                "change_type": "added",
                "manifest": "package.json",
                "name": "gpl-pkg",
                "version": "2.0.0",
                "license": "GPL-3.0",
                "vulnerabilities": []
            }
        ]
        findings = normalize_dependency_review_json(data)
        assert len(findings) == 1
        assert findings[0].id == "LIC-gpl-pkg"
        assert findings[0].license == "GPL-3.0"
        assert findings[0].package_name == "gpl-pkg"

    def test_fixture_official_added_vuln(self):
        data = json.loads((FIXTURES / "dep_review_official_added_vuln.json").read_text())
        findings = normalize_dependency_review_json(data)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "GHSA-35jh-r3h4-6jhm"
        assert f.severity == Severity.CRITICAL
        assert f.package_name == "lodash"
        assert f.installed_version == "4.17.15"
        assert f.fixed_version == "4.17.21"
        assert f.license == "MIT"
        assert f.scanner == ScannerType.DEPENDENCY_REVIEW

    def test_fixture_official_added_clean(self):
        data = json.loads((FIXTURES / "dep_review_official_added_clean.json").read_text())
        findings = normalize_dependency_review_json(data)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "LIC-chalk"
        assert f.severity == Severity.INFO
        assert f.package_name == "chalk"
        assert f.license == "MIT"

    def test_fixture_official_added_denied_license(self):
        data = json.loads((FIXTURES / "dep_review_official_added_denied_license.json").read_text())
        findings = normalize_dependency_review_json(data)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "LIC-gpl-copyleft-lib"
        assert f.license == "GPL-3.0"
        assert f.severity == Severity.INFO  # Normalized finding has INFO, policy engine enforces license

    def test_fixture_official_removed_vuln_is_skipped(self):
        """Removed vulnerable dependencies must NOT produce findings or block PRs."""
        data = json.loads((FIXTURES / "dep_review_official_removed_vuln.json").read_text())
        findings = normalize_dependency_review_json(data)
        assert findings == []

    def test_fixture_official_removed_denied_license_is_skipped(self):
        """Removed prohibited-license dependencies must NOT produce findings or block PRs."""
        data = json.loads((FIXTURES / "dep_review_official_removed_denied_license.json").read_text())
        findings = normalize_dependency_review_json(data)
        assert findings == []

    def test_invalid_change_type_raises(self):
        data = [{"change_type": "modified", "name": "foo", "vulnerabilities": []}]
        with pytest.raises(NormalizationError, match="change_type"):
            normalize_dependency_review_json(data)

    def test_non_string_change_type_raises(self):
        data = [{"change_type": 123, "name": "foo", "vulnerabilities": []}]
        with pytest.raises(NormalizationError, match="must be a string"):
            normalize_dependency_review_json(data)

    def test_non_dict_item_raises(self):
        data = ["not-a-dict"]
        with pytest.raises(NormalizationError, match="must be a mapping"):
            normalize_dependency_review_json(data)

    def test_invalid_vulnerabilities_type_raises(self):
        data = [{"name": "foo", "vulnerabilities": "not-a-list"}]
        with pytest.raises(NormalizationError, match="must be a list"):
            normalize_dependency_review_json(data)



# ---------------------------------------------------------------------------
# Generic normalize_finding_dict
# ---------------------------------------------------------------------------

class TestNormalizeFindingDict:
    def test_valid_dict_normalizes(self):
        raw = {
            "id": "CVE-2024-001",
            "scanner": "trivy",
            "title": "Test Vulnerability",
            "severity": "HIGH",
        }
        f = normalize_finding_dict(raw)
        assert f.id == "CVE-2024-001"
        assert f.severity == Severity.HIGH
        assert f.scanner == ScannerType.TRIVY

    def test_missing_id_raises(self):
        with pytest.raises(NormalizationError, match="'id' is required"):
            normalize_finding_dict({"scanner": "trivy", "title": "Test", "severity": "HIGH"})

    def test_empty_id_raises(self):
        with pytest.raises(NormalizationError, match="'id' is required"):
            normalize_finding_dict({"id": "", "scanner": "trivy", "title": "Test", "severity": "HIGH"})

    def test_missing_title_raises(self):
        with pytest.raises(NormalizationError, match="'title' is required"):
            normalize_finding_dict({"id": "CVE-001", "scanner": "trivy", "severity": "HIGH"})

    def test_missing_severity_raises(self):
        with pytest.raises(NormalizationError, match="'severity' is required"):
            normalize_finding_dict({"id": "CVE-001", "scanner": "trivy", "title": "Test"})

    def test_unknown_severity_raises(self):
        """Unknown severity must NOT silently become INFO."""
        with pytest.raises(NormalizationError, match="unrecognized severity"):
            normalize_finding_dict({
                "id": "CVE-001", "scanner": "trivy",
                "title": "Test", "severity": "EXTREME"
            })

    def test_missing_scanner_raises(self):
        """Missing scanner must NOT silently default to trivy."""
        with pytest.raises(NormalizationError, match="'scanner' is required"):
            normalize_finding_dict({"id": "CVE-001", "title": "Test", "severity": "HIGH"})

    def test_unknown_scanner_raises(self):
        """Unknown scanner must NOT silently default to trivy."""
        with pytest.raises(NormalizationError, match="unsupported scanner"):
            normalize_finding_dict({
                "id": "CVE-001", "scanner": "snyk",
                "title": "Test", "severity": "HIGH"
            })

    def test_non_dict_raises(self):
        with pytest.raises(NormalizationError, match="must be a mapping"):
            normalize_finding_dict(["not", "a", "dict"])

    def test_negative_line_number_becomes_none(self):
        """Invalid line numbers are discarded rather than stored."""
        raw = {
            "id": "CVE-001", "scanner": "trivy",
            "title": "Test", "severity": "LOW",
            "line_number": -5
        }
        f = normalize_finding_dict(raw)
        assert f.line_number is None

    def test_string_severity_case_insensitive(self):
        f = normalize_finding_dict({
            "id": "CVE-001", "scanner": "semgrep",
            "title": "Test", "severity": "critical"
        })
        assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# normalize_finding_list
# ---------------------------------------------------------------------------

class TestNormalizeFindingList:
    def test_valid_list(self):
        items = [
            {"id": "CVE-001", "scanner": "trivy", "title": "A", "severity": "HIGH"},
            {"id": "CVE-002", "scanner": "semgrep", "title": "B", "severity": "MEDIUM"},
        ]
        findings = normalize_finding_list(items)
        assert len(findings) == 2

    def test_non_list_raises(self):
        with pytest.raises(NormalizationError, match="must be a list"):
            normalize_finding_list({"key": "value"})

    def test_empty_list_valid(self):
        findings = normalize_finding_list([])
        assert findings == []

    def test_error_includes_item_index(self):
        items = [
            {"id": "CVE-001", "scanner": "trivy", "title": "A", "severity": "HIGH"},
            {"id": "", "scanner": "trivy", "title": "B", "severity": "LOW"},  # invalid
        ]
        with pytest.raises(NormalizationError, match="Item\\[1\\]"):
            normalize_finding_list(items)

    def test_fixture_clean_findings_loads(self):
        import json
        data = json.loads((FIXTURES / "clean_findings.json").read_text())
        findings = normalize_finding_list(data)
        assert findings == []

    def test_fixture_critical_findings_loads(self):
        import json
        data = json.loads((FIXTURES / "critical_findings.json").read_text())
        findings = normalize_finding_list(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_normalizer_class_normalize_list(self):
        items = [{"id": "X-001", "scanner": "semgrep", "title": "T", "severity": "INFO"}]
        findings = Normalizer.normalize_list(items)
        assert len(findings) == 1
