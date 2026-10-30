# PipelineShield Implementation Plan & Roadmap

This document outlines the phased engineering blueprint for building **PipelineShield**, an automated DevSecOps security gatekeeper platform.

---

## Architecture Principles

1. **Gatekeeper First**: The automated security gate precedes frontend decoration. The core value lies in accurate scanning, finding normalization, and strict policy enforcement.
2. **Fail-Closed Execution**: Any scanner crash, installation failure, missing report, or malformed JSON fails the CI job immediately. Suppressing scanner failures or substituting clean fallbacks is strictly prohibited.
3. **Zero-Cost Infrastructure**: Free and open-source tooling only (GitHub Actions, Trivy, Semgrep CE, GitHub Dependency Review, Vercel Hobby tier). No external databases, paid cloud servers, or commercial API keys.
4. **Reproducibility & Isolation**: Separation of concerns between the Python Policy Engine (`engine/`) and the Next.js Dashboard (`dashboard/`).
5. **Least-Privilege Security**: Minimal GitHub Actions tokens (`contents: read` only); full commit SHA action pinning.

---

## Phase Breakdown

### Phase 1: Repository & Development Environment Scaffold
- **Status**: Completed (Milestone 1)
- **Deliverables**:
  - Clean GitHub repository clone with verified `origin` remote.
  - Root `.gitignore` covering Python, Node.js, Next.js, and sensitive files.
  - MIT License and root `README.md`.
  - Phased `PROJECT_PLAN.md`.
  - Python packaging layout (`engine/pyproject.toml`, source modules, tests).
  - Next.js TypeScript App Router dashboard initialized under `dashboard/`.
  - Initial declarative security policy [`config/policy.yaml`](config/policy.yaml).
  - Architecture, testing, and threat model documentation placeholders under `docs/`.
  - First Git commit pushed to remote `main`.

---

### Phase 2: Python Security Policy Engine
- **Status**: Completed (Milestone 2)
- **Deliverables**:
  - Core data schemas using Pydantic (`Finding`, `Severity`, `ScannerType`, `PolicyRule`, `PolicyResult`).
  - Scanner finding normalizers for Trivy JSON, Semgrep JSON, and GitHub Dependency Review format.
  - Config loader with strict validation for `config/policy.yaml` (rejection of unknown keys, typed scanner configs).
  - Policy evaluation engine with support for severity thresholds, scanner enablement, license compliance (allow/deny lists), and path/finding exemptions.
  - Standardized JSON reporter and GitHub Actions step-summary Markdown reporter.
  - Command-line interface (`pipelineshield --policy ... --trivy ... --semgrep ... --dependency-review ...`).

---

### Phase 3: Automated Policy Engine Testing
- **Status**: Completed (Milestone 3)
- **Deliverables**:
  - Comprehensive unit test suite (216 tests, 92% code coverage) across all policy engine components.
  - Fixture datasets representing clean scans, critical CVEs, SAST rule violations, and dependency reviews.
  - Edge cases testing: malformed scanner outputs, empty finding lists, missing policy files, unhandled severities, license enforcement, and scanner enablement.
  - Defensive error-guard execution mode failing safely on internal faults (exit code 2).

---

### Phase 4: Trivy, Semgrep & Dependency Review CI Integration
- **Status**: Completed (Milestone 4 - Hardened)
- **Deliverables**:
  - GitHub Actions workflow (`.github/workflows/security-gate.yml`) triggered on `pull_request` and `push` to `main`.
  - Fail-closed execution: removed `|| true` and empty-file fallbacks. Scanner crashes or invalid JSON immediately fail the CI job.
  - Trivy filesystem & dependency vulnerability scanner integration.
  - Semgrep CE static analysis integration (OWASP Top 10, security-audit, secrets).
  - Official GitHub Dependency Review action integration (`actions/dependency-review-action`) on pull requests with JSON export.
  - Execution of PipelineShield Policy Engine to evaluate combined findings against policy.
  - Automated blocking of pull requests exceeding policy thresholds (exit code 1).
  - Upload of security report artifacts (`reports/security-summary.json`) and Markdown step summaries.

---

### Phase 5: Next.js Security Dashboard
- **Status**: Completed (Milestone 5 - Hardened)
- **Deliverables**:
  - Modern, responsive security dashboard built with Next.js App Router and Tailwind CSS.
  - Gate Decision status hero card (PASS, WARN, BLOCK, ERROR).
  - Clear provenance indicators distinguishing demonstration/sample reports from user-uploaded evaluation artifacts.
  - In-browser schema validation against `EvaluationResult` preventing unhandled exceptions or malformed uploads.
  - Vulnerability breakdown metrics and severity distribution bars with timestamp display.
  - Interactive finding explorer with search, severity filters, scanner filters, and remediation details.
  - Health check route (`/api/health`) documented accurately as frontend endpoint liveness check.

---

### Phase 6: Vercel Deployment Setup
- **Status**: Configured / Deployment Pending
- **Deliverables**:
  - Vercel deployment configuration (`dashboard/vercel.json`).
  - Health check endpoint (`/api/health`) for endpoint liveness monitoring.
  - Zero-error TypeScript compilation and static asset generation.
  - *Pending*: Verified deployment on a live public Vercel domain.

---

### Phase 7: Security Hardening & CI Least Privilege
- **Status**: Completed (Milestone 7)
- **Deliverables**:
  - Strict least-privilege GitHub Actions runner permissions (`contents: read` only at job and top level).
  - Unused `pull-requests: write` and `security-events: write` permissions eliminated.
  - Full immutable commit SHA pinning for all GitHub actions (`checkout`, `setup-python`, `setup-node`, `upload-artifact`, `dependency-review-action`).
  - Zero required repository secrets for core security gate runs.
  - Updated threat model documented in `docs/threat-model.md`.

---

### Phase 8: End-to-End Vulnerability Demonstration
- **Status**: Planned (Active Next Milestone)
- **Deliverables**:
  - Introduce a test pull request with a known vulnerable dependency and insecure code pattern.
  - Verify that Trivy, Semgrep, and Dependency Review detect the vulnerabilities.
  - Confirm PipelineShield evaluates the findings, emits `BLOCK`, and fails the pull request status check.
  - Verify that a clean pull request emits `PASS` and succeeds.
  - Document the end-to-end walkthrough with actual GitHub Actions run URLs and screenshots.

---

### Phase 9: Release Verification & Sign-Off
- **Status**: Planned
- **Deliverables**:
  - Independent verification of passing end-to-end CI checks.
  - Release tagging (`v1.0.0`).
  - Final documentation review.
