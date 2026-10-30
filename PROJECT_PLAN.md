# PipelineShield Implementation Plan & Roadmap

This document outlines the phased engineering blueprint for building **PipelineShield**, an automated DevSecOps security gatekeeper platform.

---

## Architecture Principles

1. **Gatekeeper First**: The automated security gate precedes frontend decoration. The core value lies in accurate scanning, finding normalization, and strict policy enforcement.
2. **Zero-Cost Infrastructure**: Free and open-source tooling only (GitHub Actions, Trivy, Semgrep CE, GitHub Dependency Review, Vercel Hobby tier). No external databases, paid cloud servers, or mandatory commercial APIs.
3. **Reproducibility & Isolation**: Separation of concerns between the Python Policy Engine (`engine/`) and the Next.js Dashboard (`dashboard/`).
4. **Actionable Feedback**: Fail early in the pull request lifecycle with human-readable PR check summaries and standardized JSON artifacts.

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
  - Verified local pytest tests and Next.js production build.
  - First Git commit pushed to remote `main`.

---

### Phase 2: Python Security Policy Engine
- **Status**: Completed (Milestone 2)
- **Deliverables**:
  - Core data schemas using Pydantic (`Finding`, `Severity`, `ScannerType`, `PolicyRule`, `PolicyResult`).
  - Scanner finding normalizers for Trivy JSON, Semgrep JSON/SARIF, and GitHub Dependency Review format.
  - Config loader with validation for `config/policy.yaml`.
  - Policy evaluation engine with support for severity thresholds, rule whitelisting, license compliance, and CVE exemptions.
  - Standardized JSON reporter and GitHub Actions step-summary Markdown reporter.
  - Command-line interface (`pipelineshield --policy ... --findings ... / --trivy ... / --semgrep ...`).

---

### Phase 3: Automated Policy Engine Testing
- **Status**: Completed (Milestone 3)
- **Deliverables**:
  - Comprehensive unit test suite (206 tests, 93% code coverage) across all policy engine components.
  - Fixture datasets representing clean scans, critical CVEs, SAST rule violations, and dependency reviews.
  - Edge cases testing: malformed scanner outputs, empty finding lists, missing policy files, unhandled severities.
  - Defensive error-guard execution mode failing safely on internal faults (exit code 2).

---

### Phase 4: Trivy, Semgrep & GitHub Actions Integration
- **Status**: Completed (Milestone 4)
- **Deliverables**:
  - GitHub Actions workflow (`.github/workflows/security-gate.yml`) triggered on `pull_request` and `push` to `main`.
  - Automated execution of Trivy filesystem and dependency vulnerability scans.
  - Automated execution of Semgrep CE with curated security rulesets (OWASP Top 10, secrets).
  - Integration of GitHub Dependency Review scanning.
  - Execution of PipelineShield Policy Engine to process scanner outputs.
  - Automated blocking of pull requests failing policy thresholds (exit code 1).
  - Upload of security report artifacts (`reports/security-summary.json`) and Markdown step summaries.

---

### Phase 5: Next.js Security Dashboard
- **Status**: Completed (Milestone 5)
- **Deliverables**:
  - Modern, responsive security dashboard built with Next.js App Router and Tailwind CSS.
  - Gate Decision status hero card (PASS, WARN, BLOCK, ERROR).
  - Vulnerability breakdown metrics and severity distribution bars.
  - Interactive finding explorer with search, severity filters, scanner filters, and remediation details.
  - Security policy viewer reflecting active declarative thresholds.
  - Preset report switcher (Block, Warn, Pass) and client-side custom JSON report upload.

---

### Phase 6: Vercel Deployment
- **Status**: Completed (Milestone 6)
- **Deliverables**:
  - Vercel deployment configuration (`dashboard/vercel.json`).
  - Health check endpoint (`/api/health`) for uptime monitoring.
  - Zero-error TypeScript compilation and static asset generation.

---

### Phase 7: Security Hardening & CI Least Privilege
- **Status**: Completed (Milestone 7)
- **Deliverables**:
  - Strict GitHub Actions runner permissions (`contents: read`, `pull-requests: write`, `security-events: write`).
  - Zero required repository secrets for core security gate runs.
  - Action pinning and safe input validation.
  - Complete threat model documented in `docs/threat-model.md`.

---

### Phase 8: End-to-End Vulnerability Demonstration
- **Status**: Active / Ready
- **Deliverables**:
  - Verified sample vulnerable datasets (`examples/trivy_sample.json`, `examples/semgrep_sample.json`).
  - Verification that the security gate catches and blocks vulnerable findings.
  - Verified clean baseline (`examples/clean_scan.json`) demonstrating successful gate passage (`PASS`).
  - Documented walkthrough with execution logs and CLI steps.

---

### Phase 9: Documentation & Release
- **Status**: Completed (Milestone 9)
- **Deliverables**:
  - Complete architecture diagrams and data flow documentation in `docs/architecture.md`.
  - Threat modeling report in `docs/threat-model.md`.
  - Contributor and testing guide in `docs/testing.md`.
  - Production release tagging (`v1.0.0`).
