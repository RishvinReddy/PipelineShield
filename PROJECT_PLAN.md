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
- **Status**: In Progress (Milestone 1)
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
- **Status**: Planned
- **Deliverables**:
  - Core data schemas using Pydantic (`Finding`, `Severity`, `ScannerType`, `PolicyRule`, `PolicyResult`).
  - Scanner finding normalizers for Trivy JSON, Semgrep JSON/SARIF, and GitHub Dependency Review format.
  - Config loader with validation for `config/policy.yaml`.
  - Policy evaluation engine with support for severity thresholds, rule whitelisting, license compliance, and CVE exemptions.
  - Standardized JSON reporter and GitHub Actions step-summary Markdown reporter.
  - Command-line interface (`pipelineshield --config ... --input ... --output ...`).

---

### Phase 3: Automated Policy Engine Testing
- **Status**: Planned
- **Deliverables**:
  - Comprehensive unit test suite for all policy engine components.
  - Fixture datasets representing clean scans, critical CVEs, SAST rule violations, and unauthorized licenses.
  - Edge cases testing: malformed scanner outputs, empty finding lists, missing policy files, unhandled severities.
  - High test coverage (>90%) with reproducible pytest invocations.

---

### Phase 4: Trivy, Semgrep & GitHub Actions Integration
- **Status**: Planned
- **Deliverables**:
  - GitHub Actions workflow (`.github/workflows/security-gate.yml`) triggered on `pull_request` and `push` to `main`.
  - Automated installation and execution of Trivy filesystem and dependency vulnerability scans.
  - Automated execution of Semgrep CE with curated security rulesets (OWASP Top 10, CWE).
  - Integration of GitHub Dependency Review action.
  - Execution of PipelineShield Policy Engine to process scanner outputs.
  - Automated blocking of pull requests failing policy thresholds (exit code 1).
  - Upload of security report artifacts (`reports/security-summary.json`).

---

### Phase 5: Next.js Security Dashboard
- **Status**: Planned
- **Deliverables**:
  - Modern, responsive security dashboard built with Next.js App Router and Tailwind CSS.
  - Pipeline status overview card (Latest Gate Decision, Scan Durations, Pass/Fail Rate).
  - Vulnerability breakdown charts and severity filters (Critical, High, Medium, Low).
  - Interactive finding explorer displaying CVE ID, file location, rule ID, and remediation recommendations.
  - Policy viewer reflecting current rules in `config/policy.yaml`.
  - Mock and live scan report loading capability.

---

### Phase 6: Vercel Deployment
- **Status**: Planned
- **Deliverables**:
  - Vercel deployment configuration for `dashboard/` root directory.
  - Automated preview deployments on PRs and production deployments on `main`.
  - Health check endpoint and verified production URL.

---

### Phase 7: Security Hardening & CI Least Privilege
- **Status**: Planned
- **Deliverables**:
  - Strict GitHub Actions job permissions (`contents: read`, `pull-requests: write`, `security-events: write`).
  - Action pinning with full commit SHA hashes.
  - Secret scanning and dependency vulnerability monitoring on the repository itself.
  - Implementation of safe environment variable handling and audit logging.

---

### Phase 8: End-to-End Vulnerability Demonstration
- **Status**: Planned
- **Deliverables**:
  - Creation of test pull requests introducing intentional vulnerable dependencies and SAST patterns.
  - Verification that the security gate catches and blocks the malicious PR.
  - Creation of a clean pull request demonstrating successful gate passage (`PASS`).
  - Documented walkthrough with screenshots and execution logs.

---

### Phase 9: Documentation & Release
- **Status**: Planned
- **Deliverables**:
  - Complete architecture diagrams and data flow documentation in `docs/architecture.md`.
  - Threat modeling report in `docs/threat-model.md`.
  - Contributor and testing guide in `docs/testing.md`.
  - Production release tagging (`v1.0.0`).
