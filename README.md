# PipelineShield 🛡️

[![CI Security Gate](https://github.com/RishvinReddy/PipelineShield/actions/workflows/security-gate.yml/badge.svg)](https://github.com/RishvinReddy/PipelineShield/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](engine/)
[![Next.js: 16](https://img.shields.io/badge/Next.js-App%20Router-black.svg)](dashboard/)

**PipelineShield** is an automated DevSecOps security gatekeeper designed to embed security enforcement directly into GitHub CI/CD pipelines. It scans codebases and dependencies, normalizes findings across multiple security scanners (Trivy, Semgrep, and GitHub Dependency Review), evaluates declarative security policies, and blocks unsafe pull requests before they reach production.

---

## 🌟 Capabilities & Status

- **Multi-Scanner Policy Enforcement**: Native parsers for **Trivy** (CVEs, IaC misconfigurations, and leaked secrets), **Semgrep CE** (SAST & secret detection), and **GitHub Dependency Review** (PR dependency diffs and licenses).
- **Declarative Policy Engine**: Typed, schema-validated policy engine driven by [`config/policy.yaml`](config/policy.yaml) with Pydantic validation enforcing customizable severity thresholds (`BLOCK`, `WARN`, `PASS`), scanner enablement gating, and license allow/deny lists.
- **Fail-Closed CI/CD Gate**: Enforces fail-closed execution in GitHub Actions: scanner crashes, installation failures, missing output files, and malformed JSON fail the CI job immediately.
- **Unified Security Dashboard**: Next.js App Router interface to inspect security posture and upload evaluation artifacts (`reports/security-summary.json`). Validated against an authoritative shared TypeScript contract schema (`dashboard/src/lib/report-validator.ts`).
- **Zero-Cost Architecture**: Built on open-source scanners, GitHub Actions, and static/serverless hosting—no external databases, paid cloud servers, or commercial API keys required.

---

## 🏗️ Architecture

```text
Developer Pull Request
         │
         ▼
GitHub Actions CI/CD (Least Privilege: contents: read)
  ├── 1. Trivy Scanner (Vulnerabilities, Misconfigurations & Secrets)
  ├── 2. Semgrep SAST (Insecure Code Patterns & Secrets)
  └── 3. GitHub Dependency Review (PR Dependency Diffs & Licenses)
         │
         ▼
Python Security Policy Engine (Fail-Closed)
  ├── Normalizes heterogeneous outputs into unified Finding models
  ├── Enforces typed scanner settings, severity thresholds & license rules
  └── Outputs Decision: PASS (0) | WARN (0) | BLOCK (1) | ERROR (2)
         │
         ├───► Gate Verdict (Blocks Pull Request on BLOCK)
         └───► Produces JSON & Markdown Security Artifacts
                    │
                    ▼
          Next.js Security Dashboard
          Shared TypeScript contract validation & interactive artifact inspection
```

---

## 📁 Repository Structure

```text
PipelineShield/
├── .github/
│   └── workflows/
│       └── security-gate.yml # CI workflow (fail-closed, conditional execution, pinned SHAs)
├── config/
│   └── policy.yaml         # Declarative DevSecOps security policy
├── engine/                 # Python Security Policy Engine
│   ├── pyproject.toml      # Packaging & test dependencies
│   ├── src/pipelineshield/ # Source package
│   │   ├── models.py        # Pydantic schemas (typed configs & scanner_status)
│   │   ├── config.py        # Strict policy YAML loader & scanner validator
│   │   ├── normalizer.py    # Native parsers (Trivy vuln/misconfig/secret, Semgrep, Dep Review)
│   │   ├── policy_engine.py # Gate evaluation & scanner enablement enforcement
│   │   ├── reporter.py      # JSON & Markdown report generators
│   │   └── cli.py           # CLI with exit codes 0 / 1 / 2
│   └── tests/              # 252 pytest unit & integration tests (93% coverage)
├── dashboard/              # Next.js App Router web dashboard
│   ├── src/lib/            # Authoritative shared TypeScript validator (report-validator.ts)
│   ├── src/app/            # App Router pages and health route
│   ├── vercel.json         # Vercel deployment configuration
│   └── package.json        # Frontend dependencies & test:contract script
├── examples/               # Example vulnerable & clean scan reports
├── scripts/                # Verification & shared contract test suites
│   ├── test_dashboard_contract.mjs # Browser validator test with real CLI reports
│   └── verify_dashboard_report.py  # End-to-end Python & contract verification runner
├── docs/                   # Technical documentation
│   ├── architecture.md     # System design & data flow
│   ├── testing.md          # Test strategy & local reproduction commands
│   └── threat-model.md     # CI/CD security threat model & least privilege
├── LICENSE                 # MIT License
├── README.md               # Project documentation
└── PROJECT_PLAN.md         # Phased implementation roadmap & progress
```
├── dashboard/              # Next.js App Router web dashboard
│   ├── src/app/            # App Router pages and health route
│   ├── vercel.json         # Vercel deployment configuration
│   └── package.json        # Frontend dependencies
├── examples/               # Example vulnerable & clean scan reports
├── docs/                   # Technical documentation
│   ├── architecture.md     # System design & data flow
│   ├── testing.md          # Test strategy & local reproduction commands
│   └── threat-model.md     # CI/CD security threat model & least privilege
├── LICENSE                 # MIT License
├── README.md               # Project documentation
└── PROJECT_PLAN.md         # Phased implementation roadmap & progress
```

---

## 🚀 Running Scanners & Engine Locally

### Prerequisites

- **Python**: 3.11+
- **Node.js**: 20+ & npm 10+
- **Trivy**: `brew install trivy` or official binary
- **Semgrep**: `pip install semgrep`

### 1. Execute Security Scanners

```bash
mkdir -p reports

# Run Trivy vulnerability scan
trivy fs --exit-code 0 --format json --output reports/trivy.json .

# Run Semgrep SAST scan
semgrep scan --config "p/security-audit" --config "p/secrets" --config "p/owasp-top-ten" --json --output reports/semgrep.json
```

### 2. Run the Policy Engine

```bash
# Setup Python virtual environment
cd engine
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"

# Run policy evaluation with generated scanner outputs
python3 -m pipelineshield.cli \
  --policy ../config/policy.yaml \
  --trivy ../reports/trivy.json \
  --semgrep ../reports/semgrep.json \
  --output ../reports/security-summary.json \
  --summary-md ../reports/summary.md
```

### 3. Run the Next.js Dashboard

```bash
cd ../dashboard
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to inspect demonstration reports or click **"Load Report JSON"** to upload `reports/security-summary.json`.

---

## 🔒 Security Policy Configuration

Policies are configured declaratively in [`config/policy.yaml`](config/policy.yaml):

```yaml
version: "1.0"
enforcement:
  mode: "strict"      # strict (fails on BLOCK), permissive (warns), monitor (reports only)
  fail_on_block: true
  fail_on_warn: false

thresholds:
  critical: "BLOCK"
  high: "BLOCK"
  medium: "WARN"
  low: "PASS"
  info: "PASS"

scanners:
  trivy:
    enabled: true
    fail_on_cve_severity: ["CRITICAL", "HIGH"] # Authoritative override for Trivy CVEs
    scan_types: ["vuln", "misconfig", "secret"]   # Dynamically fed to --scanners in CI
    ignore_unfixed: false

  semgrep:
    enabled: true
    rulesets:                                  # Dynamically fed to --config in CI
      - "p/security-audit"
      - "p/secrets"
      - "p/owasp-top-ten"
    fail_on_severity: ["ERROR"]                # Authoritative override for Semgrep findings

  dependency_review:
    enabled: true
    allow_licenses:
      - "MIT"
      - "Apache-2.0"
      - "BSD-2-Clause"
      - "BSD-3-Clause"
      - "ISC"
      - "0BSD"
    deny_licenses:
      - "GPL-3.0"
      - "AGPL-3.0"
    deny_severities:                           # Authoritative override for Dependency Review
      - "critical"
      - "high"
```

### Policy Semantics & Configuration Hierarchy
- **Authoritative Scanner Overrides**: When a scanner specifies a fail list (e.g. `fail_on_cve_severity`, `fail_on_severity`, or `deny_severities`), that list authoritatively determines which severities from that scanner trigger `BLOCK`. Findings from that scanner excluded from the fail list downgrade to `WARN` rather than forcing a gate failure.
- **Global Threshold Fallback**: If a scanner's severity list is omitted (`None`), the global `thresholds` govern.
- **Dependency Review Filtering**: GitHub Dependency Review Action findings are filtered by `change_type`. Only newly added dependencies (`change_type: "added"`) are evaluated for introduction-risk (vulnerabilities and license policies). Removed dependencies (`change_type: "removed"`) are skipped so removing a dependency never blocks a PR.
- **Pinned Scanner Tooling**: CI installs **Trivy v0.76.1** verified against official SHA256 checksum (`c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0`), **Semgrep v1.183.0**, and uses **Dependency Review Action** (`actions/dependency-review-action@3c4e3dcb1aa7874d2c16be7d79418e9b7efd6261` with `warn-only: true`).

---

## 🗺️ Implementation Roadmap & Status

- [x] **Phase 1**: Repository and Development Environment Scaffold
- [x] **Phase 2**: Python Security Policy Engine Implementation
- [x] **Phase 3**: Automated Policy Engine Testing Suite (252 tests, 93% coverage)
- [x] **Phase 4**: Trivy, Semgrep, and Dependency Review CI Integration (Fail-closed)
- [x] **Phase 5**: Next.js Security Dashboard Interface & Artifact Uploader
- [ ] **Phase 6**: Vercel Live Deployment (Configuration present; deployment pending)
- [x] **Phase 7**: Security Hardening, Commit-SHA Pinning & CI Least Privilege
- [ ] **Phase 8**: End-to-End Pull Request Adversarial Demonstration
- [ ] **Phase 9**: Final Release Sign-Off

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for detailed phase criteria.

---

## ⚠️ Current Limitations

1. **Dependency Review Execution Scope**: GitHub's Dependency Review Action executes exclusively on Pull Requests (`github.event_name == 'pull_request'`), because it requires a git diff between base and head branches. On push/dispatch runs, Trivy and Semgrep run unconditionally while Dependency Review is safely skipped.
2. **Dashboard Data**: The dashboard runs client-side without an external database. It visualizes either synthetic demonstration reports or user-uploaded `EvaluationResult` JSON files generated by CI.
3. **Vercel Deployment**: `dashboard/vercel.json` provides deployment configuration; live public domain hosting is planned in a subsequent phase.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
