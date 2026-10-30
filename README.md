# PipelineShield 🛡️

[![CI Security Gate](https://github.com/RishvinReddy/PipelineShield/actions/workflows/security-gate.yml/badge.svg)](https://github.com/RishvinReddy/PipelineShield/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](engine/)
[![Next.js: 15](https://img.shields.io/badge/Next.js-App%20Router-black.svg)](dashboard/)

**PipelineShield** is an automated DevSecOps security gatekeeper designed to embed security directly into GitHub CI/CD pipelines. It scans codebases and dependencies, normalizes findings across multiple industry-standard security scanners, evaluates configurable security policies, and blocks unsafe pull requests before they reach production.

---

## 🌟 Key Features

- **Multi-Scanner Security Gate**: Integrates **Trivy** (vulnerability & misconfiguration scanning), **Semgrep CE** (static application security testing / SAST), and **GitHub Dependency Review**.
- **Declarative Policy Engine**: Python-based policy engine driven by YAML rules with Pydantic validation to enforce customizable security thresholds (BLOCK, WARN, PASS).
- **Automated CI/CD Enforcement**: Runs in GitHub Actions on every Pull Request and merge, providing immediate feedback via PR checks and formatted security summaries.
- **Unified Security Dashboard**: Next.js App Router frontend deployed on Vercel to inspect security posture, view normalized scan reports, and track policy violations.
- **Zero Cost Architecture**: Built purely on open-source scanners, GitHub Actions, and Vercel Hobby tier—no paid APIs, external servers, or proprietary services required.

---

## 🏗️ Architecture

```
Developer Pull Request
         │
         ▼
GitHub Actions CI/CD
  ├── 1. Trivy Scanner (Filesystem & Dependency CVEs)
  ├── 2. Semgrep SAST (Insecure Code Patterns & Secrets)
  └── 3. Dependency Review (New Dependencies & Licenses)
         │
         ▼
Python Security Policy Engine
  ├── Normalizes findings into unified schema
  ├── Evaluates policy against config/policy.yaml
  └── Outputs Decision: PASS | WARN | BLOCK | ERROR
         │
         ├───► Blocks Unsafe PRs (Non-zero exit code on BLOCK)
         └───► Produces JSON & Markdown Security Artifacts
                    │
                    ▼
          Next.js Security Dashboard (Vercel)
          Unified visualization of pipeline health & findings
```

---

## 📁 Repository Structure

```text
PipelineShield/
├── .github/
│   └── workflows/          # GitHub Actions CI/CD workflows
├── config/
│   └── policy.yaml         # Declarative DevSecOps security policies
├── engine/                 # Python Security Policy Engine
│   ├── pyproject.toml      # Engine dependency and packaging metadata
│   ├── src/
│   │   └── pipelineshield/ # Engine source code
│   │       ├── models.py        # Pydantic data schemas
│   │       ├── config.py        # Policy loader & validator
│   │       ├── normalizer.py    # Scanner output normalizer
│   │       ├── policy_engine.py # Rule evaluation logic
│   │       ├── reporter.py      # Output & summary generator
│   │       └── cli.py           # Command-line interface
│   └── tests/              # Engine pytest suite
├── dashboard/              # Next.js App Router web dashboard
│   ├── src/                # Frontend application source
│   ├── package.json        # Frontend dependencies
│   └── tailwind.config.ts  # Tailwind CSS styling
├── examples/               # Example vulnerable & clean scan reports
├── reports/                # Local scan output storage (gitignored)
├── docs/                   # Engineering & architecture documentation
│   ├── architecture.md     # System design & data flow
│   ├── testing.md          # Test strategy & instructions
│   └── threat-model.md     # CI/CD security threat model
├── .gitignore              # Repository ignore rules
├── LICENSE                 # MIT License
├── README.md               # Project documentation
└── PROJECT_PLAN.md         # Phased implementation roadmap
```

---

## 🚀 Quick Start

### Prerequisites

- **Python**: 3.11+
- **Node.js**: 20+ & npm 10+
- **Git**

### 1. Python Policy Engine Setup

```bash
cd engine

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package in editable mode with test dependencies
pip install -e ".[test]"

# Run tests
pytest
```

### 2. Next.js Dashboard Setup

```bash
cd dashboard

# Install dependencies
npm install

# Start local development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to view the PipelineShield dashboard.

---

## 🔒 Security Policy Configuration

Security rules are defined declaratively in [`config/policy.yaml`](config/policy.yaml):

```yaml
version: "1.0"
enforcement:
  mode: strict # Options: strict, permissive, monitor
thresholds:
  critical: BLOCK
  high: BLOCK
  medium: WARN
  low: PASS
scanners:
  trivy:
    enabled: true
  semgrep:
    enabled: true
  dependency_review:
    enabled: true
```

---

## 🗺️ Roadmap & Phases

- [x] **Phase 1**: Repository and Development Environment Scaffold
- [ ] **Phase 2**: Python Security Policy Engine Implementation
- [ ] **Phase 3**: Automated Policy Engine Testing Suite
- [ ] **Phase 4**: Trivy, Semgrep, and GitHub Actions Security Gate Integration
- [ ] **Phase 5**: Next.js Security Dashboard Interface
- [ ] **Phase 6**: Vercel Deployment Setup
- [ ] **Phase 7**: Security Hardening & CI Least Privilege
- [ ] **Phase 8**: End-to-End Vulnerability Demonstration
- [ ] **Phase 9**: Final Production Documentation & Release

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for full phase details and deliverables.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
