# PipelineShield Architecture & System Design

## 1. System Overview

PipelineShield operates as an automated DevSecOps gatekeeper embedded into GitHub CI/CD workflows. Its core mission is to intercept code changes before merge, run automated multi-vector security analysis, normalize the findings into a common schema, evaluate custom security policies, and enforce a pass/block verdict on the pull request.

```text
+-----------------------------------------------------------+
|                   Developer Pull Request                  |
+-----------------------------------------------------------+
                              │
                              ▼
+-----------------------------------------------------------+
|             GitHub Actions Runner (Fail-Closed)           |
|                                                           |
|  +----------------+  +-----------------+  +------------+  |
|  |  Trivy Scanner |  |   Semgrep SAST  |  | Dep Review |  |
|  |  (CVE / Vulns) |  | (Code & Secrets)|  | (Licenses) |  |
|  +----------------+  +-----------------+  +------------+  |
|          │                    │                  │        |
|          ▼                    ▼                  ▼        |
|     trivy.json          semgrep.json       dep-review.json|
+-----------------------------------------------------------+
                              │
                              ▼
+-----------------------------------------------------------+
|            PipelineShield Policy Engine (Python)          |
|                                                           |
|  1. Ingestion & Normalization                             |
|     Transforms raw tool outputs into unified Finding models|
|                                                           |
|  2. Policy Evaluation                                     |
|     Validates policy.yaml (typed scanner options, rules)   |
|     Enforces severity thresholds & license allow/deny lists|
|                                                           |
|  3. Decision Generator                                    |
|     Emits verdict: PASS (0) | WARN (0) | BLOCK (1) | ERR (2)|
|                                                           |
|  4. Reporter                                              |
|     - JSON Report Artifact (reports/security-summary.json)|
|     - GitHub Step Summary Markdown (PR check details)     |
+-----------------------------------------------------------+
                              │
           ┌──────────────────┴──────────────────┐
           ▼                                     ▼
+----------------------+             +----------------------+
| GitHub Actions Gate  |             |  Next.js Dashboard   |
| (Exit 0 or Exit 1)   |             |  (Artifact Viewer)   |
+----------------------+             +----------------------+
```

---

## 2. Core Components

### 2.1 Scanner Matrix
- **Trivy**: Scans OS packages and application dependencies for known CVEs, misconfigurations, and container vulnerabilities.
- **Semgrep Community Edition**: Performs static application security testing (SAST) targeting dangerous sink functions, injection vulnerabilities, and hardcoded secrets.
- **GitHub Dependency Review**: Evaluates dependency diffs introduced by PRs via `actions/dependency-review-action`, exporting findings for policy evaluation of vulnerabilities and software licenses.

### 2.2 Normalization Layer (`pipelineshield.normalizer`)
Raw JSON scanner payloads differ substantially in format, terminology, and severity labeling. The normalizer maps heterogeneous formats into a standardized `Finding` schema:
- `id`: Unique identifier (e.g., CVE-2023-1234, semgrep-sql-injection, GHSA-xxxx).
- `scanner`: Originating tool name (`trivy`, `semgrep`, `dependency_review`).
- `title`: Human-readable summary.
- `severity`: Standardized enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `file_path`: Path to affected file.
- `line_number`: Optional line number.
- `package_name`: Affected dependency package name.
- `installed_version`: Currently installed package version.
- `fixed_version`: Minimum safe package version if available.
- `license`: Detected software license (e.g. MIT, GPL-3.0).
- `remediation`: Suggested fix or upgrade target.

### 2.3 Policy Engine (`pipelineshield.policy_engine`)
The policy engine evaluates all normalized findings against declarative rules configured in `config/policy.yaml`.
- **Enforcement Modes**:
  - `strict`: Gate fails with exit code 1 if any blocking findings exist.
  - `permissive`: Gate issues warnings but exits with code 0 unless `fail_on_warn: true`.
  - `monitor`: Gate records all findings and exits with code 0 for telemetry observation.
- **Scanner Configuration**:
  - Typed models for each scanner (`trivy`, `semgrep`, `dependency_review`). Unknown configuration keys are rejected.
  - Scanner enablement flag (`enabled: false` bypasses scanner findings).
  - Trivy `ignore_unfixed`: Ignores CVEs without available patch versions.
  - Dependency Review `allow_licenses` and `deny_licenses`: Enforces license compliance.
- **Evaluation Decisions**:
  - `BLOCK`: Hard security failure. Terminates CI step with exit code 1.
  - `WARN`: Advisory notice.
  - `PASS`: Findings within acceptable risk thresholds.
  - `ERROR`: Unhandled engine fault or invalid configuration (exit code 2).

### 2.4 Next.js Security Dashboard (`dashboard/`)
The Next.js App Router application visualizes security posture and finding details. It accepts uploaded `EvaluationResult` JSON artifacts with client-side schema validation, displaying severity distributions, remediation guides, and gate verdicts.
