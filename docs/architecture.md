# PipelineShield Architecture & System Design

## 1. System Overview

PipelineShield operates as an automated DevSecOps gatekeeper embedded into GitHub CI/CD workflows. Its core mission is to intercept code changes before merge, run automated multi-vector security analysis, normalize the findings into a common schema, evaluate custom security policies, and enforce a pass/block verdict on the pull request.

```
+-----------------------------------------------------------+
|                   Developer Pull Request                  |
+-----------------------------------------------------------+
                              │
                              ▼
+-----------------------------------------------------------+
|                    GitHub Actions Runner                  |
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
|     Compares normalized findings against policy.yaml       |
|                                                           |
|  3. Decision Generator                                    |
|     Emits verdict: PASS | WARN | BLOCK | ERROR             |
|                                                           |
|  4. Reporter                                              |
|     - JSON Report Artifact (reports/security-summary.json)|
|     - GitHub Step Summary Markdown (PR comments / checks)  |
+-----------------------------------------------------------+
                              │
           ┌──────────────────┴──────────────────┐
           ▼                                     ▼
+----------------------+             +----------------------+
| GitHub Actions Gate  |             |  Next.js Dashboard   |
| (Exit 0 or Exit 1)   |             |  (Vercel Hosted)     |
+----------------------+             +----------------------+
```

---

## 2. Core Components

### 2.1 Scanner Matrix
- **Trivy**: Scans OS packages and application dependencies for known CVEs, misconfigurations, and container vulnerabilities.
- **Semgrep Community Edition**: Performs static application security testing (SAST) targeting dangerous sink functions, injection vulnerabilities, and hardcoded secrets.
- **GitHub Dependency Review**: Evaluates dependency diffs introduced by PRs, auditing package reputation and software licensing compliance.

### 2.2 Normalization Layer (`pipelineshield.normalizer`)
Raw JSON/SARIF scanner payloads differ substantially in format, terminology, and severity labeling. The normalizer maps heterogeneous formats into a standardized `Finding` schema:
- `id`: Unique identifier (e.g., CVE-2023-1234, semgrep-sql-injection).
- `scanner`: Originating tool name (`trivy`, `semgrep`, `dependency_review`).
- `title`: Human-readable summary.
- `severity`: Standardized enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `file_path`: Path to affected file.
- `line_number`: Optional line number.
- `remediation`: Suggested fix or upgrade target.

### 2.3 Policy Engine (`pipelineshield.policy_engine`)
The policy engine evaluates all normalized findings against declarative rules configured in `config/policy.yaml`.
Evaluation actions:
- `BLOCK`: Hard security failure. Terminates CI step with exit code 1.
- `WARN`: Security advisory. Highlights in PR summary but permits execution to continue unless `fail_on_warn: true`.
- `PASS`: Findings within acceptable risk thresholds.

### 2.4 Next.js Security Dashboard (`dashboard/`)
The Next.js App Router application visualizes security posture, pipeline execution history, and finding details. It consumes normalized JSON reports and renders a dashboard with severity distributions, timeline tracking, and remediation guides.
