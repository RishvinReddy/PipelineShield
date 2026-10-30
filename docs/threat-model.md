# PipelineShield Threat Model & Security Posture

## 1. System Scope & Objective

PipelineShield guards the CI/CD pipeline against supply-chain attacks, vulnerable dependencies, insecure code patterns, secret leaks, and unauthorized license inclusions.

This threat model identifies potential attack vectors against the security gate and details corresponding mitigations.

---

## 2. Threat Matrix

| Threat ID | Threat Vector | Description | Impact | Mitigation in PipelineShield |
|---|---|---|---|---|
| **TM-01** | **Gatekeeper Bypass** | Malicious actor modifies workflow or policy file in a PR to disable checks. | High | Protect `config/policy.yaml` and `.github/workflows/` via CODEOWNERS and branch protection rules. |
| **TM-02** | **Scanner Failure Suppression** | Scanner errors, crashes, or missing outputs bypassed using `\|\| true` or empty mock fallbacks. | Critical | Fail-closed CI execution: scanner non-zero exits, missing output files, and invalid JSON fail the job immediately. |
| **TM-03** | **Scanner Evasion** | Obfuscated code or polyglot payloads designed to slip past Semgrep pattern matching. | High | Multi-layered defense: combine static analysis (Semgrep) with dependency CVE scanning (Trivy) and lockfile analysis. |
| **TM-04** | **Dependency Poisoning & Supply Chain** | Ingestion of compromised third-party packages or typo-squatted registries. | Critical | GitHub Dependency Review action and lockfile integrity verification. |
| **TM-05** | **Secret Exfiltration via CI** | PR builds accessing repository secrets or token leaks in build logs. | Critical | Minimal runner permissions (`contents: read` only); zero secrets required for core security gate runs. |
| **TM-06** | **Policy Engine Tampering** | Manipulated scanner output JSON files injected before policy evaluation. | High | Execute scanner output creation and evaluation within the same isolated CI runner job. |
| **TM-07** | **Unsafe Licenses** | Inclusion of viral/copyleft licenses (GPL, AGPL) in proprietary builds. | Medium | Dependency review license auditing enforcing policy-allowed license list. |
| **TM-08** | **Action Supply-Chain Hijack** | Compromise of third-party GitHub Action tags (e.g. mutable `@v4` tags). | High | Pin all GitHub actions to verified full immutable commit SHA hashes. |

---

## 3. Least-Privilege CI Security

GitHub Actions workflows for PipelineShield adhere to the principle of least privilege:

```yaml
permissions:
  contents: read           # Read source code only
```

- **No Write Permissions**: Workflows do not request or possess `pull-requests: write`, `security-events: write`, `packages: write`, or `actions: write`.
- **Job-Level Scoping**: Every job (`engine-test`, `dashboard-build`, `security-gate`) explicitly defines `permissions: contents: read`.
- **Immutable Action Pinning**: Third-party actions are pinned to full 40-character commit SHAs with version comments:
  - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (# v4.2.2)
  - `actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38` (# v5.4.0)
  - `actions/setup-node@1e60f6391960146644d41f2d1200fcdcc04fa3e6` (# v4.2.0)
  - `actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1` (# v4.6.1)
  - `actions/dependency-review-action@3c4e3dcb1aa7874d2c16be7d79418e9b7efd6261` (# v4.8.2)
