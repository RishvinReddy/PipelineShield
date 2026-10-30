# PipelineShield Threat Model & Security Posture

## 1. System Scope & Objective

PipelineShield guards the CI/CD pipeline against supply-chain attacks, vulnerable dependencies, insecure code patterns, secret leaks, and unauthorized license inclusions.

This threat model identifies potential attack vectors against the security gate and details corresponding mitigations.

---

## 2. Threat Matrix

| Threat ID | Threat Vector | Description | Impact | Mitigation in PipelineShield |
|---|---|---|---|---|
| **TM-01** | **Gatekeeper Bypass** | Malicious actor modifies workflow or policy file in a PR to disable checks. | High | Protect `config/policy.yaml` and `.github/workflows/` via CODEOWNERS and branch protection rules. |
| **TM-02** | **Scanner Evasion** | Obfuscated code or polyglot payloads designed to slip past Semgrep pattern matching. | High | Multi-layered defense: combine static analysis (Semgrep) with dependency CVE scanning (Trivy). |
| **TM-03** | **Dependency Confusion / Poisoning** | Ingestion of compromised third-party packages or typo-squatted registries. | Critical | GitHub Dependency Review action and lockfile integrity verification. |
| **TM-04** | **Secret Exfiltration via CI** | PR builds accessing repository secrets or token leaks in build logs. | Critical | Minimal runner permissions (`contents: read`); zero secrets required for core security gate runs. |
| **TM-05** | **Policy Engine Tampering** | Manipulated scanner output JSON files injected before policy evaluation. | High | Execute scanner output creation and evaluation within the same isolated CI runner job. |
| **TM-06** | **Unsafe Licenses** | Inclusion of viral/copyleft licenses (GPL, AGPL) in proprietary builds. | Medium | Dependency review license auditing enforcing policy-allowed license list. |

---

## 3. Least-Privilege CI Security

GitHub Actions workflows for PipelineShield adhere to the principle of least privilege:

```yaml
permissions:
  contents: read           # Read source code only
  pull-requests: write     # Post security summary on PRs
  security-events: write   # Upload SARIF findings to GitHub Security tab
```

- No write permissions to repository contents or releases from untrusted PR runs.
- Workflows explicitly specify top-level permissions to avoid inheriting default read/write tokens.
- Actions pinned to trusted versions or full commit SHA hashes.
