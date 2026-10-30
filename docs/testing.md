# PipelineShield Testing Strategy & Guidelines

This document details the automated testing approach, instructions, and quality gates for PipelineShield.

---

## 1. Testing Layers

| Layer | Component | Framework | Objective |
|---|---|---|---|
| **Unit Tests** | Python Policy Engine | `pytest` | Validate model validation, typed scanner config parsing, normalization rules, and policy evaluation logic. |
| **Integration Tests** | Multi-Scanner Pipeline | `pytest` + fixtures | Ingest real scanner outputs (Trivy, Semgrep, Dependency Review) and verify decision generation. |
| **Frontend Verification** | Next.js Dashboard | TypeScript + ESLint + Next Build | Verify type safety, schema validation, and zero-error production build. |
| **CI Simulation** | CLI Scans | Local CLI execution | Test clean, vulnerable, and error scenarios locally with exact exit codes. |

---

## 2. Python Policy Engine Testing

### Running Tests Locally

```bash
cd engine

# Activate virtual environment
source .venv/bin/activate

# Execute full pytest suite with coverage
pytest --cov=pipelineshield --cov-report=term-missing
```

### Test Suite Structure (258 passing tests, 94% coverage)

- `tests/test_imports.py`: Verifies module imports, package structure, and top-level exports.
- `tests/test_models.py`: Validates Pydantic data schemas, enums, severity ordering, and immutability.
- `tests/test_config.py`: Verifies YAML parsing, schema defaults, strict validation, and rejection of invalid/unknown scanner options (including Trivy `scan_types`).
- `tests/test_normalizer.py`: Validates native parsing of Trivy (Vulnerabilities, Misconfigurations, Secrets), Semgrep, and Dependency Review JSON fixtures, `change_type` filtering, and official GitHub Action formats.
- `tests/test_policy_engine.py`: Tests threshold evaluation, authoritative scanner-specific overrides, scanner enablement gating, Trivy `ignore_unfixed`, license allow/deny lists, path exemptions, and error-guard wrapper.
- `tests/test_reporter.py`: Tests JSON report generation, Markdown tables, and markdown-escaping for security.
- `tests/test_cli.py`: End-to-end CLI tests covering exit codes (0/1/2), multi-scanner flags, blocking/clean misconfigurations and secrets, and malformed inputs.
- `tests/fixtures/`: Real-world scanner JSON datasets for clean runs, CVEs, SAST findings, official Dependency Review additions/removals, Trivy misconfigurations, Trivy secrets, and malformed inputs.
- `scripts/test_dashboard_contract.mjs`: Node.js shared contract verification testing the actual TypeScript validator (`dashboard/src/lib/report-validator.ts`) against all CLI-generated report permutations (clean, vuln, misconfig, secret, mixed, disabled, error) and rejecting malformed vectors.
- `scripts/verify_dashboard_report.py`: Automated end-to-end verification script running full CLI generation and invoking the TypeScript contract test.

---

## 3. Frontend Quality & Contract Verification

The Next.js dashboard must pass TypeScript strict checks, the shared contract test, and production builds cleanly before any commit.

```bash
cd dashboard

# Type checking and linting (0 errors, 0 warnings required)
npm run lint

# Shared TypeScript contract validation against real CLI-generated reports
npm run test:contract

# Production compilation
npm run build
```

---

## 4. End-to-End Local CLI Verification

### Clean Scan Verification (Expected Exit Code 0)

```bash
python3 -m pipelineshield.cli \
  --policy config/policy.yaml \
  --findings examples/clean_scan.json \
  --output reports/clean_summary.json
echo "Exit code: $?"
```

### Vulnerable Scan Verification (Expected Exit Code 1)

```bash
python3 -m pipelineshield.cli \
  --policy config/policy.yaml \
  --trivy examples/trivy_sample.json \
  --semgrep examples/semgrep_sample.json \
  --output reports/vuln_summary.json
echo "Exit code: $?"
```

### Malformed JSON Verification (Expected Exit Code 2)

```bash
python3 -m pipelineshield.cli \
  --policy config/policy.yaml \
  --findings engine/tests/fixtures/malformed.json
echo "Exit code: $?"
```
