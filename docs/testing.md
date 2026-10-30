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

### Test Suite Structure (216 passing tests, 92% coverage)

- `tests/test_imports.py`: Verifies module imports, package structure, and top-level exports.
- `tests/test_models.py`: Validates Pydantic data schemas, enums, severity ordering, and immutability.
- `tests/test_config.py`: Verifies YAML parsing, schema defaults, strict validation, and rejection of invalid/unknown scanner options.
- `tests/test_normalizer.py`: Validates native parsing of Trivy, Semgrep, and Dependency Review JSON fixtures and GitHub Action formats.
- `tests/test_policy_engine.py`: Tests threshold evaluation, scanner enablement, Trivy `ignore_unfixed`, license allow/deny lists, path exemptions, and error-guard wrapper.
- `tests/test_reporter.py`: Tests JSON report generation, Markdown tables, and markdown-escaping for security.
- `tests/test_cli.py`: End-to-end CLI tests covering exit codes (0/1/2), multi-scanner flags, and malformed inputs.
- `tests/fixtures/`: Real-world scanner JSON datasets for clean runs, CVEs, SAST findings, and dependency changes.

---

## 3. Frontend Quality & Build Verification

The Next.js dashboard must pass TypeScript strict checks and production builds cleanly before any commit.

```bash
cd dashboard

# Type checking and linting (0 errors, 0 warnings required)
npm run lint

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
