# PipelineShield Testing Strategy & Guidelines

This document details the automated testing approach, instructions, and quality gates for PipelineShield.

---

## 1. Testing Layers

| Layer | Component | Framework | Objective |
|---|---|---|---|
| **Unit Tests** | Python Policy Engine | `pytest` | Validate model validation, config parsing, normalization rules, and policy evaluation logic. |
| **Integration Tests** | Multi-Scanner Pipeline | `pytest` + fixture mocks | Ingest synthetic scanner outputs and verify end-to-end report and decision generation. |
| **Frontend Tests** | Next.js Dashboard | TypeScript + ESLint + Next Build | Verify type safety, component contracts, and zero-error production build. |
| **End-to-End CI Gates** | GitHub Actions | Workflow runners | Test real scanner execution against clean and deliberately vulnerable repositories. |

---

## 2. Python Policy Engine Testing

### Running Tests Locally

```bash
cd engine

# Activate virtual environment
source .venv/bin/activate

# Execute pytest suite
pytest -v

# Run with coverage report
pytest --cov=pipelineshield --cov-report=term-missing
```

### Test Organization

- `tests/test_imports.py`: Verifies module imports, package structure, and top-level exports.
- `tests/test_models.py`: Validates Pydantic data schemas, enums, severity ordering, and immutability.
- `tests/test_config.py`: Verifies YAML parsing, schema defaults, strict validation, and rejection of invalid policies.
- `tests/test_normalizer.py`: Validates native parsing of Trivy, Semgrep, and Dependency Review JSON fixtures.
- `tests/test_policy_engine.py`: Tests threshold evaluation, path exemptions, expiration, and error-guard wrapper.
- `tests/test_reporter.py`: Tests JSON report generation, Markdown tables, and markdown-escaping for security.
- `tests/test_cli.py`: End-to-end CLI tests covering exit codes (0/1/2), multi-scanner flags, and malformed inputs.
- `tests/fixtures/`: Real-world scanner JSON datasets for clean runs, CVEs, and SAST findings.

---

## 3. Frontend Quality & Build Verification

The Next.js dashboard must pass TypeScript strict checks and production builds cleanly before any commit.

```bash
cd dashboard

# Type checking and linting
npm run lint

# Production compilation
npm run build
```

---

## 4. CI/CD Security Gate Simulation

To test the security gate behavior locally with sample scanner outputs:

```bash
# Evaluate sample clean findings
python3 -m pipelineshield.cli \
  --policy config/policy.yaml \
  --findings examples/clean-findings.json \
  --output reports/summary.json

# Evaluate sample vulnerable findings (expected exit code 1)
python3 -m pipelineshield.cli \
  --policy config/policy.yaml \
  --findings examples/vulnerable-findings.json \
  --output reports/summary.json
```
