#!/usr/bin/env node
/**
 * Shared Report Schema & Dashboard Contract Test.
 *
 * Runs directly against the TypeScript validator (dashboard/src/lib/report-validator.ts)
 * using Node.js native TypeScript execution.
 *
 * Validates:
 * 1. Real CLI-generated reports across all scanner permutations:
 *    - clean scan (PASS, exit 0)
 *    - vulnerable scan with CVEs (BLOCK, exit 1)
 *    - misconfiguration scan (BLOCK, exit 1)
 *    - secret detection scan (BLOCK, exit 1)
 *    - mixed-scanner results (retains all findings, BLOCK, exit 1)
 *    - disabled scanner configuration (marked DISABLED, exit 0)
 *    - all-scanners-disabled mode without scanner input (PASS with warning, exit 0)
 *    - non-PR push event (Dependency Review marked NOT_APPLICABLE, exit 0)
 *    - ERROR decision report handling (exit 2)
 * 2. Strict rejection of malformed test vectors:
 *    - invalid decisions, negative summary counts, float counts
 *    - unsupported scanner names
 *    - invalid severity values
 *    - missing finding IDs
 *    - non-array findings and reasons
 *    - invalid scanner_status values
 *    - summary counts inconsistent with actual findings collection
 */

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { validateReportSchema } from "../dashboard/src/lib/report-validator.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const FIXTURES_DIR = path.join(ROOT_DIR, "engine", "tests", "fixtures");
const REPORTS_DIR = path.join(ROOT_DIR, "reports");

// Support configurable Python binary (CI environment vs local .venv)
const PYTHON =
  process.env.PYTHON ||
  process.env.PYTHON_BIN ||
  (fs.existsSync(path.join(ROOT_DIR, "engine", ".venv", "bin", "python"))
    ? path.join(ROOT_DIR, "engine", ".venv", "bin", "python")
    : "python3");

function runCli(args, expectExit = 0) {
  const policyPath = path.join(ROOT_DIR, "config", "policy.yaml");
  const cmd = `"${PYTHON}" -m pipelineshield.cli --policy "${policyPath}" ${args}`;
  try {
    // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
    const stdout = execSync(cmd, { cwd: ROOT_DIR, stdio: "pipe" });
    if (expectExit !== 0) {
      throw new Error(`Expected exit ${expectExit}, but command succeeded (exit 0). Output: ${stdout}`);
    }
  } catch (err) {
    if (err.status !== expectExit) {
      throw new Error(`Expected exit ${expectExit}, but got ${err.status}. Stderr: ${err.stderr?.toString()}`);
    }
  }
}

function assertValid(data, context) {
  const res = validateReportSchema(data);
  if (!res.valid) {
    throw new Error(`Validation failed for ${context}: ${res.error}`);
  }
}

function assertInvalid(data, expectedSubstr, context) {
  const res = validateReportSchema(data);
  if (res.valid) {
    throw new Error(`Expected validation failure for ${context}, but report was marked valid.`);
  }
  if (!res.error || !res.error.toLowerCase().includes(expectedSubstr.toLowerCase())) {
    throw new Error(`Expected error matching '${expectedSubstr}' for ${context}, got '${res.error}'`);
  }
}

async function main() {
  console.log("=== PipelineShield Shared Dashboard Contract Verification ===");
  console.log(`Using Python binary: ${PYTHON}`);
  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  // -------------------------------------------------------------------------
  // 1. Real CLI Report Generations & TypeScript Dashboard Schema Validation
  // -------------------------------------------------------------------------
  console.log("[1/10] Testing CLI clean scan report...");
  const cleanOut = path.join(REPORTS_DIR, "contract_clean.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_clean.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --event-name pull_request --dependency-review "${path.join(FIXTURES_DIR, "dependency_review_clean.json")}" --output "${cleanOut}"`, 0);
  const cleanData = JSON.parse(fs.readFileSync(cleanOut, "utf-8"));
  assertValid(cleanData, "Clean scan report");
  if (cleanData.decision !== "PASS") throw new Error(`Expected decision PASS, got ${cleanData.decision}`);
  console.log("       ✓ Clean scan report valid (PASS, exit 0)");

  console.log("[2/10] Testing CLI vulnerable scan report (CVEs)...");
  const vulnOut = path.join(REPORTS_DIR, "contract_vuln.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_vulnerabilities.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --event-name pull_request --dependency-review "${path.join(FIXTURES_DIR, "dependency_review_clean.json")}" --output "${vulnOut}"`, 1);
  const vulnData = JSON.parse(fs.readFileSync(vulnOut, "utf-8"));
  assertValid(vulnData, "Vulnerable scan report");
  if (vulnData.decision !== "BLOCK") throw new Error(`Expected decision BLOCK, got ${vulnData.decision}`);
  console.log("       ✓ Vulnerable scan report valid (BLOCK, exit 1)");

  console.log("[3/10] Testing CLI Trivy misconfiguration report...");
  const misconfigOut = path.join(REPORTS_DIR, "contract_misconfig.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_blocking_misconfig.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --event-name pull_request --dependency-review "${path.join(FIXTURES_DIR, "dependency_review_clean.json")}" --output "${misconfigOut}"`, 1);
  const misconfigData = JSON.parse(fs.readFileSync(misconfigOut, "utf-8"));
  assertValid(misconfigData, "Misconfiguration report");
  if (misconfigData.decision !== "BLOCK") throw new Error(`Expected decision BLOCK, got ${misconfigData.decision}`);
  console.log("       ✓ Misconfiguration report valid (BLOCK, exit 1)");

  console.log("[4/10] Testing CLI Trivy secret detection report...");
  const secretOut = path.join(REPORTS_DIR, "contract_secret.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_exposed_secret.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --event-name pull_request --dependency-review "${path.join(FIXTURES_DIR, "dependency_review_clean.json")}" --output "${secretOut}"`, 1);
  const secretData = JSON.parse(fs.readFileSync(secretOut, "utf-8"));
  assertValid(secretData, "Secret detection report");
  if (secretData.decision !== "BLOCK") throw new Error(`Expected decision BLOCK, got ${secretData.decision}`);
  console.log("       ✓ Secret detection report valid (BLOCK, exit 1)");

  console.log("[5/10] Testing CLI mixed-scanner report (vulnerability + misconfiguration + secret)...");
  const mixedOut = path.join(REPORTS_DIR, "contract_mixed.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_mixed_results.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_findings.json")}" --event-name pull_request --dependency-review "${path.join(FIXTURES_DIR, "dep_review_official_added_vuln.json")}" --output "${mixedOut}"`, 1);
  const mixedData = JSON.parse(fs.readFileSync(mixedOut, "utf-8"));
  assertValid(mixedData, "Mixed-scanner report");
  if (mixedData.findings.length < 5) throw new Error(`Expected at least 5 findings in mixed report, got ${mixedData.findings.length}`);
  console.log("       ✓ Mixed-scanner report valid (Retains all findings, exit 1)");

  console.log("[6/10] Testing disabled scanner report status...");
  const disabledPolicyPath = path.join(REPORTS_DIR, "disabled_policy.yaml");
  fs.writeFileSync(
    disabledPolicyPath,
    `version: "1.0"\nscanners:\n  trivy:\n    enabled: false\n  semgrep:\n    enabled: true\n  dependency_review:\n    enabled: false\n`
  );
  const disabledOut = path.join(REPORTS_DIR, "contract_disabled.json");
  const disabledCmd = `"${PYTHON}" -m pipelineshield.cli --policy "${disabledPolicyPath}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --output "${disabledOut}"`;
  // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
  execSync(disabledCmd, { cwd: ROOT_DIR, stdio: "pipe" });
  const disabledData = JSON.parse(fs.readFileSync(disabledOut, "utf-8"));
  assertValid(disabledData, "Disabled scanner report");
  if (disabledData.scanner_status?.trivy !== "DISABLED") throw new Error(`Expected trivy scanner_status to be 'DISABLED', got ${disabledData.scanner_status?.trivy}`);
  if (disabledData.scanner_status?.semgrep !== "COMPLETED") throw new Error(`Expected semgrep scanner_status to be 'COMPLETED', got ${disabledData.scanner_status?.semgrep}`);
  if (disabledData.scanner_status?.dependency_review !== "DISABLED") throw new Error(`Expected dependency_review scanner_status to be 'DISABLED', got ${disabledData.scanner_status?.dependency_review}`);
  console.log("       ✓ Disabled scanner report valid (Explicit scanner_status recorded)");

  console.log("[7/10] Testing all-scanners-disabled mode without scanner inputs...");
  const allDisabledPolicyPath = path.join(REPORTS_DIR, "all_disabled_policy.yaml");
  fs.writeFileSync(
    allDisabledPolicyPath,
    `version: "1.0"\nscanners:\n  trivy:\n    enabled: false\n  semgrep:\n    enabled: false\n  dependency_review:\n    enabled: false\n`
  );
  const allDisabledOut = path.join(REPORTS_DIR, "contract_all_disabled.json");
  const allDisabledCmd = `"${PYTHON}" -m pipelineshield.cli --policy "${allDisabledPolicyPath}" --output "${allDisabledOut}"`;
  try {
    // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
    execSync(allDisabledCmd, { cwd: ROOT_DIR, stdio: "pipe" });
    throw new Error("Expected all-scanners-disabled CLI invocation to exit with code 2 (ERROR), but it exited 0");
  } catch (err) {
    if (err.status !== 2) {
      throw new Error(`Expected CLI exit code 2 for all-scanners-disabled mode, got ${err.status}`);
    }
  }
  const allDisabledData = JSON.parse(fs.readFileSync(allDisabledOut, "utf-8"));
  assertValid(allDisabledData, "All-scanners-disabled report");
  if (allDisabledData.decision !== "ERROR") {
    throw new Error(`Expected decision ERROR for all-scanners-disabled mode, got ${allDisabledData.decision}`);
  }
  if (allDisabledData.scanner_status?.trivy !== "DISABLED" ||
      allDisabledData.scanner_status?.semgrep !== "DISABLED" ||
      allDisabledData.scanner_status?.dependency_review !== "DISABLED") {
    throw new Error("Expected all scanners to be marked DISABLED");
  }
  if (!allDisabledData.reasons.some((r) => r.includes("All security scanners are disabled"))) {
    throw new Error("Expected explicit reason that all scanners were disabled");
  }
  console.log("       ✓ All-scanners-disabled mode evaluated safely (exit 2, decision ERROR, valid schema)");

  console.log("[8/10] Testing push-event scanner status (Dependency Review NOT_APPLICABLE)...");
  const pushOut = path.join(REPORTS_DIR, "contract_push.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_clean.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --event-name push --output "${pushOut}"`, 0);
  const pushData = JSON.parse(fs.readFileSync(pushOut, "utf-8"));
  assertValid(pushData, "Push event report");
  if (pushData.scanner_status?.dependency_review !== "NOT_APPLICABLE") {
    throw new Error(`Expected dependency_review to be NOT_APPLICABLE on push, got ${pushData.scanner_status?.dependency_review}`);
  }
  console.log("       ✓ Push-event scanner status recorded correctly (NOT_APPLICABLE)");

  console.log("[9/10] Testing ERROR decision report handling...");
  const errorReport = {
    decision: "ERROR",
    policy_mode: "strict",
    summary: {
      total_findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0,
      exempted: 0, blocking_count: 0, warning_count: 0,
    },
    findings: [],
    blocking_findings: [],
    warning_findings: [],
    exempted_findings: [],
    scanner_status: {
      trivy: "FAILED",
      semgrep: "COMPLETED",
      dependency_review: "NOT_APPLICABLE",
    },
    reasons: ["ERROR: Trivy execution failed or produced missing output."],
    errors: ["Scanner 'trivy' failed to run."],
  };
  assertValid(errorReport, "ERROR decision report");
  console.log("       ✓ ERROR decision report valid (Handled without crashing)");

  // -------------------------------------------------------------------------
  // 2. Strict Rejection of Malformed Vectors
  // -------------------------------------------------------------------------
  console.log("[10/10] Testing strict rejection of malformed vectors in dashboard validator...");

  // Non-object
  assertInvalid("not an object", "must be a valid json object", "Primitive root");

  // Invalid decision
  assertInvalid({ decision: "INVALID", summary: cleanData.summary }, "decision", "Invalid decision");

  // Negative summary value
  const negSummary = { ...cleanData, summary: { ...cleanData.summary, critical: -1 } };
  assertInvalid(negSummary, "non-negative integer", "Negative summary count");

  // Non-integer summary value
  const floatSummary = { ...cleanData, summary: { ...cleanData.summary, high: 1.5 } };
  assertInvalid(floatSummary, "non-negative integer", "Float summary count");

  // Unsupported scanner
  const invalidScanner = {
    ...cleanData,
    findings: [{
      id: "SNYK-001",
      title: "Snyk issue",
      severity: "HIGH",
      scanner: "snyk", // Unsupported scanner!
    }],
    summary: { ...cleanData.summary, total_findings: 1, high: 1 },
  };
  assertInvalid(invalidScanner, "scanner", "Unsupported scanner 'snyk'");

  // Invalid severity
  const invalidSev = {
    ...cleanData,
    findings: [{
      id: "CVE-001",
      title: "Test",
      severity: "EXTREME", // Invalid severity!
      scanner: "trivy",
    }],
    summary: { ...cleanData.summary, total_findings: 1 },
  };
  assertInvalid(invalidSev, "severity", "Invalid severity 'EXTREME'");

  // Missing finding ID
  const missingId = {
    ...cleanData,
    findings: [{
      title: "Missing ID",
      severity: "HIGH",
      scanner: "trivy",
    }],
    summary: { ...cleanData.summary, total_findings: 1, high: 1 },
  };
  assertInvalid(missingId, "'id' must be a non-empty string", "Missing finding ID");

  // Non-array findings
  const nonArrayFindings = { ...cleanData, findings: "not-an-array" };
  assertInvalid(nonArrayFindings, "must be an array", "Non-array findings");

  // Non-array reasons
  const nonArrayReasons = { ...cleanData, reasons: "not-an-array" };
  assertInvalid(nonArrayReasons, "must be an array of strings", "Non-array reasons");

  // Invalid scanner_status value
  const invalidStatus = {
    ...cleanData,
    scanner_status: { trivy: "INVALID_STATUS_VALUE" },
  };
  assertInvalid(invalidStatus, "invalid status", "Invalid scanner_status value");

  // Inconsistent total_findings count vs actual findings array
  const inconsistentTotal = {
    ...cleanData,
    findings: [{
      id: "CVE-2024-001",
      title: "Test Vulnerability",
      severity: "HIGH",
      scanner: "trivy",
    }],
    summary: {
      ...cleanData.summary,
      total_findings: 10, // Inconsistent with findings.length (1)
      high: 1,
    },
  };
  assertInvalid(inconsistentTotal, "does not match findings.length", "Inconsistent total_findings");

  // Inconsistent severity count vs findings array
  const inconsistentSevCount = {
    ...cleanData,
    findings: [{
      id: "CVE-2024-001",
      title: "Test Vulnerability",
      severity: "HIGH",
      scanner: "trivy",
    }],
    summary: {
      ...cleanData.summary,
      total_findings: 1,
      critical: 1, // Inconsistent with actual HIGH severity
      high: 0,
    },
  };
  assertInvalid(inconsistentSevCount, "summary severity counts do not match", "Inconsistent severity counts");

  console.log("       ✓ All malformed vectors strictly rejected by TypeScript validator.");

  // Clean up test reports
  for (const f of [cleanOut, vulnOut, misconfigOut, secretOut, mixedOut, disabledOut, disabledPolicyPath, allDisabledOut, allDisabledPolicyPath, pushOut]) {
    try { fs.unlinkSync(f); } catch {}
  }

  console.log("=== All Dashboard Contract Tests Passed Successfully ===");
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
