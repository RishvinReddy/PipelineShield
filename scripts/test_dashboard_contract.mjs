#!/usr/bin/env node
/**
 * Shared Report Schema & Dashboard Contract Test.
 *
 * Runs directly against the TypeScript validator (dashboard/src/lib/report-validator.ts)
 * using Node.js native TypeScript execution.
 *
 * Validates:
 * 1. Real CLI-generated reports across all scanner permutations (clean, vulnerable, misconfig, secret, mixed, disabled, error).
 * 2. Strict rejection of malformed test vectors (unsupported scanners, invalid severities, missing IDs, invalid counts).
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
const PYTHON = path.join(ROOT_DIR, "engine", ".venv", "bin", "python");

function runCli(args, expectExit = 0) {
  const policyPath = path.join(ROOT_DIR, "config", "policy.yaml");
  const cmd = `"${PYTHON}" -m pipelineshield.cli --policy "${policyPath}" ${args}`;
  try {
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
  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  // -------------------------------------------------------------------------
  // 1. Real CLI Report Generations & TypeScript Dashboard Schema Validation
  // -------------------------------------------------------------------------
  console.log("[1/8] Testing CLI clean scan report...");
  const cleanOut = path.join(REPORTS_DIR, "contract_clean.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_clean.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_clean.json")}" --output "${cleanOut}"`, 0);
  const cleanData = JSON.parse(fs.readFileSync(cleanOut, "utf-8"));
  assertValid(cleanData, "Clean scan report");
  if (cleanData.decision !== "PASS") throw new Error(`Expected decision PASS, got ${cleanData.decision}`);
  console.log("      ✓ Clean scan report valid (PASS, exit 0)");

  console.log("[2/8] Testing CLI vulnerable scan report (CVEs)...");
  const vulnOut = path.join(REPORTS_DIR, "contract_vuln.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_vulnerabilities.json")}" --output "${vulnOut}"`, 1);
  const vulnData = JSON.parse(fs.readFileSync(vulnOut, "utf-8"));
  assertValid(vulnData, "Vulnerable scan report");
  if (vulnData.decision !== "BLOCK") throw new Error(`Expected decision BLOCK, got ${vulnData.decision}`);
  console.log("      ✓ Vulnerable scan report valid (BLOCK, exit 1)");

  console.log("[3/8] Testing CLI Trivy misconfiguration report...");
  const misconfigOut = path.join(REPORTS_DIR, "contract_misconfig.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_blocking_misconfig.json")}" --output "${misconfigOut}"`, 1);
  const misconfigData = JSON.parse(fs.readFileSync(misconfigOut, "utf-8"));
  assertValid(misconfigData, "Misconfiguration report");
  if (misconfigData.decision !== "BLOCK") throw new Error(`Expected decision BLOCK, got ${misconfigData.decision}`);
  console.log("      ✓ Misconfiguration report valid (BLOCK, exit 1)");

  console.log("[4/8] Testing CLI Trivy secret detection report...");
  const secretOut = path.join(REPORTS_DIR, "contract_secret.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_exposed_secret.json")}" --output "${secretOut}"`, 1);
  const secretData = JSON.parse(fs.readFileSync(secretOut, "utf-8"));
  assertValid(secretData, "Secret detection report");
  if (secretData.decision !== "BLOCK") throw new Error(`Expected decision BLOCK, got ${secretData.decision}`);
  console.log("      ✓ Secret detection report valid (BLOCK, exit 1)");

  console.log("[5/8] Testing CLI mixed-scanner report (vulnerability + misconfiguration + secret)...");
  const mixedOut = path.join(REPORTS_DIR, "contract_mixed.json");
  runCli(`--trivy "${path.join(FIXTURES_DIR, "trivy_mixed_results.json")}" --semgrep "${path.join(FIXTURES_DIR, "semgrep_findings.json")}" --output "${mixedOut}"`, 1);
  const mixedData = JSON.parse(fs.readFileSync(mixedOut, "utf-8"));
  assertValid(mixedData, "Mixed-scanner report");
  if (mixedData.findings.length < 5) throw new Error(`Expected at least 5 findings in mixed report, got ${mixedData.findings.length}`);
  console.log("      ✓ Mixed-scanner report valid (Retains all findings, exit 1)");

  console.log("[6/8] Testing disabled scanner report status...");
  const disabledPolicyPath = path.join(REPORTS_DIR, "disabled_policy.yaml");
  fs.writeFileSync(
    disabledPolicyPath,
    `version: "1.0"\nscanners:\n  trivy:\n    enabled: false\n  semgrep:\n    enabled: true\n  dependency_review:\n    enabled: false\n`
  );
  const disabledOut = path.join(REPORTS_DIR, "contract_disabled.json");
  const disabledCmd = `"${PYTHON}" -m pipelineshield.cli --policy "${disabledPolicyPath}" --trivy "${path.join(FIXTURES_DIR, "trivy_vulnerabilities.json")}" --output "${disabledOut}"`;
  execSync(disabledCmd, { cwd: ROOT_DIR, stdio: "pipe" });
  const disabledData = JSON.parse(fs.readFileSync(disabledOut, "utf-8"));
  assertValid(disabledData, "Disabled scanner report");
  if (disabledData.scanner_status?.trivy !== "disabled") throw new Error("Expected trivy scanner_status to be 'disabled'");
  if (disabledData.scanner_status?.semgrep !== "enabled") throw new Error("Expected semgrep scanner_status to be 'enabled'");
  console.log("      ✓ Disabled scanner report valid (Explicit scanner_status recorded)");

  console.log("[7/8] Testing ERROR decision report handling...");
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
    reasons: ["ERROR: Policy engine failed safely."],
    errors: ["Detailed exception description"],
  };
  assertValid(errorReport, "ERROR decision report");
  console.log("      ✓ ERROR decision report valid (Handled without crashing)");

  // -------------------------------------------------------------------------
  // 2. Strict Rejection of Malformed Vectors
  // -------------------------------------------------------------------------
  console.log("[8/8] Testing strict rejection of malformed vectors in dashboard validator...");

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
  };
  assertInvalid(missingId, "'id' must be a non-empty string", "Missing finding ID");

  // Non-array findings
  const nonArrayFindings = { ...cleanData, findings: "not-an-array" };
  assertInvalid(nonArrayFindings, "must be an array", "Non-array findings");

  // Non-array reasons
  const nonArrayReasons = { ...cleanData, reasons: "not-an-array" };
  assertInvalid(nonArrayReasons, "must be an array of strings", "Non-array reasons");

  console.log("      ✓ All malformed vectors strictly rejected by TypeScript validator.");

  // Clean up test reports
  for (const f of [cleanOut, vulnOut, misconfigOut, secretOut, mixedOut, disabledOut, disabledPolicyPath]) {
    try { fs.unlinkSync(f); } catch {}
  }

  console.log("=== All Dashboard Contract Tests Passed Successfully ===");
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
