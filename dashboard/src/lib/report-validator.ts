/**
 * PipelineShield Shared Report Schema Validator Contract.
 *
 * Defines the authoritative client-side validation rules for PipelineShield
 * EvaluationResult payloads. Shared between dashboard file upload processing
 * and integration verification suites.
 */

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

export const VALID_DECISIONS = ["PASS", "WARN", "BLOCK", "ERROR"] as const;
export const VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const VALID_SCANNERS = ["trivy", "semgrep", "dependency_review", "manual"] as const;
export const VALID_SCANNER_STATUSES = [
  "COMPLETED",
  "DISABLED",
  "NOT_APPLICABLE",
  "FAILED",
] as const;

export const SUMMARY_NUMERIC_FIELDS = [
  "total_findings",
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "exempted",
  "blocking_count",
  "warning_count",
] as const;

/**
 * Validate an individual Finding record against the Python Finding schema.
 */
export function validateFinding(
  f: unknown,
  listName: string,
  index: number
): ValidationResult {
  if (!f || typeof f !== "object" || Array.isArray(f)) {
    return { valid: false, error: `${listName}[${index}] must be a valid JSON object.` };
  }
  const rec = f as Record<string, unknown>;

  // Required non-empty string fields
  if (typeof rec.id !== "string" || !rec.id.trim()) {
    return { valid: false, error: `${listName}[${index}]: 'id' must be a non-empty string.` };
  }
  if (typeof rec.title !== "string" || !rec.title.trim()) {
    return { valid: false, error: `${listName}[${index}]: 'title' must be a non-empty string.` };
  }

  // Severity enum check
  if (
    typeof rec.severity !== "string" ||
    !VALID_SEVERITIES.includes(rec.severity.toUpperCase() as (typeof VALID_SEVERITIES)[number])
  ) {
    return {
      valid: false,
      error: `${listName}[${index}]: 'severity' must be one of: ${VALID_SEVERITIES.join(", ")}.`,
    };
  }

  // Scanner enum check
  if (
    typeof rec.scanner !== "string" ||
    !VALID_SCANNERS.includes(rec.scanner.toLowerCase() as (typeof VALID_SCANNERS)[number])
  ) {
    return {
      valid: false,
      error: `${listName}[${index}]: 'scanner' must be one of: ${VALID_SCANNERS.join(", ")}. Got: '${rec.scanner}'`,
    };
  }

  // Description (optional string, defaults to "")
  if (rec.description !== undefined && rec.description !== null && typeof rec.description !== "string") {
    return { valid: false, error: `${listName}[${index}]: 'description' must be a string.` };
  }

  // Optional string fields (nullable)
  const nullableStrings = [
    "file_path",
    "package_name",
    "installed_version",
    "fixed_version",
    "license",
    "remediation",
  ] as const;

  for (const field of nullableStrings) {
    const val = rec[field];
    if (val !== undefined && val !== null && typeof val !== "string") {
      return {
        valid: false,
        error: `${listName}[${index}]: '${field}' must be a string or null.`,
      };
    }
  }

  // Optional line_number validation (nullable non-negative integer)
  if (rec.line_number !== undefined && rec.line_number !== null) {
    if (
      typeof rec.line_number !== "number" ||
      !Number.isInteger(rec.line_number) ||
      rec.line_number < 0
    ) {
      return {
        valid: false,
        error: `${listName}[${index}]: 'line_number' must be a non-negative integer or null.`,
      };
    }
  }

  // Optional cwe_ids validation (array of strings)
  if (rec.cwe_ids !== undefined && rec.cwe_ids !== null) {
    if (!Array.isArray(rec.cwe_ids) || !rec.cwe_ids.every((c) => typeof c === "string")) {
      return {
        valid: false,
        error: `${listName}[${index}]: 'cwe_ids' must be an array of strings.`,
      };
    }
  }

  // Optional metadata validation (object, not array)
  if (rec.metadata !== undefined && rec.metadata !== null) {
    if (typeof rec.metadata !== "object" || Array.isArray(rec.metadata)) {
      return {
        valid: false,
        error: `${listName}[${index}]: 'metadata' must be an object.`,
      };
    }
  }

  return { valid: true };
}

/**
 * Validate a complete EvaluationResult report payload.
 */
export function validateReportSchema(obj: unknown): ValidationResult {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { valid: false, error: "Root must be a valid JSON object." };
  }
  const rec = obj as Record<string, unknown>;

  // Decision
  if (
    typeof rec.decision !== "string" ||
    !VALID_DECISIONS.includes(rec.decision.toUpperCase() as (typeof VALID_DECISIONS)[number])
  ) {
    return {
      valid: false,
      error: `Invalid 'decision' field. Must be one of: ${VALID_DECISIONS.join(", ")}.`,
    };
  }

  // Summary object
  if (!rec.summary || typeof rec.summary !== "object" || Array.isArray(rec.summary)) {
    return { valid: false, error: "Missing or invalid 'summary' object." };
  }
  const summary = rec.summary as Record<string, unknown>;

  // Numeric summary counts must be non-negative integers
  for (const field of SUMMARY_NUMERIC_FIELDS) {
    const val = summary[field];
    if (
      typeof val !== "number" ||
      !Number.isFinite(val) ||
      !Number.isInteger(val) ||
      val < 0
    ) {
      return {
        valid: false,
        error: `Summary field '${field}' must be a non-negative integer.`,
      };
    }
  }

  // Reasons array (optional, but if present must be array of strings)
  if (rec.reasons !== undefined && rec.reasons !== null) {
    if (!Array.isArray(rec.reasons) || !rec.reasons.every((r) => typeof r === "string")) {
      return { valid: false, error: "'reasons' must be an array of strings." };
    }
  }

  // Errors array (present on ERROR reports)
  if (rec.errors !== undefined && rec.errors !== null) {
    if (!Array.isArray(rec.errors) || !rec.errors.every((e) => typeof e === "string")) {
      return { valid: false, error: "'errors' must be an array of strings." };
    }
  }

  // Scanner status (optional dictionary of scanner -> status string)
  if (rec.scanner_status !== undefined && rec.scanner_status !== null) {
    if (typeof rec.scanner_status !== "object" || Array.isArray(rec.scanner_status)) {
      return { valid: false, error: "'scanner_status' must be an object." };
    }
    const statusObj = rec.scanner_status as Record<string, unknown>;
    for (const [scanner, statusVal] of Object.entries(statusObj)) {
      if (typeof scanner !== "string" || !scanner.trim()) {
        return { valid: false, error: "scanner_status keys must be non-empty strings." };
      }
      if (
        typeof statusVal !== "string" ||
        !VALID_SCANNER_STATUSES.includes(statusVal.toUpperCase() as (typeof VALID_SCANNER_STATUSES)[number])
      ) {
        return {
          valid: false,
          error: `scanner_status['${scanner}'] has invalid status '${statusVal}'. Allowed: ${VALID_SCANNER_STATUSES.join(", ")}.`,
        };
      }
    }
  }

  // Optional policy_metadata object validation
  if (rec.policy_metadata !== undefined && rec.policy_metadata !== null) {
    if (typeof rec.policy_metadata !== "object" || Array.isArray(rec.policy_metadata)) {
      return { valid: false, error: "'policy_metadata' must be an object." };
    }
  }

  // Validate finding arrays and their items
  const findingArrays: Array<[string, unknown]> = [
    ["blocking_findings", rec.blocking_findings],
    ["warning_findings", rec.warning_findings],
    ["advisory_findings", rec.advisory_findings],
    ["exempted_findings", rec.exempted_findings],
    ["findings", rec.findings],
  ];

  for (const [name, arr] of findingArrays) {
    if (arr !== undefined && arr !== null) {
      if (!Array.isArray(arr)) {
        return { valid: false, error: `'${name}' must be an array.` };
      }
      for (let i = 0; i < arr.length; i++) {
        const itemVal = validateFinding(arr[i], name, i);
        if (!itemVal.valid) {
          return itemVal;
        }
      }
    }
  }

  // Consistency checks:
  // 1. blocking_findings.length must match summary.blocking_count
  if (rec.blocking_findings !== undefined && rec.blocking_findings !== null) {
    const bfLen = (rec.blocking_findings as unknown[]).length;
    if (summary.blocking_count !== bfLen) {
      return {
        valid: false,
        error: `summary.blocking_count (${summary.blocking_count}) does not match blocking_findings.length (${bfLen}).`,
      };
    }
  }

  // 2. warning_findings.length must match summary.warning_count
  if (rec.warning_findings !== undefined && rec.warning_findings !== null) {
    const wfLen = (rec.warning_findings as unknown[]).length;
    if (summary.warning_count !== wfLen) {
      return {
        valid: false,
        error: `summary.warning_count (${summary.warning_count}) does not match warning_findings.length (${wfLen}).`,
      };
    }
  }

  // 3. exempted_findings.length must match summary.exempted
  if (rec.exempted_findings !== undefined && rec.exempted_findings !== null) {
    const efLen = (rec.exempted_findings as unknown[]).length;
    if (summary.exempted !== efLen) {
      return {
        valid: false,
        error: `summary.exempted (${summary.exempted}) does not match exempted_findings.length (${efLen}).`,
      };
    }
  }

  // 4. If authoritative 'findings' array is present, check total and severity distribution
  if (Array.isArray(rec.findings)) {
    const fArr = rec.findings as Array<Record<string, unknown>>;
    if (summary.total_findings !== fArr.length) {
      return {
        valid: false,
        error: `summary.total_findings (${summary.total_findings}) does not match findings.length (${fArr.length}).`,
      };
    }

    let crit = 0;
    let high = 0;
    let med = 0;
    let low = 0;
    let info = 0;

    for (const f of fArr) {
      const s = String(f.severity || "").toUpperCase();
      if (s === "CRITICAL") crit++;
      else if (s === "HIGH") high++;
      else if (s === "MEDIUM") med++;
      else if (s === "LOW") low++;
      else if (s === "INFO") info++;
    }

    if (
      summary.critical !== crit ||
      summary.high !== high ||
      summary.medium !== med ||
      summary.low !== low ||
      summary.info !== info
    ) {
      return {
        valid: false,
        error: `Summary severity counts do not match findings collection. Expected: {CRITICAL: ${crit}, HIGH: ${high}, MEDIUM: ${med}, LOW: ${low}, INFO: ${info}}, Got: {critical: ${summary.critical}, high: ${summary.high}, medium: ${summary.medium}, low: ${summary.low}, info: ${summary.info}}`,
      };
    }
  }

  return { valid: true };
}
