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
 * Validate an individual Finding record.
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

  // Optional cwe_ids validation
  if (rec.cwe_ids !== undefined && rec.cwe_ids !== null) {
    if (!Array.isArray(rec.cwe_ids) || !rec.cwe_ids.every((c) => typeof c === "string")) {
      return {
        valid: false,
        error: `${listName}[${index}]: 'cwe_ids' must be an array of strings.`,
      };
    }
  }

  // Optional line_number validation
  if (rec.line_number !== undefined && rec.line_number !== null) {
    if (
      typeof rec.line_number !== "number" ||
      !Number.isInteger(rec.line_number) ||
      rec.line_number < 0
    ) {
      return {
        valid: false,
        error: `${listName}[${index}]: 'line_number' must be a non-negative integer.`,
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
  }

  // Validate finding arrays and their items
  const findingArrays: Array<[string, unknown]> = [
    ["blocking_findings", rec.blocking_findings],
    ["warning_findings", rec.warning_findings],
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

  return { valid: true };
}
