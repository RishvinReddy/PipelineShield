"use client";

import React, { useState, useMemo, ChangeEvent } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  CheckCircle2,
  Lock,
  Layers,
  ExternalLink,
  Terminal,
  Search,
  Upload,
  FileText,
  ChevronDown,
  ChevronUp,
  Printer,
  GitBranch,
  GitCommit,
  Clock,
  Check,
  XCircle,
  FileCode2,
  Info,
} from "lucide-react";
import { validateReportSchema } from "@/lib/report-validator";

interface Finding {
  id: string;
  scanner: "trivy" | "semgrep" | "dependency_review";
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  file_path?: string | null;
  line_number?: number | null;
  package_name?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  cwe_ids?: string[];
  remediation?: string | null;
}

interface EvaluationSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  exempted: number;
  blocking_count: number;
  warning_count: number;
}

interface EvaluationResult {
  decision: "PASS" | "WARN" | "BLOCK" | "ERROR";
  reasons: string[];
  summary: EvaluationSummary;
  findings?: Finding[];
  blocking_findings: Finding[];
  warning_findings: Finding[];
  advisory_findings?: Finding[];
  exempted_findings: Finding[];
  evaluated_at?: string;
  policy_metadata?: Record<string, string>;
  scanner_status?: Record<string, string>;
  errors?: string[];
}

interface ProcessedFinding extends Finding {
  gateCategory: "blocking" | "warning" | "advisory" | "exempted";
}

// Explicit demonstration datasets for all four verdict states
const SAMPLE_REPORTS: Record<
  string,
  { label: string; tag: string; isDemo: boolean; data: EvaluationResult }
> = {
  vulnerable: {
    label: "Demo: Vulnerable PR (BLOCK)",
    tag: "BLOCK (Exit 1)",
    isDemo: true,
    data: {
      decision: "BLOCK",
      reasons: [
        "1 CRITICAL finding(s) violate threshold (tolerates: BLOCK)",
        "2 HIGH finding(s) violate threshold (tolerates: BLOCK)",
      ],
      summary: {
        total_findings: 5,
        critical: 1,
        high: 2,
        medium: 1,
        low: 1,
        info: 0,
        exempted: 0,
        blocking_count: 3,
        warning_count: 1,
      },
      blocking_findings: [
        {
          id: "CVE-2022-42966",
          scanner: "trivy",
          title: "ReDoS vulnerability in python-cryptography",
          description:
            "Regular Expression Denial of Service in cryptography X.509 certificate parsing.",
          severity: "CRITICAL",
          file_path: "engine/requirements.txt",
          package_name: "cryptography",
          installed_version: "3.4.8",
          fixed_version: "38.0.3",
          cwe_ids: ["CWE-1333", "CWE-400"],
          remediation: "Upgrade cryptography to version 38.0.3 or higher.",
        },
        {
          id: "python.lang.security.audit.dangerous-subprocess-use-audit",
          scanner: "semgrep",
          title: "Potential command injection via unsanitized subprocess invocation",
          description:
            "Detected subprocess call with shell=True or dynamic untrusted command arguments.",
          severity: "HIGH",
          file_path: "engine/src/pipelineshield/runner.py",
          line_number: 142,
          cwe_ids: ["CWE-78", "CWE-88"],
          remediation:
            "Pass command arguments as a list with shell=False and sanitize parameters.",
        },
        {
          id: "GHSA-35jh-r3h4-6jhm",
          scanner: "dependency_review",
          title: "Prototype Pollution in lodash",
          description:
            "Deep clone utility functions in lodash prior to 4.17.21 allow object prototype tampering.",
          severity: "HIGH",
          file_path: "dashboard/package.json",
          package_name: "lodash",
          installed_version: "4.17.15",
          fixed_version: "4.17.21",
          cwe_ids: ["CWE-1321"],
          remediation: "Upgrade lodash to 4.17.21 in dashboard/package.json.",
        },
      ],
      warning_findings: [
        {
          id: "python.lang.security.unencrypted-socket",
          scanner: "semgrep",
          title: "Plaintext socket connection initiated without TLS wrapper",
          description: "Socket connection opened on unencrypted port.",
          severity: "MEDIUM",
          file_path: "engine/src/pipelineshield/telemetry.py",
          line_number: 89,
          cwe_ids: ["CWE-319"],
          remediation: "Wrap socket with ssl.wrap_socket() or use https protocol.",
        },
      ],
      advisory_findings: [
        {
          id: "CVE-2023-26115",
          scanner: "trivy",
          title: "ReDoS vulnerability in word-wrap",
          description: "Space complexity issue in word-wrap library.",
          severity: "LOW",
          file_path: "dashboard/package-lock.json",
          package_name: "word-wrap",
          installed_version: "1.2.3",
          fixed_version: "1.2.4",
          remediation: "Update word-wrap dependency to version 1.2.4.",
        },
      ],
      exempted_findings: [],
      evaluated_at: "2026-10-30T18:00:00Z",
      scanner_status: {
        trivy: "COMPLETED",
        semgrep: "COMPLETED",
        dependency_review: "COMPLETED",
      },
      policy_metadata: {
        name: "PipelineShield Default Security Policy",
      },
    },
  },
  clean: {
    label: "Demo: Clean Baseline (PASS)",
    tag: "PASS (Exit 0)",
    isDemo: true,
    data: {
      decision: "PASS",
      reasons: ["All findings within acceptable policy thresholds"],
      summary: {
        total_findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        exempted: 0,
        blocking_count: 0,
        warning_count: 0,
      },
      blocking_findings: [],
      warning_findings: [],
      advisory_findings: [],
      exempted_findings: [],
      evaluated_at: "2026-10-30T17:30:00Z",
      scanner_status: {
        trivy: "COMPLETED",
        semgrep: "COMPLETED",
        dependency_review: "COMPLETED",
      },
      policy_metadata: {
        name: "PipelineShield Default Security Policy",
      },
    },
  },
  warnings_only: {
    label: "Demo: Advisory Warnings (WARN)",
    tag: "WARN (Exit 0)",
    isDemo: true,
    data: {
      decision: "WARN",
      reasons: ["1 MEDIUM finding(s) meet WARN threshold"],
      summary: {
        total_findings: 2,
        critical: 0,
        high: 0,
        medium: 1,
        low: 1,
        info: 0,
        exempted: 0,
        blocking_count: 0,
        warning_count: 1,
      },
      blocking_findings: [],
      warning_findings: [
        {
          id: "CVE-2023-49083",
          scanner: "trivy",
          title: "Moderate denial of service in cryptography package",
          description: "Handling of specific PKCS#7 structures could trigger high CPU load.",
          severity: "MEDIUM",
          file_path: "engine/requirements.txt",
          package_name: "cryptography",
          installed_version: "41.0.4",
          fixed_version: "41.0.6",
          cwe_ids: ["CWE-400"],
          remediation: "Upgrade cryptography to 41.0.6.",
        },
      ],
      advisory_findings: [
        {
          id: "INFO-001",
          scanner: "semgrep",
          title: "Verbose logging of configuration state",
          description: "Debug level log statement contains environment key names.",
          severity: "LOW",
          file_path: "engine/src/pipelineshield/cli.py",
          line_number: 45,
          remediation: "Ensure log statements do not capture sensitive environment variables.",
        },
      ],
      exempted_findings: [],
      evaluated_at: "2026-10-30T17:45:00Z",
      scanner_status: {
        trivy: "COMPLETED",
        semgrep: "COMPLETED",
        dependency_review: "NOT_APPLICABLE",
      },
      policy_metadata: {
        name: "PipelineShield Default Security Policy",
      },
    },
  },
  scanner_error: {
    label: "Demo: Scanner Failure (ERROR)",
    tag: "ERROR (Exit 2)",
    isDemo: true,
    data: {
      decision: "ERROR",
      reasons: [
        "Scanner 'trivy' failed to execute or produce valid output (exit code 127)",
        "Fail-closed policy triggered: incomplete security scanning cannot produce PASS decision",
      ],
      summary: {
        total_findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        exempted: 0,
        blocking_count: 0,
        warning_count: 0,
      },
      blocking_findings: [],
      warning_findings: [],
      advisory_findings: [],
      exempted_findings: [],
      evaluated_at: "2026-10-30T17:15:00Z",
      scanner_status: {
        trivy: "FAILED",
        semgrep: "COMPLETED",
        dependency_review: "NOT_APPLICABLE",
      },
      policy_metadata: {
        name: "PipelineShield Default Security Policy",
      },
    },
  },
};

export default function Home() {
  const [activeReportKey, setActiveReportKey] = useState<string>("vulnerable");
  const [customReport, setCustomReport] = useState<EvaluationResult | null>(null);
  const [customFileName, setCustomFileName] = useState<string>("");
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "policy" | "architecture">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [scannerFilter, setScannerFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  // Active report data
  const currentResult: EvaluationResult = useMemo(() => {
    if (activeReportKey === "custom" && customReport) {
      return customReport;
    }
    return SAMPLE_REPORTS[activeReportKey]?.data || SAMPLE_REPORTS.vulnerable.data;
  }, [activeReportKey, customReport]);

  const isDemoActive = activeReportKey !== "custom";

  // Combine all findings for interactive search and filter:
  // Uses 'findings' as the authoritative superset to guarantee PASS findings are displayed
  const allFindings = useMemo<ProcessedFinding[]>(() => {
    if (Array.isArray(currentResult.findings) && currentResult.findings.length > 0) {
      const blockingIds = new Set((currentResult.blocking_findings || []).map((f) => f.id));
      const warningIds = new Set((currentResult.warning_findings || []).map((f) => f.id));
      const exemptedIds = new Set((currentResult.exempted_findings || []).map((f) => f.id));

      return currentResult.findings.map((f: Finding) => {
        let gateCategory: "blocking" | "warning" | "advisory" | "exempted" = "advisory";
        if (blockingIds.has(f.id)) {
          gateCategory = "blocking";
        } else if (warningIds.has(f.id)) {
          gateCategory = "warning";
        } else if (exemptedIds.has(f.id)) {
          gateCategory = "exempted";
        }
        return { ...f, gateCategory };
      });
    }

    // Fallback if 'findings' is not populated
    const list: ProcessedFinding[] = [];
    (currentResult.blocking_findings || []).forEach((f) =>
      list.push({ ...f, gateCategory: "blocking" })
    );
    (currentResult.warning_findings || []).forEach((f) =>
      list.push({ ...f, gateCategory: "warning" })
    );
    (currentResult.advisory_findings || []).forEach((f) =>
      list.push({ ...f, gateCategory: "advisory" })
    );
    (currentResult.exempted_findings || []).forEach((f) =>
      list.push({ ...f, gateCategory: "exempted" })
    );
    return list;
  }, [currentResult]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return allFindings.filter((item) => {
      if (severityFilter !== "ALL" && item.severity !== severityFilter) return false;
      if (scannerFilter !== "ALL" && item.scanner !== scannerFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = (item.id || "").toLowerCase().includes(q);
        const matchTitle = (item.title || "").toLowerCase().includes(q);
        const matchFile = (item.file_path || "").toLowerCase().includes(q);
        const matchPkg = (item.package_name || "").toLowerCase().includes(q);
        return matchId || matchTitle || matchFile || matchPkg;
      }
      return true;
    });
  }, [allFindings, severityFilter, scannerFilter, searchQuery]);

  // Handle report upload with schema validation
  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    setUploadError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target?.result as string);
        const validation = validateReportSchema(parsed);
        if (!validation.valid) {
          setUploadError(`Invalid PipelineShield schema: ${validation.error}`);
          return;
        }

        const normalized: EvaluationResult = {
          decision: (parsed.decision || "BLOCK").toUpperCase(),
          reasons: Array.isArray(parsed.reasons) ? parsed.reasons : [],
          summary: parsed.summary,
          findings: Array.isArray(parsed.findings) ? parsed.findings : undefined,
          blocking_findings: Array.isArray(parsed.blocking_findings)
            ? parsed.blocking_findings
            : [],
          warning_findings: Array.isArray(parsed.warning_findings) ? parsed.warning_findings : [],
          advisory_findings: Array.isArray(parsed.advisory_findings)
            ? parsed.advisory_findings
            : [],
          exempted_findings: Array.isArray(parsed.exempted_findings)
            ? parsed.exempted_findings
            : [],
          evaluated_at: parsed.evaluated_at || undefined,
          scanner_status: parsed.scanner_status || {},
          policy_metadata: parsed.policy_metadata || {},
        };

        setCustomReport(normalized);
        setCustomFileName(file.name);
        setActiveReportKey("custom");
      } catch (err) {
        setUploadError(
          `Failed to parse JSON file: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    };
    reader.readAsText(file);
  };

  const getDecisionStyles = (decision: string, reasons: string[] = []) => {
    switch (decision) {
      case "BLOCK":
        return {
          icon: ShieldAlert,
          title: "PR Security Gate: BLOCKED",
          badgeText: "Exit Code 1",
          sub: "Pull request gatekeeper failed: critical or high severity security findings violate repository policy.",
          badgeBg: "bg-[#FEF3F2] text-[#B42318] border-[#FECDCA]",
          borderAccent: "border-l-[#B42318]",
          iconColor: "text-[#B42318]",
        };
      case "WARN":
        return {
          icon: AlertTriangle,
          title: "PR Security Gate: PASSED WITH WARNINGS",
          badgeText: "Exit Code 0",
          sub: "Pull request gatekeeper passed: advisory findings were detected that require engineering review.",
          badgeBg: "bg-[#FEFCE8] text-[#A16207] border-[#FEF08A]",
          borderAccent: "border-l-[#A16207]",
          iconColor: "text-[#A16207]",
        };
      case "PASS":
        return {
          icon: ShieldCheck,
          title: "PR Security Gate: PASSED",
          badgeText: "Exit Code 0",
          sub: "Pull request gatekeeper passed: zero blocking violations or policy transgressions detected.",
          badgeBg: "bg-[#ECFDF3] text-[#18794E] border-[#A6F4C5]",
          borderAccent: "border-l-[#18794E]",
          iconColor: "text-[#18794E]",
        };
      default: {
        const isNoScan = reasons.some((r) =>
          r.toLowerCase().includes("no security scanning was performed")
        );
        return {
          icon: AlertOctagon,
          title: isNoScan ? "SECURITY ASSESSMENT NOT PERFORMED" : "GATEKEEPER EXECUTION FAULT",
          badgeText: "Exit Code 2",
          sub: isNoScan
            ? "Fail-closed trigger: zero security scanners executed or all scanners were disabled."
            : "Pipeline execution encountered an unhandled error or scanner execution failure.",
          badgeBg: "bg-[#FEF2F2] text-[#991B1B] border-[#FECACA]",
          borderAccent: "border-l-[#991B1B]",
          iconColor: "text-[#991B1B]",
        };
      }
    }
  };

  const decisionStyle = getDecisionStyles(currentResult.decision, currentResult.reasons);
  const DecisionIcon = decisionStyle.icon;

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-[#FEF3F2] text-[#B42318] border-[#FECDCA]";
      case "HIGH":
        return "bg-[#FFF7ED] text-[#C2410C] border-[#FED7AA]";
      case "MEDIUM":
        return "bg-[#FEFCE8] text-[#A16207] border-[#FEF08A]";
      case "LOW":
        return "bg-[#EFF6FF] text-[#2563A6] border-[#BFDBFE]";
      default:
        return "bg-[#F8FAFC] text-[#64748B] border-[#E2E8F0]";
    }
  };

  const getScannerBadge = (scanner: string) => {
    switch (scanner) {
      case "trivy":
        return "bg-[#F0FDFA] text-[#0D9488] border-[#99F6E4]";
      case "semgrep":
        return "bg-[#FAF5FF] text-[#7C3AED] border-[#E9D5FF]";
      case "dependency_review":
        return "bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]";
      default:
        return "bg-[#F8FAFC] text-[#475569] border-[#E2E8F0]";
    }
  };

  const getGateCategoryBadge = (category: string) => {
    switch (category) {
      case "blocking":
        return "bg-[#FEF3F2] text-[#B42318] border-[#FECDCA]";
      case "warning":
        return "bg-[#FEFCE8] text-[#A16207] border-[#FEF08A]";
      case "exempted":
        return "bg-[#F1F5F9] text-[#475569] border-[#CBD5E1]";
      default:
        return "bg-[#F8FAFC] text-[#64748B] border-[#E2E8F0]";
    }
  };

  // Strict provenance metadata: NEVER hardcode live commit SHAs or branches into uploaded or demo data
  const repoDisplay = isDemoActive
    ? "Demonstration (Synthetic)"
    : currentResult.policy_metadata?.repository || "Not available";

  const branchDisplay = isDemoActive
    ? "demo/synthetic-run"
    : currentResult.policy_metadata?.branch || "Not available";

  const commitDisplay = isDemoActive
    ? "N/A (Synthetic)"
    : currentResult.policy_metadata?.commit || "Not available";

  const evaluatedAtDisplay = currentResult.evaluated_at || "Not available";

  return (
    <div className="min-h-screen flex flex-col bg-[#F4F6F8] text-[#172435] font-sans">
      {/* Print-Only Formal Header */}
      <div className="hidden print:block p-4 border-b border-[#E2E8F0] space-y-2">
        <h1 className="text-xl font-bold text-[#172435]">
          PipelineShield — Security Assessment Report
        </h1>
        <div className="text-xs text-[#475569] grid grid-cols-2 gap-2">
          <div>Repository: <strong>{repoDisplay}</strong></div>
          <div>Branch: <strong>{branchDisplay}</strong></div>
          <div>Commit: <strong>{commitDisplay}</strong></div>
          <div>Evaluated: <strong>{evaluatedAtDisplay}</strong></div>
        </div>
        <div className="text-xs text-[#64748B] italic">
          Data Provenance: {isDemoActive ? "DEMONSTRATION DATA (MOCK)" : `Uploaded Artifact (${customFileName})`}
        </div>
      </div>

      {/* Top Navigation */}
      <header className="no-print bg-white border-b border-[#E2E8F0] sticky top-0 z-40">
        <div className="max-w-[1280px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-1.5 rounded-md bg-[#0F172A] text-white">
              <Shield className="w-4 h-4 stroke-[2.5]" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="font-semibold text-base tracking-tight text-[#172435]">
                PipelineShield
              </span>
              <span className="text-[11px] font-mono text-[#64748B] px-1.5 py-0.5 rounded bg-[#F1F5F9] border border-[#E2E8F0]">
                Gatekeeper v0.1.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-2.5">
            <button
              onClick={() => window.print()}
              className="inline-flex items-center space-x-1.5 text-xs font-medium text-[#475569] hover:text-[#172435] bg-white hover:bg-[#F8FAFC] border border-[#E2E8F0] rounded-md px-2.5 py-1.5 transition-colors cursor-pointer"
              title="Print or Export Security Report"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>

            <label className="cursor-pointer inline-flex items-center space-x-1.5 text-xs font-medium text-[#172435] bg-white hover:bg-[#F8FAFC] border border-[#E2E8F0] rounded-md px-2.5 py-1.5 transition-colors shadow-2xs">
              <Upload className="w-3.5 h-3.5 text-[#0D9488]" />
              <span>Load Report JSON</span>
              <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
            </label>

            <a
              href="https://github.com/RishvinReddy/PipelineShield"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center space-x-1 text-xs font-medium text-[#475569] hover:text-[#172435] bg-white hover:bg-[#F8FAFC] border border-[#E2E8F0] rounded-md px-2.5 py-1.5 transition-colors"
            >
              <span>GitHub</span>
              <ExternalLink className="w-3 h-3 text-[#64748B]" />
            </a>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-[1280px] w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Editorial Report Header */}
        <section className="bg-white rounded-xl border border-[#E2E8F0] p-5 shadow-2xs space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-semibold tracking-wider uppercase text-[#0D9488] bg-[#F0FDFA] border border-[#99F6E4] px-2 py-0.5 rounded">
                  Security Assessment Report
                </span>
                <span className="text-xs text-[#64748B]">
                  Automated DevSecOps Policy Gate
                </span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#172435]">
                PipelineShield CI/CD Security Audit
              </h1>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#64748B] pt-1">
                <span className="inline-flex items-center space-x-1.5 font-mono text-[#172435]">
                  <FileCode2 className="w-3.5 h-3.5 text-[#64748B]" />
                  <span>Repository: <strong className="font-semibold text-[#172435]">{repoDisplay}</strong></span>
                </span>
                <span className="inline-flex items-center space-x-1.5 font-mono">
                  <GitBranch className="w-3.5 h-3.5 text-[#64748B]" />
                  <span>Branch: <strong className="font-semibold text-[#172435]">{branchDisplay}</strong></span>
                </span>
                <span className="inline-flex items-center space-x-1.5 font-mono">
                  <GitCommit className="w-3.5 h-3.5 text-[#64748B]" />
                  <span>Commit: <strong className="font-semibold text-[#172435]">{commitDisplay}</strong></span>
                </span>
                <span className="inline-flex items-center space-x-1.5 font-mono">
                  <Clock className="w-3.5 h-3.5 text-[#64748B]" />
                  <span>Evaluated: <strong className="font-semibold text-[#172435]">{evaluatedAtDisplay}</strong></span>
                </span>
              </div>
            </div>

            {/* Quick Demo Switcher (No Print) */}
            <div className="no-print flex flex-col items-start lg:items-end space-y-2">
              <span className="text-[11px] font-medium uppercase tracking-wider text-[#64748B]">
                Switch Assessment Dataset:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(SAMPLE_REPORTS).map(([key, item]) => (
                  <button
                    key={key}
                    onClick={() => setActiveReportKey(key)}
                    className={`text-xs px-2.5 py-1 rounded-md border font-medium transition-all cursor-pointer ${
                      activeReportKey === key
                        ? "bg-[#0F172A] text-white border-[#0F172A] shadow-2xs"
                        : "bg-white text-[#475569] border-[#E2E8F0] hover:bg-[#F8FAFC] hover:text-[#172435]"
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
                {customReport && (
                  <button
                    onClick={() => setActiveReportKey("custom")}
                    className={`text-xs px-2.5 py-1 rounded-md border font-medium transition-all cursor-pointer ${
                      activeReportKey === "custom"
                        ? "bg-[#0F172A] text-white border-[#0F172A]"
                        : "bg-white text-[#475569] border-[#E2E8F0] hover:bg-[#F8FAFC]"
                    }`}
                  >
                    {customFileName ? `Uploaded: ${customFileName.slice(0, 16)}...` : "Uploaded"}
                  </button>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Upload Error Banner */}
        {uploadError && (
          <div className="flex items-center justify-between p-3.5 rounded-lg border border-[#FECDCA] bg-[#FEF3F2] text-[#B42318] text-xs">
            <div className="flex items-center space-x-2">
              <AlertOctagon className="w-4 h-4 flex-shrink-0" />
              <span>{uploadError}</span>
            </div>
            <button
              onClick={() => setUploadError(null)}
              className="text-[#B42318] hover:underline font-mono text-[11px] ml-4 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Data Provenance Notice */}
        <div className="no-print">
          {isDemoActive ? (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between px-3.5 py-2.5 rounded-lg border border-[#FED7AA] bg-[#FFF7ED] text-[#9A3412] text-xs gap-2">
              <div className="flex items-center space-x-2">
                <span className="font-bold uppercase text-[10px] px-2 py-0.5 rounded bg-[#EA580C] text-white tracking-wider flex-shrink-0">
                  DEMONSTRATION DATA (MOCK)
                </span>
                <span className="font-medium">
                  Viewing static synthetic dataset for interface inspection. Not connected to an active GitHub CI workflow telemetry stream.
                </span>
              </div>
              <span className="text-[11px] font-mono text-[#C2410C] flex-shrink-0">
                Timestamp: {evaluatedAtDisplay}
              </span>
            </div>
          ) : (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between px-3.5 py-2.5 rounded-lg border border-[#A6F4C5] bg-[#ECFDF3] text-[#14532D] text-xs gap-2">
              <div className="flex items-center space-x-2">
                <span className="font-bold uppercase text-[10px] px-2 py-0.5 rounded bg-[#16A34A] text-white tracking-wider flex-shrink-0">
                  VALIDATED ARTIFACT
                </span>
                <span>
                  Viewing client-uploaded security report: <strong>{customFileName}</strong> (Schema validated)
                </span>
              </div>
              <span className="text-[11px] font-mono text-[#18794E] flex-shrink-0">
                Timestamp: {evaluatedAtDisplay}
              </span>
            </div>
          )}
        </div>

        {/* Gate Verdict Card (Hero) */}
        <section
          className={`bg-white rounded-xl border border-[#E2E8F0] border-l-4 ${decisionStyle.borderAccent} p-6 shadow-2xs space-y-4 print-page-break`}
        >
          <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <DecisionIcon className={`w-5 h-5 ${decisionStyle.iconColor}`} />
                <h2 className="text-lg font-bold text-[#172435] tracking-tight">
                  {decisionStyle.title}
                </h2>
                <span
                  className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border ${decisionStyle.badgeBg}`}
                >
                  {decisionStyle.badgeText}
                </span>
              </div>
              <p className="text-sm text-[#475569] leading-relaxed max-w-2xl">{decisionStyle.sub}</p>

              {/* Reasons list */}
              <div className="pt-2 space-y-1">
                {currentResult.reasons.map((reason, idx) => (
                  <div key={idx} className="flex items-start space-x-2 text-xs font-mono text-[#334155]">
                    <span className="mt-1 w-1.5 h-1.5 rounded-full bg-[#64748B] flex-shrink-0" />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Status Tag */}
            <div className="flex md:flex-col items-end justify-between md:justify-center border-t md:border-t-0 md:border-l border-[#E2E8F0] pt-3 md:pt-0 md:pl-6 text-right">
              <span className="text-[11px] uppercase tracking-wider font-medium text-[#64748B]">
                Verdict Decision
              </span>
              <span
                className={`text-base font-bold uppercase mt-0.5 ${
                  currentResult.decision === "BLOCK"
                    ? "text-[#B42318]"
                    : currentResult.decision === "PASS"
                    ? "text-[#18794E]"
                    : currentResult.decision === "WARN"
                    ? "text-[#A16207]"
                    : "text-[#991B1B]"
                }`}
              >
                {currentResult.decision}
              </span>
            </div>
          </div>
        </section>

        {/* 4 KPI Cards */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 print-page-break">
          <div className="bg-white rounded-xl border border-[#E2E8F0] p-4 shadow-2xs">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
              Total Findings
            </span>
            <div className="flex items-baseline justify-between mt-1.5">
              <span className="text-2xl font-bold text-[#172435]">
                {currentResult.summary.total_findings}
              </span>
              <span className="text-xs text-[#64748B]">Across all tools</span>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-[#E2E8F0] p-4 shadow-2xs">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#B42318]">
              Blocking Violations
            </span>
            <div className="flex items-baseline justify-between mt-1.5">
              <span className="text-2xl font-bold text-[#B42318]">
                {currentResult.summary.blocking_count}
              </span>
              <span className="text-xs text-[#B42318]">Policy threshold exceeded</span>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-[#E2E8F0] p-4 shadow-2xs">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#A16207]">
              Advisory Warnings
            </span>
            <div className="flex items-baseline justify-between mt-1.5">
              <span className="text-2xl font-bold text-[#A16207]">
                {currentResult.summary.warning_count}
              </span>
              <span className="text-xs text-[#A16207]">Non-blocking review</span>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-[#E2E8F0] p-4 shadow-2xs">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#18794E]">
              Exempted Findings
            </span>
            <div className="flex items-baseline justify-between mt-1.5">
              <span className="text-2xl font-bold text-[#18794E]">
                {currentResult.summary.exempted}
              </span>
              <span className="text-xs text-[#18794E]">Rule-based waivers</span>
            </div>
          </div>
        </section>

        {/* Scanner Execution Coverage & Severity Distribution Row */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-4 print-page-break">
          {/* Scanner Coverage (5 cols) */}
          <div className="lg:col-span-5 bg-white rounded-xl border border-[#E2E8F0] p-4 shadow-2xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-[#172435]">
                Scanner Execution Coverage
              </span>
              <span className="text-[11px] text-[#64748B]">Automated CI Tools</span>
            </div>

            <div className="space-y-2 pt-1">
              {currentResult.scanner_status && Object.keys(currentResult.scanner_status).length > 0 ? (
                Object.entries(currentResult.scanner_status).map(([scanner, status]) => {
                  let statusBadge = "bg-[#F1F5F9] text-[#475569] border-[#E2E8F0]";
                  let StatusIcon = Check;
                  if (status === "COMPLETED") {
                    statusBadge = "bg-[#ECFDF3] text-[#18794E] border-[#A6F4C5]";
                    StatusIcon = Check;
                  } else if (status === "DISABLED") {
                    statusBadge = "bg-[#F8FAFC] text-[#94A3B8] border-[#E2E8F0]";
                    StatusIcon = XCircle;
                  } else if (status === "NOT_APPLICABLE") {
                    statusBadge = "bg-[#EFF6FF] text-[#2563A6] border-[#BFDBFE]";
                    StatusIcon = Info;
                  } else if (status === "FAILED") {
                    statusBadge = "bg-[#FEF3F2] text-[#B42318] border-[#FECDCA]";
                    StatusIcon = AlertOctagon;
                  }

                  return (
                    <div
                      key={scanner}
                      className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono"
                    >
                      <span className="font-semibold text-[#172435]">{scanner}</span>
                      <span
                        className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${statusBadge}`}
                      >
                        <StatusIcon className="w-3 h-3" />
                        <span>{status}</span>
                      </span>
                    </div>
                  );
                })
              ) : (
                <p className="text-xs text-[#64748B]">No scanner metadata reported.</p>
              )}
            </div>
          </div>

          {/* Severity Breakdown (7 cols) */}
          <div className="lg:col-span-7 bg-white rounded-xl border border-[#E2E8F0] p-4 shadow-2xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-[#172435]">
                Severity Distribution Breakdown
              </span>
              <span className="text-[11px] text-[#64748B]">Normalized Spectrum</span>
            </div>

            <div className="grid grid-cols-5 gap-2 pt-1">
              <div className="p-2.5 rounded-lg bg-[#FEF3F2] border border-[#FECDCA] text-center">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[#B42318]">
                  Critical
                </span>
                <p className="text-xl font-bold text-[#B42318] mt-0.5">
                  {currentResult.summary.critical}
                </p>
              </div>

              <div className="p-2.5 rounded-lg bg-[#FFF7ED] border border-[#FED7AA] text-center">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[#C2410C]">
                  High
                </span>
                <p className="text-xl font-bold text-[#C2410C] mt-0.5">
                  {currentResult.summary.high}
                </p>
              </div>

              <div className="p-2.5 rounded-lg bg-[#FEFCE8] border border-[#FEF08A] text-center">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A16207]">
                  Medium
                </span>
                <p className="text-xl font-bold text-[#A16207] mt-0.5">
                  {currentResult.summary.medium}
                </p>
              </div>

              <div className="p-2.5 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] text-center">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[#2563A6]">
                  Low
                </span>
                <p className="text-xl font-bold text-[#2563A6] mt-0.5">
                  {currentResult.summary.low}
                </p>
              </div>

              <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                  Info
                </span>
                <p className="text-xl font-bold text-[#64748B] mt-0.5">
                  {currentResult.summary.info}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Section Navigation Tabs (No Print) */}
        <div className="no-print border-b border-[#E2E8F0] flex space-x-6">
          <button
            onClick={() => setActiveTab("findings")}
            className={`pb-3 text-sm font-semibold transition-colors flex items-center space-x-2 border-b-2 cursor-pointer ${
              activeTab === "findings"
                ? "border-[#0F172A] text-[#0F172A]"
                : "border-transparent text-[#64748B] hover:text-[#172435]"
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Finding Explorer ({filteredFindings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("policy")}
            className={`pb-3 text-sm font-semibold transition-colors flex items-center space-x-2 border-b-2 cursor-pointer ${
              activeTab === "policy"
                ? "border-[#0F172A] text-[#0F172A]"
                : "border-transparent text-[#64748B] hover:text-[#172435]"
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Security Policy Rules</span>
          </button>

          <button
            onClick={() => setActiveTab("architecture")}
            className={`pb-3 text-sm font-semibold transition-colors flex items-center space-x-2 border-b-2 cursor-pointer ${
              activeTab === "architecture"
                ? "border-[#0F172A] text-[#0F172A]"
                : "border-transparent text-[#64748B] hover:text-[#172435]"
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Pipeline Architecture</span>
          </button>
        </div>

        {/* TAB 1: FINDINGS EXPLORER */}
        {(activeTab === "findings" || typeof window === "undefined") && (
          <section className="space-y-4">
            {/* Filter & Search Toolbar (No Print) */}
            <div className="no-print bg-white rounded-xl border border-[#E2E8F0] p-3.5 shadow-2xs flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-[#94A3B8]" />
                <input
                  type="text"
                  placeholder="Search by CVE, rule ID, package, or path..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-1.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-md text-xs text-[#172435] placeholder-[#94A3B8] focus:outline-none focus:border-[#0F172A] transition-colors"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-medium text-[#64748B]">Severity:</span>
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`text-[11px] px-2 py-0.5 rounded border font-medium transition-colors cursor-pointer ${
                      severityFilter === sev
                        ? "bg-[#0F172A] text-white border-[#0F172A]"
                        : "bg-[#F8FAFC] text-[#475569] border-[#E2E8F0] hover:bg-[#F1F5F9]"
                    }`}
                  >
                    {sev}
                  </button>
                ))}

                <div className="h-4 w-[1px] bg-[#E2E8F0] mx-1" />

                <span className="text-[11px] font-medium text-[#64748B]">Scanner:</span>
                {["ALL", "trivy", "semgrep", "dependency_review"].map((sc) => (
                  <button
                    key={sc}
                    onClick={() => setScannerFilter(sc)}
                    className={`text-[11px] px-2 py-0.5 rounded border font-medium transition-colors cursor-pointer ${
                      scannerFilter === sc
                        ? "bg-[#0F172A] text-white border-[#0F172A]"
                        : "bg-[#F8FAFC] text-[#475569] border-[#E2E8F0] hover:bg-[#F1F5F9]"
                    }`}
                  >
                    {sc === "dependency_review" ? "dep_review" : sc}
                  </button>
                ))}
              </div>
            </div>

            {/* Findings Table */}
            {filteredFindings.length === 0 ? (
              <div className="bg-white rounded-xl border border-[#E2E8F0] p-12 text-center space-y-2 shadow-2xs">
                <CheckCircle2 className="w-8 h-8 text-[#18794E] mx-auto" />
                <h3 className="text-sm font-semibold text-[#172435]">
                  No Findings Matching Criteria
                </h3>
                <p className="text-xs text-[#64748B]">
                  Try clearing the search query or adjusting severity and scanner filters.
                </p>
                {(searchQuery || severityFilter !== "ALL" || scannerFilter !== "ALL") && (
                  <button
                    onClick={() => {
                      setSearchQuery("");
                      setSeverityFilter("ALL");
                      setScannerFilter("ALL");
                    }}
                    className="mt-2 text-xs font-medium text-[#0D9488] hover:underline cursor-pointer"
                  >
                    Reset all filters
                  </button>
                )}
              </div>
            ) : (
              <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden shadow-2xs print-page-break">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-[#64748B] font-semibold uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4 w-28">Severity</th>
                        <th className="py-3 px-4">Finding / Identifier</th>
                        <th className="py-3 px-4 w-28">Scanner</th>
                        <th className="py-3 px-4">Affected Target</th>
                        <th className="py-3 px-4 w-28 text-center">Gate Status</th>
                        <th className="py-3 px-4 w-16 text-right no-print">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#E2E8F0]">
                      {filteredFindings.map((finding) => {
                        const isExpanded = expandedFindingId === finding.id;
                        const isBlocking = finding.gateCategory === "blocking";

                        return (
                          <React.Fragment key={finding.id}>
                            <tr
                              onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                              className={`hover:bg-[#F8FAFC] transition-colors cursor-pointer select-none ${
                                isBlocking ? "bg-[#FEF3F2]/30" : ""
                              }`}
                            >
                              {/* Severity */}
                              <td className="py-3.5 px-4 align-top">
                                <span
                                  className={`inline-block font-mono text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${getSeverityBadge(
                                    finding.severity
                                  )}`}
                                >
                                  {finding.severity}
                                </span>
                              </td>

                              {/* Title & ID */}
                              <td className="py-3.5 px-4 align-top max-w-sm">
                                <div className="space-y-0.5">
                                  <span className="font-semibold text-[#172435] block leading-snug">
                                    {finding.title}
                                  </span>
                                  <span className="font-mono text-[11px] text-[#64748B] block truncate">
                                    {finding.id}
                                  </span>
                                </div>
                              </td>

                              {/* Scanner */}
                              <td className="py-3.5 px-4 align-top">
                                <span
                                  className={`inline-block font-mono text-[10px] px-2 py-0.5 rounded border ${getScannerBadge(
                                    finding.scanner
                                  )}`}
                                >
                                  {finding.scanner === "dependency_review"
                                    ? "dep_review"
                                    : finding.scanner}
                                </span>
                              </td>

                              {/* Affected Target */}
                              <td className="py-3.5 px-4 align-top">
                                <div className="space-y-0.5 font-mono text-[11px]">
                                  {finding.file_path && (
                                    <div className="flex items-center space-x-1 text-[#334155]">
                                      <FileText className="w-3 h-3 text-[#94A3B8] flex-shrink-0" />
                                      <span className="truncate">
                                        {finding.file_path}
                                        {finding.line_number ? `:${finding.line_number}` : ""}
                                      </span>
                                    </div>
                                  )}
                                  {finding.package_name && (
                                    <div className="text-[#0D9488]">
                                      pkg: {finding.package_name}
                                      {finding.installed_version &&
                                        ` (${finding.installed_version})`}
                                    </div>
                                  )}
                                </div>
                              </td>

                              {/* Gate Status */}
                              <td className="py-3.5 px-4 align-top text-center">
                                <span
                                  className={`inline-block font-mono text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${getGateCategoryBadge(
                                    finding.gateCategory
                                  )}`}
                                >
                                  {finding.gateCategory}
                                </span>
                              </td>

                              {/* Expand Chevron (No Print) */}
                              <td className="py-3.5 px-4 align-top text-right no-print">
                                {isExpanded ? (
                                  <ChevronUp className="w-4 h-4 text-[#64748B] inline" />
                                ) : (
                                  <ChevronDown className="w-4 h-4 text-[#94A3B8] inline" />
                                )}
                              </td>
                            </tr>

                            {/* Expanded Technical Details Drawer */}
                            {(isExpanded || (typeof window !== "undefined" && window.matchMedia?.("print").matches)) && (
                              <tr className="bg-[#F8FAFC] border-t border-[#E2E8F0]">
                                <td colSpan={6} className="p-4 space-y-3">
                                  <div>
                                    <span className="text-[10px] uppercase font-semibold tracking-wider text-[#64748B]">
                                      Vulnerability Description
                                    </span>
                                    <p className="mt-1 text-xs text-[#334155] leading-relaxed">
                                      {finding.description}
                                    </p>
                                  </div>

                                  {finding.remediation && (
                                    <div className="p-3 rounded-lg bg-[#ECFDF3] border border-[#A6F4C5] space-y-1">
                                      <span className="text-[10px] font-bold uppercase tracking-wider text-[#18794E] flex items-center space-x-1">
                                        <CheckCircle2 className="w-3.5 h-3.5" />
                                        <span>Remediation Recommendation</span>
                                      </span>
                                      <p className="text-xs text-[#14532D] font-mono leading-relaxed">
                                        {finding.remediation}
                                      </p>
                                    </div>
                                  )}

                                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1 text-xs">
                                    {finding.fixed_version && (
                                      <div className="p-2 rounded bg-white border border-[#E2E8F0]">
                                        <span className="text-[10px] font-semibold uppercase text-[#64748B]">
                                          Fixed Version
                                        </span>
                                        <p className="font-mono text-[#172435] mt-0.5">
                                          {finding.fixed_version}
                                        </p>
                                      </div>
                                    )}

                                    {finding.installed_version && (
                                      <div className="p-2 rounded bg-white border border-[#E2E8F0]">
                                        <span className="text-[10px] font-semibold uppercase text-[#64748B]">
                                          Installed Version
                                        </span>
                                        <p className="font-mono text-[#172435] mt-0.5">
                                          {finding.installed_version}
                                        </p>
                                      </div>
                                    )}

                                    {finding.cwe_ids && finding.cwe_ids.length > 0 && (
                                      <div className="p-2 rounded bg-white border border-[#E2E8F0] col-span-1 sm:col-span-2 lg:col-span-1">
                                        <span className="text-[10px] font-semibold uppercase text-[#64748B]">
                                          CWE Identifiers
                                        </span>
                                        <div className="flex flex-wrap gap-1 mt-0.5">
                                          {finding.cwe_ids.map((cwe) => (
                                            <span
                                              key={cwe}
                                              className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#F1F5F9] text-[#334155] border border-[#E2E8F0]"
                                            >
                                              {cwe}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        )}

        {/* TAB 2: SECURITY POLICY RULES */}
        {activeTab === "policy" && (
          <section className="space-y-6">
            <div className="bg-white rounded-xl border border-[#E2E8F0] p-6 shadow-2xs space-y-4">
              <div className="flex items-center space-x-2">
                <Lock className="w-5 h-5 text-[#0F172A]" />
                <h3 className="text-base font-bold text-[#172435]">
                  Repository Security Policy Rules
                </h3>
              </div>
              <p className="text-xs text-[#64748B]">
                Enforced declaratively from <code className="text-[#0D9488]">config/policy.yaml</code> across all pull requests and branch merges.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
                {/* Severity Enforcement Table */}
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[#64748B]">
                    Severity Threshold Enforcement
                  </h4>
                  <div className="border border-[#E2E8F0] rounded-lg overflow-hidden">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-[11px] uppercase font-semibold text-[#64748B]">
                        <tr>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Enforcement Action</th>
                          <th className="py-2.5 px-3">CI Exit Code</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#E2E8F0] font-mono">
                        <tr className="bg-[#FEF3F2]/40">
                          <td className="py-2 px-3 font-bold text-[#B42318]">CRITICAL</td>
                          <td className="py-2 px-3 text-[#B42318] font-semibold">BLOCK</td>
                          <td className="py-2 px-3 text-[#64748B]">Exit 1</td>
                        </tr>
                        <tr className="bg-[#FFF7ED]/40">
                          <td className="py-2 px-3 font-bold text-[#C2410C]">HIGH</td>
                          <td className="py-2 px-3 text-[#C2410C] font-semibold">BLOCK</td>
                          <td className="py-2 px-3 text-[#64748B]">Exit 1</td>
                        </tr>
                        <tr className="bg-[#FEFCE8]/40">
                          <td className="py-2 px-3 font-bold text-[#A16207]">MEDIUM</td>
                          <td className="py-2 px-3 text-[#A16207] font-semibold">WARN</td>
                          <td className="py-2 px-3 text-[#64748B]">Exit 0</td>
                        </tr>
                        <tr>
                          <td className="py-2 px-3 font-bold text-[#2563A6]">LOW</td>
                          <td className="py-2 px-3 text-[#18794E] font-semibold">PASS</td>
                          <td className="py-2 px-3 text-[#64748B]">Exit 0</td>
                        </tr>
                        <tr>
                          <td className="py-2 px-3 font-bold text-[#64748B]">INFO</td>
                          <td className="py-2 px-3 text-[#18794E] font-semibold">PASS</td>
                          <td className="py-2 px-3 text-[#64748B]">Exit 0</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Scanner Configuration Rules */}
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[#64748B]">
                    Multi-Scanner Configuration
                  </h4>
                  <div className="space-y-2.5 text-xs">
                    <div className="p-3 rounded-lg border border-[#E2E8F0] bg-[#F8FAFC]">
                      <span className="font-semibold text-[#0D9488]">Trivy Vulnerabilities & Misconfigs</span>
                      <p className="text-[#64748B] mt-0.5">
                        Scans file systems, locks, and manifests for CVEs, configuration flaws, and secrets.
                      </p>
                    </div>
                    <div className="p-3 rounded-lg border border-[#E2E8F0] bg-[#F8FAFC]">
                      <span className="font-semibold text-[#7C3AED]">Semgrep SAST Rulesets</span>
                      <p className="text-[#64748B] mt-0.5">
                        Applies OWASP Top 10, security-audit, and secrets detection without broad script exemptions.
                      </p>
                    </div>
                    <div className="p-3 rounded-lg border border-[#E2E8F0] bg-[#F8FAFC]">
                      <span className="font-semibold text-[#16A34A]">GitHub Dependency Review</span>
                      <p className="text-[#64748B] mt-0.5">
                        Denies copyleft licenses (GPL-3.0, AGPL-3.0) and blocks newly introduced vulnerable packages.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* TAB 3: PIPELINE ARCHITECTURE */}
        {activeTab === "architecture" && (
          <section className="space-y-6">
            <div className="bg-white rounded-xl border border-[#E2E8F0] p-6 shadow-2xs space-y-4">
              <div className="flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-[#0F172A]" />
                <h3 className="text-base font-bold text-[#172435]">
                  Automated DevSecOps Gatekeeper Architecture
                </h3>
              </div>
              <p className="text-xs text-[#64748B]">
                Fail-closed lifecycle orchestrating multi-scanner telemetry into authoritative gate decisions.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
                <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-2">
                  <span className="text-[11px] font-mono font-bold text-[#0D9488]">Phase 01</span>
                  <h4 className="font-bold text-xs text-[#172435]">Pull Request Trigger</h4>
                  <p className="text-xs text-[#64748B] leading-relaxed">
                    Developer pushes changes or opens PR. GitHub Actions initiates parallel scanner jobs.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-2">
                  <span className="text-[11px] font-mono font-bold text-[#7C3AED]">Phase 02</span>
                  <h4 className="font-bold text-xs text-[#172435]">Multi-Scanner Execution</h4>
                  <p className="text-xs text-[#64748B] leading-relaxed">
                    Trivy, Semgrep, and Dependency Review generate heterogeneous raw JSON security outputs.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-2">
                  <span className="text-[11px] font-mono font-bold text-[#2563A6]">Phase 03</span>
                  <h4 className="font-bold text-xs text-[#172435]">Policy Normalization</h4>
                  <p className="text-xs text-[#64748B] leading-relaxed">
                    Python policy engine ingests and normalizes raw reports into strongly typed Finding models.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-2">
                  <span className="text-[11px] font-mono font-bold text-[#B42318]">Phase 04</span>
                  <h4 className="font-bold text-xs text-[#172435]">Gate Verdict Enforcement</h4>
                  <p className="text-xs text-[#64748B] leading-relaxed">
                    Outputs PASS (0), WARN (0), BLOCK (1), or ERROR (2). Fails CI closed on violations or scanner errors.
                  </p>
                </div>
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="no-print border-t border-[#E2E8F0] bg-white py-5 mt-10">
        <div className="max-w-[1280px] mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between text-xs text-[#64748B] gap-4">
          <p>© 2026 PipelineShield. Released under the MIT License.</p>
          <div className="flex items-center space-x-4 font-mono text-[11px]">
            <span>Next.js App Router</span>
            <span>•</span>
            <span>Python Policy Engine</span>
            <span>•</span>
            <span>Zero Paid Infrastructure</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
