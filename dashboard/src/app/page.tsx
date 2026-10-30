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
  ChevronRight,
  RefreshCw,
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

// Sample reports for demonstration
const SAMPLE_REPORTS: Record<string, { label: string; tag: string; isDemo: boolean; data: EvaluationResult }> = {
  vulnerable: {
    label: "Demo 1: Vulnerable PR (Mock Data)",
    tag: "BLOCKED (Exit 1)",
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
          description: "Regular Expression Denial of Service in cryptography X.509 certificate parsing.",
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
          description: "Detected subprocess call with shell=True or dynamic untrusted command arguments.",
          severity: "HIGH",
          file_path: "engine/src/pipelineshield/runner.py",
          line_number: 142,
          cwe_ids: ["CWE-78", "CWE-88"],
          remediation: "Pass command arguments as a list with shell=False and sanitize parameters.",
        },
        {
          id: "GHSA-35jh-r3h4-6jhm",
          scanner: "dependency_review",
          title: "Prototype Pollution in lodash",
          description: "Deep clone utility functions in lodash prior to 4.17.21 allow object prototype tampering.",
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
          remediation: "Update word-wrap dependency.",
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
        mode: "strict",
      },
    },
  },
  warnings_only: {
    label: "Demo 3: Advisory Warnings (Mock Data)",
    tag: "WARN (Exit 0)",
    isDemo: true,
    data: {
      decision: "WARN",
      reasons: [
        "1 MEDIUM finding(s) meet WARN threshold",
      ],
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
        mode: "strict",
      },
    },
  },
  clean: {
    label: "Demo 2: Clean Baseline (Mock Data)",
    tag: "PASSED (Exit 0)",
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
        mode: "strict",
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

    // Fallback if 'findings' is not populated (e.g. older format)
    const list: ProcessedFinding[] = [];
    (currentResult.blocking_findings || []).forEach((f) => list.push({ ...f, gateCategory: "blocking" }));
    (currentResult.warning_findings || []).forEach((f) => list.push({ ...f, gateCategory: "warning" }));
    (currentResult.advisory_findings || []).forEach((f) => list.push({ ...f, gateCategory: "advisory" }));
    (currentResult.exempted_findings || []).forEach((f) => list.push({ ...f, gateCategory: "exempted" }));
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
          blocking_findings: Array.isArray(parsed.blocking_findings) ? parsed.blocking_findings : [],
          warning_findings: Array.isArray(parsed.warning_findings) ? parsed.warning_findings : [],
          advisory_findings: Array.isArray(parsed.advisory_findings) ? parsed.advisory_findings : [],
          exempted_findings: Array.isArray(parsed.exempted_findings) ? parsed.exempted_findings : [],
          evaluated_at: parsed.evaluated_at || new Date().toISOString(),
          policy_metadata: parsed.policy_metadata || {},
        };

        setCustomReport(normalized);
        setCustomFileName(file.name);
        setActiveReportKey("custom");
      } catch (err) {
        setUploadError(`Failed to parse JSON file: ${err instanceof Error ? err.message : String(err)}`);
      }
    };
    reader.readAsText(file);
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case "BLOCK":
        return {
          icon: ShieldAlert,
          text: "BLOCKED (Exit 1)",
          sub: "PR gatekeeper failed: critical/high vulnerabilities violated policy",
          bg: "bg-rose-500/10 border-rose-500/30 text-rose-400",
          glow: "shadow-rose-500/20",
          cardBg: "from-rose-950/40 via-slate-900/60 to-slate-950 border-rose-500/30",
        };
      case "WARN":
        return {
          icon: AlertTriangle,
          text: "PASSED WITH WARNINGS (Exit 0)",
          sub: "PR gatekeeper passed: advisory findings noted for review",
          bg: "bg-amber-500/10 border-amber-500/30 text-amber-400",
          glow: "shadow-amber-500/20",
          cardBg: "from-amber-950/40 via-slate-900/60 to-slate-950 border-amber-500/30",
        };
      case "PASS":
        return {
          icon: ShieldCheck,
          text: "PASSED (Exit 0)",
          sub: "PR gatekeeper passed: zero blocking violations detected",
          bg: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
          glow: "shadow-emerald-500/20",
          cardBg: "from-emerald-950/40 via-slate-900/60 to-slate-950 border-emerald-500/30",
        };
      default:
        return {
          icon: AlertOctagon,
          text: "ENGINE ERROR (Exit 2)",
          sub: "Execution fault or configuration error encountered",
          bg: "bg-red-500/10 border-red-500/30 text-red-400",
          glow: "shadow-red-500/20",
          cardBg: "from-red-950/40 via-slate-900/60 to-slate-950 border-red-500/30",
        };
    }
  };

  const decisionMeta = getDecisionBadge(currentResult.decision);
  const DecisionIcon = decisionMeta.icon;

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-rose-500/15 text-rose-300 border-rose-500/30";
      case "HIGH":
        return "bg-orange-500/15 text-orange-300 border-orange-500/30";
      case "MEDIUM":
        return "bg-amber-500/15 text-amber-300 border-amber-500/30";
      case "LOW":
        return "bg-blue-500/15 text-blue-300 border-blue-500/30";
      default:
        return "bg-slate-500/15 text-slate-300 border-slate-500/30";
    }
  };

  const getScannerBadge = (scanner: string) => {
    switch (scanner) {
      case "trivy":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
      case "semgrep":
        return "bg-purple-500/10 text-purple-400 border-purple-500/20";
      case "dependency_review":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      default:
        return "bg-slate-500/10 text-slate-400 border-slate-500/20";
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 text-slate-950 shadow-lg shadow-emerald-500/20">
              <Shield className="w-5 h-5 stroke-[2.5]" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                PipelineShield
              </span>
              <span className="ml-2 text-xs font-mono uppercase px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Gatekeeper v0.1.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <label className="cursor-pointer inline-flex items-center space-x-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-1.5 transition-colors">
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span>Load Report JSON</span>
              <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
            </label>

            <a
              href="https://github.com/RishvinReddy/PipelineShield"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center space-x-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-1.5 transition-colors"
            >
              <span>GitHub</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Report Selector Banner */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <RefreshCw className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Active Security Report:
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {Object.entries(SAMPLE_REPORTS).map(([key, item]) => (
              <button
                key={key}
                onClick={() => setActiveReportKey(key)}
                className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-all ${
                  activeReportKey === key
                    ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/40 shadow-sm shadow-cyan-500/20"
                    : "bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700"
                }`}
              >
                {item.label}
              </button>
            ))}

            {customReport && (
              <button
                onClick={() => setActiveReportKey("custom")}
                className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-all ${
                  activeReportKey === "custom"
                    ? "bg-purple-500/10 text-purple-300 border-purple-500/40"
                    : "bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                {customFileName ? `Uploaded: ${customFileName}` : "Custom Upload"}
              </button>
            )}
          </div>
        </div>

        {/* Upload Error Banner */}
        {uploadError && (
          <div className="flex items-center justify-between p-3.5 rounded-xl border border-rose-500/40 bg-rose-950/30 text-rose-300 text-xs">
            <div className="flex items-center space-x-2">
              <AlertOctagon className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span>{uploadError}</span>
            </div>
            <button
              onClick={() => setUploadError(null)}
              className="text-rose-400 hover:text-white font-mono text-[11px] underline ml-4"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Data Provenance Indicator */}
        {isDemoActive ? (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 rounded-xl border border-cyan-500/30 bg-cyan-950/20 text-cyan-300 text-xs gap-2">
            <div className="flex items-center space-x-2">
              <span className="font-semibold uppercase px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-200 text-[10px] tracking-wide">
                Demonstration Mode
              </span>
              <span>Viewing static mock dataset for illustration. Not connected to a live CI telemetry stream.</span>
            </div>
            <span className="text-[11px] text-cyan-400/80 font-mono">
              Evaluated at: {currentResult.evaluated_at || "Demonstration run"}
            </span>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 rounded-xl border border-purple-500/30 bg-purple-950/20 text-purple-300 text-xs gap-2">
            <div className="flex items-center space-x-2">
              <span className="font-semibold uppercase px-2 py-0.5 rounded bg-purple-500/20 text-purple-200 text-[10px] tracking-wide">
                Uploaded Report
              </span>
              <span>Viewing user-uploaded artifact: <strong className="text-white">{customFileName}</strong></span>
            </div>
            <span className="text-[11px] text-purple-400/80 font-mono">
              Evaluated at: {currentResult.evaluated_at || "Recent run"}
            </span>
          </div>
        )}

        {/* Gate Decision Hero Card */}
        <section
          className={`relative overflow-hidden rounded-2xl border p-8 bg-gradient-to-br ${decisionMeta.cardBg} shadow-2xl transition-all duration-300`}
        >
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="space-y-3 max-w-2xl">
              <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-semibold border uppercase tracking-wider">
                <DecisionIcon className="w-4 h-4" />
                <span>{decisionMeta.text}</span>
              </div>

              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
                DevSecOps Security Gate Verdict
              </h1>

              <p className="text-sm text-slate-300/90 leading-relaxed">
                {decisionMeta.sub}
              </p>

              {/* Policy Reasons */}
              <div className="space-y-1.5 pt-2">
                {currentResult.reasons.map((reason, idx) => (
                  <div key={idx} className="flex items-center space-x-2 text-xs font-mono text-slate-300">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Metrics Stack */}
            <div className="grid grid-cols-2 gap-3 w-full md:w-auto">
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 min-w-[130px]">
                <span className="text-[11px] uppercase font-semibold text-slate-400 tracking-wider">
                  Total Findings
                </span>
                <p className="text-2xl font-black text-white mt-1">
                  {currentResult.summary.total_findings}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 min-w-[130px]">
                <span className="text-[11px] uppercase font-semibold text-rose-400 tracking-wider">
                  Blocking Violations
                </span>
                <p className="text-2xl font-black text-rose-400 mt-1">
                  {currentResult.summary.blocking_count}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 min-w-[130px]">
                <span className="text-[11px] uppercase font-semibold text-amber-400 tracking-wider">
                  Warnings
                </span>
                <p className="text-2xl font-black text-amber-400 mt-1">
                  {currentResult.summary.warning_count}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 min-w-[130px]">
                <span className="text-[11px] uppercase font-semibold text-emerald-400 tracking-wider">
                  Exempted
                </span>
                <p className="text-2xl font-black text-emerald-400 mt-1">
                  {currentResult.summary.exempted}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Scanner Execution Coverage */}
        {currentResult.scanner_status && Object.keys(currentResult.scanner_status).length > 0 && (
          <section className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
              Scanner Execution Coverage
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {Object.entries(currentResult.scanner_status).map(([scanner, status]) => {
                let badgeClass = "bg-slate-800 text-slate-300 border-slate-700";
                if (status === "COMPLETED") {
                  badgeClass = "bg-emerald-950/50 text-emerald-300 border-emerald-500/40";
                } else if (status === "DISABLED") {
                  badgeClass = "bg-slate-900 text-slate-400 border-slate-800";
                } else if (status === "NOT_APPLICABLE") {
                  badgeClass = "bg-blue-950/50 text-blue-300 border-blue-500/40";
                } else if (status === "FAILED") {
                  badgeClass = "bg-rose-950/50 text-rose-300 border-rose-500/40";
                }
                return (
                  <div
                    key={scanner}
                    className={`inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono border ${badgeClass}`}
                  >
                    <span className="font-semibold">{scanner}:</span>
                    <span>{status}</span>
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* Severity Distribution Bar */}
        <section className="p-6 rounded-xl border border-slate-800/80 bg-slate-900/40 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
              Severity Distribution Breakdown
            </h2>
            <span className="text-xs text-slate-500 font-mono">
              Evaluated at: {currentResult.evaluated_at || "Recent CI Run"}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-rose-500/20">
              <span className="text-xs font-semibold text-rose-400">CRITICAL</span>
              <p className="text-xl font-bold text-white mt-0.5">{currentResult.summary.critical}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-orange-500/20">
              <span className="text-xs font-semibold text-orange-400">HIGH</span>
              <p className="text-xl font-bold text-white mt-0.5">{currentResult.summary.high}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-amber-500/20">
              <span className="text-xs font-semibold text-amber-400">MEDIUM</span>
              <p className="text-xl font-bold text-white mt-0.5">{currentResult.summary.medium}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-blue-500/20">
              <span className="text-xs font-semibold text-blue-400">LOW</span>
              <p className="text-xl font-bold text-white mt-0.5">{currentResult.summary.low}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-500/20">
              <span className="text-xs font-semibold text-slate-400">INFO</span>
              <p className="text-xl font-bold text-white mt-0.5">{currentResult.summary.info}</p>
            </div>
          </div>
        </section>

        {/* Navigation Tabs */}
        <div className="border-b border-slate-800 flex space-x-6">
          <button
            onClick={() => setActiveTab("findings")}
            className={`pb-3 text-sm font-semibold transition-colors flex items-center space-x-2 border-b-2 ${
              activeTab === "findings"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Finding Explorer ({filteredFindings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("policy")}
            className={`pb-3 text-sm font-semibold transition-colors flex items-center space-x-2 border-b-2 ${
              activeTab === "policy"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Security Policy Rules</span>
          </button>

          <button
            onClick={() => setActiveTab("architecture")}
            className={`pb-3 text-sm font-semibold transition-colors flex items-center space-x-2 border-b-2 ${
              activeTab === "architecture"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Pipeline Architecture</span>
          </button>
        </div>

        {/* Tab Content: Findings */}
        {activeTab === "findings" && (
          <div className="space-y-6">
            {/* Search and Filters */}
            <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center justify-between">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search by CVE, rule ID, package, or path..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-slate-900/60 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-colors"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center space-x-1 text-xs text-slate-400 mr-2">
                  <span>Severity:</span>
                </div>
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`text-xs px-2.5 py-1 rounded-md border font-medium transition-colors ${
                      severityFilter === sev
                        ? "bg-slate-700 text-white border-slate-600"
                        : "bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-300"
                    }`}
                  >
                    {sev}
                  </button>
                ))}

                <div className="h-4 w-[1px] bg-slate-800 mx-2" />

                <div className="flex items-center space-x-1 text-xs text-slate-400 mr-2">
                  <span>Scanner:</span>
                </div>
                {["ALL", "trivy", "semgrep", "dependency_review"].map((sc) => (
                  <button
                    key={sc}
                    onClick={() => setScannerFilter(sc)}
                    className={`text-xs px-2.5 py-1 rounded-md border font-medium transition-colors ${
                      scannerFilter === sc
                        ? "bg-slate-700 text-white border-slate-600"
                        : "bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-300"
                    }`}
                  >
                    {sc === "dependency_review" ? "dep_review" : sc}
                  </button>
                ))}
              </div>
            </div>

            {/* Findings List */}
            {filteredFindings.length === 0 ? (
              <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl space-y-3">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <h3 className="text-base font-semibold text-white">No Findings Matching Query</h3>
                <p className="text-xs text-slate-400">
                  Try adjusting the severity filter or clearing the search keyword.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding) => {
                  const isExpanded = expandedFindingId === finding.id;
                  const isBlocking = finding.gateCategory === "blocking";

                  return (
                    <div
                      key={finding.id}
                      className={`rounded-xl border transition-all ${
                        isBlocking
                          ? "border-rose-500/30 bg-slate-900/50 hover:border-rose-500/50"
                          : "border-slate-800/80 bg-slate-900/30 hover:border-slate-700"
                      }`}
                    >
                      <div
                        onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                        className="p-4 sm:p-5 flex items-start justify-between cursor-pointer select-none"
                      >
                        <div className="space-y-2 max-w-3xl">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`text-[11px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${getSeverityBadge(
                                finding.severity
                              )}`}
                            >
                              {finding.severity}
                            </span>

                            <span
                              className={`text-[11px] font-mono px-2 py-0.5 rounded border ${getScannerBadge(
                                finding.scanner
                              )}`}
                            >
                              {finding.scanner}
                            </span>

                            {isBlocking && (
                              <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 font-semibold">
                                BLOCKING
                              </span>
                            )}

                            <span className="text-xs font-mono text-slate-400">
                              {finding.id}
                            </span>
                          </div>

                          <h3 className="text-sm font-semibold text-white leading-snug">
                            {finding.title}
                          </h3>

                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
                            {finding.file_path && (
                              <span className="inline-flex items-center space-x-1 font-mono text-slate-300">
                                <FileText className="w-3.5 h-3.5 text-slate-500" />
                                <span>{finding.file_path}</span>
                                {finding.line_number && <span>:{finding.line_number}</span>}
                              </span>
                            )}

                            {finding.package_name && (
                              <span className="font-mono text-cyan-400">
                                pkg: {finding.package_name}
                                {finding.installed_version && ` (${finding.installed_version})`}
                              </span>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center space-x-2 text-slate-500">
                          <ChevronRight
                            className={`w-5 h-5 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                          />
                        </div>
                      </div>

                      {/* Expanded Details Drawer */}
                      {isExpanded && (
                        <div className="px-5 pb-5 pt-2 border-t border-slate-800/60 bg-slate-950/40 rounded-b-xl space-y-4 text-xs">
                          <div>
                            <span className="text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
                              Description
                            </span>
                            <p className="mt-1 text-slate-300 leading-relaxed">
                              {finding.description}
                            </p>
                          </div>

                          {finding.remediation && (
                            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 space-y-1">
                              <span className="text-emerald-400 font-semibold uppercase text-[10px] tracking-wider flex items-center space-x-1">
                                <CheckCircle2 className="w-3 h-3" />
                                <span>Remediation Recommendation</span>
                              </span>
                              <p className="text-emerald-200/90 font-mono">
                                {finding.remediation}
                              </p>
                            </div>
                          )}

                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                            {finding.fixed_version && (
                              <div>
                                <span className="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                                  Fixed Version
                                </span>
                                <p className="mt-1 font-mono text-slate-200">
                                  {finding.fixed_version}
                                </p>
                              </div>
                            )}

                            {finding.cwe_ids && finding.cwe_ids.length > 0 && (
                              <div>
                                <span className="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                                  CWE Identifiers
                                </span>
                                <div className="mt-1 flex flex-wrap gap-1.5">
                                  {finding.cwe_ids.map((cwe: string) => (
                                    <span
                                      key={cwe}
                                      className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px]"
                                    >
                                      {cwe}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Tab Content: Policy */}
        {activeTab === "policy" && (
          <div className="space-y-6">
            <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
              <div className="flex items-center space-x-2">
                <Lock className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Declarative Policy Configuration</h3>
              </div>
              <p className="text-xs text-slate-400">
                Loaded directly from <code className="text-cyan-400">config/policy.yaml</code> in the repository root.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
                <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Severity Threshold Enforcement
                  </h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300">
                      <span>CRITICAL</span>
                      <span className="font-bold">BLOCK</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-orange-500/10 border border-orange-500/20 text-orange-300">
                      <span>HIGH</span>
                      <span className="font-bold">BLOCK</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300">
                      <span>MEDIUM</span>
                      <span className="font-bold">WARN</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-blue-500/10 border border-blue-500/20 text-blue-300">
                      <span>LOW</span>
                      <span className="font-bold">PASS</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-800/40 border border-slate-700/40 text-slate-300">
                      <span>INFO</span>
                      <span className="font-bold">PASS</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Scanner Integration Rules
                  </h4>
                  <div className="space-y-2 text-xs">
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                      <span className="font-semibold text-cyan-400">Trivy Vulnerabilities</span>
                      <p className="text-slate-400 mt-0.5">Scans fs, container images, and package locks. Fails on CRITICAL and HIGH CVEs.</p>
                    </div>
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                      <span className="font-semibold text-purple-400">Semgrep SAST Rulesets</span>
                      <p className="text-slate-400 mt-0.5">Enforces OWASP Top 10, security audit patterns, and hardcoded secret detection.</p>
                    </div>
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                      <span className="font-semibold text-emerald-400">Dependency Review</span>
                      <p className="text-slate-400 mt-0.5">Denies GPL-3.0/AGPL-3.0 copyleft licenses and blocks high/critical vulnerable additions.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab Content: Architecture */}
        {activeTab === "architecture" && (
          <div className="space-y-6">
            <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
              <div className="flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Automated DevSecOps Gatekeeper Lifecycle</h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                  <span className="text-xs font-mono text-emerald-400">Phase 01</span>
                  <h4 className="font-semibold text-sm text-white">Pull Request Trigger</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Developer pushes changes. GitHub Actions workflow launches parallel security scanner jobs.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                  <span className="text-xs font-mono text-cyan-400">Phase 02</span>
                  <h4 className="font-semibold text-sm text-white">Multi-Scanner Execution</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Trivy scans dependencies, Semgrep analyzes source code patterns, and Dependency Review validates package licenses.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                  <span className="text-xs font-mono text-purple-400">Phase 03</span>
                  <h4 className="font-semibold text-sm text-white">Policy Normalization</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Heterogeneous scanner JSONs are ingested into normalized Finding objects with strict validation.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                  <span className="text-xs font-mono text-rose-400">Phase 04</span>
                  <h4 className="font-semibold text-sm text-white">Security Gate Verdict</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    PolicyEngine outputs PASS (0), WARN (0), or BLOCK (1). Exit code 1 fails CI and blocks PR merge.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
          <p>© 2026 PipelineShield. Released under the MIT License.</p>
          <div className="flex items-center space-x-6">
            <span>Next.js App Router</span>
            <span>Python Policy Engine</span>
            <span>Zero Paid Infrastructure</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
