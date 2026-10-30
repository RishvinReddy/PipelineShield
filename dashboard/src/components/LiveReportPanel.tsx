"use client";

import React from "react";
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  RotateCw,
  ExternalLink,
  GitBranch,
  GitCommit,
  Clock,
  ShieldCheck,
  ShieldAlert,
  Radio,
} from "lucide-react";

export interface LiveReportData {
  decision?: string;
  reasons?: string[];
  summary?: {
    total_findings?: number;
    blocking_count?: number;
    warning_count?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
    exempted?: number;
  };
  scanner_status?: Record<string, string>;
  policy_metadata?: Record<string, string>;
  evaluated_at?: string;
  findings?: unknown[];
  blocking_findings?: unknown[];
  warning_findings?: unknown[];
  exempted_findings?: unknown[];
  advisory_findings?: unknown[];
}

export interface LiveReportResponse {
  success: boolean;
  error?: string;
  report?: LiveReportData;
  run?: {
    id: number;
    name: string;
    status: string;
    conclusion: string | null;
    html_url: string;
    head_sha: string;
    head_branch: string;
    event: string;
    created_at: string;
    updated_at: string;
  };
  artifact?: {
    id?: number;
    name: string;
    size_in_bytes?: number;
    expired: boolean;
    created_at?: string;
  };
  fetched_at?: string;
}

interface LiveReportPanelProps {
  liveData: LiveReportResponse | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onLoadLiveReport: (report: LiveReportData) => void;
  isLiveActive: boolean;
  activeSourceLabel: string;
}

export function LiveReportPanel({
  liveData,
  loading,
  error,
  onRefresh,
  onLoadLiveReport,
  isLiveActive,
  activeSourceLabel,
}: LiveReportPanelProps) {
  const run = liveData?.run;
  const report = liveData?.report;
  const decision = report?.decision?.toUpperCase();

  const getDecisionBadge = (dec?: string) => {
    switch (dec) {
      case "PASS":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <CheckCircle2 className="w-3.5 h-3.5" />
            PASS
          </span>
        );
      case "WARN":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            <AlertTriangle className="w-3.5 h-3.5" />
            WARN
          </span>
        );
      case "BLOCK":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
            <XCircle className="w-3.5 h-3.5" />
            BLOCK
          </span>
        );
      case "ERROR":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-100 text-red-900 border border-red-300">
            <ShieldAlert className="w-3.5 h-3.5" />
            ERROR
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
            <HelpCircle className="w-3.5 h-3.5" />
            PENDING
          </span>
        );
    }
  };

  const getScannerPill = (name: string, status?: string) => {
    const s = String(status || "UNKNOWN").toUpperCase();
    let badgeClass = "bg-slate-100 text-slate-600 border-slate-200";
    let icon = "⚪";

    if (s === "COMPLETED") {
      badgeClass = "bg-emerald-50 text-emerald-800 border-emerald-200";
      icon = "🟢";
    } else if (s === "FAILED") {
      badgeClass = "bg-rose-50 text-rose-800 border-rose-200";
      icon = "🔴";
    } else if (s === "NOT_APPLICABLE") {
      badgeClass = "bg-sky-50 text-sky-800 border-sky-200";
      icon = "🔵";
    } else if (s === "DISABLED") {
      badgeClass = "bg-slate-50 text-slate-500 border-slate-200";
      icon = "⚪";
    }

    return (
      <div
        key={name}
        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono border ${badgeClass}`}
      >
        <span>{icon}</span>
        <span className="font-semibold">{name}:</span>
        <span>{s}</span>
      </div>
    );
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden mb-6">
      {/* Top Bar Header */}
      <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center w-7 h-7 rounded-md bg-blue-50 border border-blue-200 text-blue-700">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-900 tracking-tight">
                Live GitHub Actions CI Telemetry
              </h2>
              {isLiveActive ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-100 text-emerald-800 border border-emerald-200">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 animate-ping" />
                  Active In Dashboard
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
                  Viewing: {activeSourceLabel}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Automated ingestion from GitHub Actions artifact{" "}
              <code className="text-slate-700 bg-slate-200/60 px-1 py-0.5 rounded">
                security-summary-reports
              </code>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 transition-colors"
            title="Query GitHub Actions for newest completed run"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Checking CI..." : "Refresh"}
          </button>

          {report && !isLiveActive && (
            <button
              type="button"
              onClick={() => onLoadLiveReport(report)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 rounded hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 shadow-sm transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Load Live Report
            </button>
          )}
        </div>
      </div>

      {/* Main Content Body */}
      <div className="p-5">
        {loading && !liveData && (
          <div className="py-6 flex flex-col items-center justify-center text-center">
            <div className="w-6 h-6 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mb-3" />
            <p className="text-xs font-medium text-slate-700">
              Discovering latest GitHub Actions security evaluation...
            </p>
            <p className="text-[11px] text-slate-400 mt-1">
              Connecting to GitHub Actions artifact storage
            </p>
          </div>
        )}

        {error && !loading && (
          <div className="p-4 rounded-md bg-amber-50 border border-amber-200 text-amber-900 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
            <div className="flex-1 text-xs">
              <div className="font-semibold text-amber-950 mb-0.5">
                Live Ingestion Telemetry Unavailable
              </div>
              <p className="text-amber-800 leading-relaxed mb-2">{error}</p>
              <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-amber-200/60 text-[11px]">
                <span className="text-amber-700">Fallback:</span>
                <span>Upload a JSON security report or explore demonstration scenarios below.</span>
              </div>
            </div>
          </div>
        )}

        {liveData && !error && run && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
            {/* Verdict and Overview Pill */}
            <div className="lg:col-span-4 flex items-center gap-3.5 pr-4 lg:border-r lg:border-slate-200">
              <div>
                <div className="text-[11px] uppercase font-semibold text-slate-400 tracking-wider mb-1">
                  Latest Gate Verdict
                </div>
                <div className="flex items-center gap-2">
                  {getDecisionBadge(decision)}
                  <span className="text-xs text-slate-500 font-mono">
                    exit {decision === "BLOCK" ? 1 : decision === "ERROR" ? 2 : 0}
                  </span>
                </div>
              </div>

              <div className="ml-auto text-right">
                <div className="text-[11px] uppercase font-semibold text-slate-400 tracking-wider mb-1">
                  Findings
                </div>
                <div className="text-sm font-semibold text-slate-800">
                  {report?.summary?.total_findings ?? 0}
                  <span className="text-xs font-normal text-slate-400 ml-1">
                    ({report?.summary?.blocking_count ?? 0} blocking)
                  </span>
                </div>
              </div>
            </div>

            {/* Run Metadata and Links */}
            <div className="lg:col-span-5 space-y-1.5 text-xs text-slate-600">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-medium text-slate-900">Run #{run.id}</span>
                <span className="text-slate-300">•</span>
                <span className="inline-flex items-center gap-1 text-slate-600">
                  <GitBranch className="w-3.5 h-3.5 text-slate-400" />
                  <code>{run.head_branch || "main"}</code>
                </span>
                <span className="text-slate-300">•</span>
                <span className="inline-flex items-center gap-1 text-slate-600">
                  <GitCommit className="w-3.5 h-3.5 text-slate-400" />
                  <code>{run.head_sha?.substring(0, 7)}</code>
                </span>
              </div>

              <div className="flex items-center gap-3 text-[11px] text-slate-500">
                <span className="inline-flex items-center gap-1">
                  <Clock className="w-3 h-3 text-slate-400" />
                  {run.updated_at
                    ? new Date(run.updated_at).toLocaleString()
                    : "Recently completed"}
                </span>
                <a
                  href={run.html_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 font-medium hover:underline"
                >
                  GitHub Run
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>

            {/* Scanner Status Matrix */}
            <div className="lg:col-span-3 flex flex-wrap lg:flex-col gap-1.5 justify-end">
              {report?.scanner_status ? (
                Object.entries(report.scanner_status).map(([scName, scStatus]) =>
                  getScannerPill(scName, String(scStatus))
                )
              ) : (
                <div className="text-xs text-slate-400">Scanners completed</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
