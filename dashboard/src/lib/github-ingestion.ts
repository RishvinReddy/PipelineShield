/**
 * PipelineShield Live GitHub Actions Report Ingestion Core.
 *
 * Encapsulates GitHub API querying, run selection, artifact download,
 * in-memory ZIP extraction, and contract schema validation.
 */

import { extractFileFromZip } from "./zip-extractor.ts";
import { validateReportSchema } from "./report-validator.ts";

export interface GitHubWorkflowRun {
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
  path?: string;
}

export interface GitHubArtifact {
  id: number;
  node_id: string;
  name: string;
  size_in_bytes: number;
  url: string;
  archive_download_url: string;
  expired: boolean;
  created_at: string;
  updated_at: string;
}

export interface FetchReportOptions {
  token?: string;
  repo?: string;
  isRefresh?: boolean;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  maxArchiveSizeBytes?: number;
}

export interface IngestionResult {
  status: number;
  headers?: Record<string, string>;
  body: {
    success: boolean;
    error?: string;
    report?: unknown;
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
  };
}

export const DEFAULT_REPO = "RishvinReddy/PipelineShield";
export const REPORT_ARTIFACT_NAME = "security-summary-reports";
export const TARGET_REPORT_FILE = "security-summary.json";
export const DEFAULT_FETCH_TIMEOUT_MS = 10000;
export const DEFAULT_MAX_ARCHIVE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

export function getGitHubHeaders(token?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "PipelineShield-LiveIngestion/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token && token.trim()) {
    headers.Authorization = `Bearer ${token.trim()}`;
  }
  return headers;
}

export async function fetchLatestGitHubReport(
  options: FetchReportOptions = {}
): Promise<IngestionResult> {
  const token = options.token ?? process.env.GITHUB_TOKEN;
  const repo = options.repo ?? process.env.GITHUB_REPOSITORY ?? DEFAULT_REPO;
  const isRefresh = options.isRefresh ?? false;
  const customFetch = options.fetchFn ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const maxArchiveSize = options.maxArchiveSizeBytes ?? DEFAULT_MAX_ARCHIVE_SIZE_BYTES;

  if (!token || !token.trim()) {
    return {
      status: 401,
      body: {
        success: false,
        error:
          "GITHUB_TOKEN environment variable is not configured. Live ingestion requires a valid token with Actions and Metadata read permissions.",
      },
    };
  }

  try {
    // ------------------------------------------------------------------
    // Step 1: Query GitHub Actions for recent workflow runs
    // ------------------------------------------------------------------
    const runsApiUrl = `https://api.github.com/repos/${repo}/actions/runs?per_page=20`;

    const runsResponse = await customFetch(runsApiUrl, {
      headers: getGitHubHeaders(token),
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    });

    if (!runsResponse.ok) {
      if (runsResponse.status === 401) {
        return {
          status: 401,
          body: {
            success: false,
            error:
              "GitHub authentication failed (401). Verify that GITHUB_TOKEN is valid and has not expired or been revoked.",
          },
        };
      }
      if (runsResponse.status === 403) {
        const rateRemaining = runsResponse.headers.get("x-ratelimit-remaining");
        const rateReset = runsResponse.headers.get("x-ratelimit-reset");
        if (rateRemaining === "0") {
          const resetDate = rateReset ? new Date(Number(rateReset) * 1000).toISOString() : "soon";
          return {
            status: 429,
            body: {
              success: false,
              error: `GitHub API rate limit exceeded. Limit resets at ${resetDate}.`,
            },
          };
        }
        return {
          status: 403,
          body: {
            success: false,
            error: `GitHub API access forbidden (403) for repository '${repo}'. Verify token permissions (Actions: Read, Metadata: Read).`,
          },
        };
      }
      if (runsResponse.status === 404) {
        return {
          status: 404,
          body: {
            success: false,
            error: `Repository '${repo}' not found on GitHub (404). Check GITHUB_REPOSITORY configuration.`,
          },
        };
      }

      return {
        status: runsResponse.status >= 500 ? 502 : runsResponse.status,
        body: {
          success: false,
          error: `GitHub API returned upstream error ${runsResponse.status}: ${runsResponse.statusText}`,
        },
      };
    }

    const runsData = (await runsResponse.json()) as { workflow_runs?: GitHubWorkflowRun[] };
    const allRuns = runsData.workflow_runs || [];

    // Filter for completed security gate runs
    // Include all conclusions (success, failure, etc.) because BLOCK and ERROR gates fail closed
    const eligibleRuns = allRuns.filter((r) => {
      const isCompleted = r.status === "completed";
      const isSecurityGate =
        r.name?.toLowerCase().includes("security gate") ||
        r.path?.toLowerCase().includes("security-gate");
      return isCompleted && isSecurityGate;
    });

    // Fall back to any completed run if specific name pattern doesn't match
    const selectedRuns =
      eligibleRuns.length > 0 ? eligibleRuns : allRuns.filter((r) => r.status === "completed");

    if (selectedRuns.length === 0) {
      return {
        status: 404,
        body: {
          success: false,
          error: `No completed security-gate workflow runs found for repository '${repo}'.`,
        },
      };
    }

    const latestRun = selectedRuns[0];

    // ------------------------------------------------------------------
    // Step 2: Query artifacts for the selected completed run
    // ------------------------------------------------------------------
    const artifactsApiUrl = `https://api.github.com/repos/${repo}/actions/runs/${latestRun.id}/artifacts`;
    const artifactsResponse = await customFetch(artifactsApiUrl, {
      headers: getGitHubHeaders(token),
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    });

    if (!artifactsResponse.ok) {
      return {
        status: 502,
        body: {
          success: false,
          error: `Failed to retrieve artifacts for run #${latestRun.id} (HTTP ${artifactsResponse.status}).`,
          run: {
            id: latestRun.id,
            name: latestRun.name,
            status: latestRun.status,
            conclusion: latestRun.conclusion,
            html_url: latestRun.html_url,
            head_sha: latestRun.head_sha,
            head_branch: latestRun.head_branch,
            event: latestRun.event,
            created_at: latestRun.created_at,
            updated_at: latestRun.updated_at,
          },
        },
      };
    }

    const artifactsData = (await artifactsResponse.json()) as { artifacts?: GitHubArtifact[] };
    const artifacts = artifactsData.artifacts || [];

    const targetArtifact = artifacts.find(
      (a) => a.name.toLowerCase() === REPORT_ARTIFACT_NAME.toLowerCase()
    );

    if (!targetArtifact) {
      return {
        status: 404,
        body: {
          success: false,
          error: `Run #${latestRun.id} (${latestRun.conclusion || "unknown"}) does not contain artifact '${REPORT_ARTIFACT_NAME}'.`,
          run: {
            id: latestRun.id,
            name: latestRun.name,
            status: latestRun.status,
            conclusion: latestRun.conclusion,
            html_url: latestRun.html_url,
            head_sha: latestRun.head_sha,
            head_branch: latestRun.head_branch,
            event: latestRun.event,
            created_at: latestRun.created_at,
            updated_at: latestRun.updated_at,
          },
        },
      };
    }

    if (targetArtifact.expired) {
      return {
        status: 410,
        body: {
          success: false,
          error: `Artifact '${targetArtifact.name}' for run #${latestRun.id} has expired on GitHub.`,
          run: {
            id: latestRun.id,
            name: latestRun.name,
            status: latestRun.status,
            conclusion: latestRun.conclusion,
            html_url: latestRun.html_url,
            head_sha: latestRun.head_sha,
            head_branch: latestRun.head_branch,
            event: latestRun.event,
            created_at: latestRun.created_at,
            updated_at: latestRun.updated_at,
          },
          artifact: {
            name: targetArtifact.name,
            expired: true,
          },
        },
      };
    }

    // ------------------------------------------------------------------
    // Step 3: Download artifact archive (follows GitHub 302 redirect)
    // ------------------------------------------------------------------
    const downloadUrl = `https://api.github.com/repos/${repo}/actions/artifacts/${targetArtifact.id}/zip`;
    const downloadResponse = await customFetch(downloadUrl, {
      headers: getGitHubHeaders(token),
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    });

    if (!downloadResponse.ok) {
      return {
        status: 502,
        body: {
          success: false,
          error: `Failed to download artifact archive #${targetArtifact.id} (HTTP ${downloadResponse.status}).`,
          run: {
            id: latestRun.id,
            name: latestRun.name,
            status: latestRun.status,
            conclusion: latestRun.conclusion,
            html_url: latestRun.html_url,
            head_sha: latestRun.head_sha,
            head_branch: latestRun.head_branch,
            event: latestRun.event,
            created_at: latestRun.created_at,
            updated_at: latestRun.updated_at,
          },
        },
      };
    }

    const arrayBuffer = await downloadResponse.arrayBuffer();
    const zipBuffer = Buffer.from(arrayBuffer);

    if (zipBuffer.length > maxArchiveSize) {
      return {
        status: 413,
        body: {
          success: false,
          error: `Downloaded archive size (${zipBuffer.length} bytes) exceeds safety limit of ${maxArchiveSize} bytes.`,
        },
      };
    }

    // ------------------------------------------------------------------
    // Step 4: Extract security-summary.json in memory
    // ------------------------------------------------------------------
    let extracted;
    try {
      extracted = extractFileFromZip(zipBuffer, TARGET_REPORT_FILE);
    } catch (extractErr) {
      return {
        status: 502,
        body: {
          success: false,
          error: `Failed to extract '${TARGET_REPORT_FILE}' from artifact: ${
            extractErr instanceof Error ? extractErr.message : String(extractErr)
          }`,
          run: {
            id: latestRun.id,
            name: latestRun.name,
            status: latestRun.status,
            conclusion: latestRun.conclusion,
            html_url: latestRun.html_url,
            head_sha: latestRun.head_sha,
            head_branch: latestRun.head_branch,
            event: latestRun.event,
            created_at: latestRun.created_at,
            updated_at: latestRun.updated_at,
          },
        },
      };
    }

    // ------------------------------------------------------------------
    // Step 5: Parse and validate report against authoritative schema
    // ------------------------------------------------------------------
    let reportObj: unknown;
    try {
      reportObj = JSON.parse(extracted.content);
    } catch (parseErr) {
      return {
        status: 502,
        body: {
          success: false,
          error: `Extracted '${TARGET_REPORT_FILE}' contains invalid JSON: ${
            parseErr instanceof Error ? parseErr.message : String(parseErr)
          }`,
        },
      };
    }

    const validation = validateReportSchema(reportObj);
    if (!validation.valid) {
      return {
        status: 502,
        body: {
          success: false,
          error: `Report schema validation failed: ${validation.error}`,
        },
      };
    }

    // ------------------------------------------------------------------
    // Step 6: Return authoritative live report payload
    // ------------------------------------------------------------------
    const responsePayload = {
      success: true,
      report: reportObj,
      run: {
        id: latestRun.id,
        name: latestRun.name,
        status: latestRun.status,
        conclusion: latestRun.conclusion,
        html_url: latestRun.html_url,
        head_sha: latestRun.head_sha,
        head_branch: latestRun.head_branch,
        event: latestRun.event,
        created_at: latestRun.created_at,
        updated_at: latestRun.updated_at,
      },
      artifact: {
        id: targetArtifact.id,
        name: targetArtifact.name,
        size_in_bytes: targetArtifact.size_in_bytes,
        expired: targetArtifact.expired,
        created_at: targetArtifact.created_at,
      },
      fetched_at: new Date().toISOString(),
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (isRefresh) {
      headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    } else {
      headers["Cache-Control"] = "public, s-maxage=15, stale-while-revalidate=30";
    }

    return {
      status: 200,
      headers,
      body: responsePayload,
    };
  } catch (err: unknown) {
    const isTimeout =
      err instanceof Error &&
      (err.name === "TimeoutError" || err.message.toLowerCase().includes("timeout"));
    const statusCode = isTimeout ? 504 : 500;
    const errorMsg = isTimeout
      ? "GitHub API request timed out after 10 seconds."
      : `Internal error while retrieving latest report: ${
          err instanceof Error ? err.message : String(err)
        }`;

    return {
      status: statusCode,
      body: {
        success: false,
        error: errorMsg,
      },
    };
  }
}
