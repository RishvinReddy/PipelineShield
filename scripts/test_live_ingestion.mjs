#!/usr/bin/env node
/**
 * Automated Test Suite for PipelineShield Live GitHub Actions Ingestion.
 *
 * Covers:
 * 1. Pure in-memory ZIP extraction and boundary verification (stored, deflated, zip bombs, corruption).
 * 2. GitHub Actions API integration (401, 403 rate limits, 404, 500 upstream).
 * 3. Workflow run selection (in-progress filtered out, failed/block/error runs supported).
 * 4. Artifact discovery, expiration handling (410), missing artifact handling (404).
 * 5. Corrupted archives, missing reports, invalid JSON, and schema contract validation.
 * 6. Download size limits, timeout handling, and cache-control semantics.
 */

import zlib from "zlib";
import assert from "assert/strict";
import { extractFileFromZip } from "../dashboard/src/lib/zip-extractor.ts";
import { fetchLatestGitHubReport } from "../dashboard/src/lib/github-ingestion.ts";

console.log("===============================================================================");
console.log(" PipelineShield — Live Ingestion & ZIP Extractor Test Suite");
console.log("===============================================================================\n");

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failed++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failed++;
  }
}

// ----------------------------------------------------------------------------
// Deterministic In-Memory ZIP Archive Generator
// ----------------------------------------------------------------------------
function crc32(buf) {
  let crc = 0 ^ -1;
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ -1) >>> 0;
}

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[i] = c;
}

function toExactArrayBuffer(buf) {
  return Uint8Array.prototype.slice.call(buf).buffer;
}

function buildZipArchive(entries) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const entry of entries) {
    const filenameBuf = Buffer.from(entry.name, "utf-8");
    const uncompressedBuf = Buffer.isBuffer(entry.data)
      ? entry.data
      : Buffer.from(entry.data, "utf-8");
    const uncompressedSize = entry.overrideUncompressedSize ?? uncompressedBuf.length;
    const entryCrc = crc32(uncompressedBuf);

    let compressedBuf;
    let method = entry.method ?? (entry.compress ? 8 : 0);

    if (method === 8) {
      compressedBuf = zlib.deflateRawSync(uncompressedBuf);
    } else {
      compressedBuf = uncompressedBuf;
      method = 0;
    }

    const compressedSize = entry.overrideCompressedSize ?? compressedBuf.length;

    // Local file header (30 bytes + filename)
    const localHeader = Buffer.alloc(30 + filenameBuf.length);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0, 6); // general purpose bit flag
    localHeader.writeUInt16LE(method, 8); // compression method
    localHeader.writeUInt16LE(0, 10); // last mod time
    localHeader.writeUInt16LE(0, 12); // last mod date
    localHeader.writeUInt32LE(entryCrc, 14); // crc32
    localHeader.writeUInt32LE(compressedSize, 18); // compressed size
    localHeader.writeUInt32LE(uncompressedSize, 22); // uncompressed size
    localHeader.writeUInt16LE(filenameBuf.length, 26); // filename length
    localHeader.writeUInt16LE(0, 28); // extra field length
    filenameBuf.copy(localHeader, 30);

    localHeaders.push(localHeader);
    localHeaders.push(compressedBuf);

    // Central directory header (46 bytes + filename)
    const centralHeader = Buffer.alloc(46 + filenameBuf.length);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0, 8); // flag
    centralHeader.writeUInt16LE(method, 10); // method
    centralHeader.writeUInt16LE(0, 12); // time
    centralHeader.writeUInt16LE(0, 14); // date
    centralHeader.writeUInt32LE(entryCrc, 16); // crc32
    centralHeader.writeUInt32LE(compressedSize, 20); // compressed size
    centralHeader.writeUInt32LE(uncompressedSize, 24); // uncompressed size
    centralHeader.writeUInt16LE(filenameBuf.length, 28); // filename length
    centralHeader.writeUInt16LE(0, 30); // extra length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk start
    centralHeader.writeUInt16LE(0, 36); // internal attr
    centralHeader.writeUInt32LE(0, 38); // external attr
    centralHeader.writeUInt32LE(offset, 42); // local header offset
    filenameBuf.copy(centralHeader, 46);

    centralHeaders.push(centralHeader);
    offset += localHeader.length + compressedBuf.length;
  }

  const centralDirOffset = offset;
  const centralDirSize = centralHeaders.reduce((acc, h) => acc + h.length, 0);

  // End of Central Directory Record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // signature
  eocd.writeUInt16LE(0, 4); // disk num
  eocd.writeUInt16LE(0, 6); // start disk
  eocd.writeUInt16LE(entries.length, 8); // entries on disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(centralDirSize, 12); // size of CD
  eocd.writeUInt32LE(centralDirOffset, 16); // offset of CD
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localHeaders, ...centralHeaders, eocd]);
}

// Minimal valid security report JSON
const VALID_SECURITY_REPORT = JSON.stringify({
  decision: "PASS",
  reasons: ["Zero blocking violations detected"],
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
  evaluated_at: "2026-10-30T20:00:00Z",
  scanner_status: {
    trivy: "COMPLETED",
    semgrep: "COMPLETED",
    dependency_review: "COMPLETED",
  },
  policy_metadata: {
    name: "PipelineShield Production Gatekeeper",
    repository: "RishvinReddy/PipelineShield",
    branch: "main",
    commit: "2dfafba",
  },
});

const BLOCK_SECURITY_REPORT = JSON.stringify({
  decision: "BLOCK",
  reasons: ["1 CRITICAL finding violates policy"],
  summary: {
    total_findings: 1,
    critical: 1,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    exempted: 0,
    blocking_count: 1,
    warning_count: 0,
  },
  blocking_findings: [
    {
      id: "CVE-2023-1234",
      scanner: "trivy",
      title: "Remote Code Execution",
      description: "Critical vulnerability in dependencies",
      severity: "CRITICAL",
    },
  ],
  warning_findings: [],
  advisory_findings: [],
  exempted_findings: [],
  evaluated_at: "2026-10-30T20:05:00Z",
  scanner_status: {
    trivy: "COMPLETED",
    semgrep: "COMPLETED",
    dependency_review: "COMPLETED",
  },
});

const ERROR_SECURITY_REPORT = JSON.stringify({
  decision: "ERROR",
  reasons: ["Scanner 'trivy' failed to execute"],
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
  evaluated_at: "2026-10-30T20:10:00Z",
  scanner_status: {
    trivy: "FAILED",
    semgrep: "COMPLETED",
    dependency_review: "NOT_APPLICABLE",
  },
});

// ----------------------------------------------------------------------------
// SECTION 1: Pure In-Memory ZIP Extractor Tests
// ----------------------------------------------------------------------------
console.log("Section 1: Pure In-Memory ZIP Extractor Unit Tests\n");

runTest("ZIP: Extracts uncompressed (stored, method 0) file cleanly", () => {
  const zip = buildZipArchive([
    { name: "reports/security-summary.json", data: VALID_SECURITY_REPORT, compress: false },
  ]);
  const res = extractFileFromZip(zip, "security-summary.json");
  assert.equal(res.fileName, "reports/security-summary.json");
  assert.equal(res.content, VALID_SECURITY_REPORT);
});

runTest("ZIP: Extracts deflated (method 8) file cleanly", () => {
  const zip = buildZipArchive([
    { name: "reports/security-summary.json", data: VALID_SECURITY_REPORT, compress: true },
  ]);
  const res = extractFileFromZip(zip, "security-summary.json");
  assert.equal(res.fileName, "reports/security-summary.json");
  assert.equal(res.content, VALID_SECURITY_REPORT);
});

runTest("ZIP: Matches target filename whether nested in directory or at root", () => {
  const zipRoot = buildZipArchive([
    { name: "security-summary.json", data: VALID_SECURITY_REPORT, compress: true },
  ]);
  const resRoot = extractFileFromZip(zipRoot, "security-summary.json");
  assert.equal(resRoot.fileName, "security-summary.json");

  const zipNested = buildZipArchive([
    { name: "ci/artifacts/security-summary.json", data: VALID_SECURITY_REPORT, compress: true },
  ]);
  const resNested = extractFileFromZip(zipNested, "security-summary.json");
  assert.equal(resNested.fileName, "ci/artifacts/security-summary.json");
});

runTest("ZIP: Rejects archive missing target entry with clear error", () => {
  const zip = buildZipArchive([
    { name: "other-report.txt", data: "test data", compress: false },
  ]);
  assert.throws(
    () => extractFileFromZip(zip, "security-summary.json"),
    /File 'security-summary.json' not found in ZIP archive/
  );
});

runTest("ZIP: Rejects truncated or corrupted buffer without EOCD", () => {
  const badBuffer = Buffer.from("NOT_A_VALID_ZIP_ARCHIVE_DATA_HEADER");
  assert.throws(
    () => extractFileFromZip(badBuffer, "security-summary.json"),
    /Invalid ZIP archive: End of Central Directory \(EOCD\) record not found/
  );
});

runTest("ZIP: Safety limit blocks archive exceeding max archive size", () => {
  const dummyZip = Buffer.alloc(100);
  assert.throws(
    () => extractFileFromZip(dummyZip, "security-summary.json", { maxArchiveSizeBytes: 50 }),
    /ZIP archive size \(100 bytes\) exceeds maximum allowed limit of 50 bytes/
  );
});

runTest("ZIP: Zip bomb defense rejects uncompressed size exceeding limit", () => {
  const zip = buildZipArchive([
    {
      name: "security-summary.json",
      data: "hello",
      compress: true,
      overrideUncompressedSize: 50 * 1024 * 1024, // Claims 50MB
    },
  ]);
  assert.throws(
    () => extractFileFromZip(zip, "security-summary.json", { maxUncompressedSizeBytes: 1024 }),
    /exceeds maximum allowed uncompressed limit/
  );
});

// ----------------------------------------------------------------------------
// SECTION 2: GitHub API Integration & Ingestion Logic Tests
// ----------------------------------------------------------------------------
console.log("\nSection 2: Live GitHub Actions Report Ingestion Tests\n");

await runAsyncTest("API: Missing GITHUB_TOKEN returns 401 with clear configuration guidance", async () => {
  const res = await fetchLatestGitHubReport({ token: "" });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /GITHUB_TOKEN environment variable is not configured/);
});

await runAsyncTest("API: GitHub API 401 Unauthorized propagates 401", async () => {
  const mockFetch = async () => ({
    ok: false,
    status: 401,
    statusText: "Unauthorized",
    headers: new Headers(),
    json: async () => ({ message: "Bad credentials" }),
  });

  const res = await fetchLatestGitHubReport({ token: "ghp_invalid_token", fetchFn: mockFetch });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /GitHub authentication failed/);
});

await runAsyncTest("API: GitHub API 403 Rate Limit returns 429 with reset time", async () => {
  const headers = new Headers();
  headers.set("x-ratelimit-remaining", "0");
  headers.set("x-ratelimit-reset", "1761850000");

  const mockFetch = async () => ({
    ok: false,
    status: 403,
    statusText: "Forbidden",
    headers,
    json: async () => ({ message: "API rate limit exceeded" }),
  });

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 429);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /GitHub API rate limit exceeded/);
});

await runAsyncTest("API: GitHub API 403 Forbidden without rate limit returns 403 scope error", async () => {
  const headers = new Headers();
  headers.set("x-ratelimit-remaining", "50");

  const mockFetch = async () => ({
    ok: false,
    status: 403,
    statusText: "Forbidden",
    headers,
    json: async () => ({ message: "Resource not accessible by integration" }),
  });

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 403);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /GitHub API access forbidden \(403\)/);
});

await runAsyncTest("API: GitHub API 404 Repo Not Found returns 404", async () => {
  const mockFetch = async () => ({
    ok: false,
    status: 404,
    statusText: "Not Found",
    headers: new Headers(),
    json: async () => ({ message: "Not Found" }),
  });

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 404);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /Repository '.*' not found on GitHub/);
});

await runAsyncTest("API: GitHub API 500 Server Error returns 502 Upstream Error", async () => {
  const mockFetch = async () => ({
    ok: false,
    status: 500,
    statusText: "Internal Server Error",
    headers: new Headers(),
    json: async () => ({ message: "Server Error" }),
  });

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 502);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /GitHub API returned upstream error 500/);
});

await runAsyncTest("Run Selection: In-progress run is skipped; newest completed run is chosen", async () => {
  const validZip = buildZipArchive([
    { name: "reports/security-summary.json", data: VALID_SECURITY_REPORT, compress: true },
  ]);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            {
              id: 999999,
              name: "DevSecOps Policy Enforcement Gate",
              status: "in_progress",
              conclusion: null,
            },
            {
              id: 888888,
              name: "DevSecOps Policy Enforcement Gate",
              status: "completed",
              conclusion: "success",
              html_url: "https://github.com/RishvinReddy/PipelineShield/actions/runs/888888",
              head_sha: "84cf337a1b2c",
              head_branch: "main",
              event: "push",
              created_at: "2026-10-30T19:00:00Z",
              updated_at: "2026-10-30T19:05:00Z",
            },
          ],
        }),
      };
    }
    if (url.includes("/actions/runs/888888/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [
            {
              id: 7777,
              name: "security-summary-reports",
              size_in_bytes: validZip.length,
              expired: false,
            },
          ],
        }),
      };
    }
    if (url.includes("/artifacts/7777/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(validZip),
      };
    }
    throw new Error(`Unexpected URL called: ${url}`);
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  if (res.status !== 200) {
    throw new Error(`Status ${res.status}: ${res.body?.error}`);
  }
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.run.id, 888888);
  assert.equal(res.body.run.status, "completed");
});

await runAsyncTest("Run Selection: Failed/Block runs (conclusion failure, exit code 1) are correctly ingested", async () => {
  const blockZip = buildZipArchive([
    { name: "reports/security-summary.json", data: BLOCK_SECURITY_REPORT, compress: true },
  ]);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            {
              id: 41093600024,
              name: "DevSecOps Policy Enforcement Gate",
              status: "completed",
              conclusion: "failure", // Exit 1 produced failure
              html_url: "https://github.com/RishvinReddy/PipelineShield/actions/runs/41093600024",
              head_sha: "cve-pr-sha",
              head_branch: "feat/vulnerable-test",
              event: "pull_request",
              created_at: "2026-10-30T19:00:00Z",
              updated_at: "2026-10-30T19:03:00Z",
            },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(blockZip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [
            {
              id: 1111,
              name: "security-summary-reports",
              size_in_bytes: blockZip.length,
              expired: false,
            },
          ],
        }),
      };
    }
    throw new Error(`Unexpected URL called: ${url}`);
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  if (res.status !== 200) {
    throw new Error(`Status ${res.status}: ${res.body?.error}`);
  }
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.run.conclusion, "failure");
  assert.equal(res.body.report.decision, "BLOCK");
  assert.equal(res.body.report.summary.blocking_count, 1);
});

await runAsyncTest("Run Selection: Error runs (conclusion failure, exit code 2, scanner error) are correctly ingested", async () => {
  const errorZip = buildZipArchive([
    { name: "reports/security-summary.json", data: ERROR_SECURITY_REPORT, compress: true },
  ]);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            {
              id: 41110633241,
              name: "DevSecOps Policy Enforcement Gate",
              status: "completed",
              conclusion: "failure", // Exit 2 produced failure
              html_url: "https://github.com/RishvinReddy/PipelineShield/actions/runs/41110633241",
              head_sha: "fail-sim-sha",
              head_branch: "test/scanner-failure",
              event: "workflow_dispatch",
              created_at: "2026-10-30T19:10:00Z",
              updated_at: "2026-10-30T19:12:00Z",
            },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(errorZip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [
            {
              id: 2222,
              name: "security-summary-reports",
              size_in_bytes: errorZip.length,
              expired: false,
            },
          ],
        }),
      };
    }
    throw new Error(`Unexpected URL called: ${url}`);
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  if (res.status !== 200) {
    throw new Error(`Status ${res.status}: ${res.body?.error}`);
  }
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.report.decision, "ERROR");
  assert.equal(res.body.report.scanner_status.trivy, "FAILED");
});

await runAsyncTest("Artifact: Missing security-summary-reports artifact returns 404", async () => {
  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            { id: 12345, status: "completed", conclusion: "success", name: "Security Gate" },
          ],
        }),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 555, name: "other-unrelated-artifact", expired: false }],
        }),
      };
    }
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 404);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /does not contain artifact 'security-summary-reports'/);
});

await runAsyncTest("Artifact: Expired artifact returns 410 Gone", async () => {
  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            { id: 12345, status: "completed", conclusion: "success", name: "Security Gate" },
          ],
        }),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 555, name: "security-summary-reports", expired: true }],
        }),
      };
    }
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 410);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /has expired on GitHub/);
  assert.equal(res.body.artifact.expired, true);
});

await runAsyncTest("Artifact: Oversized archive returns 413 Payload Too Large", async () => {
  const hugeZip = Buffer.alloc(1000);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            { id: 12345, status: "completed", conclusion: "success", name: "Security Gate" },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(hugeZip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 555, name: "security-summary-reports", expired: false }],
        }),
      };
    }
  };

  const res = await fetchLatestGitHubReport({
    token: "ghp_valid",
    fetchFn: mockFetch,
    maxArchiveSizeBytes: 500, // Safety cap set to 500 bytes
  });

  assert.equal(res.status, 413);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /exceeds safety limit/);
});

await runAsyncTest("Integrity: Malformed ZIP archive returns 502 with extraction failure", async () => {
  const corruptedBuffer = Buffer.from("CORRUPTED_HEADER_DATA_NOT_A_ZIP");

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            { id: 12345, status: "completed", conclusion: "success", name: "Security Gate" },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(corruptedBuffer),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 555, name: "security-summary-reports", expired: false }],
        }),
      };
    }
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 502);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /Failed to extract 'security-summary.json'/);
});

await runAsyncTest("Integrity: Archive missing security-summary.json returns 502", async () => {
  const emptyZip = buildZipArchive([
    { name: "other-file.txt", data: "hello", compress: false },
  ]);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            { id: 12345, status: "completed", conclusion: "success", name: "Security Gate" },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(emptyZip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 555, name: "security-summary-reports", expired: false }],
        }),
      };
    }
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 502);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /File 'security-summary.json' not found in ZIP archive/);
});

await runAsyncTest("Integrity: Extracted JSON with invalid schema returns 502", async () => {
  const invalidSchemaJson = JSON.stringify({
    decision: "INVALID_DECISION_VALUE",
    summary: { total_findings: "not_a_number" },
  });

  const invalidZip = buildZipArchive([
    { name: "security-summary.json", data: invalidSchemaJson, compress: false },
  ]);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            { id: 12345, status: "completed", conclusion: "success", name: "Security Gate" },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(invalidZip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 555, name: "security-summary-reports", expired: false }],
        }),
      };
    }
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: mockFetch });
  assert.equal(res.status, 502);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /Report schema validation failed/);
});

await runAsyncTest("Cache: Refresh requests return no-store Cache-Control header", async () => {
  const validZip = buildZipArchive([
    { name: "reports/security-summary.json", data: VALID_SECURITY_REPORT, compress: true },
  ]);

  const mockFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            {
              id: 111,
              name: "Security Gate",
              status: "completed",
              conclusion: "success",
              html_url: "https://github.com",
            },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(validZip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 222, name: "security-summary-reports", expired: false }],
        }),
      };
    }
  };

  const refreshRes = await fetchLatestGitHubReport({
    token: "ghp_valid",
    isRefresh: true,
    fetchFn: mockFetch,
  });
  assert.equal(refreshRes.status, 200);
  assert.match(refreshRes.headers["Cache-Control"], /no-store/);

  const regularRes = await fetchLatestGitHubReport({
    token: "ghp_valid",
    isRefresh: false,
    fetchFn: mockFetch,
  });
  assert.equal(regularRes.status, 200);
  assert.match(regularRes.headers["Cache-Control"], /public, s-maxage/);
});

await runAsyncTest("Timeout: Aborted or timed-out GitHub request returns 504 Gateway Timeout", async () => {
  const timeoutFetch = async () => {
    const err = new Error("The operation was aborted due to timeout");
    err.name = "TimeoutError";
    throw err;
  };

  const res = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: timeoutFetch });
  assert.equal(res.status, 504);
  assert.equal(res.body.success, false);
  assert.match(res.body.error, /timed out after 10 seconds/);
});

await runAsyncTest("Refresh: Subsequent refresh call dynamically picks up a newer completed run", async () => {
  let callCount = 0;
  const zip = buildZipArchive([
    { name: "reports/security-summary.json", data: VALID_SECURITY_REPORT, compress: true },
  ]);

  const dynamicFetch = async (url) => {
    if (url.includes("/actions/runs?")) {
      callCount++;
      const runId = callCount === 1 ? 5001 : 5002;
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          workflow_runs: [
            {
              id: runId,
              name: "DevSecOps Policy Enforcement Gate",
              status: "completed",
              conclusion: "success",
              head_sha: `sha_${runId}`,
            },
          ],
        }),
      };
    }
    if (url.includes("/zip")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => toExactArrayBuffer(zip),
      };
    }
    if (url.includes("/artifacts")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          artifacts: [{ id: 999, name: "security-summary-reports", expired: false }],
        }),
      };
    }
  };

  const initialRes = await fetchLatestGitHubReport({ token: "ghp_valid", fetchFn: dynamicFetch });
  assert.equal(initialRes.body.run.id, 5001);

  const refreshRes = await fetchLatestGitHubReport({
    token: "ghp_valid",
    isRefresh: true,
    fetchFn: dynamicFetch,
  });
  assert.equal(refreshRes.body.run.id, 5002);
});

console.log("\n===============================================================================");
console.log(` Results: ${passed} passed, ${failed} failed`);
console.log("===============================================================================");

if (failed > 0) {
  process.exit(1);
}
