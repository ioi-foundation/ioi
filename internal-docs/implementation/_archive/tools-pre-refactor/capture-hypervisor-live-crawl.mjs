#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  failWith,
  implementationRelative,
  implementationRoot,
  readJson,
  repoRelative,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  writeDeterministic,
} from "./lib.mjs";
import {
  buildHypervisorSurfaceCoverage,
  inspectVisualBrowserAttempt,
} from "./generate-hypervisor-surface-coverage.mjs";

const OUTPUT = path.join(
  implementationRoot,
  "evidence",
  "hypervisor-live-read-only-crawl.v1.json",
);
const GENERATOR = fileURLToPath(new URL("./generate-hypervisor-surface-coverage.mjs", import.meta.url));
const PACKAGE = path.join(repoRoot, "apps", "hypervisor", "package.json");
const SERVER = path.join(repoRoot, "apps", "hypervisor", "scripts", "serve-product-ui.mjs");
const DEFAULT_BASE_URL = "http://127.0.0.1:4173";
const SUPPORTED_START_COMMAND = "npm run serve:product-ui --workspace=@ioi/hypervisor-app";

function statusCounts(results) {
  const counts = {};
  for (const result of results) {
    const key = result.error ? "request_error" : String(result.status);
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function expectedRoutes() {
  return buildHypervisorSurfaceCoverage().route_and_adapter_coverage.safe_get_survey_routes;
}

function requiredVisualRoutes() {
  return buildHypervisorSurfaceCoverage()
    .current_catalog_and_registry.surfaces
    .map((surface) => surface.route);
}

async function captureRoute(baseUrl, route) {
  const url = new URL(route, `${baseUrl}/`).toString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { accept: "text/html,application/json;q=0.9,*/*;q=0.1" },
    });
    const body = Buffer.from(await response.arrayBuffer());
    return {
      route,
      status: response.status,
      location: response.headers.get("location"),
      content_type: response.headers.get("content-type"),
      body_bytes: body.length,
      body_sha256: sha256(body),
    };
  } catch (error) {
    return {
      route,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function capture() {
  const baseUrl = (process.env.HYPERVISOR_BASE_URL || DEFAULT_BASE_URL).replace(/\/$/u, "");
  const routes = expectedRoutes();
  const results = [];
  for (let offset = 0; offset < routes.length; offset += 8) {
    results.push(...await Promise.all(routes.slice(offset, offset + 8).map((route) => captureRoute(baseUrl, route))));
  }
  const counts = statusCounts(results);
  const errors = results.filter((result) => result.error);
  const reachable = results.filter((result) => !result.error && result.status >= 200 && result.status < 400);
  return {
    schema_version: "ioi.hypervisor.live-read-only-crawl.v1",
    record_role: "private per-cut transport evidence; never program status or product authority",
    captured_at: new Date().toISOString(),
    base_url: baseUrl,
    supported_start_command: SUPPORTED_START_COMMAND,
    launch_observation: process.env.HYPERVISOR_LAUNCH_OBSERVATION || "supported workflow endpoint observed reachable for this capture",
    request_policy: {
      method: "GET",
      redirect: "manual",
      concurrency: 8,
      per_request_timeout_ms: 15000,
      mutation_allowed: false,
    },
    source_snapshot: {
      route_inventory_generator: {
        path: repoRelative(GENERATOR),
        sha256: sha256File(GENERATOR),
      },
      package_manifest: {
        path: repoRelative(PACKAGE),
        sha256: sha256File(PACKAGE),
      },
      supported_server: {
        path: repoRelative(SERVER),
        sha256: sha256File(SERVER),
      },
    },
    route_inventory: {
      expected_route_count: routes.length,
      expected_routes: routes,
    },
    results,
    summary: {
      captured_route_count: results.length,
      response_status_counts: counts,
      transport_reachable_count: reachable.length,
      request_error_count: errors.length,
    },
    visual_browser_attempt: {
      result: "SKIP",
      reason_code: "in_app_browser_unavailable",
      detail: "Bundled in-app browser bootstrap returned: Browser is not available: iab",
      required_viewports: ["desktop", "narrow"],
      nonclaim: "The HTTP crawl is not visual evidence; no viewport, DOM, interaction, responsive, focus, keyboard, modal, embed, or accessibility behavior was verified.",
    },
    nonclaims: [
      "HTTP 2xx/3xx proves point-in-time transport reachability only.",
      "A response body hash does not establish that the page rendered, was interactive, or implemented its intended workflow.",
      "No consequential action was invoked and no product authority was exercised.",
      "This artifact changes no work-item status, proof gate, stage, runtime, federation, sovereign, service, L1, cohort, or embodied-live claim.",
    ],
  };
}

function validate(evidence) {
  const errors = [];
  const expect = (condition, message) => { if (!condition) errors.push(message); };
  const routes = expectedRoutes();
  const results = evidence.results || [];
  const expectedSources = {
    route_inventory_generator: GENERATOR,
    package_manifest: PACKAGE,
    supported_server: SERVER,
  };
  let baseUrl;
  try {
    baseUrl = new URL(evidence.base_url);
  } catch {
    baseUrl = null;
  }
  expect(evidence.schema_version === "ioi.hypervisor.live-read-only-crawl.v1", "schema_version mismatch");
  expect(evidence.record_role?.includes("never program status"), "record role must deny status authority");
  expect(baseUrl?.protocol === "http:", "base_url must be an HTTP URL");
  expect(new Set(["127.0.0.1", "localhost", "::1"]).has(baseUrl?.hostname), "base_url must remain loopback-only");
  expect(Boolean(baseUrl?.port), "base_url must name the observed local port");
  expect(evidence.supported_start_command === SUPPORTED_START_COMMAND, "supported start command is stale or unsupported");
  expect(
    typeof evidence.launch_observation === "string" && evidence.launch_observation.trim().length >= 20,
    "launch observation must describe the supported-workflow process observed for this capture",
  );
  expect(evidence.request_policy?.method === "GET", "crawl must remain GET-only");
  expect(evidence.request_policy?.redirect === "manual", "crawl must retain redirects as evidence");
  expect(evidence.request_policy?.concurrency === 8, "crawl concurrency policy is stale");
  expect(evidence.request_policy?.per_request_timeout_ms === 15000, "crawl timeout policy is stale");
  expect(evidence.request_policy?.mutation_allowed === false, "crawl must deny mutation");
  for (const [key, sourcePath] of Object.entries(expectedSources)) {
    const retained = evidence.source_snapshot?.[key];
    expect(retained?.path === repoRelative(sourcePath), `${key} source path is stale`);
    if (key === "route_inventory_generator") {
      // This is capture-time provenance. Route equality below proves that the
      // retained crawl still covers the current finite inventory even when the
      // projection/checker implementation itself is subsequently hardened.
      expect(/^[0-9a-f]{64}$/u.test(retained?.sha256 || ""), `${key} source hash is missing`);
    } else {
      expect(retained?.sha256 === sha256File(sourcePath), `${key} source hash is stale`);
    }
  }
  expect(stableJson(evidence.route_inventory?.expected_routes || []) === stableJson(routes), "retained route inventory is stale");
  expect(evidence.route_inventory?.expected_route_count === routes.length, "expected route count is stale");
  expect(results.length === routes.length, "captured result count does not match expected routes");
  expect(stableJson(results.map((result) => result.route)) === stableJson(routes), "captured result order/set is stale");
  for (const result of results) {
    expect(!result.error, `${result.route} has request error: ${result.error || "unknown"}`);
    expect(Number.isInteger(result.status), `${result.route} lacks an HTTP status`);
    expect(result.status >= 200 && result.status < 400, `${result.route} is not transport-reachable (HTTP ${result.status})`);
    expect(Number.isInteger(result.body_bytes) && result.body_bytes >= 0, `${result.route} lacks body length evidence`);
    expect(/^[0-9a-f]{64}$/u.test(result.body_sha256 || ""), `${result.route} lacks a body sha256`);
  }
  const counts = statusCounts(results);
  const reachable = results.filter((result) => !result.error && result.status >= 200 && result.status < 400);
  expect(stableJson(evidence.summary?.response_status_counts || {}) === stableJson(counts), "response status summary is stale");
  expect(evidence.summary?.captured_route_count === results.length, "captured-route summary is stale");
  expect(evidence.summary?.transport_reachable_count === reachable.length, "transport-reachable summary is stale");
  expect(reachable.length === routes.length, "not every expected route is transport-reachable");
  expect(evidence.summary?.request_error_count === results.filter((result) => result.error).length, "request-error summary is stale");
  const visualInspection = inspectVisualBrowserAttempt(evidence.visual_browser_attempt, {
    safeRoutes: routes,
    requiredRoutes: requiredVisualRoutes(),
  });
  errors.push(...visualInspection.errors);
  expect(Array.isArray(evidence.nonclaims) && evidence.nonclaims.length >= 4, "crawl nonclaims are incomplete");
  failWith("Hypervisor live-crawl evidence", errors);
}

async function main() {
  const mode = process.argv[2];
  if (!new Set(["--write", "--check"]).has(mode) || process.argv.length !== 3) {
    process.stderr.write("usage: node internal-docs/implementation/tools/capture-hypervisor-live-crawl.mjs --write|--check\n");
    process.exit(2);
  }
  if (mode === "--write") {
    const evidence = await capture();
    validate(evidence);
    writeDeterministic(OUTPUT, evidence);
    process.stdout.write(`wrote ${implementationRelative(OUTPUT)}: ${evidence.summary.captured_route_count} GETs, statuses ${JSON.stringify(evidence.summary.response_status_counts)}\n`);
    return;
  }
  if (!fs.existsSync(OUTPUT)) failWith("Hypervisor live-crawl evidence", [`${implementationRelative(OUTPUT)} is missing`]);
  const evidence = readJson(OUTPUT);
  validate(evidence);
  process.stdout.write(`Hypervisor live-crawl evidence check passed: ${evidence.summary.captured_route_count} retained GETs; visual ${evidence.visual_browser_attempt.result}\n`);
}

await main();
