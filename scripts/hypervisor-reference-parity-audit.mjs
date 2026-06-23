#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright";

const DEFAULT_REFERENCE_ROUTES = [
  "/",
  "/workspaces",
  "/details/019ed128-a3fd-7433-8cc3-99afed4a8ac4/logs",
  "/automations",
  "/projects",
  "/ai?user-settings=profile",
  "/insights",
];

const DEFAULT_HYPERVISOR_ROUTES = [
  "/",
  "/projects",
  "/automations",
  "/applications",
  "/sessions",
  "/models",
  "/authority",
  "/agents",
  "/environments",
  "/foundry",
  "/privacy",
  "/receipts",
  "/workbench",
];

const DEFAULT_REPLAY_ENDPOINT = "http://127.0.0.1:8765";

const REQUIRED_HYPERVISOR_FAMILIES = [
  "app_shell",
  "assets",
  "daemon_core",
  "editor_workspace",
  "streams_history",
];

const HARD_MARKERS = [
  /requires a Hypervisor host bridge/i,
  /missing (?:Hypervisor )?host bridge/i,
  /missing daemon endpoint/i,
  /no daemon endpoint/i,
  /connection refused/i,
  /ERR_CONNECTION_REFUSED/i,
  /No editor open/i,
  /Maximum update depth exceeded/i,
  /Live connector catalog unavailable/i,
  /Fixture projection/i,
  /runtime fetch failed/i,
];

const DIRECT_REPLAY_PROBES = [
  { name: "dev replay status", method: "GET", route: "/v1/hypervisor/dev-replay/status" },
  { name: "model snapshot", method: "GET", route: "/v1/model-mount/snapshot" },
  { name: "model capabilities", method: "GET", route: "/v1/model-capabilities" },
  { name: "authority", method: "GET", route: "/v1/model-mount/authority" },
  { name: "authority evidence", method: "GET", route: "/v1/authority-evidence" },
  { name: "sessions", method: "GET", route: "/v1/hypervisor/sessions" },
  { name: "session history", method: "GET", route: "/v1/hypervisor/sessions/dev-replay-session/history" },
  { name: "projects", method: "GET", route: "/v1/hypervisor/projects" },
  { name: "automations", method: "GET", route: "/v1/hypervisor/automations" },
  { name: "applications", method: "GET", route: "/v1/hypervisor/applications" },
  { name: "workbench snapshot", method: "GET", route: "/v1/hypervisor/workbench/snapshot" },
  { name: "workbench files", method: "GET", route: "/v1/hypervisor/workbench/files" },
  { name: "workbench git status", method: "GET", route: "/v1/hypervisor/workbench/git/status" },
  { name: "workbench problems", method: "GET", route: "/v1/hypervisor/workbench/problems" },
  { name: "workbench ports", method: "GET", route: "/v1/hypervisor/workbench/ports" },
  { name: "workbench logs", method: "GET", route: "/v1/hypervisor/workbench/logs" },
  {
    name: "workbench terminal create",
    method: "POST",
    route: "/v1/hypervisor/workbench/terminal",
    body: { cols: 100, rows: 28 },
    assert: (json) => ({
      ok: Boolean(json?.sessionId || json?.session_id),
      details: { sessionId: json?.sessionId ?? json?.session_id ?? null },
    }),
  },
  {
    name: "workbench terminal read",
    method: "GET",
    route: "/v1/hypervisor/workbench/terminal/terminal%3Adev-replay%2Fdefault/read",
    assert: (json) => ({
      ok:
        Array.isArray(json?.chunks) &&
        json.chunks.some((chunk) =>
          /Hypervisor dev replay|Qwen local/i.test(String(chunk?.text ?? "")),
        ),
      details: { chunkCount: Array.isArray(json?.chunks) ? json.chunks.length : 0 },
    }),
  },
  { name: "foundry jobs", method: "GET", route: "/v1/hypervisor/foundry/jobs" },
  { name: "foundry evals", method: "GET", route: "/v1/hypervisor/foundry/evals" },
  { name: "foundry packages", method: "GET", route: "/v1/hypervisor/foundry/packages" },
  {
    name: "foundry job proposal",
    method: "POST",
    route: "/v1/hypervisor/foundry/jobs/proposals",
    body: { job_ref: "foundry-job:harness-qwen-eval" },
    assert: (json) => ({
      ok: /foundry-job/i.test(String(json?.admission_id ?? json?.proposal_ref ?? "")),
      details: { admissionId: json?.admission_id ?? json?.proposal_ref ?? null },
    }),
  },
  {
    name: "automation run proposal",
    method: "POST",
    route: "/v1/hypervisor/automation-runs/proposals",
    body: { template_ref: "automation-template:reference-parity" },
    assert: (json) => ({
      ok: /automation-run/i.test(String(json?.admission_id ?? json?.proposal_ref ?? "")),
      details: { admissionId: json?.admission_id ?? json?.proposal_ref ?? null },
    }),
  },
  { name: "receipt evidence", method: "GET", route: "/v1/hypervisor/receipt-evidence" },
  { name: "receipts list", method: "GET", route: "/v1/hypervisor/receipts" },
  {
    name: "receipt detail",
    method: "GET",
    route: "/v1/hypervisor/receipts/transcript",
    assert: (json) => ({
      ok: /receipt:\/\//i.test(String(json?.receipt?.receipt_ref ?? "")),
      details: { receiptRef: json?.receipt?.receipt_ref ?? null },
    }),
  },
  {
    name: "replay detail",
    method: "GET",
    route: "/v1/hypervisor/replay/terminal-dev-replay",
    assert: (json) => ({
      ok: Array.isArray(json?.timeline) && json.timeline.length > 0,
      details: { timelineCount: Array.isArray(json?.timeline) ? json.timeline.length : 0 },
    }),
  },
  { name: "artifact refs", method: "GET", route: "/v1/hypervisor/artifact-refs" },
  {
    name: "archive restore validity",
    method: "GET",
    route: "/v1/hypervisor/archive-restore-validity",
    assert: (json) => ({
      ok: Boolean(json?.archive_restore_validity?.valid),
      details: {
        restoreRef: json?.archive_restore_validity?.restore_ref ?? null,
      },
    }),
  },
  {
    name: "local Qwen harness comparison",
    method: "POST",
    route: "/v1/hypervisor/harness-public-fixture-runs",
    body: {
      task_ref: "task:reference-parity/local-qwen",
      candidate_selection_refs: [
        "agent-harness-adapter:codex_cli",
        "agent-harness-adapter:deepseek_tui",
        "agent-harness-adapter:claude_code_cli",
        "agent-harness-adapter:generic_cli",
      ],
    },
    assert: (json) => {
      const reports = Array.isArray(json?.candidate_reports)
        ? json.candidate_reports
        : [];
      const labels = reports.map((report) => String(report?.label ?? ""));
      return {
        ok:
          reports.length >= 4 &&
          labels.some((label) => /Codex OSS \/ Qwen/i.test(label)) &&
          labels.some((label) => /DeepSeek TUI \/ Qwen/i.test(label)) &&
          labels.some((label) => /Claude Code example \/ Qwen/i.test(label)) &&
          labels.some((label) => /Generic CLI \/ Qwen/i.test(label)),
        details: { candidateReportCount: reports.length, labels },
      };
    },
  },
];

function parseArgs(argv) {
  const options = {
    reference: null,
    hypervisor: null,
    replay: DEFAULT_REPLAY_ENDPOINT,
    evidence: ".tmp/hypervisor-reference-parity-audit.json",
    timeoutMs: 20_000,
    waitMs: 1_800,
    screenshots: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--reference") options.reference = argv[++index];
    else if (arg === "--hypervisor") options.hypervisor = argv[++index];
    else if (arg === "--replay") options.replay = argv[++index];
    else if (arg === "--evidence") options.evidence = argv[++index];
    else if (arg === "--timeout-ms") options.timeoutMs = Number(argv[++index]);
    else if (arg === "--wait-ms") options.waitMs = Number(argv[++index]);
    else if (arg === "--no-screenshots") options.screenshots = false;
    else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!options.hypervisor) {
    throw new Error("--hypervisor is required");
  }
  return options;
}

function printUsage() {
  console.log(`Usage:
  node scripts/hypervisor-reference-parity-audit.mjs \\
    --reference http://127.0.0.1:9226 \\
    --hypervisor http://127.0.0.1:1420 \\
    --evidence .tmp/hypervisor-reference-parity-audit-final.json

Options:
  --replay <url>       Replay endpoint for direct route probes. Defaults to ${DEFAULT_REPLAY_ENDPOINT}
  --no-screenshots     Do not write route screenshots.
  --timeout-ms <n>     Browser navigation timeout.
  --wait-ms <n>        Post-load settling delay per route.`);
}

function normalizeBaseUrl(value) {
  if (!value) return null;
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function joinUrl(base, route) {
  return new URL(route, `${normalizeBaseUrl(base)}/`).toString();
}

function sanitizeRouteForFile(route) {
  if (route === "/") return "root";
  return route
    .replace(/^\//, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120);
}

function classifyRequest(url, resourceType) {
  const families = new Set();
  let pathname = "";
  try {
    pathname = new URL(url).pathname;
  } catch {
    pathname = url;
  }

  if (resourceType === "document") families.add("app_shell");
  if (["script", "stylesheet", "image", "font"].includes(resourceType)) {
    families.add("assets");
  }
  if (
    /\.(?:js|css|png|jpe?g|webp|svg|ico|woff2?|map)$/i.test(pathname) ||
    pathname.startsWith("/assets/")
  ) {
    families.add("assets");
  }
  if (
    pathname.startsWith("/api/") ||
    pathname.startsWith("/segment/") ||
    pathname.includes("/sentry-tunnel")
  ) {
    families.add("api_data");
  }
  if (
    pathname.startsWith("/v1/") ||
    pathname.startsWith("/supervisor/") ||
    pathname.includes("/supervisor.v1.")
  ) {
    families.add("daemon_core");
  }
  if (
    pathname.includes("/events") ||
    pathname.includes("/live") ||
    pathname.includes("/history") ||
    pathname.includes("EventStream")
  ) {
    families.add("streams_history");
  }
  if (
    pathname.includes("/workbench") ||
    pathname.includes("/workspace") ||
    pathname.includes("/terminal") ||
    pathname.includes("ResolveEditorURL") ||
    pathname.endsWith("/editor.html")
  ) {
    families.add("editor_workspace");
  }
  if (resourceType === "document" && !path.extname(pathname)) {
    families.add("fallbacks");
  }
  if (families.size === 0) families.add("other");
  return [...families];
}

function createFamilyCounter() {
  return {
    app_shell: 0,
    api_data: 0,
    daemon_core: 0,
    streams_history: 0,
    editor_workspace: 0,
    assets: 0,
    fallbacks: 0,
    other: 0,
  };
}

function addFamilies(counter, families) {
  for (const family of families) {
    counter[family] = (counter[family] ?? 0) + 1;
  }
}

function findHardMarkers(text) {
  const matches = [];
  for (const marker of HARD_MARKERS) {
    const match = text.match(marker);
    if (match) matches.push(match[0]);
  }
  return [...new Set(matches)];
}

function isBenignRequestFailure(url, failureText) {
  if (/ERR_ABORTED/i.test(failureText) && /\/events|\/live|\/history/i.test(url)) {
    return true;
  }
  return false;
}

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function auditRoute(browser, target, route, options) {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 980 },
    deviceScaleFactor: 1,
  });
  const url = joinUrl(target.baseUrl, route);
  const families = createFamilyCounter();
  const requests = [];
  const failedRequests = [];
  const badResponses = [];
  const consoleErrors = [];
  const consoleWarnings = [];
  const pageErrors = [];

  page.on("console", (message) => {
    const entry = {
      type: message.type(),
      text: message.text(),
      location: message.location(),
    };
    if (message.type() === "error") consoleErrors.push(entry);
    else if (message.type() === "warning") consoleWarnings.push(entry);
  });
  page.on("pageerror", (error) => {
    pageErrors.push({
      message: error.message,
      stack: String(error.stack ?? "").slice(0, 2_000),
    });
  });
  page.on("request", (request) => {
    const requestFamilies = classifyRequest(request.url(), request.resourceType());
    addFamilies(families, requestFamilies);
    requests.push({
      method: request.method(),
      url: request.url(),
      resourceType: request.resourceType(),
      families: requestFamilies,
    });
  });
  page.on("requestfailed", (request) => {
    const failureText = request.failure()?.errorText ?? "unknown";
    if (isBenignRequestFailure(request.url(), failureText)) return;
    failedRequests.push({
      method: request.method(),
      url: request.url(),
      resourceType: request.resourceType(),
      failureText,
    });
  });
  page.on("response", (response) => {
    const status = response.status();
    if (status >= 400) {
      badResponses.push({
        status,
        url: response.url(),
        resourceType: response.request().resourceType(),
      });
    }
  });

  const routeResult = {
    target: target.name,
    route,
    url,
    ok: false,
    status: null,
    bodyTextLength: 0,
    bodyTextSample: "",
    consoleErrors,
    consoleWarnings,
    pageErrors,
    failedRequests,
    badResponses,
    requestCount: 0,
    serviceRequestCount: 0,
    families,
    hardMarkers: [],
    screenshot: null,
    hypervisorRuntime: null,
  };

  try {
    const response = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: options.timeoutMs,
    });
    routeResult.status = response?.status() ?? null;
    await page.waitForTimeout(options.waitMs);

    const bodyText = await page
      .locator("body")
      .innerText({ timeout: 5_000 })
      .catch(() => "");
    routeResult.bodyTextLength = bodyText.length;
    routeResult.bodyTextSample = bodyText.replace(/\s+/g, " ").trim().slice(0, 1_200);
    routeResult.hardMarkers = findHardMarkers(
      `${bodyText}\n${consoleErrors.map((entry) => entry.text).join("\n")}\n${pageErrors
        .map((entry) => entry.message)
        .join("\n")}`,
    );

    if (target.name === "hypervisor") {
      routeResult.hypervisorRuntime = await page
        .evaluate(() => ({
          daemonEndpoint: window.localStorage.getItem("ioi.hypervisor.daemonEndpoint"),
          modelMountEndpoint: window.localStorage.getItem("ioi.modelMounts.daemonEndpoint"),
          devReplayReady: Boolean(window.__HYPERVISOR_DEV_REPLAY__),
          hostBridgeReady: Boolean(window.__HYPERVISOR_HOST_BRIDGE__),
        }))
        .catch((error) => ({ error: String(error?.message ?? error) }));
    }

    if (options.screenshots) {
      const screenshotPath = path.join(
        options.screenshotDir,
        target.name,
        `${sanitizeRouteForFile(route)}.png`,
      );
      await fs.mkdir(path.dirname(screenshotPath), { recursive: true });
      await page.screenshot({ path: screenshotPath, fullPage: false });
      routeResult.screenshot = screenshotPath;
    }
  } catch (error) {
    pageErrors.push({
      message: String(error?.message ?? error),
      stack: String(error?.stack ?? "").slice(0, 2_000),
    });
  } finally {
    routeResult.requestCount = requests.length;
    routeResult.serviceRequestCount = requests.filter((request) =>
      request.families.some((family) =>
        ["api_data", "daemon_core", "streams_history", "editor_workspace"].includes(family),
      ),
    ).length;
    routeResult.ok =
      routeResult.status !== null &&
      routeResult.status < 400 &&
      routeResult.bodyTextLength > 0 &&
      consoleErrors.length === 0 &&
      pageErrors.length === 0 &&
      failedRequests.length === 0 &&
      badResponses.length === 0 &&
      routeResult.hardMarkers.length === 0;
    await page.close().catch(() => undefined);
  }

  return routeResult;
}

async function auditTarget(browser, target, routes, options) {
  if (!target.baseUrl) {
    return {
      name: target.name,
      baseUrl: null,
      skipped: true,
      routes: [],
      totals: createTargetTotals([]),
    };
  }
  const routeResults = [];
  for (const route of routes) {
    routeResults.push(await auditRoute(browser, target, route, options));
  }
  return {
    name: target.name,
    baseUrl: target.baseUrl,
    skipped: false,
    routes: routeResults,
    totals: createTargetTotals(routeResults),
  };
}

function createTargetTotals(routes) {
  const families = createFamilyCounter();
  for (const route of routes) {
    for (const [family, count] of Object.entries(route.families ?? {})) {
      families[family] = (families[family] ?? 0) + count;
    }
  }
  return {
    routeCount: routes.length,
    okRoutes: routes.filter((route) => route.ok).length,
    requestCount: routes.reduce((sum, route) => sum + route.requestCount, 0),
    serviceRequestCount: routes.reduce((sum, route) => sum + route.serviceRequestCount, 0),
    consoleErrors: routes.reduce((sum, route) => sum + route.consoleErrors.length, 0),
    consoleWarnings: routes.reduce((sum, route) => sum + route.consoleWarnings.length, 0),
    pageErrors: routes.reduce((sum, route) => sum + route.pageErrors.length, 0),
    failedRequests: routes.reduce((sum, route) => sum + route.failedRequests.length, 0),
    badResponses: routes.reduce((sum, route) => sum + route.badResponses.length, 0),
    hardMarkers: routes.reduce((sum, route) => sum + route.hardMarkers.length, 0),
    families,
  };
}

async function fetchProbe(baseUrl, probe) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7_500);
  const startedAt = Date.now();
  try {
    const response = await fetch(joinUrl(baseUrl, probe.route), {
      method: probe.method,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: probe.body ? JSON.stringify(probe.body) : undefined,
      signal: controller.signal,
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    const assertion = probe.assert ? probe.assert(json) : { ok: true, details: {} };
    return {
      name: probe.name,
      route: probe.route,
      method: probe.method,
      ok: response.ok && assertion.ok,
      status: response.status,
      durationMs: Date.now() - startedAt,
      schemaVersion: json?.schema_version ?? null,
      assertion: assertion.details ?? {},
      bodyKeys: json && typeof json === "object" ? Object.keys(json).slice(0, 20) : [],
      bodySample: text.replace(/\s+/g, " ").trim().slice(0, 500),
    };
  } catch (error) {
    return {
      name: probe.name,
      route: probe.route,
      method: probe.method,
      ok: false,
      status: null,
      durationMs: Date.now() - startedAt,
      error: String(error?.message ?? error),
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchSseProbe(baseUrl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3_000);
  const route = "/v1/hypervisor/sessions/dev-replay-session/events";
  const startedAt = Date.now();
  try {
    const response = await fetch(joinUrl(baseUrl, route), {
      headers: { Accept: "text/event-stream" },
      signal: controller.signal,
    });
    const reader = response.body?.getReader();
    let text = "";
    if (reader) {
      const chunk = await reader.read();
      text = Buffer.from(chunk.value ?? []).toString("utf8");
      await reader.cancel().catch(() => undefined);
    }
    return {
      name: "session events stream",
      route,
      method: "GET",
      ok: response.ok && /event:\s*(session_state|readiness|terminal_chunk)/i.test(text),
      status: response.status,
      durationMs: Date.now() - startedAt,
      bodySample: text.replace(/\s+/g, " ").trim().slice(0, 500),
    };
  } catch (error) {
    return {
      name: "session events stream",
      route,
      method: "GET",
      ok: false,
      status: null,
      durationMs: Date.now() - startedAt,
      error: String(error?.message ?? error),
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function runReplayProbes(replayEndpoint) {
  const probes = [];
  for (const probe of DIRECT_REPLAY_PROBES) {
    probes.push(await fetchProbe(replayEndpoint, probe));
  }
  probes.push(await fetchSseProbe(replayEndpoint));
  return {
    endpoint: replayEndpoint,
    probes,
    totals: {
      probeCount: probes.length,
      okProbes: probes.filter((probe) => probe.ok).length,
      failedProbes: probes.filter((probe) => !probe.ok).length,
    },
  };
}

function isBlockingInteractionRequestFailure(entry) {
  return !/ERR_ABORTED/i.test(String(entry.failureText ?? ""));
}

async function runHypervisorInteractionProbes(browser, baseUrl, options) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 980 },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();
  const consoleErrors = [];
  const consoleWarnings = [];
  const pageErrors = [];
  const failedRequests = [];

  page.on("console", (message) => {
    const entry = {
      type: message.type(),
      text: message.text(),
      location: message.location(),
    };
    if (message.type() === "error") consoleErrors.push(entry);
    if (message.type() === "warning") consoleWarnings.push(entry);
  });
  page.on("pageerror", (error) => {
    pageErrors.push({
      message: error.message,
      stack: String(error.stack ?? "").slice(0, 2_000),
    });
  });
  page.on("requestfailed", (request) => {
    failedRequests.push({
      method: request.method(),
      url: request.url(),
      resourceType: request.resourceType(),
      failureText: request.failure()?.errorText ?? "unknown",
    });
  });

  async function goto(route, waitMs = options.waitMs) {
    await page.goto(joinUrl(baseUrl, route), {
      waitUntil: "domcontentloaded",
      timeout: options.timeoutMs,
    });
    await page.waitForTimeout(waitMs);
  }

  async function bodyText() {
    return page
      .locator("body")
      .innerText({ timeout: 5_000 })
      .then((text) => text.replace(/\s+/g, " ").trim())
      .catch(() => "");
  }

  const result = {
    ok: false,
    consoleErrors,
    consoleWarnings,
    pageErrors,
    failedRequests,
    blockingFailedRequests: [],
    maxUpdateDepthWarnings: 0,
    hardMarkers: [],
    runtime: null,
    leftNavSurfaces: "",
    applicationsLauncher: {
      ok: false,
      // Canon: Applications is a query/modal catalog launcher, not a pinned rail.
      launcherPresent: false,
      // Canon: `Open Application` is a singular active slot (<= 1 in the rail).
      openApplicationCount: 0,
      // The obsolete permanent pinned rail must be gone.
      pinnedRailNodeCount: 0,
      // Required specialized surfaces must remain reachable via the catalog.
      requiredCatalogIds: [
        "foundry",
        "models",
        "workers",
        "connectors",
        "policies",
        "receipts",
        "monitoring",
      ],
    },
    workbench: {
      ok: false,
      workspaceHostCount: 0,
      noEditorOpenCount: 0,
      terminalPanelCount: 0,
      terminalProjectionOk: false,
      documentTabCount: 0,
    },
    newSession: {
      ok: false,
      choices: [],
      agentOptions: [],
      selectedAgentLabel: "",
      launchedSessionCount: 0,
      transcriptLineCount: 0,
      modelName: "",
      receiptRefsVisible: false,
    },
    applications: {
      ok: false,
      count: 0,
      ids: [],
    },
    automations: {
      ok: false,
      proposalRef: "",
      admissionState: "",
    },
    foundry: {
      ok: false,
      candidateCount: 0,
      state: "",
    },
    receipts: {
      ok: false,
      recordCount: 0,
      selectedReceiptRef: "",
      replayRef: "",
    },
  };

  try {
    await goto("/workbench", Math.max(options.waitMs, 4_000));
    result.runtime = await page
      .evaluate(() => ({
        daemonEndpoint: window.localStorage.getItem("ioi.hypervisor.daemonEndpoint"),
        modelMountEndpoint: window.localStorage.getItem("ioi.modelMounts.daemonEndpoint"),
        devReplayReady: Boolean(window.__HYPERVISOR_DEV_REPLAY__),
        hostBridgeReady: Boolean(window.__HYPERVISOR_HOST_BRIDGE__),
      }))
      .catch((error) => ({ error: String(error?.message ?? error) }));
    result.leftNavSurfaces =
      (await page
        .locator("[data-left-nav-surfaces]")
        .first()
        .getAttribute("data-left-nav-surfaces")
        .catch(() => "")) ?? "";
    result.applicationsLauncher.launcherPresent =
      (await page
        .locator("[data-applications-launcher]")
        .count()
        .catch(() => 0)) > 0;
    result.applicationsLauncher.openApplicationCount = await page
      .locator("[data-open-application]")
      .count()
      .catch(() => 0);
    result.applicationsLauncher.pinnedRailNodeCount = await page
      .locator("[data-pinned-application-id]")
      .count()
      .catch(() => 0);
    result.applicationsLauncher.ok =
      result.applicationsLauncher.launcherPresent &&
      result.applicationsLauncher.openApplicationCount <= 1 &&
      result.applicationsLauncher.pinnedRailNodeCount === 0;
    result.workbench.workspaceHostCount = await page
      .locator(".hypervisor-workspace-host")
      .count()
      .catch(() => 0);
    result.workbench.noEditorOpenCount = await page
      .getByText("No editor open", { exact: false })
      .count()
      .catch(() => 0);
    result.workbench.terminalPanelCount = await page
      .locator(".workspace-terminal-panel")
      .count()
      .catch(() => 0);
    result.workbench.documentTabCount = await page
      .locator("[data-workspace-document-id]")
      .count()
      .catch(() => 0);
    const terminalText = await page
      .locator(".workspace-terminal-view")
      .innerText({ timeout: 5_000 })
      .catch(() => "");
    result.workbench.terminalProjectionOk =
      /Hypervisor dev replay|Qwen local/i.test(terminalText);
    result.workbench.ok =
      result.workbench.workspaceHostCount > 0 &&
      result.workbench.noEditorOpenCount === 0 &&
      result.workbench.terminalPanelCount > 0 &&
      result.workbench.documentTabCount > 0 &&
      result.workbench.terminalProjectionOk;

    await page.locator('[data-window-surface="new-session"]').first().click();
    await page.waitForTimeout(500);
    result.newSession.choices = await page
      .locator("[data-new-session-start-mode]")
      .evaluateAll((nodes) =>
        nodes.map((node) => node.textContent?.replace(/\s+/g, " ").trim() ?? ""),
      )
      .catch(() => []);
    await page.locator('[data-new-session-start-mode="scratch"]').click();
    await page.waitForTimeout(500);
    const agentSelect = page
      .locator(".hypervisor-new-session-modal__configure select")
      .first();
    result.newSession.agentOptions = await agentSelect
      .locator("option")
      .evaluateAll((nodes) =>
        nodes.map((node) => node.textContent?.replace(/\s+/g, " ").trim() ?? ""),
      )
      .catch(() => []);
    await agentSelect.selectOption({ label: "DeepSeek TUI / Qwen" });
    result.newSession.selectedAgentLabel = await agentSelect
      .locator("option:checked")
      .innerText()
      .catch(() => "");
    await page
      .locator(".hypervisor-new-session-modal__configure textarea")
      .first()
      .fill("Audit route-backed local Qwen session launch.");
    await page.locator('[data-new-session-start-selected="true"]').click();
    await page.waitForTimeout(Math.max(options.waitMs, 2_200));
    result.newSession.launchedSessionCount = await page
      .locator("[data-launched-session-ref]")
      .count()
      .catch(() => 0);
    result.newSession.transcriptLineCount = Number(
      (await page
        .locator("[data-launched-session-terminal-transcript-lines]")
        .first()
        .getAttribute("data-launched-session-terminal-transcript-lines")
        .catch(() => "0")) ?? "0",
    );
    result.newSession.modelName =
      (await page
        .locator("[data-launched-session-model-name]")
        .first()
        .getAttribute("data-launched-session-model-name")
        .catch(() => "")) ?? "";
    result.newSession.receiptRefsVisible = /receipt:\/\//i.test(await bodyText());
    result.newSession.ok =
      result.newSession.choices.some((choice) => /Start from project/i.test(choice)) &&
      result.newSession.choices.some((choice) => /Start from URL/i.test(choice)) &&
      result.newSession.choices.some((choice) => /Start from scratch/i.test(choice)) &&
      [
        "Codex OSS / Qwen",
        "DeepSeek TUI / Qwen",
        "Claude Code example / Qwen",
        "Generic CLI / Qwen",
      ].every((label) => result.newSession.agentOptions.includes(label)) &&
      /DeepSeek TUI \/ Qwen/i.test(result.newSession.selectedAgentLabel) &&
      result.newSession.launchedSessionCount > 0 &&
      result.newSession.transcriptLineCount > 0 &&
      /qwen/i.test(result.newSession.modelName);

    await goto("/applications");
    result.applications.ids = await page
      .locator("[data-hypervisor-application-id]")
      .evaluateAll((nodes) =>
        nodes.map((node) => node.getAttribute("data-hypervisor-application-id") ?? ""),
      )
      .catch(() => []);
    result.applications.count = result.applications.ids.length;
    result.applications.ok = result.applicationsLauncher.requiredCatalogIds.every(
      (id) => result.applications.ids.includes(id),
    );

    await goto("/automations");
    await page
      .locator("[data-automation-run-proposal-template]")
      .first()
      .click({ timeout: 5_000 })
      .catch(() => undefined);
    await page.waitForTimeout(1_000);
    result.automations.proposalRef =
      (await page
        .locator("[data-automation-run-proposal]")
        .first()
        .getAttribute("data-automation-run-proposal")
        .catch(() => "")) ?? "";
    result.automations.admissionState =
      (await page
        .locator("[data-automation-run-admission-state]")
        .first()
        .getAttribute("data-automation-run-admission-state")
        .catch(() => "")) ?? "";
    result.automations.ok =
      /automation/i.test(result.automations.proposalRef) &&
      result.automations.admissionState.length > 0;

    await goto("/foundry");
    result.foundry.state =
      (await page
        .locator("[data-hypervisor-harness-comparison-state]")
        .first()
        .getAttribute("data-hypervisor-harness-comparison-state")
        .catch(() => "")) ?? "";
    result.foundry.candidateCount = await page
      .locator("[data-harness-comparison-candidate]")
      .count()
      .catch(() => 0);
    result.foundry.ok =
      result.foundry.candidateCount >= 4 && /admitted|loading|requesting/.test(result.foundry.state);

    await goto("/receipts");
    result.receipts.recordCount = await page
      .locator("[data-receipt-evidence-record]")
      .count()
      .catch(() => 0);
    await page
      .locator("[data-receipt-evidence-review]")
      .nth(1)
      .click({ timeout: 3_000 })
      .catch(() => undefined);
    await page.waitForTimeout(500);
    result.receipts.selectedReceiptRef =
      (await page
        .locator("[data-receipt-evidence-detail]")
        .first()
        .getAttribute("data-receipt-evidence-detail")
        .catch(() => "")) ?? "";
    result.receipts.replayRef =
      (await page
        .locator("[data-receipt-evidence-replay-ref]")
        .first()
        .getAttribute("data-receipt-evidence-replay-ref")
        .catch(() => "")) ?? "";
    result.receipts.ok =
      result.receipts.recordCount > 0 &&
      /receipt:\/\//i.test(result.receipts.selectedReceiptRef) &&
      /replay/i.test(result.receipts.replayRef);

    const finalText = await bodyText();
    result.hardMarkers = findHardMarkers(
      `${finalText}\n${consoleErrors.map((entry) => entry.text).join("\n")}\n${pageErrors
        .map((entry) => entry.message)
        .join("\n")}`,
    );
    result.maxUpdateDepthWarnings = consoleWarnings.filter((entry) =>
      /Maximum update depth exceeded/i.test(entry.text),
    ).length;
    result.blockingFailedRequests = failedRequests.filter(
      isBlockingInteractionRequestFailure,
    );
    result.ok =
      consoleErrors.length === 0 &&
      pageErrors.length === 0 &&
      result.blockingFailedRequests.length === 0 &&
      result.maxUpdateDepthWarnings === 0 &&
      result.hardMarkers.length === 0 &&
      result.runtime?.daemonEndpoint &&
      result.runtime?.modelMountEndpoint &&
      result.runtime?.devReplayReady === true &&
      result.runtime?.hostBridgeReady === true &&
      result.applicationsLauncher.ok &&
      result.workbench.ok &&
      result.newSession.ok &&
      result.applications.ok &&
      result.automations.ok &&
      result.foundry.ok &&
      result.receipts.ok;
  } catch (error) {
    pageErrors.push({
      message: String(error?.message ?? error),
      stack: String(error?.stack ?? "").slice(0, 2_000),
    });
    result.blockingFailedRequests = failedRequests.filter(
      isBlockingInteractionRequestFailure,
    );
    result.ok = false;
  } finally {
    await context.close().catch(() => undefined);
  }

  return result;
}

function summarizeFailures(evidence) {
  const failures = [];
  const hypervisor = evidence.targets.hypervisor;
  if (hypervisor.totals.consoleErrors > 0) {
    failures.push(`Hypervisor console errors: ${hypervisor.totals.consoleErrors}`);
  }
  if (hypervisor.totals.pageErrors > 0) {
    failures.push(`Hypervisor page errors: ${hypervisor.totals.pageErrors}`);
  }
  if (hypervisor.totals.failedRequests > 0) {
    failures.push(`Hypervisor failed requests: ${hypervisor.totals.failedRequests}`);
  }
  if (hypervisor.totals.badResponses > 0) {
    failures.push(`Hypervisor bad responses: ${hypervisor.totals.badResponses}`);
  }
  if (hypervisor.totals.hardMarkers > 0) {
    failures.push(`Hypervisor hard marker matches: ${hypervisor.totals.hardMarkers}`);
  }
  const combinedFamilyCoverage = evidence.comparison.hypervisorCombinedRequiredFamilies ?? {};
  const missingFamilies = REQUIRED_HYPERVISOR_FAMILIES.filter(
    (family) => combinedFamilyCoverage[family] !== true,
  );
  if (missingFamilies.length > 0) {
    failures.push(`Hypervisor missing route families: ${missingFamilies.join(", ")}`);
  }
  const badRuntimeRoutes = hypervisor.routes.filter((route) => {
    if (route.route === "/") return false;
    const runtime = route.hypervisorRuntime;
    return (
      runtime &&
      (!runtime.daemonEndpoint ||
        !runtime.modelMountEndpoint ||
        runtime.devReplayReady !== true ||
        runtime.hostBridgeReady !== true)
    );
  });
  if (badRuntimeRoutes.length > 0) {
    failures.push(
      `Hypervisor dev replay runtime not seeded on routes: ${badRuntimeRoutes
        .map((route) => route.route)
        .join(", ")}`,
    );
  }
  const workbench = hypervisor.routes.find((route) => route.route === "/workbench");
  if (!workbench?.ok) failures.push("Workbench route did not pass route audit");
  if (workbench && workbench.serviceRequestCount === 0) {
    failures.push("Workbench did not issue replay/daemon-shaped requests");
  }
  if (evidence.replayRouteProbes.totals.failedProbes > 0) {
    failures.push(`Replay route probe failures: ${evidence.replayRouteProbes.totals.failedProbes}`);
  }
  const interactions = evidence.hypervisorInteractionProbes;
  if (!interactions?.ok) {
    failures.push("Hypervisor interaction probes did not pass");
    for (const [key, value] of Object.entries(interactions ?? {})) {
      if (
        value &&
        typeof value === "object" &&
        "ok" in value &&
        value.ok !== true
      ) {
        failures.push(`Interaction probe failed: ${key}`);
      }
    }
    if ((interactions?.consoleErrors?.length ?? 0) > 0) {
      failures.push(`Interaction console errors: ${interactions.consoleErrors.length}`);
    }
    if ((interactions?.pageErrors?.length ?? 0) > 0) {
      failures.push(`Interaction page errors: ${interactions.pageErrors.length}`);
    }
    if ((interactions?.blockingFailedRequests?.length ?? 0) > 0) {
      failures.push(
        `Interaction failed requests: ${interactions.blockingFailedRequests.length}`,
      );
    }
    if ((interactions?.maxUpdateDepthWarnings ?? 0) > 0) {
      failures.push("Workbench emitted Maximum update depth warning");
    }
  }
  for (const [key, value] of Object.entries(evidence.completionChecklist ?? {})) {
    if (value !== true) {
      failures.push(`Completion checklist failed: ${key}`);
    }
  }
  return failures;
}

function createReplayFamilyCoverage(replayRouteProbes) {
  const okProbeNames = new Set(
    replayRouteProbes.probes
      .filter((probe) => probe.ok)
      .map((probe) => probe.name),
  );
  return {
    daemon_core: replayRouteProbes.totals.okProbes > 0,
    streams_history:
      okProbeNames.has("session events stream") &&
      okProbeNames.has("session history"),
    editor_workspace:
      okProbeNames.has("workbench snapshot") &&
      okProbeNames.has("workbench files"),
  };
}

function replayProbeOk(evidence, name) {
  return Boolean(
    evidence.replayRouteProbes?.probes?.some(
      (probe) => probe.name === name && probe.ok,
    ),
  );
}

function createCompletionChecklist(evidence) {
  const interactions = evidence.hypervisorInteractionProbes;
  const hypervisorRoutes = evidence.targets.hypervisor?.routes ?? [];
  const referenceLeftNav = ["home", "projects", "automations", "applications", "sessions"];
  const firstRouteRuntime = hypervisorRoutes.find((route) => route.route !== "/")
    ?.hypervisorRuntime;

  return {
    local_dev_replay_server_starts: replayProbeOk(evidence, "dev replay status"),
    dev_endpoint_seeding_works:
      interactions?.runtime?.daemonEndpoint === evidence.options.replay &&
      interactions?.runtime?.modelMountEndpoint === evidence.options.replay &&
      interactions?.runtime?.devReplayReady === true,
    host_bridge_missing_degrades_to_replay:
      interactions?.runtime?.hostBridgeReady === true,
    models_route_has_no_connection_refused:
      replayProbeOk(evidence, "model snapshot") &&
      replayProbeOk(evidence, "model capabilities"),
    authority_route_has_no_failed_runtime_fetches:
      replayProbeOk(evidence, "authority") &&
      replayProbeOk(evidence, "authority evidence"),
    workbench_opens_default_project_workspace_session:
      interactions?.workbench?.ok === true,
    workbench_has_no_max_update_depth_warning:
      interactions?.maxUpdateDepthWarnings === 0,
    sessions_launch_through_local_qwen_agent_harness_adapter:
      interactions?.newSession?.ok === true,
    terminal_transcript_projection_appears_in_sessions_and_workbench:
      interactions?.newSession?.transcriptLineCount > 0 &&
      interactions?.workbench?.terminalProjectionOk === true &&
      replayProbeOk(evidence, "workbench terminal read"),
    receipts_replay_refs_appear_for_sessions_and_projects:
      interactions?.receipts?.ok === true &&
      replayProbeOk(evidence, "receipts list") &&
      replayProbeOk(evidence, "replay detail"),
    shell_ia_is_home_projects_automations_applications_sessions:
      interactions?.leftNavSurfaces === referenceLeftNav.join(" "),
    applications_launcher_singular_open_application_and_catalog:
      interactions?.applicationsLauncher?.ok === true &&
      interactions?.applications?.ok === true,
    automations_foundry_receipts_are_route_backed_and_interactive:
      interactions?.automations?.ok === true &&
      interactions?.foundry?.ok === true &&
      interactions?.receipts?.ok === true &&
      replayProbeOk(evidence, "automation run proposal") &&
      replayProbeOk(evidence, "foundry job proposal"),
    no_missing_daemon_or_host_bridge_errors:
      interactions?.hardMarkers?.length === 0 &&
      Boolean(firstRouteRuntime?.daemonEndpoint),
    playright_side_by_side_runtime_gate_passes:
      evidence.targets.hypervisor?.totals?.okRoutes ===
        evidence.targets.hypervisor?.totals?.routeCount &&
      evidence.replayRouteProbes?.totals?.failedProbes === 0 &&
      interactions?.ok === true,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  options.reference = normalizeBaseUrl(options.reference);
  options.hypervisor = normalizeBaseUrl(options.hypervisor);
  options.replay = normalizeBaseUrl(options.replay);
  options.screenshotDir = path.join(
    path.dirname(options.evidence),
    `${path.basename(options.evidence, path.extname(options.evidence))}-screenshots`,
  );

  await ensureDir(options.evidence);
  if (options.screenshots) await fs.mkdir(options.screenshotDir, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  let referenceAudit = null;
  let hypervisorAudit = null;
  let hypervisorInteractionProbes = null;
  try {
    referenceAudit = await auditTarget(
      browser,
      { name: "reference", baseUrl: options.reference },
      DEFAULT_REFERENCE_ROUTES,
      options,
    );
    hypervisorAudit = await auditTarget(
      browser,
      { name: "hypervisor", baseUrl: options.hypervisor },
      DEFAULT_HYPERVISOR_ROUTES,
      options,
    );
    hypervisorInteractionProbes = await runHypervisorInteractionProbes(
      browser,
      options.hypervisor,
      options,
    );
  } finally {
    await browser.close();
  }

  const replayRouteProbes = await runReplayProbes(options.replay);
  const replayFamilyCoverage = createReplayFamilyCoverage(replayRouteProbes);
  const evidence = {
    generatedAt: new Date().toISOString(),
    generated_at: new Date().toISOString(),
    options: {
      reference: options.reference,
      hypervisor: options.hypervisor,
      replay: options.replay,
      screenshots: options.screenshots ? options.screenshotDir : null,
      timeoutMs: options.timeoutMs,
      waitMs: options.waitMs,
    },
    routeSets: {
      reference: DEFAULT_REFERENCE_ROUTES,
      hypervisor: DEFAULT_HYPERVISOR_ROUTES,
    },
    targets: {
      reference: referenceAudit,
      hypervisor: hypervisorAudit,
    },
    replayRouteProbes,
    hypervisorInteractionProbes,
    comparison: {
      referenceCleanlinessAuthority:
        "npm run check:ioi-reference is the authoritative reference mirror cleanliness gate; this side-by-side audit records persistent mirror noise but fails on Hypervisor parity regressions.",
      referenceServiceRequests: referenceAudit?.totals?.serviceRequestCount ?? 0,
      hypervisorServiceRequests: hypervisorAudit?.totals?.serviceRequestCount ?? 0,
      hypervisorRequiredFamilies: Object.fromEntries(
        REQUIRED_HYPERVISOR_FAMILIES.map((family) => [
          family,
          (hypervisorAudit?.totals?.families?.[family] ?? 0) > 0,
        ]),
      ),
      replayFamilyCoverage,
      hypervisorCombinedRequiredFamilies: Object.fromEntries(
        REQUIRED_HYPERVISOR_FAMILIES.map((family) => [
          family,
          (hypervisorAudit?.totals?.families?.[family] ?? 0) > 0 ||
            replayFamilyCoverage[family] === true,
        ]),
      ),
    },
  };
  evidence.completionChecklist = createCompletionChecklist(evidence);
  evidence.final_evidence_shape = {
    generated_at: evidence.generated_at,
    reference: {
      base_url: options.reference,
      routes: referenceAudit?.routes ?? [],
      console_errors: referenceAudit?.totals?.consoleErrors ?? 0,
      failed_assets: referenceAudit?.totals?.failedRequests ?? 0,
      route_families: referenceAudit?.totals?.families ?? {},
    },
    hypervisor: {
      base_url: options.hypervisor,
      routes: hypervisorAudit?.routes ?? [],
      console_errors: hypervisorAudit?.totals?.consoleErrors ?? 0,
      failed_assets: hypervisorAudit?.totals?.failedRequests ?? 0,
      bad_responses: hypervisorAudit?.routes?.flatMap((route) => route.badResponses) ?? [],
      route_families: hypervisorAudit?.totals?.families ?? {},
      screenshots: hypervisorAudit?.routes?.map((route) => route.screenshot).filter(Boolean) ?? [],
      workbench: {
        render_loop_warnings: hypervisorInteractionProbes?.maxUpdateDepthWarnings ?? null,
        host_bridge_errors:
          hypervisorInteractionProbes?.hardMarkers?.filter((marker) =>
            /host bridge/i.test(marker),
          ).length ?? null,
        default_editor_open:
          hypervisorInteractionProbes?.workbench?.documentTabCount > 0 &&
          hypervisorInteractionProbes?.workbench?.noEditorOpenCount === 0,
      },
      models: {
        snapshot_ok: replayProbeOk(evidence, "model snapshot"),
      },
      authority: {
        evidence_ok: replayProbeOk(evidence, "authority evidence"),
      },
      sessions: {
        events_stream_ok: replayProbeOk(evidence, "session events stream"),
        terminal_projection_ok:
          hypervisorInteractionProbes?.newSession?.transcriptLineCount > 0,
      },
    },
  };
  evidence.failures = summarizeFailures(evidence);
  evidence.ok = evidence.failures.length === 0;

  await fs.writeFile(options.evidence, `${JSON.stringify(evidence, null, 2)}\n`);

  console.log(
    `[hypervisor-reference-parity-audit] ${evidence.ok ? "PASS" : "FAIL"} ` +
      `hypervisor routes ${hypervisorAudit.totals.okRoutes}/${hypervisorAudit.totals.routeCount}; ` +
      `replay probes ${replayRouteProbes.totals.okProbes}/${replayRouteProbes.totals.probeCount}; ` +
      `evidence ${options.evidence}`,
  );
  if (!evidence.ok) {
    for (const failure of evidence.failures) console.error(`- ${failure}`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
