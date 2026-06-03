#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { chromium } from "playwright";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./autopilot-electron-app-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./autopilot-workbench-shell-patch.mjs";

const repoRoot = AUTOPILOT_ELECTRON.repoRoot;
const evidenceRoot =
  process.env.AUTOPILOT_HISTORIC_RUN_GUI_REPLAY_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-9-evidence-replay-product-boundary/historic-run-gui-replay";
const traceRefsPath =
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-9-evidence-replay-product-boundary/trace-refs.json";

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForChildExit(child, timeoutMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(false);
    }, timeoutMs);
    function onExit() {
      clearTimeout(timer);
      resolve(true);
    }
    child.once("exit", onExit);
  });
}

async function waitForPredicate(predicate, timeoutMs, intervalMs = 250) {
  const deadline = Date.now() + timeoutMs;
  let latest;
  while (Date.now() < deadline) {
    latest = await predicate();
    if (latest) return latest;
    await wait(intervalMs);
  }
  return latest;
}

function listen(server) {
  return new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen(server.address());
    });
  });
}

function closeServer(server) {
  return new Promise((resolveClose) => {
    if (!server) {
      resolveClose();
      return;
    }
    server.close(() => resolveClose());
  });
}

async function getFreePort() {
  const server = createNetServer();
  await listen(server);
  const { port } = server.address();
  await closeServer(server);
  return port;
}

async function waitForCdp(port, timeoutMs = 45_000) {
  return waitForPredicate(async () => {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      return response.ok ? response.json() : null;
    } catch {
      return null;
    }
  }, timeoutMs, 500);
}

function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
  });
  response.end(body);
}

function readRequestBody(request) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("error", rejectBody);
    request.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolveBody(raw ? JSON.parse(raw) : {});
      } catch (error) {
        rejectBody(error);
      }
    });
  });
}

function bridgeState(daemonEndpoint) {
  return {
    schemaVersion: "ioi.workbench-bridge-state.v1",
    generatedAtMs: Date.now(),
    workspace: {
      name: "ioi",
      path: repoRoot,
      rootPath: repoRoot,
    },
    summary: {
      activeRunCount: 0,
      policyIssueCount: 0,
      connectorCount: 0,
    },
    modelMountingStatus: {
      status: "connected",
      endpoint: daemonEndpoint,
    },
    modelMounting: {
      routes: [],
      server: {
        status: "running",
        endpoint: daemonEndpoint,
      },
    },
    workflows: [],
    runs: [],
    policy: {
      activeIssueCount: 0,
      issues: [],
    },
    connections: [],
  };
}

function createBridge({ daemonEndpoint, requests, commands, deliveredCommands }) {
  return createServer(async (request, response) => {
    try {
      if (request.method === "OPTIONS") {
        sendJson(response, 204, {});
        return;
      }
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/state") {
        sendJson(response, 200, bridgeState(daemonEndpoint));
        return;
      }
      if (request.method === "GET" && url.pathname === "/commands") {
        const next = commands.splice(0);
        deliveredCommands.push(...next);
        sendJson(response, 200, next);
        return;
      }
      if (request.method === "POST" && url.pathname === "/requests") {
        const body = await readRequestBody(request);
        requests.push(body);
        sendJson(response, 200, { ok: true });
        return;
      }
      sendJson(response, 404, { error: "not_found" });
    } catch (error) {
      sendJson(response, 500, { error: String(error?.message ?? error) });
    }
  });
}

function queueCommand(commands, command, payload = {}) {
  const commandId = `${command}:${Date.now()}:${commands.length}`;
  commands.push({ commandId, command, args: [payload] });
  return commandId;
}

async function cleanupProofUserDataProcesses(userDataDir) {
  if (!userDataDir) return;
  for (const signal of ["TERM", "KILL"]) {
    const pgrep = spawnSync("pgrep", ["-f", userDataDir], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const pids = String(pgrep.stdout || "")
      .split(/\s+/)
      .map((value) => Number(value))
      .filter((pid) => Number.isInteger(pid) && pid > 1 && pid !== process.pid);
    if (pids.length > 0) {
      spawnSync("kill", [`-${signal}`, ...pids.map(String)], { stdio: "ignore" });
      await wait(signal === "TERM" ? 900 : 250);
    }
  }
}

async function requireNewRequest(requests, predicate, label, startIndex = requests.length, timeoutMs = 45_000) {
  const request = await waitForPredicate(
    () => requests.slice(startIndex).find((candidate) => predicate(candidate)),
    timeoutMs,
    300,
  );
  if (!request) throw new Error(`Timed out waiting for bridge request: ${label}`);
  return request;
}

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    for (const candidate of page.frames()) {
      try {
        if ((await candidate.locator(selector).count()) > 0) return candidate;
      } catch {
        // VS Code swaps webview frames during startup.
      }
    }
    return null;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function publicReplayRows(traceSummary) {
  const observed = new Set(traceSummary.observedToolNames || []);
  const rows = [
    {
      id: "historic-replay.thread-started",
      kind: "historic.thread",
      status: "completed",
      summary: "Loaded archived daemon thread start.",
    },
    {
      id: "historic-replay.browser-observed",
      kind: "historic.browser.observation",
      status: "completed",
      summary: observed.has("browser__inspect")
        ? "Replayed browser observation from archived evidence."
        : "Archived browser observation was unavailable.",
    },
    {
      id: "historic-replay.browser-action",
      kind: "historic.browser.action",
      status: "completed",
      summary: observed.has("browser__click_at") || observed.has("browser__click")
        ? "Replayed browser action from archived evidence."
        : "Archived browser action was unavailable.",
    },
    {
      id: "historic-replay.final-handoff",
      kind: "historic.final_handoff",
      status: "completed",
      summary: observed.has("chat__reply")
        ? "Replayed final handoff from archived evidence."
        : "Archived final handoff was unavailable.",
    },
  ];
  return rows.map((row) => ({
    ...row,
    receiptRefs: ["receipt_stage9_historic_replay"],
  }));
}

function buildHistoricReplayBundle(outputDir) {
  const traceRefs = loadJson(traceRefsPath);
  const summaryRef = traceRefs.refs.find((ref) => ref.kind === "daemon_trace_summary");
  const liveProofRef = traceRefs.refs.find((ref) => ref.kind === "live_gui_proof");
  if (!summaryRef?.path || !liveProofRef?.path) {
    throw new Error("Stage 9 trace refs do not include the live proof and daemon trace summary.");
  }
  const traceSummary = loadJson(summaryRef.path);
  const liveProof = loadJson(liveProofRef.path);
  const rows = publicReplayRows(traceSummary);
  const sourceInventory = {
    traceRefsPath,
    liveProofPath: liveProofRef.path,
    daemonTraceSummaryPath: summaryRef.path,
    observedToolNames: traceSummary.observedToolNames || [],
    observedEventKinds: traceSummary.observedEventKinds || [],
    sourceScenarioId: liveProof.scenarioId || null,
  };
  writeFileSync(join(outputDir, "historic-replay-source-inventory.json"), `${JSON.stringify(sourceInventory, null, 2)}\n`);
  const trajectoryEvent = {
    id: "stage9.historic.trajectory-replay",
    event_id: "stage9.historic.trajectory-replay",
    event_kind: "trajectory.replay",
    kind: "trajectory.replay",
    status: "ready",
    summary: "Historic run replay loaded from archived evidence without live tool execution.",
    receiptRefs: ["receipt_stage9_historic_replay"],
    payload_summary: {
      schemaVersion: "ioi.studio.trajectory_replay.v1",
      status: "ready",
      detail: "Historic run replay loaded from archived evidence without live tool execution.",
      trajectoryIdStable: true,
      replayCursorObserved: true,
      guiReconnected: false,
      replayIdsStable: true,
      replayFromCursorEmpty: true,
      sideEffectCount: 0,
      duplicateSideEffectCount: 0,
      rows,
    },
  };
  const events = [
    trajectoryEvent,
    ...rows.map((row, index) => ({
      id: row.id,
      event_id: row.id,
      event_kind: row.kind,
      kind: row.kind,
      seq: index + 1,
      status: row.status,
      summary: row.summary,
      receiptRefs: row.receiptRefs,
      payload_summary: {
        schemaVersion: "ioi.stage9.historic_replay_row.v1",
        status: row.status,
        summary: row.summary,
        redaction: "applied_before_projection",
        source: "archived_evidence",
      },
    })),
  ];
  const turns = [
    {
      role: "assistant",
      content: "Historic run replay loaded from archived evidence. No live tool execution was requested.",
      createdAt: new Date().toISOString(),
      receiptRefs: ["receipt_stage9_historic_replay"],
    },
  ];
  return { traceRefs, traceSummary, liveProof, rows, events, turns, sourceInventory };
}

async function replayDomEvidence(frame) {
  const replayRows = await frame.locator('[data-testid="studio-replay-step-detail"]').evaluateAll((nodes) =>
    nodes.map((node) => ({
      text: node.textContent || "",
      kind: node.querySelector("strong")?.textContent || "",
      id: node.querySelector("code")?.textContent || "",
      summary: node.querySelector("span")?.textContent || "",
    })),
  );
  const panel = frame.locator('[data-testid="studio-trajectory-replay-panel"]').first();
  const panelEvidence = {
    count: await panel.count(),
    visible: await panel.isVisible().catch(() => false),
    status: await panel.getAttribute("data-panel-status").catch(() => null),
    traceLinkCount: await panel.locator('[data-testid="studio-view-trace-link"]').count().catch(() => 0),
    verifiedBadgeCount: await panel.locator('[data-testid="studio-verified-badge"]').count().catch(() => 0),
    text: await panel.textContent().catch(() => ""),
  };
  const drawerText = await frame.locator('[data-testid="studio-utility-drawer"]').first().textContent().catch(() => "");
  return { replayRows, panel: panelEvidence, drawerText };
}

function replayReady(evidence) {
  const ids = new Set(evidence.replayRows.map((row) => row.id));
  return (
    evidence.panel.status === "ready" &&
    evidence.panel.visible &&
    evidence.panel.traceLinkCount > 0 &&
    evidence.panel.verifiedBadgeCount > 0 &&
    ids.has("historic-replay.browser-observed") &&
    ids.has("historic-replay.browser-action") &&
    ids.has("historic-replay.final-handoff")
  );
}

async function expandStudioUtilityDrawer(frame, timeoutMs = 10_000) {
  return waitForPredicate(async () => {
    try {
      if ((await frame.locator('[data-testid="studio-utility-drawer"].is-expanded').count()) > 0) return true;
      const toggle = frame.locator('[data-testid="studio-utility-toggle"]').first();
      await toggle.click({ timeout: 1500 }).catch(async () => {
        await frame.evaluate(() => {
          document.querySelector('[data-testid="studio-utility-toggle"]')?.click();
        });
      });
      return (await frame.locator('[data-testid="studio-utility-drawer"].is-expanded').count()) > 0;
    } catch {
      return false;
    }
  }, timeoutMs, 250);
}

function liveExecutionRequests(requests, deliveredCommands) {
  const allowedRequestTypes = new Set([
    "runs.open",
    "studio.open",
    "studio.parityPlusEvents.injected",
    "workbench.commandRouteReceipt",
    "workbench.contextSnapshot",
    "workbench.inspectionTargetIndex",
  ]);
  const executionRequestPattern =
    /(^|\.)chat\.(submit|send)$|(^|\.)agent\.(start|submit|resume|retry|invoke)$|(^|\.)model\.(complete|completion|invoke|request|submit)|(^|\.)tool\.(execute|invoke|request|submit)|completion\.create|toolCall|tool_call/i;
  const requestMatches = requests.filter((request) => {
    const requestType = String(request?.requestType || "");
    if (allowedRequestTypes.has(requestType)) return false;
    return executionRequestPattern.test(requestType);
  });
  const allowedCommands = new Set(["ioi.studio.open", "ioi.studio.injectParityPlusEvents"]);
  const commandMatches = deliveredCommands.filter((command) => {
    const commandId = String(command?.command || "");
    if (allowedCommands.has(commandId)) return false;
    return /chat|submit|tool|invoke|model|completion|agent/i.test(commandId);
  });
  return { requestMatches, commandMatches };
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);
  const historicBundle = buildHistoricReplayBundle(outputDir);
  writeFileSync(join(outputDir, "injected-historic-replay-events.json"), `${JSON.stringify(historicBundle.events, null, 2)}\n`);
  writeFileSync(join(outputDir, "injected-historic-replay-turns.json"), `${JSON.stringify(historicBundle.turns, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage9-historic-replay-daemon-"));
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const screenshots = [];
  const consoleLogs = [];
  const pageErrors = [];
  const stdoutPath = join(outputDir, "electron-stdout.log");
  const stderrPath = join(outputDir, "electron-stderr.log");
  let server;
  let app;
  let browser;
  let context;
  let tracingStarted = false;
  let userDataDir;
  let extensionsDir;

  try {
    server = createBridge({
      daemonEndpoint: daemon.endpoint,
      requests,
      commands,
      deliveredCommands,
    });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage9-historic-replay-user-"));
    extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage9-historic-replay-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);

    app = spawn(
      AUTOPILOT_ELECTRON.binary,
      [
        `--remote-debugging-port=${cdpPort}`,
        `--user-data-dir=${userDataDir}`,
        `--extensions-dir=${extensionsDir}`,
        "--disable-updates",
        "--disable-workspace-trust",
        "--new-window",
        repoRoot,
      ],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          IOI_WORKSPACE_IDE_BRIDGE_URL: bridgeUrl,
          IOI_DAEMON_ENDPOINT: daemon.endpoint,
          IOI_AUTOPILOT_CANONICAL_SHELL: "vscode-electron-fork",
          IOI_WORKBENCH_NATIVE_SHELL: "1",
          IOI_AUTOPILOT_STUDIO_TEST_HOOKS: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    app.stdout.on("data", (chunk) => appendFileSync(stdoutPath, chunk));
    app.stderr.on("data", (chunk) => appendFileSync(stderrPath, chunk));
    writeFileSync(join(outputDir, "pid"), `${app.pid}\n`);

    const cdpVersion = await waitForCdp(cdpPort);
    if (!cdpVersion) throw new Error("Electron app did not expose a CDP endpoint.");
    writeFileSync(join(outputDir, "cdp-version.json"), `${JSON.stringify(cdpVersion, null, 2)}\n`);

    browser = await chromium.connectOverCDP(`http://127.0.0.1:${cdpPort}`);
    context = browser.contexts()[0] ?? (await browser.newContext());
    context.on("page", (page) => {
      page.on("console", (message) => {
        consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() });
      });
      page.on("pageerror", (error) => {
        pageErrors.push(String(error?.stack ?? error?.message ?? error));
      });
    });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    tracingStarted = true;
    const page = await waitForPredicate(
      () => context.pages().find((candidate) => !candidate.isClosed()) ?? null,
      30_000,
      250,
    );
    if (!page) throw new Error("No Playwright page was available for the Electron fork.");
    page.on("console", (message) => {
      consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() });
    });
    page.on("pageerror", (error) => {
      pageErrors.push(String(error?.stack ?? error?.message ?? error));
    });
    await page.setViewportSize({ width: 1600, height: 950 }).catch(() => undefined);

    let startIndex = requests.length;
    queueCommand(commands, "ioi.studio.open", { phase: "chat" });
    await requireNewRequest(requests, (request) => request?.requestType === "studio.open", "studio.open", startIndex);
    let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "studio-open.png", screenshots);

    startIndex = requests.length;
    queueCommand(commands, "ioi.studio.injectParityPlusEvents", {
      status: "completed",
      events: historicBundle.events,
      turns: historicBundle.turns,
    });
    const injectionRequest = await requireNewRequest(
      requests,
      (request) => request?.requestType === "studio.parityPlusEvents.injected",
      "studio.parityPlusEvents.injected",
      startIndex,
    );
    studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
    const drawerExpanded = await expandStudioUtilityDrawer(studioFrame);
    if (!drawerExpanded) {
      throw new Error("Studio utility drawer did not expand for historic replay proof.");
    }

    const domEvidence = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const evidence = await replayDomEvidence(studioFrame);
        return replayReady(evidence) ? evidence : null;
      } catch {
        return null;
      }
    }, 20_000, 300);
    if (!domEvidence) {
      const latest = await replayDomEvidence(studioFrame).catch((error) => ({ error: String(error) }));
      throw new Error(`Historic replay rows did not hydrate in the live GUI: ${JSON.stringify(latest)}`);
    }
    await screenshot(page, outputDir, "studio-historic-run-replay.png", screenshots);

    await studioFrame.locator('[data-testid="studio-trajectory-replay-panel"] [data-testid="studio-view-trace-link"]').first().click();
    const traceRequest = await requireNewRequest(
      requests,
      (request) =>
        request?.requestType === "runs.open" &&
        (request?.traceTarget?.kind || request?.payload?.traceTarget?.kind) === "trajectory.replay",
      "runs.open trajectory replay trace target",
      startIndex,
    );
    await screenshot(page, outputDir, "studio-historic-run-replay-trace-link.png", screenshots);

    const liveRequests = liveExecutionRequests(requests, deliveredCommands);
    const drawerText = domEvidence.drawerText || "";
    const forbiddenUiPatterns = [
      /browser__/,
      /agent__/,
      /chat__/,
      /\/tmp\//,
      /http:\/\/127\.0\.0\.1/,
      /daemonStateDir/,
      /parsed-trace/,
      /artifact_run_runtime_service/,
      /sk-[A-Za-z0-9]/,
    ];
    const checks = {
      sourceTraceRefsLoaded: Boolean(historicBundle.traceRefs?.refs?.length),
      sourceTraceSummaryLoaded: Boolean(historicBundle.traceSummary?.traceCount),
      electronLaunched: Boolean(cdpVersion),
      studioOpened: true,
      injectionBridgeRequestRecorded: Boolean(injectionRequest),
      replayRowsHydrated: replayReady(domEvidence),
      traceLinkRoutesToRuns: Boolean(traceRequest),
      noLiveExecutionRequests: liveRequests.requestMatches.length === 0 && liveRequests.commandMatches.length === 0,
      productUiAvoidsRawEvidencePaths: forbiddenUiPatterns.every((pattern) => !pattern.test(drawerText)),
      readOnlyHistoricReplayTextVisible: /Historic run replay loaded from archived evidence/i.test(drawerText),
    };
    const proof = {
      schemaVersion: "ioi.autopilot.stage9.historic-run-gui-replay-proof.v1",
      passed: Object.values(checks).every(Boolean),
      generatedAt: new Date().toISOString(),
      sourceInventory: historicBundle.sourceInventory,
      daemonEndpoint: daemon.endpoint,
      screenshots,
      injectionRequest,
      traceRequest,
      domEvidence,
      liveExecutionRequestAudit: liveRequests,
      checks,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Historic-run GUI replay proof failed checks: ${JSON.stringify(checks)}`);
    }
    return proof;
  } finally {
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
    writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
    if (tracingStarted && context) {
      await context.tracing.stop({ path: join(outputDir, "playwright-trace.zip") }).catch(() => undefined);
    }
    await browser?.close().catch(() => undefined);
    if (app && !app.killed) {
      app.kill("SIGTERM");
      const exited = await waitForChildExit(app, 5000);
      if (!exited && app.exitCode === null) app.kill("SIGKILL");
    }
    await cleanupProofUserDataProcesses(userDataDir);
    await closeServer(server);
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
    if (extensionsDir) rmSync(extensionsDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
    rmSync(daemonStateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}

const outputDir = process.argv[2] || join(evidenceRoot, timestamp());
const proof = await runProof(outputDir);
console.log(JSON.stringify({ outputDir, passed: proof.passed }, null, 2));
