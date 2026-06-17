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
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchExtensionTargets,
} from "./hypervisor-workbench-adapter-host-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./autopilot-workbench-shell-patch.mjs";

const repoRoot = HYPERVISOR_WORKBENCH_ADAPTER_HOST.repoRoot;
const evidenceRoot =
  process.env.AUTOPILOT_CRASH_RESTART_REPLAY_LIVE_GUI_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-5-stop-cancel-recover-stop-hook/live-gui-crash-restart-replay";

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
      routes: [
        {
          id: "route.local-first",
          routeId: "route.local-first",
          status: "ready",
          modelId: "autopilot-native-fixture",
          endpointId: "endpoint.agent-studio.native",
          capabilities: ["chat", "responses", "structured_output"],
        },
      ],
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

async function requireRequest(requests, predicate, label, timeoutMs = 45_000) {
  const request = await waitForPredicate(
    () => requests.find((candidate) => predicate(candidate)),
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

function runProofScript({ label, args, outputDir }) {
  const result = spawnSync(process.execPath, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  writeFileSync(join(outputDir, `${label}-stdout.log`), result.stdout || "");
  writeFileSync(join(outputDir, `${label}-stderr.log`), result.stderr || "");
  const summary = {
    label,
    command: [process.execPath, ...args],
    status: result.status,
    signal: result.signal,
    error: result.error ? String(result.error?.stack || result.error?.message || result.error) : null,
  };
  writeFileSync(join(outputDir, `${label}-run.json`), `${JSON.stringify(summary, null, 2)}\n`);
  if (result.status !== 0 || result.error) {
    throw new Error(`${label} failed: ${JSON.stringify(summary)}`);
  }
  return summary;
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function crashRecoveryEvents({ reportCard, crashProof }) {
  const replay = crashProof.replay || {};
  const beforeCrashLastSeq = Number(replay.before_crash_last_seq || 0);
  const continuationSeqStart = Number(reportCard.continuationSeqStart || 0);
  const sharedRefs = ["receipt_stage5_crash_restart_replay"];
  const makeEvent = ({ id, kind, status = "passed", summary, payload = {} }) => ({
    id,
    event_id: id,
    event_kind: kind,
    kind,
    status,
    summary,
    receiptRefs: sharedRefs,
    payload_summary: {
      schemaVersion: "ioi.studio.crash_restart_replay.v1",
      status,
      summary,
      ...payload,
    },
    payload: {
      schemaVersion: "ioi.studio.crash_restart_replay.v1",
      status,
      summary,
      ...payload,
    },
  });
  return [
    {
      id: "stage5.engine.reconnect.restored",
      event_id: "stage5.engine.reconnect.restored",
      event_kind: "engine.reconnect",
      kind: "engine.reconnect",
      status: "restored",
      summary: "Daemon restart recovered the replay cursor.",
      receiptRefs: sharedRefs,
      payload_summary: {
        schemaVersion: "ioi.studio.engine_reconnect_banner.v1",
        status: "restored",
        summary: "Daemon restart recovered the replay cursor.",
        bannerLabel: `Autopilot Engine reconnected after daemon restart; replay cursor resumed at seq ${continuationSeqStart}.`,
        composerFrozen: false,
      },
      payload: {
        schemaVersion: "ioi.studio.engine_reconnect_banner.v1",
        bannerLabel: `Autopilot Engine reconnected after daemon restart; replay cursor resumed at seq ${continuationSeqStart}.`,
        composerFrozen: false,
      },
    },
    makeEvent({
      id: "stage5.replay.process_exit",
      kind: "replay.process_exit",
      summary: "Daemon process exit captured during crash drill.",
      payload: { rowKind: "process_exit" },
    }),
    makeEvent({
      id: "stage5.replay.safe_boot",
      kind: "replay.safe_boot",
      summary: "Daemon restarted from the durable state directory.",
      payload: { rowKind: "safe_boot" },
    }),
    makeEvent({
      id: "stage5.replay.integrity",
      kind: "replay.integrity",
      summary: `${Number(replay.after_restart_event_count || 0)} events replayed after restart with ${Number(reportCard.duplicateTerminalEvents || 0)} duplicate terminal events.`,
      payload: {
        rowKind: "replay_integrity",
        afterRestartEventCount: Number(replay.after_restart_event_count || 0),
        replayFromLastSeqCount: Number(replay.replay_from_last_seq_count || 0),
        duplicateTerminalEvents: Number(reportCard.duplicateTerminalEvents || 0),
      },
    }),
    makeEvent({
      id: "stage5.replay.continuation",
      kind: "replay.continuation",
      summary: `Next turn started at seq ${continuationSeqStart} after replay seq ${beforeCrashLastSeq}.`,
      payload: {
        rowKind: "continuation",
        continuationSeqStart,
        beforeCrashLastSeq,
      },
    }),
  ];
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
  const reconnect = frame.locator('[data-testid="studio-engine-reconnect-banner"]').first();
  const reconnectEvidence = {
    count: await reconnect.count(),
    visible: await reconnect.isVisible().catch(() => false),
    status: await reconnect.getAttribute("data-panel-status").catch(() => null),
    text: await reconnect.textContent().catch(() => ""),
    traceLinkCount: await reconnect.locator('[data-testid="studio-view-trace-link"]').count().catch(() => 0),
    verifiedBadgeCount: await reconnect.locator('[data-testid="studio-verified-badge"]').count().catch(() => 0),
  };
  const drawerText = await frame.locator('[data-testid="studio-utility-drawer"]').first().textContent().catch(() => "");
  return { replayRows, reconnect: reconnectEvidence, drawerText };
}

function replayReady(evidence) {
  const ids = new Set(evidence.replayRows.map((row) => row.id));
  return (
    evidence.reconnect.status === "restored" &&
    evidence.reconnect.visible &&
    evidence.reconnect.traceLinkCount > 0 &&
    evidence.reconnect.verifiedBadgeCount > 0 &&
    ids.has("stage5.replay.process_exit") &&
    ids.has("stage5.replay.safe_boot") &&
    ids.has("stage5.replay.integrity") &&
    ids.has("stage5.replay.continuation")
  );
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  const crashProofPath = join(outputDir, "workflow-crash-restart-timeline-resume-proof.json");
  const reportCardProofPath = join(outputDir, "workflow-crash-recovery-report-card-proof.json");
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);
  runProofScript({
    label: "crash-restart-timeline",
    args: ["scripts/lib/workflow-crash-restart-timeline-resume-proof.mjs", crashProofPath],
    outputDir,
  });
  runProofScript({
    label: "crash-recovery-report-card",
    args: ["scripts/lib/workflow-crash-recovery-report-card-proof.mjs", reportCardProofPath, crashProofPath],
    outputDir,
  });
  const crashProof = loadJson(crashProofPath);
  const reportCardProof = loadJson(reportCardProofPath);
  const reportCard = reportCardProof.reportCard;
  if (crashProof.passed !== true) throw new Error("Fresh crash/restart replay proof did not pass.");
  if (reportCardProof.passed !== true || reportCard?.status !== "ready") {
    throw new Error("Crash recovery report card did not pass.");
  }

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage5-replay-gui-daemon-"));
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
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage5-replay-gui-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage5-replay-gui-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);

    app = spawn(
      HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary,
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
          IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-workbench-adapter-host",
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

    queueCommand(commands, "ioi.studio.open", { phase: "chat" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "studio-open.png", screenshots);

    const events = crashRecoveryEvents({ reportCard, crashProof });
    writeFileSync(join(outputDir, "injected-crash-restart-replay-events.json"), `${JSON.stringify(events, null, 2)}\n`);
    queueCommand(commands, "ioi.studio.injectParityPlusEvents", {
      status: "completed",
      events,
    });
    const injectionRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "studio.parityPlusEvents.injected",
      "studio.parityPlusEvents.injected",
    );
    studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
    await studioFrame.locator('[data-testid="studio-utility-toggle"]').first().click();
    const drawerExpanded = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        return (await studioFrame.locator('[data-testid="studio-utility-drawer"].is-expanded').count()) > 0;
      } catch {
        return false;
      }
    }, 5_000, 200);
    if (!drawerExpanded) {
      throw new Error("Studio utility drawer did not expand for replay proof.");
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
      throw new Error(`Crash/restart replay rows did not hydrate in the live GUI: ${JSON.stringify(latest)}`);
    }
    await screenshot(page, outputDir, "studio-crash-restart-replay.png", screenshots);

    await studioFrame.locator('[data-testid="studio-engine-reconnect-banner"] [data-testid="studio-view-trace-link"]').first().click();
    const traceRequest = await requireRequest(
      requests,
      (request) =>
        request?.requestType === "runs.open" &&
        (request?.traceTarget?.kind || request?.payload?.traceTarget?.kind) === "engine.reconnect",
      "runs.open engine reconnect trace target",
    );
    await screenshot(page, outputDir, "studio-crash-restart-replay-trace-link.png", screenshots);

    const drawerText = domEvidence.drawerText || "";
    const checks = {
      freshCrashRestartProofPassed: crashProof.passed === true,
      reportCardReady: reportCardProof.passed === true && reportCard?.status === "ready",
      electronLaunched: Boolean(cdpVersion),
      studioOpened: true,
      injectionBridgeRequestRecorded: Boolean(injectionRequest),
      replayRowsHydrated: replayReady(domEvidence),
      engineReconnectPanelRestored: domEvidence.reconnect.status === "restored",
      traceLinkRoutesToRuns: Boolean(traceRequest),
      productUiAvoidsRawStatePath: !/\/tmp\/ioi-stage12-|stateDir|workspaceRoot|firstDaemon|secondDaemon/.test(drawerText),
      productUiAvoidsPidLeak: !/\bpid\s+\d+/i.test(drawerText),
    };
    const proof = {
      schemaVersion: "ioi.autopilot.stage5.crash-restart-replay-live-gui-proof.v1",
      passed: Object.values(checks).every(Boolean),
      generatedAt: new Date().toISOString(),
      crashProofPath,
      reportCardProofPath,
      daemonEndpoint: daemon.endpoint,
      screenshots,
      injectionRequest,
      traceRequest,
      domEvidence,
      checks,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Crash/restart replay live GUI proof failed checks: ${JSON.stringify(checks)}`);
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
      await wait(1200);
      if (app.exitCode === null) app.kill("SIGKILL");
    }
    await cleanupProofUserDataProcesses(userDataDir);
    await closeServer(server);
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}

const outputDir = process.argv[2] || join(evidenceRoot, timestamp());
const proof = await runProof(outputDir);
console.log(JSON.stringify({ outputDir, passed: proof.passed }, null, 2));
