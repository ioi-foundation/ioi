#!/usr/bin/env node
import { spawn } from "node:child_process";
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
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus";

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
        // VS Code replaces webview frames during mode changes.
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

function sampleParityPlusEvents() {
  return [
    {
      id: "stage35.engine.reconnect",
      kind: "engine.reconnect",
      status: "reconnecting",
      summary: "Engine reconnect state observed.",
      receiptRefs: ["receipt_stage35_engine_reconnect"],
      payload: {
        schemaVersion: "ioi.studio.engine_reconnect_banner.v1",
        bannerLabel: "Reconnecting to Autopilot Engine (Attempt 2/5)...",
        composerFrozen: true,
      },
    },
    {
      id: "stage35.chat.responsibility",
      kind: "chat.responsibility",
      status: "ready",
      summary: "Ask direct and Agent chat__reply contract verified.",
      receiptRefs: ["receipt_stage35_chat_responsibility"],
      payload: {
        schemaVersion: "ioi.studio.chat_responsibility_contract.v1",
        detail: "Direct Chat stayed direct; Agent emitted chat__reply before agent__complete.",
        directToolLeakCount: 0,
        missingAgentReplyCount: 0,
      },
    },
    {
      id: "stage35.engine.guard.security",
      kind: "engine.guard.security",
      status: "blocked",
      summary: "Engine Guard blocked an unsafe merge.",
      receiptRefs: ["receipt_stage35_engine_guard_security"],
      payload: {
        schemaVersion: "ioi.studio.engine_guard_security_scan.v1",
        mergeBlockReason: "Plaintext secret finding redacted; merge disabled.",
        findingCount: 1,
        mergeActionDisabled: true,
      },
    },
    {
      id: "stage35.worker.contribution",
      kind: "worker.contribution",
      status: "ready",
      summary: "Worker output linked to one review hunk.",
      receiptRefs: ["receipt_stage35_worker_contribution"],
      payload: {
        schemaVersion: "ioi.studio.worker_contribution_trace.v1",
        contributionCount: 1,
        workerIds: ["subagent.stage35.implement"],
      },
    },
  ];
}

async function panelEvidence(frame) {
  const panels = [
    "studio-engine-reconnect-banner",
    "studio-chat-responsibility-contract",
    "studio-engine-guard-security-scan",
    "studio-worker-contribution-trace",
  ];
  const evidence = {};
  for (const panel of panels) {
    const locator = frame.locator(`[data-testid="${panel}"]`).first();
    evidence[panel] = {
      count: await locator.count(),
      visible: await locator.isVisible().catch(() => false),
      status: await locator.getAttribute("data-panel-status").catch(() => null),
      text: await locator.textContent().catch(() => ""),
      traceLinkCount: await locator.locator('[data-testid="studio-view-trace-link"]').count().catch(() => 0),
      verifiedBadgeCount: await locator.locator('[data-testid="studio-verified-badge"]').count().catch(() => 0),
    };
  }
  return evidence;
}

function panelsReady(evidence) {
  return (
    evidence["studio-engine-reconnect-banner"]?.status === "reconnecting" &&
    evidence["studio-chat-responsibility-contract"]?.status === "ready" &&
    evidence["studio-engine-guard-security-scan"]?.status === "blocked" &&
    evidence["studio-worker-contribution-trace"]?.status === "ready" &&
    Object.values(evidence).every((item) => item.visible && item.traceLinkCount > 0 && item.verifiedBadgeCount > 0)
  );
}

async function run(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage35-daemon-"));
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
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage35-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage35-ext-"));
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

    queueCommand(commands, "ioi.studio.open", { phase: "chat" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "studio-parity-plus-open.png", screenshots);

    queueCommand(commands, "ioi.studio.injectParityPlusEvents", {
      status: "completed",
      events: sampleParityPlusEvents(),
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
      throw new Error("Studio utility drawer did not expand before parity-plus panel click-through.");
    }
    const readyEvidence = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const evidence = await panelEvidence(studioFrame);
        return panelsReady(evidence) ? evidence : null;
      } catch {
        return null;
      }
    }, 20_000, 300);
    if (!readyEvidence) {
      const latestEvidence = await panelEvidence(studioFrame).catch((error) => ({ error: String(error) }));
      throw new Error(`Parity-plus panels did not hydrate in the live GUI: ${JSON.stringify(latestEvidence)}`);
    }

    await screenshot(page, outputDir, "studio-parity-plus-hydrated.png", screenshots);
    await studioFrame.locator('[data-testid="studio-engine-reconnect-banner"] [data-testid="studio-view-trace-link"]').first().click();
    const traceRequest = await requireRequest(
      requests,
      (request) =>
        request?.requestType === "runs.open" &&
        (request?.traceTarget?.kind || request?.payload?.traceTarget?.kind) === "engine.reconnect",
      "runs.open engine reconnect trace target",
    );
    await screenshot(page, outputDir, "studio-parity-plus-trace-link.png", screenshots);

    const proof = {
      schemaVersion: "ioi.autopilot.stage35.chat-trace-parity-plus-live-gui-proof.v1",
      passed: true,
      daemonEndpoint: daemon.endpoint,
      screenshots,
      injectedEventCount: sampleParityPlusEvents().length,
      injectionRequest,
      traceRequest,
      panelEvidence: readyEvidence,
      checks: {
        electronLaunched: Boolean(cdpVersion),
        studioOpened: true,
        injectionBridgeRequestRecorded: Boolean(injectionRequest),
        panelsHydrated: true,
        traceLinksVisible: Object.values(readyEvidence).every((item) => item.traceLinkCount > 0),
        verifiedBadgesVisible: Object.values(readyEvidence).every((item) => item.verifiedBadgeCount > 0),
        traceLinkRoutesToRuns: Boolean(traceRequest),
      },
    };
    writeFileSync(join(outputDir, "workflow-chat-trace-parity-plus-live-gui-proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
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
    await closeServer(server);
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
  }
}

async function main() {
  const outputDir =
    process.argv[2] ||
    join(repoRoot, evidenceRoot, `${timestamp()}-stage35-chat-trace-parity-plus-live-gui`);
  ensureDir(outputDir);
  const proof = await run(outputDir);
  console.log(JSON.stringify({ ok: proof.passed, outputDir, proof }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
