#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
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
import { applyHypervisorWorkbenchShellPatch } from "./hypervisor-workbench-shell-patch.mjs";
import {
  bootstrapNativeRuntimeModelRoute,
  configureRuntimeAgentServiceInferenceEnv,
} from "./hypervisor-runtime-agent-service-inference.mjs";

const repoRoot = HYPERVISOR_WORKBENCH_ADAPTER_HOST.repoRoot;
const evidenceRoot =
  process.env.AUTOPILOT_TRAJECTORY_RECONNECT_LIVE_GUI_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-1-trajectory-brain/live-gui-trajectory-reconnect";

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

async function createDaemonModelInvocationToken(endpoint) {
  const response = await fetch(`${endpoint}/v1/model-mount/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-trajectory-reconnect-live-gui",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.embeddings:*",
        "model.import:*",
        "model.download:*",
        "model.mount:*",
        "model.load:*",
        "model.unload:*",
        "model.unmount:*",
        "model.tokenize:*",
        "model.context:*",
        "route.write:*",
        "route.use:*",
        "server.logs:*",
        "backend.control:*",
      ],
      denied: ["connector.*"],
      source: "trajectory-reconnect-live-gui-proof",
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to create daemon token (${response.status}): ${text}`);
  }
  const parsed = text ? JSON.parse(text) : {};
  if (!parsed.token) throw new Error("Daemon token response did not include a token.");
  return parsed;
}

function bridgeState({ daemonEndpoint, runtimeModelRoute }) {
  const routeId = runtimeModelRoute?.routeId || "route.local-first";
  const modelId = runtimeModelRoute?.modelId || "hypervisor-native-fixture";
  const endpointId = runtimeModelRoute?.endpointId || "endpoint.agent-studio.native";
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
          id: routeId,
          routeId,
          status: "ready",
          modelId,
          endpointId,
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

function createBridge({ daemonEndpoint, runtimeModelRoute, requests, commands, deliveredCommands }) {
  return createServer(async (request, response) => {
    try {
      if (request.method === "OPTIONS") {
        sendJson(response, 204, {});
        return;
      }
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/state") {
        sendJson(response, 200, bridgeState({ daemonEndpoint, runtimeModelRoute }));
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

async function trajectoryReconnectDomEvidence(frame) {
  const panel = frame.locator('[data-testid="studio-trajectory-replay-panel"]').first();
  const rowLocator = panel.locator('[data-testid="studio-trajectory-replay-step-row"]');
  const rows = await rowLocator.evaluateAll((nodes) =>
    nodes.map((node) => ({
      kind: node.getAttribute("data-trajectory-step-kind"),
      status: node.getAttribute("data-trajectory-step-status"),
      id: node.querySelector("code")?.textContent || "",
      text: node.textContent || "",
    })),
  );
  const replayRows = await frame.locator('[data-testid="studio-replay-step-detail"]').evaluateAll((nodes) =>
    nodes.map((node) => ({
      kind: node.querySelector("strong")?.textContent || "",
      id: node.querySelector("code")?.textContent || "",
      summary: node.querySelector("span")?.textContent || "",
    })),
  );
  const drawerText = await frame.locator('[data-testid="studio-utility-drawer"]').first().textContent().catch(() => "");
  return {
    panel: {
      count: await panel.count(),
      visible: await panel.isVisible().catch(() => false),
      status: await panel.getAttribute("data-panel-status").catch(() => null),
      trajectoryIdStable: await panel.getAttribute("data-trajectory-id-stable").catch(() => null),
      replayCursorObserved: await panel.getAttribute("data-trajectory-replay-cursor-observed").catch(() => null),
      guiReconnected: await panel.getAttribute("data-trajectory-gui-reconnected").catch(() => null),
      replayIdsStable: await panel.getAttribute("data-trajectory-replay-ids-stable").catch(() => null),
      replayFromCursorEmpty: await panel.getAttribute("data-trajectory-replay-from-cursor-empty").catch(() => null),
      sideEffectCount: await panel.getAttribute("data-trajectory-side-effect-count").catch(() => null),
      duplicateSideEffectCount: await panel.getAttribute("data-trajectory-duplicate-side-effect-count").catch(() => null),
      traceLinkCount: await panel.locator('[data-testid="studio-view-trace-link"]').count().catch(() => 0),
      verifiedBadgeCount: await panel.locator('[data-testid="studio-verified-badge"]').count().catch(() => 0),
      text: await panel.textContent().catch(() => ""),
    },
    rows,
    replayRows,
    drawerText,
  };
}

function trajectoryDomReady(evidence, { requireReconnect = false } = {}) {
  const rowKinds = new Set(evidence.rows.map((row) => row.kind));
  return (
    evidence.panel.visible &&
    evidence.panel.status === "ready" &&
    evidence.panel.trajectoryIdStable === "true" &&
    evidence.panel.replayCursorObserved === "true" &&
    (!requireReconnect || evidence.panel.guiReconnected === "true") &&
    evidence.panel.replayIdsStable === "true" &&
    evidence.panel.replayFromCursorEmpty === "true" &&
    evidence.panel.sideEffectCount === "1" &&
    evidence.panel.duplicateSideEffectCount === "0" &&
    evidence.panel.traceLinkCount > 0 &&
    evidence.panel.verifiedBadgeCount > 0 &&
    rowKinds.has("thread.started") &&
    rowKinds.has("memory.write") &&
    evidence.replayRows.length > 0
  );
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyHypervisorWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-trajectory-reconnect-daemon-"));
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  const token = await createDaemonModelInvocationToken(daemon.endpoint);
  const runtimeModelRoute = await bootstrapNativeRuntimeModelRoute({
    repoRoot,
    daemonEndpoint: daemon.endpoint,
    token: token.token,
    workspaceDir: join(daemonStateDir, "model-fixtures"),
  });
  configureRuntimeAgentServiceInferenceEnv({
    daemonEndpoint: daemon.endpoint,
    token: token.token,
    modelId: runtimeModelRoute.modelId,
    routeId: runtimeModelRoute.routeId,
    env: process.env,
    overwrite: true,
  });

  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const screenshots = [];
  const consoleLogs = [];
  const pageErrors = [];
  let server;
  const launches = [];
  let userDataDir;
  let extensionsDir;

  try {
    server = createBridge({
      daemonEndpoint: daemon.endpoint,
      runtimeModelRoute,
      requests,
      commands,
      deliveredCommands,
    });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-trajectory-reconnect-user-"));
    extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-trajectory-reconnect-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    writeFileSync(join(outputDir, "runtime-model-route.json"), `${JSON.stringify(runtimeModelRoute, null, 2)}\n`);

    async function launchElectron(label) {
      const cdpPort = await getFreePort();
      const stdoutPath = join(outputDir, `electron-${label}-stdout.log`);
      const stderrPath = join(outputDir, `electron-${label}-stderr.log`);
      const app = spawn(
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
            IOI_DAEMON_TOKEN: token.token,
            IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-workbench-adapter-host",
            IOI_WORKBENCH_NATIVE_SHELL: "1",
            IOI_AUTOPILOT_STUDIO_TEST_HOOKS: "1",
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      app.stdout.on("data", (chunk) => appendFileSync(stdoutPath, chunk));
      app.stderr.on("data", (chunk) => appendFileSync(stderrPath, chunk));
      const launch = { label, app, browser: null, context: null, tracingStarted: false, cdpPort };
      launches.push(launch);
      writeFileSync(join(outputDir, `pid-${label}`), `${app.pid}\n`);
      const cdpVersion = await waitForCdp(cdpPort);
      if (!cdpVersion) throw new Error(`Electron ${label} app did not expose a CDP endpoint.`);
      writeFileSync(join(outputDir, `cdp-version-${label}.json`), `${JSON.stringify(cdpVersion, null, 2)}\n`);
      const browser = await chromium.connectOverCDP(`http://127.0.0.1:${cdpPort}`);
      const context = browser.contexts()[0] ?? (await browser.newContext());
      launch.browser = browser;
      launch.context = context;
      context.on("page", (page) => {
        page.on("console", (message) => {
          consoleLogs.push({ phase: label, type: message.type(), text: message.text(), location: message.location() });
        });
        page.on("pageerror", (error) => {
          pageErrors.push({ phase: label, error: String(error?.stack ?? error?.message ?? error) });
        });
      });
      await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
      launch.tracingStarted = true;
      const page = await waitForPredicate(
        () => context.pages().find((candidate) => !candidate.isClosed()) ?? null,
        30_000,
        250,
      );
      if (!page) throw new Error(`No Playwright page was available for Electron ${label}.`);
      page.on("console", (message) => {
        consoleLogs.push({ phase: label, type: message.type(), text: message.text(), location: message.location() });
      });
      page.on("pageerror", (error) => {
        pageErrors.push({ phase: label, error: String(error?.stack ?? error?.message ?? error) });
      });
      await page.setViewportSize({ width: 1600, height: 950 }).catch(() => undefined);
      return { ...launch, page, cdpVersion };
    }

    async function closeElectron(launch, traceFile) {
      if (!launch) return;
      if (launch.tracingStarted && launch.context) {
        await launch.context.tracing.stop({ path: join(outputDir, traceFile) }).catch(() => undefined);
        launch.tracingStarted = false;
      }
      await launch.browser?.close().catch(() => undefined);
      if (launch.app && !launch.app.killed) {
        launch.app.kill("SIGTERM");
        const exited = await waitForChildExit(launch.app, 5000);
        if (!exited && launch.app.exitCode === null) {
          launch.app.kill("SIGKILL");
          await waitForChildExit(launch.app, 2500);
        }
      }
    }

    async function openStudio(page, label) {
      const startIndex = requests.length;
      queueCommand(commands, "ioi.studio.open", { phase: "chat" });
      await requireNewRequest(requests, (request) => request?.requestType === "studio.open", `studio.open ${label}`, startIndex);
      const studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
      await screenshot(page, outputDir, `studio-open-${label}.png`, screenshots);
      return studioFrame;
    }

    async function expandDrawer(page) {
      let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
      const drawer = studioFrame.locator('[data-testid="studio-utility-drawer"].is-expanded');
      if ((await drawer.count().catch(() => 0)) === 0) {
        await studioFrame.locator('[data-testid="studio-utility-toggle"]').first().click();
      }
      const expanded = await waitForPredicate(async () => {
        try {
          studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
          return (await studioFrame.locator('[data-testid="studio-utility-drawer"].is-expanded').count()) > 0;
        } catch {
          return false;
        }
      }, 5_000, 200);
      if (!expanded) throw new Error("Studio utility drawer did not expand for trajectory replay proof.");
      return studioFrame;
    }

    async function waitForTrajectoryDom(page, options = {}) {
      const domEvidence = await waitForPredicate(async () => {
        try {
          const studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
          const evidence = await trajectoryReconnectDomEvidence(studioFrame);
          return trajectoryDomReady(evidence, options) ? evidence : null;
        } catch {
          return null;
        }
      }, 25_000, 300);
      if (!domEvidence) {
        const studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000).catch(() => null);
        const latest = studioFrame
          ? await trajectoryReconnectDomEvidence(studioFrame).catch((error) => ({ error: String(error) }))
          : { error: "studio frame unavailable" };
        throw new Error(`Trajectory replay panel did not hydrate in the live GUI: ${JSON.stringify(latest)}`);
      }
      return domEvidence;
    }

    const createLaunch = await launchElectron("create");
    await openStudio(createLaunch.page, "create");
    let startIndex = requests.length;
    queueCommand(commands, "ioi.studio.exerciseTrajectoryReplayReconnect", { phase: "create" });
    const createRequest = await requireNewRequest(
      requests,
      (request) =>
        request?.requestType === "studio.trajectoryReplayReconnect.exercised" &&
        request?.payload?.phase === "create",
      "studio.trajectoryReplayReconnect.exercised create",
      startIndex,
      90_000,
    );
    await expandDrawer(createLaunch.page);
    const createDomEvidence = await waitForTrajectoryDom(createLaunch.page);
    await screenshot(createLaunch.page, outputDir, "studio-trajectory-replay-create.png", screenshots);
    const threadId = createRequest?.payload?.threadId;
    const expectedReplayIds = createRequest?.payload?.replayIds || [];
    const expectedReplayCursor = createRequest?.payload?.replayCursor || 0;
    if (!threadId) throw new Error("Create phase did not return a daemon thread id.");
    if (!expectedReplayIds.length) throw new Error("Create phase did not return replay ids.");
    await closeElectron(createLaunch, "playwright-trace-create.zip");
    await cleanupProofUserDataProcesses(userDataDir);
    await wait(750);

    const reconnectLaunch = await launchElectron("reconnect");
    await openStudio(reconnectLaunch.page, "reconnect");
    startIndex = requests.length;
    queueCommand(commands, "ioi.studio.exerciseTrajectoryReplayReconnect", {
      phase: "reconnect",
      threadId,
      expectedThreadId: threadId,
      expectedReplayIds,
      expectedReplayCursor,
    });
    const reconnectRequest = await requireNewRequest(
      requests,
      (request) =>
        request?.requestType === "studio.trajectoryReplayReconnect.exercised" &&
        request?.payload?.phase === "reconnect",
      "studio.trajectoryReplayReconnect.exercised reconnect",
      startIndex,
      90_000,
    );
    let studioFrame = await expandDrawer(reconnectLaunch.page);
    const reconnectDomEvidence = await waitForTrajectoryDom(reconnectLaunch.page, { requireReconnect: true });
    await screenshot(reconnectLaunch.page, outputDir, "studio-trajectory-replay-reconnect.png", screenshots);
    await studioFrame.locator('[data-testid="studio-trajectory-replay-panel"] [data-testid="studio-view-trace-link"]').first().click();
    const traceRequest = await requireNewRequest(
      requests,
      (request) =>
        request?.requestType === "runs.open" &&
        (request?.traceTarget?.kind || request?.payload?.traceTarget?.kind) === "trajectory.replay",
      "runs.open trajectory replay trace target",
      startIndex,
    );
    await screenshot(reconnectLaunch.page, outputDir, "studio-trajectory-replay-trace-link.png", screenshots);
    await closeElectron(reconnectLaunch, "playwright-trace-reconnect.zip");

    const drawerText = reconnectDomEvidence.drawerText || "";
    const replayIdsStableAcrossGuiRestart =
      JSON.stringify(createRequest?.payload?.replayIds || []) === JSON.stringify(reconnectRequest?.payload?.replayIds || []);
    const replayCursorStableAcrossGuiRestart =
      Number(createRequest?.payload?.replayCursor || 0) === Number(reconnectRequest?.payload?.replayCursor || 0);
    const checks = {
      createElectronLaunched: Boolean(createLaunch.cdpVersion),
      reconnectElectronLaunched: Boolean(reconnectLaunch.cdpVersion),
      createBridgeLifecyclePassed: createRequest?.payload?.passed === true,
      reconnectBridgeLifecyclePassed: reconnectRequest?.payload?.passed === true,
      createDomPanelReady: trajectoryDomReady(createDomEvidence),
      reconnectDomPanelReady: trajectoryDomReady(reconnectDomEvidence, { requireReconnect: true }),
      sameThreadAfterGuiRestart: createRequest?.payload?.threadId === reconnectRequest?.payload?.threadId,
      replayIdsStableAcrossGuiRestart,
      replayCursorStableAcrossGuiRestart,
      replayFromCursorEmptyAfterReconnect: reconnectRequest?.payload?.eventsSinceCursorCount === 0,
      sideEffectRecordedExactlyOnceAfterReconnect: reconnectRequest?.payload?.sideEffectRecordCount === 1,
      duplicateSideEffectsAbsent: reconnectRequest?.payload?.duplicateSideEffectCount === 0,
      reconnectDidNotWriteSideEffect: reconnectRequest?.payload?.sideEffectWriteAttempted === false,
      traceLinkRoutesToRuns: Boolean(traceRequest),
      productUiAvoidsRawMemoryPath: !/\/tmp\/|recordsPath|policiesPath|memoryPath|brainRoot|workspaceRoot/.test(drawerText),
      productUiAvoidsRawThreadIds: !/\bthread_[a-f0-9-]{20,}\b/i.test(drawerText),
    };
    const proof = {
      schemaVersion: "ioi.autopilot.stage1.trajectory-reconnect-live-gui-proof.v1",
      passed: Object.values(checks).every(Boolean),
      generatedAt: new Date().toISOString(),
      daemonEndpoint: daemon.endpoint,
      runtimeModelRoute,
      screenshots,
      createRequest,
      reconnectRequest,
      traceRequest,
      createDomEvidence,
      reconnectDomEvidence,
      checks,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Trajectory reconnect live GUI proof failed checks: ${JSON.stringify(checks)}`);
    }
    return proof;
  } finally {
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
    writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
    for (const launch of launches.reverse()) {
      if (launch.tracingStarted && launch.context) {
        await launch.context.tracing.stop({ path: join(outputDir, `playwright-trace-${launch.label}-final.zip`) }).catch(() => undefined);
      }
      await launch.browser?.close().catch(() => undefined);
      if (launch.app && !launch.app.killed) {
        launch.app.kill("SIGTERM");
        await wait(1200);
        if (launch.app.exitCode === null) launch.app.kill("SIGKILL");
      }
    }
    await cleanupProofUserDataProcesses(userDataDir);
    await closeServer(server);
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
    if (extensionsDir) rmSync(extensionsDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}

const outputDir = process.argv[2] || join(evidenceRoot, timestamp());
const proof = await runProof(outputDir);
console.log(JSON.stringify({ outputDir, passed: proof.passed }, null, 2));
