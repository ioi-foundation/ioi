#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  appendFileSync,
  mkdtempSync,
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
import {
  cleanupProofUserDataProcesses,
  clickLocatorWithDomFallback,
  closeServer,
  ensureDir,
  findFrameWithTestId as harnessFindFrameWithTestId,
  getFreePort,
  listen,
  queueCommand,
  readRequestBody,
  requireNewRequest,
  screenshot,
  sendJson,
  timestamp,
  wait,
  waitForCdp as harnessWaitForCdp,
  waitForChildExit,
  waitForPredicate,
} from "./live-gui-proof-harness/index.mjs";

const repoRoot = AUTOPILOT_ELECTRON.repoRoot;
const evidenceRoot =
  process.env.AUTOPILOT_MANAGED_SESSION_RECONNECT_LIVE_GUI_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-8-browser-computer-session-runtime-polish/live-gui-managed-session-reconnect";

async function waitForCdp(port, timeoutMs = 45_000) {
  return harnessWaitForCdp(port, waitForPredicate, timeoutMs);
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
          modelId: "runtime-control-test-model",
          endpointId: "endpoint.runtime-control-test",
          capabilities: ["chat"],
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

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  return harnessFindFrameWithTestId(page, testId, waitForPredicate, timeoutMs);
}

async function fetchJson(url, options = {}) {
  const { headers, ...rest } = options;
  const response = await fetch(url, {
    ...rest,
    headers: { "content-type": "application/json", ...(headers ?? {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} for ${url}: ${text}`);
  }
  return body;
}

function managedSessionReconnectBridge(calls, managedState) {
  function sessionCard(input = {}) {
    return {
      id: managedState.managedSessionId,
      kind: "sandbox_browser",
      surface_label: "Sandbox browser",
      status: "waiting_for_user",
      status_label: "Waiting for user",
      control_state: managedState.controlState,
      waiting_for_user: true,
      waiting_reason: "login",
      replay_ready: true,
      session_id: managedState.managedSessionId,
      thread_id: input.threadId,
      runtime_session_id: input.sessionId,
      page_title: "Login gate fixture",
      target: "fixture://login-gate",
      detail: "Runtime-managed browser session waiting for operator input.",
    };
  }

  function inspection(input = {}) {
    return {
      bridge_id: "managed-session-live-gui-reconnect-bridge",
      source: "runtime_service",
      status: "active",
      thread_id: input.threadId,
      session_id: input.sessionId,
      managed_sessions: {
        schema_version: "ioi.runtime.managed-session.v1",
        thread_id: input.threadId,
        sessions: [sessionCard(input)],
        product_lane: [],
        replay: {
          available: true,
          replayable: true,
          source: "persisted_runtime_service_state",
        },
      },
    };
  }

  return {
    bridgeId: "managed-session-live-gui-reconnect-bridge",
    async startThread(input) {
      calls.push({ operation: "start_thread", input });
      return {
        session_id: managedState.runtimeSessionId,
        status: "active",
        source: "runtime_service",
        events: [
          {
            event_id: "evt_thread_started_managed_session_live_gui_reconnect",
            event_kind: "thread.started",
            status: "completed",
            created_at: new Date().toISOString(),
            payload: {},
          },
        ],
      };
    },
    async inspectThread(input) {
      calls.push({ operation: "inspect_thread", input });
      return inspection(input);
    },
    async controlThread(input) {
      calls.push({ operation: "control_thread", input });
      if (input.action === "take_over_session") {
        managedState.controlState = "take_over";
      } else if (input.action === "return_agent") {
        managedState.controlState = "return_agent";
      } else if (input.action === "observe_session") {
        managedState.controlState = "observe";
      }
      return {
        schema_version: "ioi.runtime.managed-session-control.live-gui-test.v1",
        action: input.action,
        status: "completed",
        inspection: inspection(input),
      };
    },
  };
}

async function seedRuntimeControlModelRoute(store) {
  store.modelMounting.importModel({
    model_id: "runtime-control-test-model",
    provider_id: "provider.local.folder",
    capabilities: ["chat"],
  });
  store.modelMounting.mountEndpoint({
    id: "endpoint.runtime-control-test",
    model_id: "runtime-control-test-model",
    provider_id: "provider.local.folder",
    capabilities: ["chat"],
  });
  await store.modelMounting.loadModel({
    endpoint_id: "endpoint.runtime-control-test",
    load_policy: { mode: "eager" },
  });
  store.modelMounting.upsertRoute({
    id: "route.local-first",
    role: "chat",
    fallback: ["endpoint.runtime-control-test"],
    provider_eligibility: ["local_folder"],
  });
}

function firstManagedSession(inspection) {
  return inspection?.managed_sessions?.sessions?.[0] || inspection?.managedSessions?.sessions?.[0] || null;
}

async function managedSessionDomEvidence(frame) {
  const cards = frame.locator('[data-testid="studio-managed-session-card"]');
  const cardCount = await cards.count().catch(() => 0);
  if (cardCount === 0) {
    return { cardCount: 0, visible: false };
  }
  const card = cards.last();
  const labels = await card.locator('[data-testid="studio-managed-session-mode-label"]').allTextContents().catch(() => []);
  const waiting = card.locator('[data-testid="studio-managed-session-waiting"]').first();
  return {
    cardCount,
    visible: await card.isVisible().catch(() => false),
    sessionId: await card.getAttribute("data-session-id").catch(() => null),
    sessionKind: await card.getAttribute("data-session-kind").catch(() => null),
    sessionLabel: await card.getAttribute("data-session-label").catch(() => null),
    sessionStatus: await card.getAttribute("data-session-status").catch(() => null),
    controlState: await card.getAttribute("data-control-state").catch(() => null),
    waitingVisible: await waiting.isVisible().catch(() => false),
    labels,
    text: await card.textContent().catch(() => ""),
  };
}

function managedSessionDomReady(evidence, expected = {}) {
  const hasLabels = ["Sandbox browser", "Local browser", "Desktop"].every((label) =>
    evidence.labels?.some((observed) => String(observed || "").trim() === label),
  );
  return (
    evidence.visible &&
    evidence.sessionId === expected.managedSessionId &&
    evidence.controlState === expected.controlState &&
    evidence.waitingVisible &&
    hasLabels
  );
}

async function waitForManagedSessionDom(page, expected, timeoutMs = 30_000) {
  const evidence = await waitForPredicate(async () => {
    try {
      const frame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
      const current = await managedSessionDomEvidence(frame);
      return managedSessionDomReady(current, expected) ? current : null;
    } catch {
      return null;
    }
  }, timeoutMs, 300);
  if (!evidence) {
    const frame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000).catch(() => null);
    const latest = frame ? await managedSessionDomEvidence(frame).catch((error) => ({ error: String(error) })) : { error: "studio frame unavailable" };
    throw new Error(`Managed session card did not hydrate in the live GUI: ${JSON.stringify(latest)}`);
  }
  return evidence;
}

async function ensureManagedSessionExpanded(frame) {
  const card = frame.locator('[data-testid="studio-managed-session-card"]').last();
  const expanded = card.locator('[data-testid="studio-managed-session-expanded-view"]').first();
  if (await expanded.isVisible().catch(() => false)) {
    return card;
  }
  await clickLocatorWithDomFallback(card.locator('[data-testid="studio-managed-session-expand"]').first());
  await expanded.waitFor({ state: "visible", timeout: 7000 });
  return card;
}

async function clickManagedSessionControl(page, testId, expectedControlState) {
  let lastError = null;
  let clicked = false;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const frame = await findFrameWithTestId(page, "agent-studio-operational-chat");
      const card = await ensureManagedSessionExpanded(frame);
      await clickLocatorWithDomFallback(card.locator(`[data-testid="${testId}"]`).first());
      clicked = true;
      break;
    } catch (error) {
      lastError = error;
      if (!/Frame was detached|Execution context was destroyed|Target closed/i.test(String(error?.message || error))) {
        throw error;
      }
      await wait(350);
    }
  }
  if (!clicked && lastError) throw lastError;
  const observed = await waitForPredicate(
    async () => {
      const frame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000).catch(() => null);
      if (!frame) return null;
      const card = frame.locator('[data-testid="studio-managed-session-card"]').last();
      const state = await card.getAttribute("data-control-state").catch(() => null);
      return state === expectedControlState ? state : null;
    },
    7000,
    100,
  );
  if (observed !== expectedControlState) {
    throw new Error(`Managed session control did not reach ${expectedControlState}.`);
  }
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-managed-session-reconnect-daemon-"));
  const calls = [];
  const managedState = {
    runtimeSessionId: "session_managed_live_gui_reconnect",
    managedSessionId: "sandbox_browser:live_gui_login_gate",
    controlState: "observe",
  };
  const daemon = await startRuntimeDaemonService({
    cwd: repoRoot,
    stateDir: daemonStateDir,
    runtimeBridge: managedSessionReconnectBridge(calls, managedState),
  });
  await seedRuntimeControlModelRoute(daemon.store);
  const thread = await daemon.store.createThread({
    runtime_profile: "runtime_service",
    options: {
      runtime_profile: "runtime_service",
      local: { cwd: repoRoot },
    },
  });
  const threadId = thread.thread_id || thread.threadId;

  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const screenshots = [];
  const consoleLogs = [];
  const pageErrors = [];
  const launches = [];
  let server;
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
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-managed-session-reconnect-user-"));
    extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-managed-session-reconnect-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    writeFileSync(join(outputDir, "thread.json"), `${JSON.stringify(thread, null, 2)}\n`);

    async function launchElectron(label) {
      const cdpPort = await getFreePort();
      const stdoutPath = join(outputDir, `electron-${label}-stdout.log`);
      const stderrPath = join(outputDir, `electron-${label}-stderr.log`);
      const app = spawn(
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

    async function openStudio(launch, label) {
      const startIndex = requests.length;
      queueCommand(commands, "ioi.studio.open", { phase: "chat" });
      await requireNewRequest(requests, (request) => request?.requestType === "studio.open", `studio.open ${label}`, startIndex);
      const studioFrame = await findFrameWithTestId(launch.page, "agent-studio-operational-chat");
      await screenshot(launch.page, outputDir, `studio-open-${label}.png`, screenshots);
      return studioFrame;
    }

    const createLaunch = await launchElectron("create");
    await openStudio(createLaunch, "create");
    let startIndex = requests.length;
    queueCommand(commands, "ioi.studio.exerciseManagedSessionReconnect", {
      phase: "create",
      threadId,
      expectedManagedSessionId: managedState.managedSessionId,
      expectedRuntimeSessionId: managedState.runtimeSessionId,
      expectedControlState: "observe",
    });
    const createRequest = await requireNewRequest(
      requests,
      (request) =>
        request?.requestType === "studio.managedSessionReconnect.exercised" &&
        request?.payload?.phase === "create",
      "studio.managedSessionReconnect.exercised create",
      startIndex,
      90_000,
    );
    const createDomEvidence = await waitForManagedSessionDom(createLaunch.page, {
      managedSessionId: managedState.managedSessionId,
      controlState: "observe",
    });
    await screenshot(createLaunch.page, outputDir, "managed-session-reconnect-create-observe.png", screenshots);

    await clickManagedSessionControl(createLaunch.page, "studio-managed-session-take-over", "take_over");
    const takeOverDomEvidence = await waitForManagedSessionDom(createLaunch.page, {
      managedSessionId: managedState.managedSessionId,
      controlState: "take_over",
    });
    await screenshot(createLaunch.page, outputDir, "managed-session-reconnect-create-take-over.png", screenshots);
    await wait(300);
    const daemonAfterTakeover = await fetchJson(`${daemon.endpoint}/v1/threads/${encodeURIComponent(threadId)}/managed-sessions`);
    const daemonTakeoverCard = firstManagedSession(daemonAfterTakeover);

    await closeElectron(createLaunch, "playwright-trace-create.zip");
    await cleanupProofUserDataProcesses(userDataDir);
    await wait(750);

    const reconnectLaunch = await launchElectron("reconnect");
    await openStudio(reconnectLaunch, "reconnect");
    startIndex = requests.length;
    queueCommand(commands, "ioi.studio.exerciseManagedSessionReconnect", {
      phase: "reconnect",
      threadId,
      expectedManagedSessionId: managedState.managedSessionId,
      expectedRuntimeSessionId: managedState.runtimeSessionId,
      expectedControlState: "take_over",
    });
    const reconnectRequest = await requireNewRequest(
      requests,
      (request) =>
        request?.requestType === "studio.managedSessionReconnect.exercised" &&
        request?.payload?.phase === "reconnect",
      "studio.managedSessionReconnect.exercised reconnect",
      startIndex,
      90_000,
    );
    const reconnectDomEvidence = await waitForManagedSessionDom(reconnectLaunch.page, {
      managedSessionId: managedState.managedSessionId,
      controlState: "take_over",
    });
    await screenshot(reconnectLaunch.page, outputDir, "managed-session-reconnect-rehydrated-take-over.png", screenshots);

    await clickManagedSessionControl(reconnectLaunch.page, "studio-managed-session-return", "return_agent");
    const returnDomEvidence = await waitForManagedSessionDom(reconnectLaunch.page, {
      managedSessionId: managedState.managedSessionId,
      controlState: "return_agent",
    });
    await screenshot(reconnectLaunch.page, outputDir, "managed-session-reconnect-returned.png", screenshots);
    await wait(300);
    const daemonAfterReturn = await fetchJson(`${daemon.endpoint}/v1/threads/${encodeURIComponent(threadId)}/managed-sessions`);
    const daemonReturnCard = firstManagedSession(daemonAfterReturn);

    await closeElectron(reconnectLaunch, "playwright-trace-reconnect.zip");

    const startCalls = calls.filter((call) => call.operation === "start_thread");
    const inspectCalls = calls.filter((call) => call.operation === "inspect_thread");
    const controlCalls = calls.filter((call) => call.operation === "control_thread");
    const checks = {
      createElectronLaunched: Boolean(createLaunch.cdpVersion),
      reconnectElectronLaunched: Boolean(reconnectLaunch.cdpVersion),
      createBridgeLifecyclePassed: createRequest?.payload?.passed === true,
      reconnectBridgeLifecyclePassed: reconnectRequest?.payload?.passed === true,
      createDomCardReady: managedSessionDomReady(createDomEvidence, {
        managedSessionId: managedState.managedSessionId,
        controlState: "observe",
      }),
      uiTakeoverRendered: managedSessionDomReady(takeOverDomEvidence, {
        managedSessionId: managedState.managedSessionId,
        controlState: "take_over",
      }),
      uiTakeoverPersistedInDaemon: daemonTakeoverCard?.control_state === "take_over",
      reconnectRenderedSameManagedSession: managedSessionDomReady(reconnectDomEvidence, {
        managedSessionId: managedState.managedSessionId,
        controlState: "take_over",
      }),
      reconnectBridgeSawSameRuntimeSession: reconnectRequest?.payload?.runtimeSessionId === managedState.runtimeSessionId,
      reconnectBridgeSawReplayReady: reconnectRequest?.payload?.replayReady === true,
      reconnectBridgeSawWaitingForUser: reconnectRequest?.payload?.waitingForUser === true,
      uiReturnRendered: managedSessionDomReady(returnDomEvidence, {
        managedSessionId: managedState.managedSessionId,
        controlState: "return_agent",
      }),
      uiReturnPersistedInDaemon: daemonReturnCard?.control_state === "return_agent",
      startThreadCalledOnce: startCalls.length === 1,
      duplicateRuntimeStartAbsent: startCalls.length === 1,
      controlThreadCalledForTakeoverAndReturn: controlCalls.length === 2,
      inspectThreadUsedForCreateAndReconnect: inspectCalls.length >= 2,
      waitingForUserReplayedAfterReconnect: reconnectDomEvidence.waitingVisible === true,
      productUiAvoidsRuntimeSessionLeak: !String(reconnectDomEvidence.text || "").includes(managedState.runtimeSessionId),
    };
    const proof = {
      schemaVersion: "ioi.autopilot.stage8.managed-session-reconnect-live-gui-proof.v1",
      passed: Object.values(checks).every(Boolean),
      generatedAt: new Date().toISOString(),
      daemonEndpoint: daemon.endpoint,
      threadId,
      managedSessionId: managedState.managedSessionId,
      runtimeSessionId: managedState.runtimeSessionId,
      screenshots,
      createRequest,
      reconnectRequest,
      createDomEvidence,
      takeOverDomEvidence,
      reconnectDomEvidence,
      returnDomEvidence,
      daemonAfterTakeover,
      daemonAfterReturn,
      runtimeBridgeCalls: calls,
      checks,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Managed session reconnect live GUI proof failed checks: ${JSON.stringify(checks)}`);
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
    rmSync(daemonStateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}

const outputDir = process.argv[2] || join(evidenceRoot, timestamp());
const proof = await runProof(outputDir);
console.log(JSON.stringify({ outputDir, passed: proof.passed }, null, 2));
