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
import { dirname, join } from "node:path";

import { chromium } from "playwright";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./autopilot-electron-app-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./autopilot-workbench-shell-patch.mjs";
import {
  bootstrapNativeRuntimeModelRoute,
  configureRuntimeAgentServiceBridgeEnv,
  configureRuntimeAgentServiceInferenceEnv,
} from "./autopilot-runtime-agent-service-bridge.mjs";
import { collectDaemonRuntimeTraceSummaryBestEffort } from "./agent-studio-live-gui-validation/trace-summary.mjs";

const repoRoot = AUTOPILOT_ELECTRON.repoRoot;
const evidenceRoot =
  process.env.AUTOPILOT_STAGE5_STOP_HOOK_REPAIR_LIVE_GUI_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-5-stop-cancel-recover-stop-hook/live-gui-stop-hook-repair-loop";

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

async function createDaemonModelInvocationToken(endpoint) {
  const response = await fetch(`${endpoint}/api/v1/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-stage5-stop-hook-repair-live-gui",
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
      source: "stage5-stop-hook-repair-live-gui-proof",
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
  const modelId = runtimeModelRoute?.modelId || "autopilot-native-fixture";
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

async function requireRequest(requests, predicate, label, timeoutMs = 150_000) {
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

function prepareFixture(runId) {
  const fixtureRootRelativePath = "stage5-stop-hook-repair-workspace-fixtures";
  const fixtureDir = join(repoRoot, fixtureRootRelativePath, runId);
  ensureDir(fixtureDir);
  const helperRelativePath = `${fixtureRootRelativePath}/${runId}/status-labels.mjs`;
  const testRelativePath = `${fixtureRootRelativePath}/${runId}/status-labels.test.mjs`;
  const helperPath = join(repoRoot, helperRelativePath);
  const testPath = join(repoRoot, testRelativePath);
  writeFileSync(
    helperPath,
    [
      "export function normalizeStatusLabel(status) {",
      "  return String(status || \"\").trim();",
      "}",
      "",
    ].join("\n"),
    "utf8",
  );
  writeFileSync(
    testPath,
    [
      "import assert from \"node:assert/strict\";",
      "import test from \"node:test\";",
      "import { normalizeStatusLabel } from \"./status-labels.mjs\";",
      "",
      "test(\"normalizes run statuses\", () => {",
      "  assert.equal(normalizeStatusLabel(\"waiting_for_input\"), \"Waiting for input\");",
      "  assert.equal(normalizeStatusLabel(\"completed\"), \"Completed\");",
      "});",
      "",
    ].join("\n"),
    "utf8",
  );
  return {
    fixtureDir,
    helperPath,
    testPath,
    helperRelativePath,
    testRelativePath,
  };
}

async function stage5DomEvidence(frame) {
  return frame.evaluate(() => {
    const assistantNodes = Array.from(document.querySelectorAll(
      '[data-testid="studio-assistant-answer-text"], [data-testid="studio-streaming-output"]',
    ));
    const answerNode = assistantNodes[assistantNodes.length - 1] || null;
    const answerText = String(answerNode?.textContent || "").replace(/\s+/g, " ").trim();
    const workBars = Array.from(document.querySelectorAll("[data-testid='studio-run-status-bar']"));
    const workBar = workBars[workBars.length - 1] || null;
    if (workBar) {
      workBar.open = true;
      workBar.setAttribute("open", "");
    }
    const drawer = document.querySelector("[data-testid='studio-utility-drawer']");
    const toolTimeline = document.querySelector("[data-testid='studio-tool-timeline']");
    const diffHunks = Array.from(document.querySelectorAll(
      "[data-testid='studio-inline-diff-hunks'], [data-testid='studio-native-diff-hunk']",
    ));
    const productLeakPatterns = [
      /\bERROR_CLASS=/i,
      /\bStopHookBlocked\b/i,
      /\bstop_hook/i,
      /\bchat_reply_blocked_by_stop_hook\b/i,
      /\bstop_hook_completion_blocked\b/i,
      /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
      /\b(?:autopilot-)?native-fixture\b/i,
      /\btool\.(?:completed|failed|started)\b/i,
      /\.tmp\/autopilot-stage5-stop-hook-repair/i,
      /stage5-stop-hook-repair-workspace-fixtures/i,
      /\/home\/[^<\s]+/i,
      /\/tmp\/[^<\s]+/i,
    ];
    const operationalText = [
      String(workBar?.textContent || ""),
      String(drawer?.textContent || ""),
      String(toolTimeline?.textContent || ""),
      diffHunks.map((node) => String(node.textContent || "")).join("\n"),
    ].join("\n");
    return {
      assistantText: answerText,
      answerReportsPassingValidation: /repaired|passes|validation/i.test(answerText),
      productRawLeaks: productLeakPatterns.filter((pattern) => pattern.test(answerText)).map(String),
      workLaneTextSample: String(workBar?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 1600),
      drawerTextSample: String(drawer?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 1600),
      toolTimelineTextSample: String(toolTimeline?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 1600),
      hunkTextSample: diffHunks.map((node) => String(node.textContent || "").replace(/\s+/g, " ").trim()).join(" ").slice(0, 1600),
      hunkCount: diffHunks.length,
      operationalRepairLoop:
        /shell(::|__)run|file(::|__)edit|validation|hunk|status-label|normalizeStatusLabel/i.test(operationalText),
      hunkVisible: /normalizeStatusLabel|status-labels\.mjs|file(::|__)edit/i.test(operationalText),
      answerCardCount: document.querySelectorAll('[data-testid="studio-assistant-answer-card"]').length,
      documentedWorkCount: document.querySelectorAll('[data-studio-turn-role="assistant"][data-documented-work="true"]').length,
    };
  });
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function domReady(evidence) {
  return Boolean(
    evidence?.answerReportsPassingValidation &&
    evidence?.operationalRepairLoop &&
    evidence?.hunkVisible &&
    firstArray(evidence?.productRawLeaks).length === 0
  );
}

function traceToolCompletionCount(summary, toolName) {
  return firstArray(summary?.toolCompletions).filter((entry) => entry?.toolName === toolName).length;
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF = "1";
  process.env.IOI_FORCE_NATIVE_FIXTURE_MODEL_ROUTE = "1";
  process.env.IOI_STUDIO_ALLOW_FIXTURE_MODELS = "1";

  const runId = `run-${timestamp()}`;
  const fixture = prepareFixture(runId);
  writeFileSync(join(outputDir, "fixture.json"), `${JSON.stringify(fixture, null, 2)}\n`);

  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const initialValidation = spawnSync("node", ["--test", fixture.testRelativePath], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  writeFileSync(join(outputDir, "initial-validation.json"), `${JSON.stringify({
    status: initialValidation.status,
    stdout: initialValidation.stdout,
    stderr: initialValidation.stderr,
  }, null, 2)}\n`);
  if (initialValidation.status === 0) {
    throw new Error("Stage 5 fixture test unexpectedly passed before the repair loop.");
  }

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage5-stop-hook-repair-gui-daemon-"));
  const stage5FixtureStateDir = join(daemonStateDir, "stage5-stop-hook-repair-state");
  process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR = stage5FixtureStateDir;
  configureRuntimeAgentServiceBridgeEnv({
    repoRoot,
    stateDir: daemonStateDir,
    workspaceRoot: repoRoot,
    env: process.env,
    overwrite: true,
    build: true,
  });
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
      runtimeModelRoute,
      requests,
      commands,
      deliveredCommands,
    });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage5-stop-hook-repair-gui-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage5-stop-hook-repair-gui-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "daemon-state-dir"), `${daemonStateDir}\n`);
    writeFileSync(join(outputDir, "stage5-fixture-state-dir"), `${stage5FixtureStateDir}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    writeFileSync(join(outputDir, "runtime-model-route.json"), `${JSON.stringify(runtimeModelRoute, null, 2)}\n`);

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
          IOI_DAEMON_TOKEN: token.token,
          IOI_AUTOPILOT_CANONICAL_SHELL: "vscode-electron-fork",
          IOI_WORKBENCH_NATIVE_SHELL: "1",
          IOI_AUTOPILOT_STUDIO_TEST_HOOKS: "1",
          IOI_STAGE5_STOP_HOOK_REPAIR_PROOF: "1",
          IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR: stage5FixtureStateDir,
          IOI_FORCE_NATIVE_FIXTURE_MODEL_ROUTE: "1",
          IOI_STUDIO_ALLOW_FIXTURE_MODELS: "1",
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

    const stage5Prompt = [
      `ARP_P0_007_PROOF_TOKEN repair loop for normalizeStatusLabel at ${fixture.helperRelativePath}.`,
      "Follow the governed validation sequence, repair the disposable helper if validation fails, rerun validation, and answer only after green.",
    ].join(" ");
    queueCommand(commands, "ioi.studio.exerciseStage5StopHookRepairLoop", {
      prompt: stage5Prompt,
      helperPath: fixture.helperRelativePath,
      routeId: runtimeModelRoute.routeId,
      modelId: runtimeModelRoute.modelId,
    });
    const repairRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "studio.stage5StopHookRepairLoop.exercised",
      "studio.stage5StopHookRepairLoop.exercised",
      210_000,
    );
    studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
    await screenshot(page, outputDir, "stage5-stop-hook-repair-final.png", screenshots);
    await studioFrame.locator('[data-testid="studio-utility-toggle"]').first().click().catch(() => undefined);
    await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        return (await studioFrame.locator('[data-testid="studio-utility-drawer"].is-expanded').count()) > 0;
      } catch {
        return false;
      }
    }, 5_000, 200);
    await screenshot(page, outputDir, "stage5-stop-hook-repair-work-lane.png", screenshots);

    const domEvidence = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const evidence = await stage5DomEvidence(studioFrame);
        return domReady(evidence) ? evidence : null;
      } catch {
        return null;
      }
    }, 25_000, 300);
    if (!domEvidence) {
      const latest = await stage5DomEvidence(studioFrame).catch((error) => ({ error: String(error) }));
      throw new Error(`Stage 5 stop-hook repair DOM evidence did not become ready: ${JSON.stringify(latest)}`);
    }

    const finalValidation = spawnSync("node", ["--test", fixture.testRelativePath], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    writeFileSync(join(outputDir, "final-validation.json"), `${JSON.stringify({
      status: finalValidation.status,
      stdout: finalValidation.stdout,
      stderr: finalValidation.stderr,
    }, null, 2)}\n`);

    const daemonRuntimeTraceSummary = collectDaemonRuntimeTraceSummaryBestEffort({
      daemonStateDir,
      outputDir,
      label: "stage5-stop-hook-repair",
      repoRoot,
    });
    const requestPayload = repairRequest?.payload || {};
    const requestChecks = requestPayload.checks || {};
    const traceCompleted = new Set(firstArray(daemonRuntimeTraceSummary?.completedToolNames));
    const traceFailed = new Set(firstArray(daemonRuntimeTraceSummary?.failedToolNames));
    const traceChatReplyFailures = firstArray(daemonRuntimeTraceSummary?.toolFailures).filter((entry) =>
      entry?.toolName === "chat__reply" && /StopHookBlocked|stop_hook/i.test(`${entry?.errorClass || ""}\n${entry?.output || ""}`)
    );
    const checks = {
      electronLaunched: Boolean(cdpVersion),
      studioOpened: true,
      bridgeProofObserved: Boolean(repairRequest),
      firstValidationFailedBeforeRepair: initialValidation.status !== 0,
      firstValidationCommandCompleted: requestChecks.firstValidationCommandCompleted === true && traceCompleted.has("shell__run"),
      failingValidationObserved: requestChecks.failingValidationObserved === true,
      prematureChatReplyBlocked: requestChecks.prematureChatReplyBlocked === true &&
        (traceFailed.has("chat__reply") || traceChatReplyFailures.length > 0),
      hunkEditCompleted: requestChecks.hunkEditCompleted === true && traceCompleted.has("file__edit"),
      hunkWorkflowProjected: requestChecks.hunkWorkflowProjected === true && domEvidence.hunkVisible === true,
      validationReranAfterEdit: requestChecks.validationReranAfterEdit === true &&
        traceToolCompletionCount(daemonRuntimeTraceSummary, "shell__run") >= 2,
      passingValidationObserved: requestChecks.passingValidationObserved === true && finalValidation.status === 0,
      finalChatReplyCompleted: requestChecks.finalChatReplyCompleted === true && traceCompleted.has("chat__reply"),
      domFinalAnswerVisible: domEvidence.answerReportsPassingValidation === true,
      domWorkLaneShowsRepairLoop: domEvidence.operationalRepairLoop === true,
      productTranscriptClean: firstArray(domEvidence.productRawLeaks).length === 0 && requestChecks.productTranscriptClean === true,
      screenshotsCaptured: screenshots.some((item) => item.file === "stage5-stop-hook-repair-final.png" && item.exists) &&
        screenshots.some((item) => item.file === "stage5-stop-hook-repair-work-lane.png" && item.exists),
    };
    const proof = {
      schemaVersion: "ioi.autopilot.stage5.stop-hook-repair-loop-live-gui-proof.v1",
      passed: Object.values(checks).every(Boolean),
      generatedAt: new Date().toISOString(),
      prompt: stage5Prompt,
      fixture: {
        helperRelativePath: fixture.helperRelativePath,
        testRelativePath: fixture.testRelativePath,
      },
      daemonEndpoint: daemon.endpoint,
      runtimeModelRoute,
      screenshots,
      repairRequest,
      domEvidence,
      daemonRuntimeTraceSummary,
      checks,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Stage 5 stop-hook repair live GUI proof failed checks: ${JSON.stringify(checks)}`);
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
    rmSync(fixture.fixtureDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}

const outputDir = process.argv[2] || join(evidenceRoot, timestamp());
ensureDir(dirname(outputDir));
const proof = await runProof(outputDir);
console.log(JSON.stringify({ outputDir, passed: proof.passed }, null, 2));
