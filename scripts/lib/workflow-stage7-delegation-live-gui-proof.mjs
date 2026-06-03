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
  process.env.AUTOPILOT_STAGE7_DELEGATION_LIVE_GUI_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-7-delegation-subagent-lanes/live-gui-delegation-lifecycle";

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
      audience: "autopilot-stage7-delegation-live-gui",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.import:*",
        "model.mount:*",
        "model.load:*",
        "route.write:*",
        "route.use:*",
      ],
    }),
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(`Failed to create daemon token: ${JSON.stringify(json)}`);
  }
  return json;
}

function bridgeState(daemonEndpoint, runtimeModelRoute) {
  const routeId = runtimeModelRoute.routeId || "route.local-first";
  const modelId = runtimeModelRoute.modelId || "runtime-control-test-model";
  const endpointId = runtimeModelRoute.endpointId || "endpoint.stage7-delegation";
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
        sendJson(response, 200, bridgeState(daemonEndpoint, runtimeModelRoute));
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

async function fetchDaemonJson(endpoint, routePath) {
  const response = await fetch(new URL(routePath, `${endpoint}/`));
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`Daemon request failed (${response.status}): ${JSON.stringify(body)}`);
  }
  return body;
}

async function cleanupProofUserDataProcesses(userDataDir) {
  if (!userDataDir) return;
  const { spawnSync } = await import("node:child_process");
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

async function seedRuntimeModelRoute(daemon) {
  const modelId = "stage7-delegation-model";
  const endpointId = "endpoint.stage7-delegation";
  const routeId = "route.local-first";
  daemon.store.modelMounting.importModel({
    model_id: modelId,
    provider_id: "provider.local.folder",
    capabilities: ["chat", "responses", "structured_output"],
  });
  daemon.store.modelMounting.mountEndpoint({
    id: endpointId,
    model_id: modelId,
    provider_id: "provider.local.folder",
    capabilities: ["chat", "responses", "structured_output"],
  });
  await daemon.store.modelMounting.loadModel({
    endpoint_id: endpointId,
    load_policy: { mode: "eager" },
  });
  daemon.store.modelMounting.upsertRoute({
    id: routeId,
    role: "chat",
    fallback: [endpointId],
    provider_eligibility: ["local_folder"],
  });
  return { routeId, modelId, endpointId };
}

async function domEvidence(studioFrame) {
  return studioFrame.evaluate(() => {
    const text = String(document.body?.innerText || "").replace(/\s+/g, " ").trim();
    return {
      textSample: text.slice(0, 3000),
      hasWorkerCard: document.querySelectorAll('[data-testid="studio-worker-status-card"]').length > 0,
      hasBrowserCard: document.querySelectorAll('[data-testid="studio-browser-status-card"]').length > 0,
      hasWorkerTracePanel: document.querySelectorAll('[data-testid="studio-worker-contribution-trace"]').length > 0,
      hasTrajectoryPanel: document.querySelectorAll('[data-testid="studio-trajectory-replay-panel"]').length > 0,
      hasDelegationSummary: /Delegation \/ subagent lanes|delegated worker|failed child recovered/i.test(text),
      hasBrowserSubagent: /Browser subagent artifact|browser subagent managed artifact/i.test(text),
    };
  });
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS = "1";
  process.env.IOI_STUDIO_ALLOW_FIXTURE_MODELS = "1";

  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage7-delegation-daemon-"));
  let daemon = await startRuntimeDaemonService({
    cwd: repoRoot,
    stateDir: daemonStateDir,
  });
  const token = await createDaemonModelInvocationToken(daemon.endpoint);
  const runtimeModelRoute = await seedRuntimeModelRoute(daemon);

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
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage7-delegation-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage7-delegation-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "daemon-state-dir"), `${daemonStateDir}\n`);
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

    queueCommand(commands, "ioi.studio.exerciseStage7DelegationLifecycle", {
      routeId: runtimeModelRoute.routeId,
      modelId: runtimeModelRoute.modelId,
    });
    const lifecycleRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "studio.stage7DelegationLifecycle.exercised",
      "studio.stage7DelegationLifecycle.exercised",
      45_000,
    );
    studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
    const finalEvidence = await domEvidence(studioFrame).catch(() => null);
    await screenshot(page, outputDir, "stage7-delegation-after-lifecycle.png", screenshots);

    const threadId = lifecycleRequest?.payload?.threadId;
    const expectedSubagentIds = new Set(Object.values(lifecycleRequest?.payload?.subagentIds ?? {}).filter(Boolean));
    if (!threadId) throw new Error("Stage 7 lifecycle request did not include a threadId.");
    const preRestartSubagents = await fetchDaemonJson(daemon.endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`);
    await daemon.close();
    daemon = null;
    daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
    writeFileSync(join(outputDir, "daemon-restarted-endpoint"), `${daemon.endpoint}\n`);
    const recoveredSubagents = await fetchDaemonJson(daemon.endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`);
    writeFileSync(join(outputDir, "pre-restart-subagents.json"), `${JSON.stringify(preRestartSubagents, null, 2)}\n`);
    writeFileSync(join(outputDir, "recovered-subagents.json"), `${JSON.stringify(recoveredSubagents, null, 2)}\n`);
    const recoveredIds = new Set((recoveredSubagents.subagents ?? []).map((record) => record.subagent_id || record.subagentId));
    const recoveredFailedChild = (recoveredSubagents.subagents ?? []).find((record) =>
      (record.subagent_id || record.subagentId) === lifecycleRequest?.payload?.subagentIds?.failedChild,
    );
    const checks = {
      electronLaunched: true,
      studioOpened: true,
      lifecycleProofRequestObserved: lifecycleRequest?.payload?.passed === true,
      delegatedWorkerSpawned: lifecycleRequest?.payload?.checks?.delegatedWorkerSpawned === true,
      failedChildRecovered: lifecycleRequest?.payload?.checks?.failedChildRecovered === true,
      browserSubagentSpawned: lifecycleRequest?.payload?.checks?.browserSubagentSpawned === true,
      domDelegationVisible: Boolean(finalEvidence?.hasDelegationSummary || finalEvidence?.hasWorkerCard),
      domBrowserSubagentVisible: Boolean(finalEvidence?.hasBrowserSubagent || finalEvidence?.hasBrowserCard),
      preRestartSubagentsVisible: preRestartSubagents.count >= 3,
      restartRecoveredSubagents: recoveredSubagents.count >= 3 &&
        [...expectedSubagentIds].every((id) => recoveredIds.has(id)),
      restartRecoveredFailedChild:
        recoveredFailedChild?.restart_status === "restarted" ||
        recoveredFailedChild?.restartStatus === "restarted",
      screenshotsCaptured: screenshots.length >= 2 && screenshots.every((entry) => entry.exists),
    };
    const passed = Object.values(checks).every(Boolean);
    const proof = {
      schemaVersion: "ioi.autopilot.stage7.delegation.live-gui-proof.v1",
      passed,
      generatedAt: new Date().toISOString(),
      outputDir,
      checks,
      bridgeRequests: {
        lifecycle: lifecycleRequest,
      },
      subagents: {
        preRestart: preRestartSubagents,
        recovered: recoveredSubagents,
      },
      domEvidence: {
        final: finalEvidence,
      },
      screenshots,
      productLeakAudit: {
        rawRuntimePayloadLeakObserved: /IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND|runtime-agent-service-bridge|raw child payload|secret_child_payload/i.test(
          `${finalEvidence?.textSample || ""}`,
        ),
      },
    };
    proof.checks.productTranscriptClean = proof.productLeakAudit.rawRuntimePayloadLeakObserved === false;
    proof.passed = proof.passed && proof.checks.productTranscriptClean;
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Stage 7 delegation live GUI proof failed: ${JSON.stringify(checks)}`);
    }
    return proof;
  } finally {
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
    writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
    if (context && tracingStarted) {
      await context.tracing.stop({ path: join(outputDir, "playwright-trace.zip") }).catch(() => undefined);
    }
    if (browser) await browser.close().catch(() => undefined);
    if (app && !app.killed) {
      app.kill("SIGTERM");
      await wait(1200);
      if (app.exitCode === null) app.kill("SIGKILL");
    }
    await cleanupProofUserDataProcesses(userDataDir);
    await closeServer(server);
    if (daemon) await daemon.close().catch(() => undefined);
    rmSync(daemonStateDir, { recursive: true, force: true });
  }
}

const outputDir = join(evidenceRoot, timestamp());
try {
  const proof = await runProof(outputDir);
  console.log(JSON.stringify({ outputDir, passed: proof.passed }, null, 2));
} catch (error) {
  ensureDir(outputDir);
  writeFileSync(
    join(outputDir, "failure.json"),
    `${JSON.stringify({ error: String(error?.stack || error?.message || error), outputDir }, null, 2)}\n`,
  );
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
}
