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
  process.env.AUTOPILOT_POLICY_LEASE_LIVE_GUI_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-runtime-parity-plus/stage-4-policy-lease-sandbox/live-gui-policy-lease-allow-revoke-expiry";

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
  const response = await fetch(`${endpoint}/v1/model-mount/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-policy-lease-live-gui",
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
      source: "policy-lease-live-gui-proof",
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
  const modelId = runtimeModelRoute?.modelId || "stories260k";
  const endpointId = runtimeModelRoute?.endpointId || "endpoint.stories260k";
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
      artifacts: [
        {
          id: modelId,
          modelId,
          name: modelId,
          publisher: "ioi",
          family: "llm",
          format: "GGUF",
          status: "mounted",
        },
      ],
      endpoints: [
        {
          id: endpointId,
          modelId,
          routeId,
          status: "ready",
        },
      ],
      instances: [
        {
          id: `instance.${modelId}`,
          endpointId,
          modelId,
          status: "mounted",
        },
      ],
      routes: [
        {
          id: routeId,
          routeId,
          endpointId,
          modelId,
          status: "ready",
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
        sendJson(response, 200, { ok: true });
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

async function requireRequest(requests, predicate, label, timeoutMs = 45_000, startIndex = 0) {
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
        // VS Code can swap webview frames during startup.
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

async function policyLeaseDomEvidence(page) {
  const frame = await findFrameWithTestId(page, "agent-studio-operational-chat", 15_000);
  const drawer = frame.locator('[data-testid="studio-utility-drawer"]').first();
  const drawerClass = (await drawer.getAttribute("class").catch(() => "")) || "";
  if (!drawerClass.includes("is-expanded")) {
    await frame.locator('[data-testid="studio-utility-toggle"]').first().click({ timeout: 10_000 }).catch(() => undefined);
  }
  await frame.locator('[data-testid="studio-runtime-cockpit"]').first().waitFor({ state: "visible", timeout: 10_000 });
  await frame.locator('[data-testid="studio-policy-lease-dialog"]').first().waitFor({ state: "visible", timeout: 20_000 });
  return await frame.evaluate(() => {
    const root = document.querySelector('[data-testid="agent-studio-operational-chat"]');
    const attr = (name) => root?.getAttribute(name) || "";
    const cards = Array.from(document.querySelectorAll('[data-testid="studio-policy-lease-dialog"]')).map((card) => ({
      status: card.getAttribute("data-lease-status") || "",
      decision: card.getAttribute("data-lease-decision") || "",
      lifecycle: card.getAttribute("data-lease-lifecycle") || "",
      didExecute: card.getAttribute("data-lease-did-execute") || "",
      executedBeforeExpiry: card.getAttribute("data-lease-executed-before-expiry") || "",
      afterRevokeBlocked: card.getAttribute("data-lease-after-revoke-blocked") || "",
      afterExpiryBlocked: card.getAttribute("data-lease-after-expiry-blocked") || "",
      text: card.textContent?.replace(/\s+/g, " ").trim() || "",
    }));
    return {
      rootAttributes: {
        policyLeaseDialogObserved: attr("data-policy-lease-dialog-observed"),
        allowOnceObserved: attr("data-policy-lease-allow-once-observed"),
        revokeObserved: attr("data-policy-lease-revoke-observed"),
        expiryObserved: attr("data-policy-lease-expiry-observed"),
        revokedActionBlocked: attr("data-policy-lease-revoked-action-blocked"),
        expiredActionBlocked: attr("data-policy-lease-expired-action-blocked"),
      },
      cards,
    };
  });
}

async function runProof(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyHypervisorWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "ioi-policy-lease-live-gui-daemon-"));

  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  const daemonModelToken = await createDaemonModelInvocationToken(daemon.endpoint);
  const runtimeModelRoute = await bootstrapNativeRuntimeModelRoute({
    repoRoot,
    daemonEndpoint: daemon.endpoint,
    token: daemonModelToken.token,
    workspaceDir: daemonStateDir,
  });
  const runtimeInference = configureRuntimeAgentServiceInferenceEnv({
    daemonEndpoint: daemon.endpoint,
    token: daemonModelToken.token,
    modelId: runtimeModelRoute.modelId,
    routeId: runtimeModelRoute.routeId,
    overwrite: true,
  });
  writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
  writeFileSync(join(outputDir, "daemon-model-token-grant.json"), `${JSON.stringify({ ...daemonModelToken, token: "redacted" }, null, 2)}\n`);
  writeFileSync(join(outputDir, "runtime-model-route.json"), `${JSON.stringify(runtimeModelRoute, null, 2)}\n`);
  writeFileSync(join(outputDir, "runtime-inference-env.json"), `${JSON.stringify({ ...runtimeInference, token: runtimeInference.configured ? "redacted" : undefined }, null, 2)}\n`);

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
    userDataDir = mkdtempSync(join(tmpdir(), "ioi-policy-lease-live-gui-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "ioi-policy-lease-live-gui-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
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
          IOI_DAEMON_TOKEN: daemonModelToken.token,
          IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-workbench-adapter-host",
          IOI_WORKBENCH_NATIVE_SHELL: "1",
          IOI_AUTOPILOT_STUDIO_TEST_HOOKS: "1",
          AUTOPILOT_SKIP_OVERVIEW: "1",
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
      page.on("console", (message) => consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() }));
      page.on("pageerror", (error) => pageErrors.push(String(error?.stack ?? error?.message ?? error)));
    });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    tracingStarted = true;
    const page = await waitForPredicate(
      () => context.pages().find((candidate) => !candidate.isClosed()) ?? null,
      30_000,
      250,
    );
    if (!page) throw new Error("No Playwright page was available for the Electron fork.");
    page.on("console", (message) => consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() }));
    page.on("pageerror", (error) => pageErrors.push(String(error?.stack ?? error?.message ?? error)));
    await page.setViewportSize({ width: 1550, height: 925 }).catch(() => undefined);

    queueCommand(commands, "ioi.studio.open", { phase: "policy-lease-live-gui" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "studio-open.png", screenshots);

    const lifecycleStart = requests.length;
    queueCommand(commands, "ioi.studio.exercisePolicyLeaseLifecycle", { phase: "policy-lease-live-gui" });
    const lifecycleRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "studio.policyLeaseLifecycle.exercised",
      "studio.policyLeaseLifecycle.exercised",
      75_000,
      lifecycleStart,
    );

    const domEvidence = await waitForPredicate(async () => {
      try {
        const evidence = await policyLeaseDomEvidence(page);
        const statuses = new Set(evidence.cards.map((card) => card.status));
        return statuses.has("pending") && statuses.has("active") && statuses.has("revoked") && statuses.has("expired")
          ? evidence
          : null;
      } catch {
        return null;
      }
    }, 30_000, 300);
    if (!domEvidence) {
      throw new Error("Live GUI did not render pending, active, revoked, and expired policy lease cards.");
    }
    await screenshot(page, outputDir, "policy-lease-lifecycle.png", screenshots);

    const statusSet = new Set(domEvidence.cards.map((card) => card.status));
    const allowCard = domEvidence.cards.find((card) => card.decision === "allow_once");
    const revokedCard = domEvidence.cards.find((card) => card.status === "revoked");
    const expiredCard = domEvidence.cards.find((card) => card.status === "expired");
    const checks = {
      electronLaunched: Boolean(cdpVersion),
      studioOpened: true,
      bridgeLifecyclePassed: lifecycleRequest?.payload?.passed === true,
      rootDialogObserved: domEvidence.rootAttributes.policyLeaseDialogObserved === "true",
      rootAllowOnceObserved: domEvidence.rootAttributes.allowOnceObserved === "true",
      rootRevokeObserved: domEvidence.rootAttributes.revokeObserved === "true",
      rootExpiryObserved: domEvidence.rootAttributes.expiryObserved === "true",
      rootRevokedRetryBlocked: domEvidence.rootAttributes.revokedActionBlocked === "true",
      rootExpiredRetryBlocked: domEvidence.rootAttributes.expiredActionBlocked === "true",
      pendingCardVisible: statusSet.has("pending"),
      activeAllowOnceCardVisible: allowCard?.status === "active" && allowCard?.didExecute === "true",
      revokedCardBlocksRetry: revokedCard?.afterRevokeBlocked === "true",
      expiredCardBlocksRetry: expiredCard?.afterExpiryBlocked === "true",
      expiredCardExecutedBeforeExpiry: expiredCard?.executedBeforeExpiry === "true",
    };
    const proof = {
      schemaVersion: "ioi.autopilot.stage4.policy-lease-lifecycle-live-gui-proof.v1",
      passed: Object.values(checks).every(Boolean),
      generatedAt: new Date().toISOString(),
      screenshots,
      lifecycleRequest,
      domEvidence,
      checks,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    if (!proof.passed) {
      throw new Error(`Policy lease live GUI proof failed checks: ${JSON.stringify(checks)}`);
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
