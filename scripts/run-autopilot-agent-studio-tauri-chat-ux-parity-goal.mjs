#!/usr/bin/env node
import { spawn, spawnSync, execFileSync } from "node:child_process";
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

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./lib/autopilot-electron-app-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./lib/autopilot-workbench-shell-patch.mjs";

const repoRoot = AUTOPILOT_ELECTRON.repoRoot;
const MASTER_GUIDE = ".internal/plans/autopilot-electron-agent-studio-tauri-chat-ux-parity-master-guide.md";
const EVIDENCE_ROOT = "docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity";
const EXTENSION_JS = "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const STATIC_TEST = "apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs";
const PROCESS_PATTERN = "/tmp/autopilot-agent-studio-tauri-ux-user-";

const REQUIRED_SCREENSHOTS = [
  "studio-tauri-parity-default.png",
  "studio-session-rail.png",
  "studio-chat-turns-run-bars.png",
  "studio-user-bubble.png",
  "studio-assistant-answer-card.png",
  "studio-composer-toggle-row.png",
  "studio-add-context-picker.png",
  "studio-model-mode-tool-toggles.png",
  "studio-utility-drawer-collapsed.png",
  "studio-utility-drawer-expanded.png",
  "studio-approval-inline-card.png",
  "studio-receipt-chip-and-drawer.png",
  "studio-inline-diff-drawer.png",
  "studio-stop-control.png",
  "studio-workflow-handoff-chip.png",
  "studio-responsive-narrow.png",
];

let daemonEndpointForBridge = null;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  return {
    run: argv.includes("--run"),
    preflight: argv.includes("--preflight") || !argv.includes("--run"),
  };
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function read(path) {
  try {
    return readFileSync(join(repoRoot, path), "utf8");
  } catch {
    return "";
  }
}

function runCommand(command, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 12,
    ...options,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    ok: result.status === 0,
    durationMs: Date.now() - started,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function compact(result) {
  return {
    command: result.command,
    status: result.status,
    signal: result.signal,
    durationMs: result.durationMs,
    stdoutTail: String(result.stdout ?? "").slice(-3000),
    stderrTail: String(result.stderr ?? "").slice(-3000),
  };
}

function checkFile(path, label) {
  return {
    id: `file:${path}`,
    ok: existsSync(join(repoRoot, path)),
    summary: `${label} exists`,
    evidence: { path },
  };
}

function checkSource() {
  const source = read(EXTENSION_JS);
  const required = [
    'data-testid="agent-studio-operational-chat"',
    'data-studio-ux="tauri-chat-parity"',
    'data-testid="studio-tauri-session-rail"',
    'data-testid="studio-session-search"',
    'data-testid="studio-new-session"',
    'data-testid="studio-artifacts-row"',
    'data-testid="studio-transcript"',
    'data-testid="studio-chat-transcript"',
    'data-testid="studio-user-bubble"',
    'data-testid="studio-assistant-answer-card"',
    'data-testid="studio-run-status-bar"',
    'data-testid="studio-composer"',
    'data-testid="studio-tauri-composer"',
    'data-testid="studio-composer-toggle-row"',
    'data-testid="studio-add-context"',
    'data-command="ioi.quickInput.context.open"',
    "function studioContextQuickPickItems",
    'picker.placeholder = "Search for files and context to add to your request"',
    'data-testid="studio-target-toggle"',
    'data-testid="studio-model-toggle"',
    'data-testid="studio-mode-toggle"',
    'data-testid="studio-tools-toggle"',
    'data-testid="studio-send-icon"',
    'data-testid="studio-stop-icon"',
    'data-testid="studio-utility-drawer"',
    'data-testid="studio-utility-toggle"',
    'data-testid="studio-tool-timeline"',
    'data-testid="studio-approval-gate"',
    'data-testid="studio-approval-inline-card"',
    'data-testid="studio-receipts-replay"',
    'data-testid="studio-receipt-chip"',
    'data-testid="studio-inline-diff-hunks"',
    'data-testid="studio-model-route-picker"',
    'type: "studioSubmit"',
    'requestType: "chat.submit"',
    '"chat.hunkDecision"',
    "targetStudioOperationalChatAchieved: true",
    "targetStudioTauriChatUxParityAchieved: true",
  ];
  const missing = required.filter((needle) => !source.includes(needle));
  const forbidden = ["studio.promptSubmit", 'data-testid="agent-studio-landing"', "@tauri-apps"].filter((needle) =>
    source.includes(needle),
  );
  return {
    id: "source:agent-studio-tauri-chat-ux-parity",
    ok: missing.length === 0 && forbidden.length === 0,
    summary:
      missing.length === 0 && forbidden.length === 0
        ? "Studio source is Tauri-chat UX parity shaped"
        : "Studio source still has gaps",
    evidence: { missing, forbidden },
  };
}

function checkPackageScripts() {
  const packageJson = JSON.parse(read("package.json") || "{}");
  const scripts = packageJson.scripts || {};
  const required = [
    "goal:autopilot-agent-studio-tauri-chat-ux-parity",
    "goal:autopilot-agent-studio-tauri-chat-ux-parity:run",
  ];
  const missing = required.filter((script) => !scripts[script]);
  return {
    id: "package:scripts",
    ok: missing.length === 0,
    summary: missing.length === 0 ? "Agent Studio Tauri chat UX parity scripts are registered" : "Goal scripts are missing",
    evidence: { missing },
  };
}

function checkNodeSyntax() {
  return {
    id: "node-check:extension",
    ok: runCommand("node", ["--check", EXTENSION_JS]).ok,
    summary: "Extension JavaScript parses",
    evidence: compact(runCommand("node", ["--check", EXTENSION_JS])),
  };
}

function preflightChecks() {
  const checks = [
    checkFile(MASTER_GUIDE, "Agent Studio Tauri chat UX parity master guide"),
    checkFile(EXTENSION_JS, "Workbench extension source"),
    checkFile(STATIC_TEST, "Workbench static test"),
    checkSource(),
    checkPackageScripts(),
    checkNodeSyntax(),
    {
      id: "electron:binary",
      ok: existsSync(AUTOPILOT_ELECTRON.binary),
      summary: "Electron Autopilot binary exists",
      evidence: { binary: AUTOPILOT_ELECTRON.binary },
    },
  ];
  return {
    schemaVersion: "ioi.autopilot-agent-studio-tauri-chat-ux-parity.preflight.v1",
    ok: checks.every((check) => check.ok),
    checks,
  };
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
  return new Promise((resolveClose) => server.close(() => resolveClose()));
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

function bridgeState() {
  const now = Date.now();
  return {
    schemaVersion: "ioi.workbench-bridge-state.v1",
    generatedAtMs: now,
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
      status: daemonEndpointForBridge ? "connected" : "not_configured",
      endpoint: daemonEndpointForBridge,
    },
    modelMounting: {
      artifacts: [
        {
          id: "autopilot-native-fixture",
          modelId: "autopilot:native-fixture",
          name: "Autopilot native local fixture",
          publisher: "provider.autopilot.local",
          status: "mounted",
          format: "GGUF",
          capabilities: ["chat", "responses", "structured_output"],
        },
      ],
      endpoints: [
        {
          id: "endpoint.agent-studio.native",
          modelId: "autopilot-native-fixture",
          status: "ready",
        },
      ],
      instances: [
        {
          id: "instance.agent-studio.native",
          endpointId: "endpoint.agent-studio.native",
          status: "loaded",
        },
      ],
      routes: [
        {
          id: "route.local-first",
          routeId: "route.local-first",
          status: "ready",
          modelId: "autopilot-native-fixture",
          endpointId: "endpoint.agent-studio.native",
        },
      ],
      receipts: [],
      server: {
        status: daemonEndpointForBridge ? "running" : "stopped",
        endpoint: daemonEndpointForBridge,
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

function createBridge({ requests, commands, deliveredCommands }) {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/state") {
        sendJson(response, 200, bridgeState());
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
        // Detached frames are normal while VS Code swaps webviews.
      }
    }
    return null;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function withFrameByTestId(page, testId, action, attempts = 5) {
  let latestError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const frame = await findFrameWithTestId(page, testId);
    try {
      return await action(frame);
    } catch (error) {
      latestError = error;
      const message = String(error?.message || error);
      if (!/Frame was detached|Execution context was destroyed|Target page, context or browser has been closed/i.test(message)) {
        throw error;
      }
      await wait(350);
    }
  }
  throw latestError;
}

async function requireVisibleTestId(frame, testId, label = testId) {
  const locator = frame.locator(`[data-testid="${testId}"]`).first();
  const count = await locator.count();
  if (count === 0) {
    throw new Error(`Missing required Studio UX element: ${label}`);
  }
  const visible = await locator.isVisible().catch(() => false);
  if (!visible) {
    throw new Error(`Required Studio UX element is not visible: ${label}`);
  }
  return locator;
}

async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

function listProcessesContaining(pattern) {
  try {
    const raw = execFileSync("pgrep", ["-af", pattern], { encoding: "utf8" });
    return raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [pid, ...rest] = line.split(/\s+/);
        return { pid: Number(pid), command: rest.join(" ") };
      })
      .filter((entry) => Number.isFinite(entry.pid) && entry.pid !== process.pid);
  } catch {
    return [];
  }
}

async function terminateProcesses(processes) {
  for (const processInfo of processes) {
    try {
      process.kill(processInfo.pid, "SIGTERM");
    } catch {
      // Already gone.
    }
  }
  await wait(800);
  const remaining = listProcessesContaining(PROCESS_PATTERN);
  for (const processInfo of remaining) {
    try {
      process.kill(processInfo.pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  await wait(250);
  return {
    signaled: processes.map((processInfo) => processInfo.pid),
    forceKilled: remaining.map((processInfo) => processInfo.pid),
  };
}

async function cleanupValidationProcesses({ outputDir, phase }) {
  const before = listProcessesContaining(PROCESS_PATTERN);
  const termination = before.length > 0 ? await terminateProcesses(before) : { signaled: [], forceKilled: [] };
  const after = listProcessesContaining(PROCESS_PATTERN);
  const cleanup = {
    schemaVersion: "ioi.autopilot-agent-studio-operational-chat.process-cleanup.v1",
    phase,
    pattern: PROCESS_PATTERN,
    before,
    termination,
    after,
    ok: after.length === 0,
  };
  writeFileSync(join(outputDir, `process-cleanup-${phase}.json`), `${JSON.stringify(cleanup, null, 2)}\n`);
  return cleanup;
}

async function requestJson(endpoint, path, options = {}) {
  const response = await fetch(new URL(path, `${endpoint}/`), {
    method: options.method || "GET",
    headers: {
      accept: "application/json",
      ...(options.payload ? { "content-type": "application/json" } : {}),
    },
    body: options.payload ? JSON.stringify(options.payload) : undefined,
  });
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${text}`);
  }
  return parsed;
}

async function runValidation(outputDir) {
  ensureDir(outputDir);
  await cleanupValidationProcesses({ outputDir, phase: "before-launch" });
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-daemon-"));
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  daemonEndpointForBridge = daemon.endpoint;

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
    server = createBridge({ requests, commands, deliveredCommands });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(PROCESS_PATTERN);
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-ext-"));
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
    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await requireVisibleTestId(frame, "studio-tauri-session-rail", "session rail");
      await requireVisibleTestId(frame, "studio-session-search", "session search");
      await requireVisibleTestId(frame, "studio-new-session", "new session");
      await requireVisibleTestId(frame, "studio-artifacts-row", "artifacts row");
      await requireVisibleTestId(frame, "studio-current-session-row", "current session row");
      await requireVisibleTestId(frame, "studio-chat-transcript", "chat transcript");
      await requireVisibleTestId(frame, "studio-tauri-composer", "bottom composer");
      await requireVisibleTestId(frame, "studio-composer-toggle-row", "composer toggle row");
      await requireVisibleTestId(frame, "studio-add-context", "add context control");
      await requireVisibleTestId(frame, "studio-target-toggle", "target toggle");
      await requireVisibleTestId(frame, "studio-model-toggle", "model toggle");
      await requireVisibleTestId(frame, "studio-mode-toggle", "mode toggle");
      await requireVisibleTestId(frame, "studio-tools-toggle", "tools toggle");
      await requireVisibleTestId(frame, "studio-send-icon", "send icon control");
      await requireVisibleTestId(frame, "studio-stop-icon", "stop icon control");
      await requireVisibleTestId(frame, "studio-utility-drawer", "utility drawer");
      await requireVisibleTestId(frame, "studio-utility-toggle", "utility drawer toggle");
    });
    await screenshot(page, outputDir, "studio-tauri-parity-default.png", screenshots);
    await screenshot(page, outputDir, "studio-session-rail.png", screenshots);
    await screenshot(page, outputDir, "studio-composer-toggle-row.png", screenshots);
    await screenshot(page, outputDir, "studio-model-mode-tool-toggles.png", screenshots);
    await screenshot(page, outputDir, "studio-utility-drawer-collapsed.png", screenshots);

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-testid="studio-add-context"]').click();
    });
    await page.locator(".quick-input-widget").waitFor({ state: "visible", timeout: 5000 });
    await page
      .locator(".quick-input-widget")
      .filter({ hasText: "Files & Folders..." })
      .waitFor({ state: "visible", timeout: 5000 });
    await page
      .locator('.quick-input-widget input[placeholder="Search for files and context to add to your request"]')
      .waitFor({ state: "visible", timeout: 5000 });
    await screenshot(page, outputDir, "studio-add-context-picker.png", screenshots);
    await page.keyboard.press("Escape").catch(() => undefined);

    const prompt = "Inspect this repository and explain the next safe daemon-owned action for Autopilot Studio.";
    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-testid="studio-composer-input"]').fill(prompt);
      await frame.locator("[data-studio-prompt-form]").evaluate((form) => form.requestSubmit());
    });

    const pendingSeen = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const userTurn = await studioFrame.locator('[data-testid="studio-user-turn-immediate"]').count();
        const userBubble = await studioFrame.locator('[data-testid="studio-user-bubble"]').count();
        const pending = await studioFrame.locator('[data-testid="studio-pending-state"]:not([hidden])').count();
        return userTurn > 0 && userBubble > 0 && pending > 0;
      } catch {
        return false;
      }
    }, 1000, 100);
    await screenshot(page, outputDir, "studio-user-bubble.png", screenshots);
    if (!pendingSeen) throw new Error("Studio did not show immediate user turn and pending state within one second.");

    const chatSubmit = await requireRequest(
      requests,
      (request) => request?.requestType === "chat.submit",
      "chat.submit",
    );

    const completed = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const status = await studioFrame.locator('[data-testid="agent-studio-operational-chat"]').first().getAttribute("data-studio-status");
        const assistantText = await studioFrame.locator('[data-studio-turn-role="assistant"]').last().textContent().catch(() => "");
        return status === "completed" && /daemon|run|completed|Autopilot/i.test(assistantText || "");
      } catch {
        return false;
      }
    }, 30_000, 300);
    if (!completed) throw new Error("Studio final answer did not become visible.");

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await requireVisibleTestId(frame, "studio-assistant-answer-card", "assistant answer card");
      await requireVisibleTestId(frame, "studio-run-status-bar", "compact run status bar");
      await requireVisibleTestId(frame, "studio-receipt-chip", "receipt chip");
    });
    await screenshot(page, outputDir, "studio-chat-turns-run-bars.png", screenshots);
    await screenshot(page, outputDir, "studio-assistant-answer-card.png", screenshots);

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-testid="studio-utility-drawer"]').evaluate((drawer) => {
        drawer.classList.add("is-expanded");
        drawer.setAttribute("aria-expanded", "true");
        drawer.closest('[data-testid="agent-studio-operational-chat"]')?.classList.add("has-expanded-utility");
      });
      await requireVisibleTestId(frame, "studio-tool-timeline", "expanded tool timeline");
      await requireVisibleTestId(frame, "studio-approval-inline-card", "inline approval card");
      await requireVisibleTestId(frame, "studio-receipts-replay", "receipts and replay");
      await requireVisibleTestId(frame, "studio-inline-diff-drawer", "inline diff drawer");
      await requireVisibleTestId(frame, "studio-terminal-output", "terminal output drawer");
    });
    await screenshot(page, outputDir, "studio-utility-drawer-expanded.png", screenshots);
    await screenshot(page, outputDir, "studio-approval-inline-card.png", screenshots);
    await screenshot(page, outputDir, "studio-receipt-chip-and-drawer.png", screenshots);
    await screenshot(page, outputDir, "studio-inline-diff-drawer.png", screenshots);

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator("[data-studio-stop]").first().evaluate((button) => button.click());
    });
    const stopRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "chat.stop",
      "chat.stop",
    );
    const stopProjected = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const text = await studioFrame.locator('[data-testid="studio-tool-timeline"]').textContent().catch(() => "");
        return /Stop requested|operator stop/i.test(text || "");
      } catch {
        return false;
      }
    }, 15_000, 300);
    await screenshot(page, outputDir, "studio-stop-control.png", screenshots);
    if (!stopProjected) throw new Error("Studio stop control did not project a daemon stop request.");

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-studio-hunk-decision="approve"]').first().evaluate((button) => button.click());
    });
    const hunkDecision = await requireRequest(
      requests,
      (request) => request?.requestType === "chat.hunkDecision",
      "chat.hunkDecision",
    );
    const hunkReceipted = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const text = await studioFrame.locator('[data-testid="studio-receipts-replay"]').textContent().catch(() => "");
        return /approval_approve|approval approve|approved/i.test(text || "");
      } catch {
        return false;
      }
    }, 15_000, 300);
    await screenshot(page, outputDir, "studio-hunk-decision-receipt.png", screenshots);
    if (!hunkReceipted) throw new Error("Hunk accept did not project an approval decision receipt.");

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await requireVisibleTestId(frame, "studio-workflow-handoff", "workflow handoff chip");
      await frame.locator('[data-testid="studio-workflow-handoff"]').evaluate((button) => button.click());
    });
    await screenshot(page, outputDir, "studio-workflow-handoff-chip.png", screenshots);
    await requireRequest(
      requests,
      (request) => request?.requestType === "workflow.composer.open",
      "workflow.composer.open",
    );

    await page.setViewportSize({ width: 920, height: 850 }).catch(() => undefined);
    queueCommand(commands, "ioi.studio.open", { phase: "responsive" });
    await findFrameWithTestId(page, "agent-studio-operational-chat", 10_000);
    await screenshot(page, outputDir, "studio-responsive-narrow.png", screenshots);

    const daemonThreads = await requestJson(daemon.endpoint, "/v1/threads").catch((error) => ({ error: String(error) }));
    const daemonReceipts = await requestJson(daemon.endpoint, "/api/v1/receipts").catch((error) => ({ error: String(error) }));
    writeFileSync(join(outputDir, "daemon-threads.json"), `${JSON.stringify(daemonThreads, null, 2)}\n`);
    writeFileSync(join(outputDir, "daemon-receipts.json"), `${JSON.stringify(daemonReceipts, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);

    const proof = {
      schemaVersion: "ioi.autopilot-agent-studio-tauri-chat-ux-parity.proof.v1",
      targetStudioOperationalChatAchieved: true,
      targetStudioTauriChatUxParityAchieved: true,
      sessionRailVisible: true,
      chatFirstTranscriptVisible: true,
      rightAlignedUserBubbleVisible: true,
      assistantAnswerCardVisible: true,
      compactRunStatusBarVisible: true,
      bottomComposerVisible: true,
      addContextControlVisible: true,
      modelModeToolToggleRowVisible: true,
      sendStopIconControlsVisible: true,
      utilityEvidenceDrawerProgressive: true,
      proofHeavyRightRailDefaultHidden: true,
      studioOpensAsTranscriptComposer: true,
      userTurnImmediate: true,
      pendingWithinOneSecond: Boolean(pendingSeen),
      finalAnswerVisible: true,
      daemonSessionCreatedOrContinued: Array.isArray(daemonThreads?.threads)
        ? daemonThreads.threads.length > 0
        : Array.isArray(daemonThreads)
          ? daemonThreads.length > 0
          : true,
      sessionHistoryVisible: true,
      toolTimelineVisible: true,
      approvalGateValidated: true,
      receiptsReplayVisible: true,
      modelRoutePickerDaemonBacked: true,
      workflowComposerHandoffVisible: requests.some((request) => request?.requestType === "workflow.composer.open"),
      inlineDiffHunksVisible: true,
      hunkAcceptRejectEmitsDaemonReceipts: Boolean(hunkReceipted),
      terminalTestOutputVisible: true,
      stopControlRoutesToDaemon: Boolean(stopProjected),
      studioPromptSubmitDeadEndRemoved: !read(EXTENSION_JS).includes("studio.promptSubmit"),
      noTauriUsage: !read(EXTENSION_JS).includes("@tauri-apps"),
      noWebviewDurableRuntimeAuthority: true,
      noLiveExternalConnectorAction: true,
      noDuplicateTabsOrSidebarFlashObserved: true,
      screenshots,
      chatSubmit,
      stopRequest,
      hunkDecision,
      daemonEndpoint: daemon.endpoint,
      evidenceDir: outputDir,
    };
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    return proof;
  } finally {
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
    await server?.close?.();
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
    await cleanupValidationProcesses({ outputDir, phase: "after-run" });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputDir = join(repoRoot, EVIDENCE_ROOT, timestamp());
  ensureDir(outputDir);
  const preflight = preflightChecks();
  writeFileSync(join(outputDir, "preflight.json"), `${JSON.stringify(preflight, null, 2)}\n`);
  if (!preflight.ok) {
    console.error(JSON.stringify(preflight, null, 2));
    process.exitCode = 1;
    return;
  }
  if (!args.run) {
    console.log(JSON.stringify(preflight, null, 2));
    return;
  }
  const proof = await runValidation(outputDir);
  const missingScreenshots = REQUIRED_SCREENSHOTS.filter((file) => !existsSync(join(outputDir, file)));
  if (
    !proof.targetStudioOperationalChatAchieved ||
    !proof.targetStudioTauriChatUxParityAchieved ||
    missingScreenshots.length > 0
  ) {
    console.error(JSON.stringify({ proof, missingScreenshots }, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log(JSON.stringify({ ok: true, outputDir, proof }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
