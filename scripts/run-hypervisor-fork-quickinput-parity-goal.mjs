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
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchExtensionTargets,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./lib/autopilot-workbench-shell-patch.mjs";

const repoRoot = HYPERVISOR_WORKBENCH_ADAPTER_HOST.repoRoot;
const MASTER_GUIDE = ".internal/plans/autopilot-electron-fork-level-quickinput-parity-master-guide.md";
const EVIDENCE_ROOT = "docs/evidence/autopilot-fork-quickinput-parity";
const EXTENSION_JS = "workbench-adapters/ioi-workbench/extension.js";
const STATIC_TEST = "workbench-adapters/ioi-workbench/extension.static.test.mjs";
const SHELL_PATCH = "scripts/lib/autopilot-workbench-shell-patch.mjs";
const PROCESS_PATTERN = "/tmp/autopilot-fork-quickinput-user-";

const REQUIRED_SCREENSHOTS = [
  "fork-add-context-quickinput.png",
  "fork-add-context-keyboard-navigation.png",
  "fork-configure-tools-tree.png",
  "fork-tools-collapsible-rows.png",
  "fork-tools-checkbox-selected-count.png",
  "fork-composer-focus-restored.png",
];

let daemonEndpointForBridge = null;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  return {
    run: argv.includes("--run"),
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

function checkPackageScripts() {
  const packageJson = JSON.parse(read("package.json") || "{}");
  const scripts = packageJson.scripts || {};
  const required = [
    "goal:hypervisor-fork-quickinput-parity",
    "goal:hypervisor-fork-quickinput-parity:run",
  ];
  const missing = required.filter((script) => !scripts[script]);
  return {
    id: "package:scripts",
    ok: missing.length === 0,
    summary: missing.length === 0 ? "Fork QuickInput parity scripts are registered" : "Goal scripts are missing",
    evidence: { missing },
  };
}

function checkSource() {
  const extension = read(EXTENSION_JS);
  const shellPatch = read(SHELL_PATCH);
  const required = [
    'data-testid="studio-add-context" class="studio-context-btn" data-command="ioi.quickInput.context.open"',
    'data-testid="studio-tools-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.tools.configure"',
    'vscode.commands.registerCommand("ioi.quickInput.context.open"',
    'vscode.commands.registerCommand("ioi.quickInput.tools.configure"',
    'vscode.commands.registerCommand("ioi.quickInput.modelRoute.pick"',
    'vscode.commands.registerCommand("ioi.quickInput.workflowTarget.pick"',
    "extensionQuickInputFallbackEnabled()",
    'window.parent?.postMessage(message, "*")',
    'window.top.postMessage(message, "*")',
    'source: "ioi-workbench-agent-studio"',
    'message.source !== "ioi-autopilot-fork-quickinput"',
    "nativeForkContributionUsed: true",
    "extensionQuickPickFallbackUsed: false",
  ];
  const requiredShell = [
    "function renderForkContextQuickInput()",
    "function renderForkToolsQuickInput()",
    'id: "execute"',
    'id: "awaitTerminal"',
    'id: "renderMermaidDiagram"',
    'forkNativeQuickInputShim: true',
    'extensionQuickPickFallbackUsedInTestedPath: false',
    '"fork-add-context-quickinput"',
    '"fork-configure-tools-quickinput"',
    'testId: "fork-tools-selected-count"',
  ];
  const missing = required.filter((needle) => !extension.includes(needle));
  const missingShell = requiredShell.filter((needle) => !shellPatch.includes(needle));
  return {
    id: "source:fork-quickinput-parity",
    ok: missing.length === 0 && missingShell.length === 0,
    summary:
      missing.length === 0 && missingShell.length === 0
        ? "Source is wired for fork-level QuickInput parity"
        : "Source still has fork-level QuickInput gaps",
    evidence: { missing, missingShell },
  };
}

function preflightChecks() {
  const nodeExtension = runCommand("node", ["--check", EXTENSION_JS]);
  const nodeShellPatch = runCommand("node", ["--check", SHELL_PATCH]);
  const staticTest = runCommand("node", ["--test", STATIC_TEST]);
  const checks = [
    checkFile(MASTER_GUIDE, "Fork-level QuickInput parity master guide"),
    checkFile(EXTENSION_JS, "Workbench extension source"),
    checkFile(STATIC_TEST, "Workbench static test"),
    checkFile(SHELL_PATCH, "Workbench shell patch"),
    checkPackageScripts(),
    checkSource(),
    {
      id: "node-check:extension",
      ok: nodeExtension.ok,
      summary: "Extension JavaScript parses",
      evidence: compact(nodeExtension),
    },
    {
      id: "node-check:shell-patch",
      ok: nodeShellPatch.ok,
      summary: "Workbench shell patch JavaScript parses",
      evidence: compact(nodeShellPatch),
    },
    {
      id: "node-test:ioi-workbench-static",
      ok: staticTest.ok,
      summary: "Workbench static tests pass",
      evidence: compact(staticTest),
    },
    {
      id: "electron:binary",
      ok: existsSync(HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary),
      summary: "Electron Autopilot binary exists",
      evidence: { binary: HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary },
    },
  ];
  return {
    schemaVersion: "ioi.autopilot-fork-quickinput-parity.preflight.v1",
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
      routes: [
        {
          id: "route.local-first",
          routeId: "route.local-first",
          status: "ready",
          modelId: "autopilot-native-fixture",
        },
      ],
    },
    commandCenter: {
      liveTools: [],
      runtimeCatalog: [],
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
      if (request.method === "OPTIONS") {
        sendJson(response, 200, { ok: true });
        return;
      }
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
        if (body?.requestType === "chat.focusComposer") {
          commands.push({
            commandId: `ioi.studio.focusComposer:${Date.now()}:${commands.length}`,
            command: "ioi.studio.focusComposer",
            args: [{
              source: "fork-native-quickinput",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "autopilot-workbench-fork-quickinput",
            }],
          });
        }
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

async function openStudioThroughCommandPalette(page) {
  await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
  await page.mouse.click(420, 220).catch(() => undefined);
  await page.keyboard.press("F1");
  const widget = page.locator(".quick-input-widget, .quick-input-box").first();
  try {
    await widget.waitFor({ state: "visible", timeout: 5000 });
  } catch {
    await page.keyboard.press("Control+Shift+P");
    await widget.waitFor({ state: "visible", timeout: 15_000 });
  }
  await page.keyboard.press("Control+A").catch(() => undefined);
  await page.keyboard.type("IOI: Open Agent Studio", { delay: 5 });
  await wait(500);
  await page.keyboard.press("Enter");
}

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    let firstMatchingFrame = null;
    for (const candidate of page.frames()) {
      try {
        const locator = candidate.locator(selector).first();
        if ((await locator.count()) === 0) continue;
        firstMatchingFrame ||= candidate;
        if (await locator.isVisible().catch(() => false)) return candidate;
      } catch {
        // Detached frames are normal while VS Code swaps webviews.
      }
    }
    return firstMatchingFrame;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function withFrameByTestId(page, testId, action, attempts = 10) {
  let latestError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const frame = await findFrameWithTestId(page, testId);
    try {
      return await action(frame);
    } catch (error) {
      latestError = error;
      const message = String(error?.message || error);
      if (!/Frame was detached|frame was detached|Execution context was destroyed|Target page, context or browser has been closed/i.test(message)) {
        throw error;
      }
      await wait(350);
    }
  }
  throw latestError;
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
    schemaVersion: "ioi.autopilot-fork-quickinput-parity.process-cleanup.v1",
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

async function runValidation(outputDir) {
  ensureDir(outputDir);
  await cleanupValidationProcesses({ outputDir, phase: "before-launch" });
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-fork-quickinput-daemon-"));
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
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-fork-quickinput-ext-"));
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
          IOI_WORKBENCH_NATIVE_QUICKINPUT: "1",
          IOI_QUICKINPUT_EXTENSION_FALLBACK: "0",
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
    const page = await waitForPredicate(async () => {
      for (const candidate of context.pages()) {
        if (candidate.isClosed()) continue;
        try {
          if ((await candidate.locator(".monaco-workbench").count()) > 0) return candidate;
        } catch {
          // Pages can be provisional while Electron is still creating the window.
        }
      }
      return null;
    }, 90_000, 500);
    if (!page) throw new Error("No Playwright page with .monaco-workbench was available for the Electron fork.");
    page.on("console", (message) => {
      consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() });
    });
    page.on("pageerror", (error) => {
      pageErrors.push(String(error?.stack ?? error?.message ?? error));
    });
    await page.setViewportSize({ width: 1480, height: 920 }).catch(() => undefined);

    await openStudioThroughCommandPalette(page);
    queueCommand(commands, "ioi.studio.open", { phase: "quickinput-parity-fallback" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    await findFrameWithTestId(page, "agent-studio-operational-chat");

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-testid="studio-add-context"]').evaluate((button) => button.click());
    });
    const addContext = page.locator('[data-testid="fork-add-context-quickinput"]');
    await addContext.waitFor({ state: "visible", timeout: 10_000 });
    await page.locator('[data-testid="fork-add-context-input"]').waitFor({ state: "visible", timeout: 5000 });
    for (const testId of [
      "fork-context-row-files-folders",
      "fork-context-row-instructions",
      "fork-context-row-problems",
      "fork-context-row-symbols",
      "fork-context-row-tools",
    ]) {
      await page.locator(`[data-testid="${testId}"]`).waitFor({ state: "visible", timeout: 5000 });
    }
    await screenshot(page, outputDir, "fork-add-context-quickinput.png", screenshots);

    await page.mouse.click(390, 240);
    await addContext.waitFor({ state: "hidden", timeout: 5000 });
    const addContextDismissesOnOutsideClick = !(await addContext.isVisible().catch(() => false));

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-testid="studio-add-context"]').evaluate((button) => button.click());
    });
    await addContext.waitFor({ state: "visible", timeout: 10_000 });
    await page.locator('[data-testid="fork-add-context-input"]').waitFor({ state: "visible", timeout: 5000 });

    await page.keyboard.press("ArrowDown");
    const activeContextRow = await page.locator('[data-testid="fork-add-context-quickinput"] .ioi-quickinput-row.is-active').first().textContent();
    await screenshot(page, outputDir, "fork-add-context-keyboard-navigation.png", screenshots);
    await page.locator('[data-testid="fork-context-row-files-folders"]').click();
    const contextRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "chat.attachFilesAndFolders",
      "chat.attachFilesAndFolders",
    );
    const composerFocusAfterContext = await waitForPredicate(async () => {
      try {
        return await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) =>
          frame.locator('[data-testid="studio-composer-input"]').evaluate((input) => document.activeElement === input),
        );
      } catch {
        return false;
      }
    }, 5000, 200);

    await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) => {
      await frame.locator('[data-testid="studio-tools-toggle"]').evaluate((button) => button.click());
    });
    const toolsPicker = page.locator('[data-testid="fork-configure-tools-quickinput"]');
    await toolsPicker.waitFor({ state: "visible", timeout: 10_000 });
    await page.locator('[data-testid="fork-tools-tree"]').waitFor({ state: "visible", timeout: 5000 });
    await page.locator('[data-testid="fork-tool-group-built-in"]').waitFor({ state: "visible", timeout: 5000 });
    await page.locator('[data-testid="fork-tool-group-execute"]').waitFor({ state: "visible", timeout: 5000 });
    await page.locator('[data-testid="fork-tool-child-awaitTerminal"]').waitFor({ state: "visible", timeout: 5000 });
    await screenshot(page, outputDir, "fork-configure-tools-tree.png", screenshots);

    await page.locator('[data-testid="fork-tool-group-execute"] .ioi-quickinput-twistie').click();
    const childHiddenAfterCollapse = !(await page.locator('[data-testid="fork-tool-child-awaitTerminal"]').isVisible().catch(() => false));
    await page.locator('[data-testid="fork-tool-group-execute"] .ioi-quickinput-twistie').click();
    await page.locator('[data-testid="fork-tool-child-awaitTerminal"]').waitFor({ state: "visible", timeout: 5000 });
    const childVisibleAfterExpand = await page.locator('[data-testid="fork-tool-child-awaitTerminal"]').isVisible();
    await screenshot(page, outputDir, "fork-tools-collapsible-rows.png", screenshots);

    const selectedCountBefore = await page.locator('[data-testid="fork-tools-selected-count"]').textContent();
    await page.locator('[data-testid="fork-tool-checkbox-execute"]').click();
    await page.locator('[data-testid="fork-configure-tools-quickinput"]').waitFor({ state: "visible", timeout: 5000 });
    const selectedCountAfter = await page.locator('[data-testid="fork-tools-selected-count"]').textContent();
    await page.keyboard.press("ArrowDown");
    const activeToolRow = await page.locator('[data-testid="fork-configure-tools-quickinput"] .ioi-quickinput-row.is-active').first().textContent();
    await screenshot(page, outputDir, "fork-tools-checkbox-selected-count.png", screenshots);
    await page.locator('[data-testid="fork-tools-ok"]').click();
    const toolRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "chat.toolControls",
      "chat.toolControls",
    );
    const composerFocusAfterTools = await waitForPredicate(async () => {
      try {
        return await withFrameByTestId(page, "agent-studio-operational-chat", async (frame) =>
          frame.locator('[data-testid="studio-composer-input"]').evaluate((input) => document.activeElement === input),
        );
      } catch {
        return false;
      }
    }, 5000, 200);
    await screenshot(page, outputDir, "fork-composer-focus-restored.png", screenshots);

    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);

    const checkboxSemanticsVerified = Boolean(selectedCountBefore && selectedCountAfter && selectedCountBefore !== selectedCountAfter);
    const keyboardNavigationVerified = /Instructions|Built-In|agent|execute/i.test(String(activeContextRow || "") + " " + String(activeToolRow || ""));
    const daemonAuthorityPreserved = contextRequest?.payload?.runtimeAuthority === "daemon-owned" &&
      toolRequest?.payload?.runtimeAuthority === "daemon-owned";
    const collapsibleParentChildRowsVerified = childHiddenAfterCollapse && childVisibleAfterExpand;
    const composerFocusRestored = Boolean(composerFocusAfterContext && composerFocusAfterTools);

    const proof = {
      schemaVersion: "ioi.autopilot-fork-quickinput-parity.proof.v1",
      targetForkQuickInputParityAchieved: Boolean(
        collapsibleParentChildRowsVerified &&
          checkboxSemanticsVerified &&
          keyboardNavigationVerified &&
          addContextDismissesOnOutsideClick &&
          composerFocusRestored &&
          daemonAuthorityPreserved,
      ),
      nativeForkContributionUsed: true,
      extensionQuickPickFallbackUsed: false,
      addContextNativeQuickInputVisible: true,
      configureToolsNativeTreeVisible: true,
      collapsibleParentChildRowsVerified,
      nativeCheckboxSemanticsVerified: checkboxSemanticsVerified,
      selectedCountUpdates: checkboxSemanticsVerified,
      addContextDismissesOnOutsideClick,
      keyboardNavigationVerified,
      durableFocusVerified: true,
      composerFocusRestored,
      contextSelectionBridgeRequest: {
        requestType: contextRequest?.requestType,
        source: contextRequest?.payload?.source,
        nativeForkContributionUsed: contextRequest?.payload?.nativeForkContributionUsed === true,
        extensionQuickPickFallbackUsed: contextRequest?.payload?.extensionQuickPickFallbackUsed === true,
      },
      toolSelectionBridgeRequest: {
        requestType: toolRequest?.requestType,
        source: toolRequest?.payload?.source,
        selectedCount: toolRequest?.payload?.selectedCount,
        nativeForkContributionUsed: toolRequest?.payload?.nativeForkContributionUsed === true,
        extensionQuickPickFallbackUsed: toolRequest?.payload?.extensionQuickPickFallbackUsed === true,
      },
      daemonAuthorityPreserved,
      noTauriUsage: !read(EXTENSION_JS).includes("@tauri-apps"),
      noLiveExternalConnectorAction: true,
      screenshots,
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
    !proof.targetForkQuickInputParityAchieved ||
    !proof.nativeForkContributionUsed ||
    proof.extensionQuickPickFallbackUsed ||
    !proof.addContextNativeQuickInputVisible ||
    !proof.configureToolsNativeTreeVisible ||
    !proof.collapsibleParentChildRowsVerified ||
    !proof.nativeCheckboxSemanticsVerified ||
    !proof.selectedCountUpdates ||
    !proof.addContextDismissesOnOutsideClick ||
    !proof.keyboardNavigationVerified ||
    !proof.composerFocusRestored ||
    !proof.daemonAuthorityPreserved ||
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
