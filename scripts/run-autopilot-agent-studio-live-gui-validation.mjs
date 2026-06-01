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
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { chromium } from "playwright";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import { createSubmitPrompt } from "./lib/agent-studio-live-gui-validation/prompt-submit.mjs";
import {
  approvalPauseSummary,
  assertNotCannedDaemonProjection,
  assertPromptForbiddenTermsAbsent,
  assertPromptSpecificResponse,
  assertSemanticModelResponse,
  isApprovalPauseText,
  promptResultToolName,
} from "./lib/agent-studio-live-gui-validation/response-assertions.mjs";
import {
  DEFAULT_AGENT_STUDIO_CHAT_SCENARIO,
  resolveAgentStudioChatScenario,
} from "./lib/autopilot-agent-studio-chat-scenarios.mjs";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./lib/autopilot-electron-app-paths.mjs";
import {
  bootstrapNativeRuntimeModelRoute,
  configureRuntimeAgentServiceBridgeEnv,
  configureRuntimeAgentServiceInferenceEnv,
} from "./lib/autopilot-runtime-agent-service-bridge.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./lib/autopilot-workbench-shell-patch.mjs";

const repoRoot = AUTOPILOT_ELECTRON.repoRoot;
const MASTER_GUIDE =
  process.env.AUTOPILOT_AGENT_STUDIO_MASTER_GUIDE ||
  ".internal/plans/autopilot-electron-agent-studio-chat-ux-playwright-hardening-master-guide.md";
const EVIDENCE_ROOT =
  process.env.AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT ||
  "docs/evidence/autopilot-agent-studio-chat-ux-playwright-hardening";
const UPDATE_MASTER_GUIDE = process.env.AUTOPILOT_AGENT_STUDIO_UPDATE_GUIDE !== "0";
const EXTENSION_JS = "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const STATIC_TEST = "apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs";
const SHELL_PATCH = "scripts/lib/autopilot-workbench-shell-patch.mjs";
const STUDIO_SOURCE_PARTS = [
  EXTENSION_JS,
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js",
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-completion.js",
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/operational-surface.js",
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-surface.js",
];
const PROCESS_PATTERN = "/tmp/autopilot-agent-studio-live-gui-validation-user-";
const DEFAULT_VALIDATION_TIMEOUT_MS = 15 * 60 * 1000;
const VALIDATION_TIMEOUT_MS = Number(
  process.env.AUTOPILOT_AGENT_STUDIO_VALIDATION_TIMEOUT_MS || DEFAULT_VALIDATION_TIMEOUT_MS,
);

let daemonEndpointForBridge = null;
let liveBridgeRequestLogPath = null;
let liveBridgeCommandLogPath = null;
let studioFrameCache = null;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  const scenarioArg = argv.find((arg) => arg.startsWith("--scenario="));
  const scenarioIndex = argv.indexOf("--scenario");
  return {
    run: argv.includes("--run"),
    preflight: argv.includes("--preflight") || !argv.includes("--run"),
    scenario: scenarioArg
      ? scenarioArg.slice("--scenario=".length)
      : scenarioIndex >= 0
        ? argv[scenarioIndex + 1]
        : DEFAULT_AGENT_STUDIO_CHAT_SCENARIO,
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
    maxBuffer: 1024 * 1024 * 16,
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

function setupWorkspaceSymlinkProbe(outputDir, daemonStateDir, scenario) {
  const probe = scenario.workspaceSymlinkProbe;
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) return null;
  const relativeSymlinkPath = String(probe.symlinkPath || "").trim();
  const targetFileName = String(probe.targetFileName || "outside-symlink-target.txt").trim();
  if (!relativeSymlinkPath || relativeSymlinkPath.includes("..") || relativeSymlinkPath.startsWith("/")) {
    throw new Error(`Invalid workspace symlink probe path: ${relativeSymlinkPath || "<empty>"}`);
  }
  if (!targetFileName || targetFileName.includes("/") || targetFileName.includes("\\")) {
    throw new Error(`Invalid workspace symlink probe target filename: ${targetFileName || "<empty>"}`);
  }

  const symlinkPath = join(repoRoot, relativeSymlinkPath);
  const targetPath = join(daemonStateDir, targetFileName);
  rmSync(symlinkPath, { recursive: true, force: true });
  writeFileSync(targetPath, String(probe.targetContent || "outside-workspace-canary"));
  symlinkSync(targetPath, symlinkPath);
  const setup = {
    relativeSymlinkPath,
    symlinkPath,
    targetPath,
    targetContentBytes: Buffer.byteLength(String(probe.targetContent || "outside-workspace-canary")),
  };
  writeFileSync(join(outputDir, "workspace-symlink-probe-setup.json"), `${JSON.stringify(setup, null, 2)}\n`);
  return setup;
}

function cleanupWorkspaceSymlinkProbe(outputDir, setup) {
  if (!setup) return;
  rmSync(setup.symlinkPath, { recursive: true, force: true });
  rmSync(setup.targetPath, { recursive: true, force: true });
  writeFileSync(
    join(outputDir, "workspace-symlink-probe-cleanup.json"),
    `${JSON.stringify({
      symlinkPath: setup.symlinkPath,
      targetPath: setup.targetPath,
      symlinkExistsAfterCleanup: existsSync(setup.symlinkPath),
      targetExistsAfterCleanup: existsSync(setup.targetPath),
    }, null, 2)}\n`,
  );
}

function setupWorkspaceFixture(outputDir, scenario) {
  if (!scenario.workspaceFixture) return null;
  const fixtureId = `${safeFilePart(scenario.id || "scenario")}-${Date.now().toString(36)}-${process.pid.toString(36)}`;
  const relativeRoot = join(".tmp", "autopilot-tool-catalogue-live", fixtureId);
  const fixtureRoot = join(repoRoot, relativeRoot);
  rmSync(fixtureRoot, { recursive: true, force: true });
  ensureDir(fixtureRoot);
  ensureDir(join(fixtureRoot, "nested"));
  ensureDir(join(fixtureRoot, "models"));
  ensureDir(join(fixtureRoot, "media"));
  writeFileSync(join(fixtureRoot, "readme.md"), [
    "# Tool catalogue live fixture",
    "",
    "TOOLCAT_CANARY=rust-agent-studio-live",
    "This directory is disposable and scoped to one GUI run.",
    "",
  ].join("\n"));
  writeFileSync(join(fixtureRoot, "notes.txt"), "alpha\nbeta\nTOOLCAT_CANARY\ngamma\n");
  writeFileSync(join(fixtureRoot, "edit-target.txt"), "line one\nline two\nline three\n");
  writeFileSync(join(fixtureRoot, "nested", "upload.txt"), "upload fixture for browser__upload\n");
  writeFileSync(join(fixtureRoot, "models", "toolcat-model.gguf"), "model fixture bytes\n");
  writeFileSync(
    join(fixtureRoot, "media", "pixel.png"),
    Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=",
      "base64",
    ),
  );
  const setup = {
    relativeRoot,
    fixtureRoot,
    readmePath: join(fixtureRoot, "readme.md"),
    notesPath: join(fixtureRoot, "notes.txt"),
    editTargetPath: join(fixtureRoot, "edit-target.txt"),
    uploadPath: join(fixtureRoot, "nested", "upload.txt"),
    modelPath: join(fixtureRoot, "models", "toolcat-model.gguf"),
    imagePath: join(fixtureRoot, "media", "pixel.png"),
  };
  writeFileSync(join(outputDir, "workspace-fixture-setup.json"), `${JSON.stringify(setup, null, 2)}\n`);
  return setup;
}

function cleanupWorkspaceFixture(outputDir, setup) {
  if (!setup) return;
  rmSync(setup.fixtureRoot, { recursive: true, force: true });
  writeFileSync(
    join(outputDir, "workspace-fixture-cleanup.json"),
    `${JSON.stringify({
      fixtureRoot: setup.fixtureRoot,
      fixtureExistsAfterCleanup: existsSync(setup.fixtureRoot),
      timestamp: new Date().toISOString(),
    }, null, 2)}\n`,
  );
}

function setupUserWorkspaceFixture(outputDir, scenario) {
  if (!scenario.userWorkspaceFixture) return null;
  const fixtureRoot = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-user-repo-"));
  ensureDir(join(fixtureRoot, "src"));
  ensureDir(join(fixtureRoot, "tests"));
  writeFileSync(join(fixtureRoot, "README.md"), [
    "# Pawprint Orders",
    "",
    "Pawprint Orders is a small customer-order dashboard used for Agent Studio product reliability tests.",
    "It fetches order data through a typed API client, formats totals for the UI, and includes a deliberately failing unit test.",
    "",
    "Key files:",
    "",
    "- `src/apiClient.mjs` configures the API base URL.",
    "- `src/format.mjs` formats order totals.",
    "- `tests/format.test.mjs` verifies the formatter.",
    "",
  ].join("\n"));
  writeFileSync(join(fixtureRoot, "package.json"), `${JSON.stringify({
    type: "module",
    scripts: {
      test: "node --test tests/*.test.mjs",
    },
    dependencies: {},
    devDependencies: {},
  }, null, 2)}\n`);
  writeFileSync(join(fixtureRoot, "src", "apiClient.mjs"), [
    "export const API_BASE_URL = \"https://api.pawprint-orders.example/v1\";",
    "",
    "export async function fetchOrders(fetchImpl = fetch) {",
    "  const response = await fetchImpl(`${API_BASE_URL}/orders`);",
    "  if (!response.ok) throw new Error(`Order API failed: ${response.status}`);",
    "  return response.json();",
    "}",
    "",
  ].join("\n"));
  writeFileSync(join(fixtureRoot, "src", "format.mjs"), [
    "export function formatOrderTotal(cents) {",
    "  return (Number(cents) / 100).toFixed(2);",
    "}",
    "",
  ].join("\n"));
  writeFileSync(join(fixtureRoot, "src", "orders.mjs"), [
    "import { formatOrderTotal } from \"./format.mjs\";",
    "",
    "export function summarizeOrder(order) {",
    "  return `${order.customer}: ${formatOrderTotal(order.totalCents)}`;",
    "}",
    "",
  ].join("\n"));
  writeFileSync(join(fixtureRoot, "tests", "format.test.mjs"), [
    "import test from \"node:test\";",
    "import assert from \"node:assert/strict\";",
    "import { formatOrderTotal } from \"../src/format.mjs\";",
    "",
    "test(\"formats order totals as dollars\", () => {",
    "  assert.equal(formatOrderTotal(1299), \"$12.99\");",
    "});",
    "",
  ].join("\n"));
  const gitInit = spawnSync("git", ["init"], {
    cwd: fixtureRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  const setup = {
    fixtureRoot,
    readmePath: join(fixtureRoot, "README.md"),
    apiClientPath: join(fixtureRoot, "src", "apiClient.mjs"),
    formatPath: join(fixtureRoot, "src", "format.mjs"),
    testPath: join(fixtureRoot, "tests", "format.test.mjs"),
    gitInit: {
      status: gitInit.status,
      stderrTail: String(gitInit.stderr || "").slice(-1000),
    },
  };
  writeFileSync(join(outputDir, "user-workspace-fixture-setup.json"), `${JSON.stringify(setup, null, 2)}\n`);
  return setup;
}

function cleanupUserWorkspaceFixture(outputDir, setup) {
  if (!setup) return;
  rmSync(setup.fixtureRoot, { recursive: true, force: true });
  writeFileSync(
    join(outputDir, "user-workspace-fixture-cleanup.json"),
    `${JSON.stringify({
      fixtureRoot: setup.fixtureRoot,
      fixtureExistsAfterCleanup: existsSync(setup.fixtureRoot),
      timestamp: new Date().toISOString(),
    }, null, 2)}\n`,
  );
}

function browserFixtureHtml() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Tool Catalogue Fixture</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 32px; line-height: 1.4; }
    main { max-width: 720px; }
    label { display: block; margin: 16px 0 6px; }
    input, select, textarea, button { font: inherit; padding: 8px; }
    canvas { border: 1px solid #888; display: block; margin-top: 18px; }
  </style>
</head>
<body>
  <main>
    <h1>Tool Catalogue Fixture</h1>
    <p id="fixture-copy">TOOLCAT_BROWSER_CANARY visible for find_text and copy tests.</p>
    <label for="toolcat-select">Scenario select</label>
    <select id="toolcat-select" data-testid="toolcat-select">
      <option value="alpha">Alpha Option</option>
      <option value="beta">Beta Option</option>
      <option value="gamma">Gamma Option</option>
    </select>
    <label for="toolcat-input">Scenario input</label>
    <input id="toolcat-input" data-testid="toolcat-input" value="" placeholder="type here">
    <button id="toolcat-button" data-testid="toolcat-button" onclick="document.querySelector('#status').textContent='button clicked';">Activate fixture button</button>
    <input id="toolcat-file" data-testid="toolcat-file" type="file">
    <p id="status" role="status">ready</p>
    <a id="second-link" href="/second">Second page</a>
    <canvas id="toolcat-canvas" width="240" height="120" aria-label="blue square canvas"></canvas>
  </main>
  <script>
    const canvas = document.getElementById("toolcat-canvas");
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#276ef1";
    ctx.fillRect(20, 20, 80, 60);
    ctx.fillStyle = "#111";
    ctx.fillText("canvas target", 24, 96);
  </script>
</body>
</html>`;
}

async function startBrowserFixture(outputDir, scenario) {
  if (!scenario.browserFixture) return null;
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/api/status") {
      sendJson(response, 200, {
        ok: true,
        fixture: "tool-catalogue-browser",
        canary: "TOOLCAT_BROWSER_CANARY",
      });
      return;
    }
    if (url.pathname === "/media/transcript.txt") {
      const body = "Tool catalogue media transcript fixture.";
      response.writeHead(200, {
        "content-type": "text/plain; charset=utf-8",
        "content-length": Buffer.byteLength(body),
      });
      response.end(body);
      return;
    }
    const body = url.pathname === "/second"
      ? "<!doctype html><title>Second Fixture Page</title><p>Second page loaded for browser back/tab proof.</p><a href='/'>Back home</a>"
      : browserFixtureHtml();
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "content-length": Buffer.byteLength(body),
    });
    response.end(body);
  });
  const address = await listen(server);
  const fixture = {
    server,
    url: `http://127.0.0.1:${address.port}/`,
    statusUrl: `http://127.0.0.1:${address.port}/api/status`,
    secondUrl: `http://127.0.0.1:${address.port}/second`,
    mediaUrl: `http://127.0.0.1:${address.port}/media/transcript.txt`,
  };
  writeFileSync(
    join(outputDir, "browser-fixture-server.json"),
    `${JSON.stringify({
      url: fixture.url,
      statusUrl: fixture.statusUrl,
      secondUrl: fixture.secondUrl,
      mediaUrl: fixture.mediaUrl,
    }, null, 2)}\n`,
  );
  return fixture;
}

function safeFilePart(value) {
  return String(value || "item").replace(/[^A-Za-z0-9_.-]+/g, "-").slice(0, 80);
}

function expandScenarioPrompt(prompt, context = {}) {
  return String(prompt || "").replace(/\{\{([A-Za-z0-9_]+)\}\}/g, (match, key) => {
    const value = context[key];
    return value === undefined || value === null ? match : String(value);
  });
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
    "goal:autopilot-agent-studio-live-gui-validation",
    "goal:autopilot-agent-studio-live-gui-validation:run",
  ];
  const missing = required.filter((script) => !scripts[script]);
  return {
    id: "package:scripts",
    ok: missing.length === 0,
    summary: missing.length === 0 ? "Agent Studio live GUI validation scripts are registered" : "Goal scripts are missing",
    evidence: { missing },
  };
}

function checkSource() {
  const source = STUDIO_SOURCE_PARTS.map((part) => read(part)).join("\n");
  const required = [
    "let studioPanelLastHtml = null;",
    "let studioPanelNonce = null;",
    "function updateStudioPanelHtml(state)",
    "const pageNonce = getPageNonce ? getPageNonce() : (studioPanelNonce || (studioPanelNonce = nonce()));",
    'data-testid="studio-composer-input"',
    'data-testid="studio-send-button"',
    'data-command="ioi.quickInput.context.open"',
    'data-command="ioi.quickInput.tools.configure"',
    'data-command="ioi.quickInput.modelRoute.pick"',
    'data-command="ioi.quickInput.workflowTarget.pick"',
    'data-command="ioi.quickInput.agentMode.pick"',
    "border-top: 0;",
    'requestType: "chat.submit"',
    "streamStudioModelCompletion",
    '"/v1/chat/completions"',
    "assistantStreamDelta",
    '"chat.stop"',
  ];
  const missing = required.filter((needle) => !source.includes(needle));
  const forbidden = [
    'data-testid="agent-studio-landing"',
    "studio.promptSubmit",
    "@tauri-apps",
    "studioPanel.webview.html = studioPanelHtml(state);",
  ].filter((needle) => source.includes(needle));
  return {
    id: "source:agent-studio-live-gui-validation",
    ok: missing.length === 0 && forbidden.length === 0,
    summary:
      missing.length === 0 && forbidden.length === 0
        ? "Studio source is hardened for stable chat focus"
        : "Studio source still has focus or fallback gaps",
    evidence: { missing, forbidden },
  };
}

function preflightChecks() {
  const nodeExtension = runCommand("node", ["--check", EXTENSION_JS]);
  const nodeShellPatch = runCommand("node", ["--check", SHELL_PATCH]);
  const staticTest = runCommand("node", ["--test", STATIC_TEST]);
  const checks = [
    checkFile(MASTER_GUIDE, "Agent Studio live GUI validation master guide"),
    checkFile(EXTENSION_JS, "Workbench extension source"),
    checkFile(STATIC_TEST, "Workbench static test"),
    checkFile(SHELL_PATCH, "Workbench shell patch"),
    checkSource(),
    checkPackageScripts(),
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
      ok: existsSync(AUTOPILOT_ELECTRON.binary),
      summary: "Electron Autopilot binary exists",
      evidence: { binary: AUTOPILOT_ELECTRON.binary },
    },
  ];
  return {
    schemaVersion: "ioi.autopilot-agent-studio-live-gui-validation.preflight.v1",
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
    const remainingMs = Math.max(1, deadline - Date.now());
    const predicateTimeoutMs = Math.min(2000, remainingMs);
    const value = await Promise.race([
      Promise.resolve().then(predicate),
      wait(predicateTimeoutMs).then(() => ({ __ioiPredicateTimedOut: true })),
    ]);
    if (value?.__ioiPredicateTimedOut) {
      latest = false;
    } else {
      latest = value;
    }
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

async function createDaemonModelInvocationToken(endpoint) {
  const response = await fetch(`${endpoint}/api/v1/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-agent-studio-playwright-hardening",
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
      denied: ["connector.*", "filesystem.write", "shell.exec"],
      source: "agent-studio-live-gui-validation",
    }),
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to create daemon model token (${response.status}): ${body}`);
  }
  const parsed = body ? JSON.parse(body) : {};
  if (!parsed.token) {
    throw new Error("Daemon model token response did not include a token.");
  }
  return parsed;
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
  const modelMounting = {
    artifacts: [
      {
        id: "stories260k",
        modelId: "stories260k",
        name: "stories260k",
        publisher: "ioi",
        family: "llm",
        format: "GGUF",
        status: "mounted",
      },
      {
        id: "qwen/qwen3.5-9b",
        modelId: "qwen/qwen3.5-9b",
        name: "qwen/qwen3.5-9b",
        publisher: "provider.llama-cpp",
        family: "llm",
        format: "GGUF",
        status: "mounted",
        capabilities: ["chat", "responses"],
      },
      {
        id: "local:unmounted-demo",
        modelId: "local:unmounted-demo",
        name: "Local unmounted demo",
        publisher: "provider.local",
        family: "llm",
        format: "GGUF",
        status: "installed",
      },
    ],
    endpoints: [
      {
        id: "endpoint.stories260k",
        modelId: "stories260k",
        routeId: "route.fixture",
        status: "ready",
      },
      {
        id: "endpoint.qwen35",
        modelId: "qwen/qwen3.5-9b",
        routeId: "route.local-first",
        providerId: "provider.llama-cpp",
        backendId: "backend.llama-cpp",
        capabilities: ["chat", "responses"],
        status: "ready",
      },
      {
        id: "endpoint.unmounted",
        modelId: "local:unmounted-demo",
        routeId: "route.unmounted-demo",
        status: "installed",
      },
    ],
    instances: [
      {
        id: "instance.stories260k",
        endpointId: "endpoint.stories260k",
        modelId: "stories260k",
        status: "mounted",
      },
      {
        id: "instance.qwen35",
        endpointId: "endpoint.qwen35",
        modelId: "qwen/qwen3.5-9b",
        status: "mounted",
      },
    ],
    routes: [
      {
        id: "route.local-first",
        routeId: "route.local-first",
        endpointId: "endpoint.qwen35",
        modelId: "qwen/qwen3.5-9b",
        status: "ready",
      },
      {
        id: "route.fixture",
        routeId: "route.fixture",
        endpointId: "endpoint.stories260k",
        modelId: "stories260k",
        status: "ready",
      },
      {
        id: "route.unmounted-demo",
        routeId: "route.unmounted-demo",
        endpointId: "endpoint.unmounted",
        modelId: "local:unmounted-demo",
        status: "installed",
      },
    ],
  };
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
    modelMounting,
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
        if (liveBridgeCommandLogPath && next.length > 0) {
          appendFileSync(liveBridgeCommandLogPath, `${JSON.stringify({ at: new Date().toISOString(), commands: next })}\n`);
        }
        sendJson(response, 200, next);
        return;
      }
      if (request.method === "POST" && url.pathname === "/requests") {
        const body = await readRequestBody(request);
        requests.push(body);
        if (liveBridgeRequestLogPath) {
          appendFileSync(liveBridgeRequestLogPath, `${JSON.stringify({ at: new Date().toISOString(), request: body })}\n`);
        }
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
        if (body?.requestType === "chat.agentMode.select") {
          commands.push({
            commandId: `ioi.studio.applyAgentMode:${Date.now()}:${commands.length}`,
            command: "ioi.studio.applyAgentMode",
            args: [{
              ...(body.payload && typeof body.payload === "object" ? body.payload : {}),
              source: "fork-native-quickinput",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "autopilot-workbench-fork-quickinput",
            }],
          });
        }
        if (body?.requestType === "chat.permissionMode.select") {
          commands.push({
            commandId: `ioi.studio.applyPermissionMode:${Date.now()}:${commands.length}`,
            command: "ioi.studio.applyPermissionMode",
            args: [{
              ...(body.payload && typeof body.payload === "object" ? body.payload : {}),
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

async function requireRequest(requests, predicate, label, timeoutMs = 45_000, startIndex = 0) {
  const request = await waitForPredicate(
    () => requests.slice(startIndex).find((candidate) => predicate(candidate)),
    timeoutMs,
    250,
  );
  if (!request) throw new Error(`Timed out waiting for bridge request: ${label}`);
  return request;
}

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    for (const candidate of page.frames()) {
      try {
        const locator = candidate.locator(selector).first();
        if ((await locator.count()) === 0) continue;
        if (await locator.isVisible().catch(() => false)) return candidate;
      } catch {
        // Webview frames can detach while VS Code swaps editor contents.
      }
    }
    return null;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  if (testId === "agent-studio-operational-chat") {
    studioFrameCache = frame;
  }
  return frame;
}

function isFrameLifecycleError(error) {
  const message = String(error?.message || error);
  return /Frame (was|has been) detached|Execution context was destroyed|Target page, context or browser has been closed|Cannot find context with specified id|DOM\.scrollIntoViewIfNeeded/i.test(message);
}

async function withStudioFrame(page, action, attempts = 12) {
  let latestError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const cachedFrame = studioFrameCache;
    if (cachedFrame && !cachedFrame.isDetached?.()) {
      try {
        return await action(cachedFrame);
      } catch (error) {
        latestError = error;
        if (!isFrameLifecycleError(error)) {
          throw error;
        }
        studioFrameCache = null;
        await wait(100);
      }
    }
    const frame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    try {
      return await action(frame);
    } catch (error) {
      latestError = error;
      if (!isFrameLifecycleError(error)) {
        throw error;
      }
      studioFrameCache = null;
      await wait(300);
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

async function captureManagedSessionViewportProof(page, outputDir, screenshots, { required = false } = {}) {
  return withStudioFrame(page, async (frame) => {
    const card = frame.locator('[data-testid="studio-managed-session-card"]').last();
    const cardCount = await frame.locator('[data-testid="studio-managed-session-card"]').count();
    if (cardCount === 0) {
      if (required) {
        throw new Error("Managed browser/computer live session card was not rendered.");
      }
      return null;
    }
    await card.waitFor({ state: "visible", timeout: 7000 });
    await screenshot(page, outputDir, "managed-session-compact.png", screenshots);
    const expand = card.locator('[data-testid="studio-managed-session-expand"]').first();
    await expand.click();
    const expanded = card.locator('[data-testid="studio-managed-session-expanded-view"]').first();
    await expanded.waitFor({ state: "visible", timeout: 7000 });
    await screenshot(page, outputDir, "managed-session-expanded-observe.png", screenshots);
    await card.locator('[data-testid="studio-managed-session-take-over"]').first().click();
    await screenshot(page, outputDir, "managed-session-take-over.png", screenshots);
    await card.locator('[data-testid="studio-managed-session-return"]').first().click();
    await screenshot(page, outputDir, "managed-session-returned-to-agent.png", screenshots);
    const labels = await card
      .locator('[data-testid="studio-managed-session-mode-label"]')
      .allTextContents();
    const root = frame.locator('[data-testid="agent-studio-operational-chat"]').first();
    const attrs = {
      managedLiveViewportObserved: await root.getAttribute("data-managed-live-viewport-observed"),
      managedSessionLabelsObserved: await root.getAttribute("data-managed-session-labels-observed"),
      managedSessionCount: await root.getAttribute("data-managed-session-count"),
      sessionKind: await card.getAttribute("data-session-kind"),
      sessionLabel: await card.getAttribute("data-session-label"),
      sessionStatus: await card.getAttribute("data-session-status"),
      controlState: await card.getAttribute("data-control-state"),
    };
    const hasRequiredLabels = ["Sandbox browser", "Local browser", "Desktop"].every((label) =>
      labels.some((observed) => String(observed || "").trim() === label),
    );
    if (required && !hasRequiredLabels) {
      throw new Error(`Managed session labels incomplete: ${labels.join(", ")}`);
    }
    if (required && attrs.managedLiveViewportObserved !== "true") {
      throw new Error("Managed live viewport root attribute was not observed.");
    }
    return {
      cardCount,
      labels,
      hasRequiredLabels,
      ...attrs,
      screenshots: [
        "managed-session-compact.png",
        "managed-session-expanded-observe.png",
        "managed-session-take-over.png",
        "managed-session-returned-to-agent.png",
      ],
    };
  });
}

async function captureConversationArtifactProof(page, outputDir, screenshots, { required = false } = {}) {
  return withStudioFrame(page, async (frame) => {
    const cards = frame.locator('[data-testid="studio-conversation-artifact-card"]');
    if (required) {
      await cards.first().waitFor({ state: "visible", timeout: 240_000 });
    }
    const cardCount = await cards.count();
    if (cardCount === 0) {
      if (required) {
        throw new Error("Conversation artifact embed was not rendered in Agent Studio chat.");
      }
      return null;
    }
    await cards.first().waitFor({ state: "visible", timeout: 7000 });
    await screenshot(page, outputDir, "conversation-artifact-compact.png", screenshots);
    const classLabels = await frame.locator('[data-testid="studio-conversation-artifact-type"]').allTextContents();
    const titles = await frame.locator('[data-testid="studio-conversation-artifact-title"]').allTextContents();
    const firstCard = cards.first();
    await firstCard.locator('[data-testid="studio-conversation-artifact-expand"]').click();
    await firstCard.locator('[data-testid="studio-conversation-artifact-expanded-view"]').waitFor({ state: "visible", timeout: 7000 });
    await screenshot(page, outputDir, "conversation-artifact-expanded.png", screenshots);
    const actionButtons = firstCard.locator('[data-testid="studio-conversation-artifact-action"]');
    const actionCount = await actionButtons.count();
    let promotionStateObserved = false;
    if (actionCount > 0) {
      await actionButtons.first().click();
      await wait(900);
      frame = await findFrameWithTestId(page, "agent-studio-operational-chat");
      await screenshot(page, outputDir, "conversation-artifact-action-state.png", screenshots);
      const currentFirstCard = frame.locator('[data-testid="studio-conversation-artifact-card"]').first();
      const expandedVisible = await currentFirstCard
        .locator('[data-testid="studio-conversation-artifact-expanded-view"]')
        .isVisible()
        .catch(() => false);
      if (!expandedVisible) {
        await currentFirstCard.locator('[data-testid="studio-conversation-artifact-expand"]').click();
        await currentFirstCard.locator('[data-testid="studio-conversation-artifact-expanded-view"]').waitFor({ state: "visible", timeout: 7000 });
      }
      const promoteButton = currentFirstCard.locator('[data-studio-artifact-action="promote"]').first();
      if (await promoteButton.isVisible().catch(() => false)) {
        await promoteButton.click();
        await wait(900);
        frame = await findFrameWithTestId(page, "agent-studio-operational-chat");
        await screenshot(page, outputDir, "conversation-artifact-promoted-state.png", screenshots);
        promotionStateObserved = true;
      }
    }
    const compareCount = await frame.locator('[data-testid="studio-conversation-artifact-compare-state"]').count();
    if (compareCount > 0) {
      await screenshot(page, outputDir, "conversation-artifact-compare-state.png", screenshots);
    }
    let documentFidelityText = "";
    const importedDocumentCard = frame.locator('[data-testid="studio-conversation-artifact-card"][data-artifact-class="imported_document"]').first();
    if (await importedDocumentCard.count()) {
      const importedExpanded = await importedDocumentCard
        .locator('[data-testid="studio-conversation-artifact-expanded-view"]')
        .isVisible()
        .catch(() => false);
      if (!importedExpanded) {
        await importedDocumentCard.locator('[data-testid="studio-conversation-artifact-expand"]').click();
        await importedDocumentCard.locator('[data-testid="studio-conversation-artifact-expanded-view"]').waitFor({ state: "visible", timeout: 7000 });
      }
      documentFidelityText = await importedDocumentCard.locator('[data-testid="studio-conversation-artifact-fidelity"]').textContent().catch(() => "");
      await screenshot(page, outputDir, "conversation-artifact-document-fidelity.png", screenshots);
    }
    const rendererMeta = await frame.locator('[data-testid="studio-conversation-artifact-renderer-meta"]').first().textContent().catch(() => "");
    const traceLinkCount = await frame.locator('[data-testid="studio-view-trace-link"]').count();
    const previewSrcdocs = await frame
      .locator('[data-testid="studio-conversation-artifact-preview-frame"]')
      .evaluateAll((frames) => frames.map((item) => item.getAttribute("srcdoc") || ""));
    const sourcePreviewText = await frame
      .locator('[data-testid="studio-conversation-artifact-source-preview"]')
      .allTextContents()
      .catch(() => []);
    const previewSurface = [...previewSrcdocs, ...sourcePreviewText].join("\n");
    const artifactTemplateLeaks = [
      /\bchat__reply\b/i,
      /\bagent__complete\b/i,
      /\bTOOLCAT_/i,
      /\/home\/[^<\s]+/i,
      /Workspace root:/i,
      /You are in \//i,
      /<span>Overview<\/span>\s*<span>Risks<\/span>\s*<span>Action plan<\/span>/i,
      /\bWhat it means\b/i,
      /\bHow to start\b/i,
    ].filter((pattern) => pattern.test(previewSurface || "")).map((pattern) => String(pattern));
    const rawText = await frame.locator('[data-testid="studio-chat-transcript"]').textContent().catch(() => "");
    const rawLeaks = [
      /conversation-artifacts\/assets/i,
      /receipt_artifact_[a-z0-9_]+/i,
      /\{\\?\"artifact/i,
      /build\.log/i,
    ].filter((pattern) => pattern.test(rawText || "")).map((pattern) => String(pattern));
    if (required && rawLeaks.length > 0) {
      throw new Error(`Artifact transcript leaked raw evidence details: ${rawLeaks.join(", ")}`);
    }
    if (required && !/sandbox/i.test(rendererMeta || "")) {
      throw new Error(`Artifact renderer metadata did not expose sandbox policy: ${rendererMeta}`);
    }
    if (required && classLabels.some((label) => /website/i.test(label)) && artifactTemplateLeaks.length > 0) {
      throw new Error(`Artifact preview leaked invalid/canned generator content: ${artifactTemplateLeaks.join(", ")}`);
    }
    return {
      cardCount,
      classLabels,
      titles,
      actionCount,
      compareCount,
      promotionStateObserved,
      documentFidelityText,
      traceLinkCount,
      rendererMeta,
      previewTextSample: previewSurface.replace(/\s+/g, " ").trim().slice(0, 500),
      artifactTemplateLeaks,
      rawLeaks,
      screenshots: [
        "conversation-artifact-compact.png",
        "conversation-artifact-expanded.png",
        "conversation-artifact-action-state.png",
        ...(promotionStateObserved ? ["conversation-artifact-promoted-state.png"] : []),
        ...(compareCount > 0 ? ["conversation-artifact-compare-state.png"] : []),
        ...(documentFidelityText ? ["conversation-artifact-document-fidelity.png"] : []),
      ],
    };
  });
}

async function activeComposerState(frame) {
  return frame.evaluate(() => {
    const input = document.querySelector("[data-testid='studio-composer-input']");
    const composer = document.querySelector("[data-testid='studio-composer']");
    const dock = document.querySelector("[data-testid='studio-tauri-composer']");
    const active = document.activeElement;
    const inputStyle = input ? getComputedStyle(input) : null;
    const composerStyle = composer ? getComputedStyle(composer) : null;
    const dockRect = dock?.getBoundingClientRect?.();
    return {
      activeTag: active?.tagName || null,
      activeTestId: active?.getAttribute?.("data-testid") || null,
      activeIsComposer: active === input,
      value: input?.value || "",
      composerBorderTopWidth: composerStyle?.borderTopWidth || "",
      composerBorderTopStyle: composerStyle?.borderTopStyle || "",
      inputFocusedOutline: inputStyle?.outlineStyle || "",
      dockRect: dockRect ? {
        x: dockRect.x,
        y: dockRect.y,
        width: dockRect.width,
        height: dockRect.height,
      } : null,
    };
  });
}

async function assertComposerFocused(page, label, timeoutMs = 4000) {
  const state = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const current = await activeComposerState(frame);
        return current.activeIsComposer ? current : null;
      }, 3);
    } catch {
      return null;
    }
  }, timeoutMs, 100);
  if (!state) throw new Error(`Composer did not keep or restore focus: ${label}`);
  return state;
}

async function focusComposer(page) {
  await withStudioFrame(page, async (frame) => {
    const input = frame.locator('[data-testid="studio-composer-input"]').first();
    await input.click();
  });
  return assertComposerFocused(page, "click");
}

async function setComposerValue(page, value) {
  await withStudioFrame(page, async (frame) => {
    const input = frame.locator('[data-testid="studio-composer-input"]').first();
    await input.fill(value);
    await input.click();
  });
  const stableState = await waitForPredicate(async () => {
    try {
      const state = await withStudioFrame(page, async (frame) => {
        const input = frame.locator('[data-testid="studio-composer-input"]').first();
        const currentValue = await input.inputValue({ timeout: 100 }).catch(() => "");
        return { ...(await activeComposerState(frame)), value: currentValue };
      }, 3);
      return state?.activeIsComposer && state.value === value ? state : null;
    } catch {
      return null;
    }
  }, 1200, 100);
  if (stableState) return stableState;
  await withStudioFrame(page, async (frame) => {
    await frame.evaluate((nextValue) => {
      const input = document.querySelector('[data-testid="studio-composer-input"]');
      if (!input) return;
      input.value = nextValue;
      input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: nextValue }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
      input.focus();
    }, value);
  });
  const fallbackState = await waitForPredicate(async () => {
    try {
      const state = await withStudioFrame(page, async (frame) => {
        const input = frame.locator('[data-testid="studio-composer-input"]').first();
        const currentValue = await input.inputValue({ timeout: 100 }).catch(() => "");
        return { ...(await activeComposerState(frame)), value: currentValue };
      }, 3);
      return state?.activeIsComposer && state.value === value ? state : null;
    } catch {
      return null;
    }
  }, 1200, 100);
  if (!fallbackState) {
    const state = await assertComposerFocused(page, "set value");
    throw new Error(`Composer value did not stick after setting prompt: expected ${value.length} chars, observed ${state.value.length}`);
  }
  return fallbackState;
}

async function latestAssistantText(page) {
  return withStudioFrame(page, async (frame) => {
    const paragraphs = frame.locator('[data-testid="studio-assistant-answer-text"], [data-testid="studio-streaming-output"]');
    const paragraphCount = await paragraphs.count();
    if (paragraphCount === 0) {
      return "";
    }
    const text = await paragraphs.nth(paragraphCount - 1).textContent({ timeout: 50 }).catch(() => "");
    return String(text || "").trim();
  });
}

function normalizeScenarioExecutionMode(value) {
  const normalized = String(value || "agent").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return ["ask", "chat", "chat_only", "chatonly", "direct_chat", "direct_model"].includes(normalized)
    ? "ask"
    : "agent";
}

function normalizeScenarioApprovalMode(value) {
  const normalized = String(value || "suggest").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (["auto_review", "auto_local", "autolocal", "auto"].includes(normalized)) {
    return "auto_local";
  }
  if (["full_access", "fullaccess", "never_prompt", "neverprompt", "yolo"].includes(normalized)) {
    return "never_prompt";
  }
  return "suggest";
}

function normalizeScenarioReasoningEffort(value) {
  const normalized = String(value || "none").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (["off", "disabled", "false", "no", "none"].includes(normalized)) return "none";
  if (["low", "medium", "high", "xhigh"].includes(normalized)) return normalized;
  return "none";
}

function threadModeForApprovalMode(approvalMode) {
  return normalizeScenarioApprovalMode(approvalMode) === "never_prompt" ? "yolo" : "agent";
}

async function currentStudioExecutionMode(page) {
  return withStudioFrame(page, async (frame) => {
    const raw = await frame.locator('[data-testid="studio-mode-toggle"]').first().getAttribute("data-studio-mode");
    return normalizeScenarioExecutionMode(raw || "agent");
  });
}

async function currentStudioApprovalMode(page) {
  return withStudioFrame(page, async (frame) => {
    const raw = await frame.locator('[data-testid="studio-permissions-toggle"]').first().getAttribute("data-approval-mode");
    return normalizeScenarioApprovalMode(raw || "suggest");
  });
}

async function currentStudioReasoningEffort(page) {
  return withStudioFrame(page, async (frame) => {
    const picker = frame.locator('[data-testid="studio-reasoning-effort-picker"]').first();
    if (!(await picker.count())) return "none";
    const raw = await picker.inputValue({ timeout: 500 }).catch(() => "");
    return normalizeScenarioReasoningEffort(raw || "none");
  });
}

async function selectStudioReasoningEffort(page, reasoningEffort) {
  const targetEffort = normalizeScenarioReasoningEffort(reasoningEffort);
  const currentEffort = await currentStudioReasoningEffort(page);
  if (currentEffort === targetEffort) {
    return {
      changed: false,
      requestedReasoningEffort: targetEffort,
      observedReasoningEffort: currentEffort,
    };
  }
  await withStudioFrame(page, async (frame) => {
    const picker = frame.locator('[data-testid="studio-reasoning-effort-picker"]').first();
    await picker.waitFor({ state: "visible", timeout: 7000 });
    await picker.selectOption(targetEffort);
  });
  const observedEffort = await waitForPredicate(async () => {
    const nextEffort = await currentStudioReasoningEffort(page).catch(() => "");
    return nextEffort === targetEffort ? nextEffort : "";
  }, 5000, 100);
  if (observedEffort !== targetEffort) {
    throw new Error(`Studio reasoning selector did not switch to ${targetEffort}; observed ${observedEffort || "unknown"}.`);
  }
  await assertComposerFocused(page, `reasoning effort switch ${targetEffort}`);
  return {
    changed: true,
    requestedReasoningEffort: targetEffort,
    observedReasoningEffort: observedEffort,
  };
}

async function selectStudioExecutionMode(page, requests, executionMode) {
  const targetMode = normalizeScenarioExecutionMode(executionMode);
  const currentMode = await currentStudioExecutionMode(page);
  if (currentMode === targetMode) {
    return {
      changed: false,
      requestedMode: targetMode,
      observedMode: currentMode,
      bridgeRequestObserved: false,
    };
  }

  const startIndex = requests.length;
  await withStudioFrame(page, async (frame) => {
    await frame.locator('[data-testid="studio-mode-toggle"]').click();
  });
  const host = page.locator('[data-testid="fork-agent-mode-quickinput"]').first();
  await host.waitFor({ state: "visible", timeout: 7000 });
  await host.locator(`[data-testid="fork-agent-mode-quickinput-row-${targetMode}"]`).click();
  await host.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
    await host.waitFor({ state: "hidden", timeout: 7000 });
  });
  const modeRequest = await requireRequest(
    requests,
    (request) =>
      request?.requestType === "chat.agentMode.select" &&
      normalizeScenarioExecutionMode(request?.payload?.executionMode || request?.payload?.selectionId || request?.payload?.label) === targetMode,
    `chat.agentMode.select:${targetMode}`,
    7000,
    startIndex,
  );
  const observedMode = await waitForPredicate(async () => {
    const nextMode = await currentStudioExecutionMode(page).catch(() => "");
    return nextMode === targetMode ? nextMode : "";
  }, 5000, 100);
  if (observedMode !== targetMode) {
    throw new Error(`Studio mode selector did not switch to ${targetMode}; observed ${observedMode || "unknown"}.`);
  }
  await assertComposerFocused(page, `mode switch ${targetMode}`);
  return {
    changed: true,
    requestedMode: targetMode,
    observedMode,
    bridgeRequestObserved: true,
    requestType: modeRequest?.requestType,
    selectionId: modeRequest?.payload?.selectionId,
  };
}

async function selectStudioApprovalMode(page, requests, approvalMode) {
  const targetMode = normalizeScenarioApprovalMode(approvalMode);
  const currentMode = await currentStudioApprovalMode(page);
  if (currentMode === targetMode) {
    return {
      changed: false,
      requestedApprovalMode: targetMode,
      observedApprovalMode: currentMode,
      bridgeRequestObserved: false,
    };
  }

  const startIndex = requests.length;
  await withStudioFrame(page, async (frame) => {
    await frame.locator('[data-testid="studio-permissions-toggle"]').click();
  });
  const host = page.locator('[data-testid="fork-permission-mode-quickinput"]').first();
  await host.waitFor({ state: "visible", timeout: 7000 });
  const targetRow = host.locator(`[data-testid="fork-permission-mode-quickinput-row-${targetMode}"]`);
  await targetRow.evaluate((row) => {
    row.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
  });
  await host.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
    await host.waitFor({ state: "hidden", timeout: 7000 });
  });
  const modeRequest = await requireRequest(
    requests,
    (request) =>
      request?.requestType === "chat.permissionMode.select" &&
      normalizeScenarioApprovalMode(request?.payload?.approvalMode || request?.payload?.approval_mode || request?.payload?.selectionId || request?.payload?.label) === targetMode,
    `chat.permissionMode.select:${targetMode}`,
    7000,
    startIndex,
  );
  const observedMode = await waitForPredicate(async () => {
    const nextMode = await currentStudioApprovalMode(page).catch(() => "");
    return nextMode === targetMode ? nextMode : "";
  }, 5000, 100);
  if (observedMode !== targetMode) {
    throw new Error(`Studio permissions selector did not switch to ${targetMode}; observed ${observedMode || "unknown"}.`);
  }
  await assertComposerFocused(page, `permission mode switch ${targetMode}`);
  return {
    changed: true,
    requestedApprovalMode: targetMode,
    observedApprovalMode: observedMode,
    bridgeRequestObserved: true,
    requestType: modeRequest?.requestType,
    selectionId: modeRequest?.payload?.selectionId,
    threadMode: threadModeForApprovalMode(targetMode),
  };
}

async function startFreshStudioSession(page, requests, label = "catalogue row") {
  const startIndex = requests.length;
  await withStudioFrame(page, async (frame) => {
    const button = frame.locator('[data-testid="studio-new-session-icon"], [data-testid="studio-new-session"]').first();
    await button.click();
  });
  const request = await requireRequest(
    requests,
    (item) => item?.requestType === "chat.newSession",
    `chat.newSession:${label}`,
    7000,
    startIndex,
  );
  await assertComposerFocused(page, `fresh session ${label}`);
  return {
    requested: true,
    requestType: request?.requestType,
  };
}

function markPromptPhase(timing, label, phaseStartedAtMs = Date.now(), extra = {}) {
  timing.phases.push({
    label,
    elapsedMs: Date.now() - timing.startedAtMs,
    durationMs: Date.now() - phaseStartedAtMs,
    ...extra,
  });
  writePromptTiming(timing.timingPath, { ...timing, status: "phase" });
}

function writePromptTiming(timingPath, timing) {
  if (!timingPath) {
    return;
  }
  appendFileSync(timingPath, `${JSON.stringify(timing)}\n`);
}

function toolcatSingleToolFromPrompt(prompt) {
  const match = String(prompt || "").match(/\btoolcat_tool=([^\s]+)/i);
  return match?.[1]?.trim() || "";
}

function humanToolLabel(toolName) {
  return String(toolName || "")
    .replace(/__/g, " ")
    .replace(/[_.-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function assistantTextMatchesPrompt(prompt, assistantText) {
  const toolName = toolcatSingleToolFromPrompt(prompt);
  if (!toolName || !/\bTOOLCAT_SINGLE_TOOL\b/i.test(String(prompt || ""))) {
    return true;
  }
  const normalizedText = String(assistantText || "")
    .replace(/__/g, " ")
    .replace(/[_.-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
  const label = humanToolLabel(toolName);
  return normalizedText.includes(label) || normalizedText.includes(toolName.toLowerCase());
}

function shouldContinueAfterPromptFailure(scenario, prompt) {
  return Boolean(scenario?.continueOnPromptFailure)
    || String(scenario?.id || "").startsWith("toolcat-")
    || /\bTOOLCAT_SINGLE_TOOL\b/i.test(String(prompt || ""));
}

const submitPrompt = createSubmitPrompt({
  assertNotCannedDaemonProjection,
  assertSemanticModelResponse,
  assistantTextMatchesPrompt,
  latestAssistantText,
  markPromptPhase,
  normalizeScenarioExecutionMode,
  requireRequest,
  screenshot,
  setComposerValue,
  wait,
  waitForPredicate,
  withStudioFrame,
  writePromptTiming,
});

async function openAndDismissQuickInput(page, frameButtonSelector, expectedTestId, dismiss = "escape") {
  await withStudioFrame(page, async (frame) => {
    await frame.locator(frameButtonSelector).click();
  });
  const host = page.locator(`[data-testid="${expectedTestId}"]`).first();
  await host.waitFor({ state: "visible", timeout: 7000 });
  if (dismiss === "outside") {
    await page.locator('[data-testid="fork-quickinput-backdrop"]').click({ position: { x: 5, y: 5 } });
  } else {
    await page.keyboard.press("Escape");
  }
  await host.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
    await host.waitFor({ state: "hidden", timeout: 7000 });
  });
  await assertComposerFocused(page, `${expectedTestId} dismissal`);
}

async function openQuickInputWithRetry(page, frameButtonSelector, expectedTestId, attempts = 2) {
  const host = page.locator(`[data-testid="${expectedTestId}"]`).first();
  let lastError = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    await withStudioFrame(page, async (frame) => {
      await frame.locator(frameButtonSelector).click({ force: true });
    });
    try {
      await host.waitFor({ state: "visible", timeout: attempt === attempts - 1 ? 7000 : 2500 });
      return host;
    } catch (error) {
      lastError = error;
      await wait(250);
    }
  }
  throw lastError || new Error(`Quick input did not open: ${expectedTestId}`);
}

async function dismissQuickInput(page, host, label, dismiss = "escape") {
  if (dismiss === "outside") {
    await page.locator('[data-testid="fork-quickinput-backdrop"]').click({ position: { x: 5, y: 5 } });
  } else {
    await page.keyboard.press("Escape");
  }
  await host.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
    await host.waitFor({ state: "hidden", timeout: 7000 });
  });
  await assertComposerFocused(page, `${label} dismissal`);
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

async function cleanupValidationProcesses({ outputDir, phase }) {
  const processes = listProcessesContaining(PROCESS_PATTERN);
  const before = processes.map((processInfo) => ({ ...processInfo }));
  for (const processInfo of processes) {
    try {
      process.kill(processInfo.pid, "SIGTERM");
    } catch {
      // Already gone.
    }
  }
  await wait(900);
  const stubborn = listProcessesContaining(PROCESS_PATTERN);
  for (const processInfo of stubborn) {
    try {
      process.kill(processInfo.pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  const after = listProcessesContaining(PROCESS_PATTERN);
  const proof = {
    schemaVersion: "ioi.autopilot-agent-studio-live-gui-validation.process-cleanup.v1",
    phase,
    pattern: PROCESS_PATTERN,
    before,
    after,
    cleaned: before.length,
    orphanProcesses: after,
    ok: after.length === 0,
    timestamp: new Date().toISOString(),
  };
  writeFileSync(join(outputDir, `process-cleanup-${phase}.json`), `${JSON.stringify(proof, null, 2)}\n`);
  if (!proof.ok) {
    throw new Error(`Validation left orphan processes for ${phase}`);
  }
  return proof;
}

function updateGuideStatus({ outputDir, proof, blocker = null }) {
  if (!UPDATE_MASTER_GUIDE) return;
  const path = join(repoRoot, MASTER_GUIDE);
  const current = read(MASTER_GUIDE);
  const status =
    proof?.targetStudioChatUxHardened && proof?.targetStudioModelBackedStreamingAchieved ? "Achieved" : "Blocked";
  const lines = [
    "## Latest Validation",
    "",
    `Status: ${status}`,
    "",
    `Evidence: \`${outputDir.replace(repoRoot + "/", "")}/\``,
    "",
    `Root cause: the earlier harness validated focus and daemon turn completion, but it did not prove model-backed token streaming and allowed canned Agentgres run projections to masquerade as assistant answers. Studio now routes chat through daemon-owned \`/v1/chat/completions\` streaming, and this harness rejects canned daemon projections.`,
    "",
    `Queries tested: ${proof?.queriesTested?.length ? proof.queriesTested.map((item) => item.kind).join(", ") : "pending"}.`,
    "",
    `Remaining blockers: ${blocker || proof?.remainingBlockers || "none"}.`,
    "",
    `Connector sprint readiness impact: Agent Studio chat focus and prompt submission are Playwright-controlled and daemon-routed; connector work remains dry-run only.`,
    "",
  ].join("\n");
  const updated = current.includes("## Latest Validation")
    ? current.replace(/## Latest Validation[\s\S]*$/m, lines)
    : `${current.trimEnd()}\n\n${lines}`;
  writeFileSync(path, updated);
}

function parseMaybeJson(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed || !["{", "["].includes(trimmed[0])) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function traceObject(value) {
  const parsed = parseMaybeJson(value);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
}

function traceKernelEventObjects(event) {
  const data = event?.data && typeof event.data === "object" ? event.data : {};
  const candidates = [
    data.kernel_event,
    data.kernelEvent,
    data.payload_summary?.kernel_event,
    data.payloadSummary?.kernelEvent,
    event?.payload_summary?.kernel_event,
    event?.payloadSummary?.kernelEvent,
    event?.payload?.kernel_event,
    event?.payload?.kernelEvent,
  ];
  return candidates.map(traceObject).filter(Boolean);
}

function traceRoutingReceipts(event) {
  const receipts = [];
  for (const kernelEvent of traceKernelEventObjects(event)) {
    const routing = traceObject(kernelEvent.RoutingReceipt) || kernelEvent.RoutingReceipt;
    if (routing && typeof routing === "object" && !Array.isArray(routing)) {
      receipts.push(routing);
    }
  }
  return receipts;
}

function actualTraceToolNames(event, toolNamePattern) {
  const names = new Set();
  const data = event?.data && typeof event.data === "object" ? event.data : {};
  const addToolNames = (value) => {
    if (typeof value !== "string") return;
    if (toolNamePattern.test(value)) names.add(value);
    toolNamePattern.lastIndex = 0;
  };
  const addToolNamesFromActionJson = (value) => {
    const parsed = parseMaybeJson(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
    addToolNames(parsed.name);
    addToolNames(parsed.tool_name);
    addToolNames(parsed.toolName);
    addToolNames(parsed.tool_normalization?.normalized_name);
    addToolNames(parsed.tool_normalization?.raw_name);
  };

  for (const key of ["tool_name", "toolName", "tool"]) {
    const value = data[key];
    addToolNames(value);
  }
  for (const source of [event, event?.payload, event?.payload_summary, event?.payloadSummary]) {
    if (!source || typeof source !== "object") continue;
    addToolNames(source.tool_name);
    addToolNames(source.toolName);
    addToolNames(source.tool);
    addToolNamesFromActionJson(source.action_json);
    addToolNamesFromActionJson(source.actionJson);
  }
  for (const kernelEvent of traceKernelEventObjects(event)) {
    addToolNames(kernelEvent?.AgentActionResult?.tool_name);
    addToolNames(kernelEvent?.RoutingReceipt?.tool_name);
    addToolNames(kernelEvent?.WorkloadReceipt?.tool_name);
    addToolNames(kernelEvent?.WorkloadReceipt?.receipt?.Exec?.tool_name);
    addToolNamesFromActionJson(kernelEvent?.RoutingReceipt?.action_json);
    addToolNamesFromActionJson(kernelEvent?.RoutingReceipt?.actionJson);
  }
  for (const receipt of traceRoutingReceipts(event)) {
    addToolNames(receipt.tool_name);
    addToolNames(receipt.toolName);
    addToolNamesFromActionJson(receipt.action_json);
    addToolNamesFromActionJson(receipt.actionJson);
  }
  return [...names];
}

function collectDaemonRuntimeTraceSummary({ daemonStateDir, outputDir }) {
  const artifactsDir = join(daemonStateDir, "artifacts");
  const traceOutputDir = join(outputDir, "daemon-runtime-traces");
  ensureDir(traceOutputDir);
  const traceFiles = existsSync(artifactsDir)
    ? readdirSync(artifactsDir).filter((file) => file.endsWith("_trace_json.json")).sort()
    : [];
  const summaries = [];
  const observedToolNames = new Set();
  const completedToolNames = new Set();
  const failedToolNames = new Set();
  const observedEventKinds = new Set();
  const toolCompletions = [];
  const toolFailures = [];
  const toolNamePattern = /\b(?:screen|[a-z][a-z0-9_]*(?:__[a-z0-9_]+)+|computer_use\.[a-z0-9_]+)\b/g;

  for (const file of traceFiles) {
    const sourcePath = join(artifactsDir, file);
    let artifact;
    try {
      artifact = JSON.parse(readFileSync(sourcePath, "utf8"));
    } catch {
      continue;
    }
    let trace = null;
    try {
      trace = typeof artifact.content === "string" ? JSON.parse(artifact.content) : artifact.content;
    } catch {
      trace = null;
    }
    const events = Array.isArray(trace?.events) ? trace.events : [];
    const prompt = events
      .map((event) => event?.data?.prompt)
      .find((value) => typeof value === "string" && value.trim());
    for (const event of events) {
      const eventKind = event?.data?.event_kind || event?.data?.eventKind || event?.type;
      if (eventKind) observedEventKinds.add(String(eventKind));
      const eventToolNames = actualTraceToolNames(event, toolNamePattern);
      for (const toolName of eventToolNames) {
        observedToolNames.add(toolName);
      }
      const runtimeEventKind = String(event?.data?.runtimeEventKind || event?.data?.runtime_event_kind || "");
      const eventType = String(event?.type || "");
      const isToolCompleted = eventType === "tool_completed" || runtimeEventKind === "tool.completed";
      const isToolFailed = eventType === "tool_failed" || runtimeEventKind === "tool.failed";
      const routingReceipts = traceRoutingReceipts(event);
      const routingSucceeded = routingReceipts.some((receipt) => receipt?.post_state?.success === true);
      const routingFailed = routingReceipts.some(
        (receipt) => receipt?.post_state?.success === false || receipt?.failure_class_name,
      );
      if (isToolCompleted || routingSucceeded) {
        for (const toolName of eventToolNames) {
          completedToolNames.add(toolName);
          toolCompletions.push({
            file,
            toolName,
            output: String(event?.data?.output || event?.data?.raw_output || event?.data?.message || "").slice(0, 1000),
          });
        }
      }
      if (isToolFailed || routingFailed) {
        for (const toolName of eventToolNames) {
          failedToolNames.add(toolName);
          toolFailures.push({
            file,
            toolName,
            errorClass:
              event?.data?.error_class ||
              event?.data?.errorClass ||
              routingReceipts.find((receipt) => receipt?.failure_class_name)?.failure_class_name ||
              null,
            output: String(event?.data?.output || event?.data?.raw_output || event?.data?.message || "").slice(0, 1000),
          });
        }
      }
    }
    const parsedTracePath = join(traceOutputDir, basename(file).replace(/_trace_json\.json$/, ".parsed-trace.json"));
    writeFileSync(parsedTracePath, `${JSON.stringify(trace || artifact, null, 2)}\n`);
    summaries.push({
      file,
      runId: artifact.runId || trace?.runId || null,
      prompt: prompt || null,
      eventCount: events.length,
      toolNames: [...new Set(events.flatMap((event) => actualTraceToolNames(event, toolNamePattern)))].sort(),
      eventKinds: [...new Set(events.map((event) => event?.data?.event_kind || event?.data?.eventKind || event?.type).filter(Boolean))].sort(),
      parsedTracePath: parsedTracePath.replace(repoRoot + "/", ""),
    });
  }

  const eventLogDir = join(daemonStateDir, "events");
  const eventLogFiles = existsSync(eventLogDir)
    ? readdirSync(eventLogDir).filter((file) => file.endsWith(".jsonl")).sort()
    : [];
  const eventLogSummaries = [];
  for (const file of eventLogFiles) {
    const sourcePath = join(eventLogDir, file);
    const lines = readFileSync(sourcePath, "utf8")
      .split(/\r?\n/)
      .filter((line) => line.trim());
    let eventCount = 0;
    const fileToolNames = new Set();
    const fileEventKinds = new Set();
    for (const line of lines) {
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }
      eventCount += 1;
      const eventKind =
        event?.event_kind ||
        event?.eventKind ||
        event?.payload?.event_kind ||
        event?.payloadSummary?.event_kind ||
        event?.payload_summary?.event_kind ||
        event?.type;
      if (eventKind) {
        observedEventKinds.add(String(eventKind));
        fileEventKinds.add(String(eventKind));
      }
      const eventToolNames = actualTraceToolNames(event, toolNamePattern);
      for (const toolName of eventToolNames) {
        observedToolNames.add(toolName);
        fileToolNames.add(toolName);
      }
      const routingReceipts = traceRoutingReceipts(event);
      const routingSucceeded = routingReceipts.some((receipt) => receipt?.post_state?.success === true);
      const routingFailed = routingReceipts.some(
        (receipt) => receipt?.post_state?.success === false || receipt?.failure_class_name,
      );
      const isToolCompleted = eventKind === "tool.completed" || routingSucceeded;
      const isToolFailed = eventKind === "tool.failed" || routingFailed;
      if (isToolCompleted || routingSucceeded) {
        for (const toolName of eventToolNames) {
          completedToolNames.add(toolName);
          toolCompletions.push({
            file,
            toolName,
            output: String(event?.payload?.output || event?.payload_summary?.output || event?.payloadSummary?.output || "").slice(0, 1000),
          });
        }
      }
      if (isToolFailed) {
        for (const toolName of eventToolNames) {
          failedToolNames.add(toolName);
          toolFailures.push({
            file,
            toolName,
            errorClass:
              event?.payload?.error_class ||
              event?.payload_summary?.error_class ||
              event?.payloadSummary?.errorClass ||
              routingReceipts.find((receipt) => receipt?.failure_class_name)?.failure_class_name ||
              null,
            output: String(event?.payload?.output || event?.payload_summary?.output || event?.payloadSummary?.output || "").slice(0, 1000),
          });
        }
      }
    }
    eventLogSummaries.push({
      file,
      eventCount,
      toolNames: [...fileToolNames].sort(),
      eventKinds: [...fileEventKinds].sort(),
    });
  }

  const summary = {
    schemaVersion: "ioi.autopilot-agent-studio.daemon-runtime-trace-summary.v1",
    daemonStateDir,
    traceCount: summaries.length,
    observedToolNames: [...observedToolNames].sort(),
    completedToolNames: [...completedToolNames].sort(),
    failedToolNames: [...failedToolNames].sort(),
    observedEventKinds: [...observedEventKinds].sort(),
    toolCompletions,
    toolFailures,
    traces: summaries,
    eventLogs: eventLogSummaries,
  };
  writeFileSync(join(outputDir, "daemon-runtime-trace-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

function collectDaemonRuntimeTraceSummaryBestEffort({ daemonStateDir, outputDir, label }) {
  try {
    return collectDaemonRuntimeTraceSummary({ daemonStateDir, outputDir });
  } catch (error) {
    writeFileSync(
      join(outputDir, `daemon-runtime-trace-summary-${label || "best-effort"}-error.json`),
      `${JSON.stringify({
        label,
        error: String(error?.stack || error?.message || error),
        timestamp: new Date().toISOString(),
      }, null, 2)}\n`,
    );
    return null;
  }
}

async function runValidation(outputDir, { scenario = resolveAgentStudioChatScenario() } = {}) {
  ensureDir(outputDir);
  studioFrameCache = null;
  await cleanupValidationProcesses({ outputDir, phase: "before-launch" });
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-hardening-daemon-"));
  writeFileSync(join(outputDir, "daemon-state-dir"), `${daemonStateDir}\n`);
  const workspaceSymlinkProbe = setupWorkspaceSymlinkProbe(outputDir, daemonStateDir, scenario);
  let userWorkspaceFixture = null;
  let openWorkspaceRoot = repoRoot;
  userWorkspaceFixture = setupUserWorkspaceFixture(outputDir, scenario);
  if (userWorkspaceFixture?.fixtureRoot) {
    openWorkspaceRoot = userWorkspaceFixture.fixtureRoot;
  }
  writeFileSync(join(outputDir, "opened-workspace-root"), `${openWorkspaceRoot}\n`);
  const runtimeBridgeAllowCommands = Array.isArray(scenario.runtimeBridgeAllowCommands)
    ? scenario.runtimeBridgeAllowCommands.map((value) => String(value || "").trim()).filter(Boolean)
    : [];
  if (runtimeBridgeAllowCommands.length > 0) {
    process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ALLOW_COMMANDS = runtimeBridgeAllowCommands.join(",");
  }
  const runtimeProcessEnv =
    scenario.runtimeProcessEnv && typeof scenario.runtimeProcessEnv === "object" && !Array.isArray(scenario.runtimeProcessEnv)
      ? Object.fromEntries(
        Object.entries(scenario.runtimeProcessEnv)
          .filter(([key, value]) => /^[A-Z_][A-Z0-9_]*$/i.test(key) && typeof value === "string"),
      )
      : {};
  for (const [key, value] of Object.entries(runtimeProcessEnv)) {
    process.env[key] = value;
  }
  const runtimeBridge = configureRuntimeAgentServiceBridgeEnv({
    repoRoot,
    stateDir: daemonStateDir,
    workspaceRoot: openWorkspaceRoot,
    overwrite: true,
  });
  writeFileSync(
    join(outputDir, "runtime-bridge-env.json"),
    `${JSON.stringify({
      ...runtimeBridge,
      allowCommands: runtimeBridgeAllowCommands,
      injectedEnvKeys: Object.keys(runtimeProcessEnv),
    }, null, 2)}\n`,
  );
  if (!runtimeBridge.configured) {
    throw new Error(`RuntimeAgentService bridge could not be configured: ${runtimeBridge.reason || "unknown"}`);
  }
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  daemonEndpointForBridge = daemon.endpoint;
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
  writeFileSync(join(outputDir, "runtime-model-route.json"), `${JSON.stringify(runtimeModelRoute, null, 2)}\n`);
  writeFileSync(
    join(outputDir, "runtime-inference-env.json"),
    `${JSON.stringify({ ...runtimeInference, token: runtimeInference.configured ? "redacted" : undefined }, null, 2)}\n`,
  );

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
  let partialProof = null;
  let page = null;
  let workspaceFixture = null;
  let browserFixture = null;
  let scenarioRuntimeContext = {};
  liveBridgeRequestLogPath = join(outputDir, "bridge-requests.live.jsonl");
  liveBridgeCommandLogPath = join(outputDir, "bridge-commands.live.jsonl");
  const validationWatchdog = setTimeout(async () => {
    const blocker = `Validation exceeded ${VALIDATION_TIMEOUT_MS}ms without completing.`;
    try {
      await page?.screenshot({ path: join(outputDir, "failure-timeout.png"), fullPage: true }).catch(() => undefined);
      writeFileSync(join(outputDir, "timeout-blocker.json"), `${JSON.stringify({ blocker, at: new Date().toISOString() }, null, 2)}\n`);
      writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
      writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
      writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
      writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
      collectDaemonRuntimeTraceSummaryBestEffort({ daemonStateDir, outputDir, label: "timeout" });
      updateGuideStatus({ outputDir, proof: partialProof, blocker });
      if (tracingStarted && context) {
        await context.tracing.stop({ path: join(outputDir, "playwright-trace.zip") }).catch(() => undefined);
        tracingStarted = false;
      }
      await browser?.close().catch(() => undefined);
      if (app && !app.killed) {
        app.kill("SIGTERM");
        await wait(1200);
        if (app.exitCode === null) app.kill("SIGKILL");
      }
      if (browserFixture?.server) {
        await closeServer(browserFixture.server).catch(() => undefined);
      }
      await server?.close?.();
      await daemon.close().catch(() => undefined);
      if (userDataDir) rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
      cleanupUserWorkspaceFixture(outputDir, userWorkspaceFixture);
      cleanupWorkspaceFixture(outputDir, workspaceFixture);
      await cleanupValidationProcesses({ outputDir, phase: "timeout-run" });
    } catch {
      // The watchdog is best-effort evidence and cleanup before exiting.
    } finally {
      process.exit(1);
    }
  }, VALIDATION_TIMEOUT_MS);

  try {
    server = createBridge({ requests, commands, deliveredCommands });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(PROCESS_PATTERN);
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-hardening-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "daemon-model-token-grant.json"), `${JSON.stringify({ ...daemonModelToken, token: "redacted" }, null, 2)}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    workspaceFixture = setupWorkspaceFixture(outputDir, scenario);
    browserFixture = await startBrowserFixture(outputDir, scenario);
    scenarioRuntimeContext = {
      workspaceFixtureRoot: workspaceFixture?.fixtureRoot || "",
      workspaceFixtureRelativeRoot: workspaceFixture?.relativeRoot || "",
      workspaceFixtureReadmePath: workspaceFixture?.readmePath || "",
      workspaceFixtureNotesPath: workspaceFixture?.notesPath || "",
      workspaceFixtureEditTargetPath: workspaceFixture?.editTargetPath || "",
      workspaceFixtureUploadPath: workspaceFixture?.uploadPath || "",
      workspaceFixtureModelPath: workspaceFixture?.modelPath || "",
      workspaceFixtureImagePath: workspaceFixture?.imagePath || "",
      userWorkspaceRoot: userWorkspaceFixture?.fixtureRoot || "",
      userWorkspaceReadmePath: userWorkspaceFixture?.readmePath || "",
      userWorkspaceApiClientPath: userWorkspaceFixture?.apiClientPath || "",
      userWorkspaceFormatPath: userWorkspaceFixture?.formatPath || "",
      userWorkspaceTestPath: userWorkspaceFixture?.testPath || "",
      browserFixtureUrl: browserFixture?.url || "",
      browserFixtureStatusUrl: browserFixture?.statusUrl || "",
      browserFixtureSecondUrl: browserFixture?.secondUrl || "",
      browserFixtureMediaUrl: browserFixture?.mediaUrl || "",
      daemonEndpoint: daemon.endpoint,
      computerUseProvidersUrl: `${daemon.endpoint}/v1/computer-use/providers`,
    };
    writeFileSync(join(outputDir, "scenario-runtime-context.json"), `${JSON.stringify(scenarioRuntimeContext, null, 2)}\n`);

    app = spawn(
      AUTOPILOT_ELECTRON.binary,
      [
        `--remote-debugging-port=${cdpPort}`,
        `--user-data-dir=${userDataDir}`,
        `--extensions-dir=${extensionsDir}`,
        "--disable-updates",
        "--disable-workspace-trust",
        "--new-window",
        openWorkspaceRoot,
      ],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          IOI_WORKSPACE_IDE_BRIDGE_URL: bridgeUrl,
          IOI_DAEMON_ENDPOINT: daemon.endpoint,
          IOI_DAEMON_TOKEN: daemonModelToken.token,
          IOI_DAEMON_MODEL_ID: runtimeModelRoute.modelId,
          IOI_AUTOPILOT_CANONICAL_SHELL: "vscode-electron-fork",
          IOI_WORKBENCH_NATIVE_SHELL: "1",
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
    page = await waitForPredicate(
      () => context.pages().find((candidate) => !candidate.isClosed()) ?? null,
      30_000,
      250,
    );
    if (!page) throw new Error("No Playwright page was available for the Electron fork.");
    page.on("console", (message) => consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() }));
    page.on("pageerror", (error) => pageErrors.push(String(error?.stack ?? error?.message ?? error)));
    await page.setViewportSize({ width: 1550, height: 925 }).catch(() => undefined);

    queueCommand(commands, "ioi.studio.open", { phase: "chat-hardening" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "before-focus-fix.png", screenshots);

    await focusComposer(page);
    await wait(2600);
    const focusedAfterPoll = await assertComposerFocused(page, "after bridge poll");
    if (focusedAfterPoll.composerBorderTopWidth !== "0px" || focusedAfterPoll.composerBorderTopStyle !== "none") {
      throw new Error(`Composer separator still visible: ${focusedAfterPoll.composerBorderTopWidth} ${focusedAfterPoll.composerBorderTopStyle}`);
    }
    await screenshot(page, outputDir, "focused-textarea.png", screenshots);

    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.fill("");
      await input.type("slow focus test", { delay: 45 });
    });
    await wait(2300);
    const slowState = await assertComposerFocused(page, "slow typing after poll");
    if (slowState.value !== "slow focus test") {
      throw new Error(`Slow typing value changed unexpectedly: ${slowState.value}`);
    }

    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.fill("");
      await input.type("fast-query repo symbols policy", { delay: 0 });
      await input.press(process.platform === "darwin" ? "Meta+A" : "Control+A");
      await page.keyboard.insertText("pasted workspace context request");
    });
    const pasteState = await assertComposerFocused(page, "paste and selection");
    if (pasteState.value !== "pasted workspace context request") {
      throw new Error(`Paste/selection flow wrote the wrong value: ${pasteState.value}`);
    }
    await setComposerValue(page, "");

    await openAndDismissQuickInput(page, '[data-testid="studio-add-context"]', "fork-add-context-quickinput", "outside");
    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-add-context"]').click();
    });
    await page.locator('[data-testid="fork-add-context-quickinput"]').waitFor({ state: "visible", timeout: 7000 });
    await screenshot(page, outputDir, "add-context-picker.png", screenshots);
    await page.keyboard.press("Escape");
    await page.locator('[data-testid="fork-add-context-quickinput"]').waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
      await page.locator('[data-testid="fork-add-context-quickinput"]').waitFor({ state: "hidden", timeout: 7000 });
    });
    await assertComposerFocused(page, "add context escape");

    const toolsHost = await openQuickInputWithRetry(
      page,
      '[data-testid="studio-tools-toggle"]',
      "fork-configure-tools-quickinput",
      3,
    );
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowRight");
    await page.keyboard.press(" ");
    await screenshot(page, outputDir, "tools-picker.png", screenshots);
    await dismissQuickInput(page, toolsHost, "tools", "escape");

    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-model-toggle"]').click();
    });
    const modelHost = page.locator('[data-testid="fork-model-route-quickinput"]').first();
    await modelHost.waitFor({ state: "visible", timeout: 7000 });
    const modelText = await modelHost.textContent();
    if (!/mounted|active|loaded/i.test(modelText || "") || /local unmounted demo|No mounted models/i.test(modelText || "")) {
      throw new Error(`Model selector did not show mounted models only: ${modelText}`);
    }
    await screenshot(page, outputDir, "model-selector-mounted-models.png", screenshots);
    await page.keyboard.press("Escape");
    await modelHost.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
      await modelHost.waitFor({ state: "hidden", timeout: 7000 });
    });
    await assertComposerFocused(page, "model selector escape");

    await openAndDismissQuickInput(page, '[data-testid="studio-mode-toggle"]', "fork-agent-mode-quickinput", "escape");
    await openAndDismissQuickInput(page, '[data-testid="studio-target-toggle"]', "fork-workflow-target-quickinput", "escape");
    await screenshot(page, outputDir, "menus-dismissed-cleanly.png", screenshots);

    const emptyStart = requests.length;
    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.evaluate((element) => {
        element.value = "   ";
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.focus();
      });
      await frame.locator('[data-testid="studio-send-button"]').click();
    });
    await wait(1400);
    const emptySubmit = requests
      .slice(emptyStart)
      .find((request) => request?.requestType === "chat.submit" && !String(request?.payload?.prompt || "").trim());
    if (emptySubmit) {
      throw new Error("Empty prompt unexpectedly emitted a bridge request.");
    }
    await assertComposerFocused(page, "empty prompt");

    const promptCases = scenario.promptCases;
    const promptResults = [];
    const promptTimingLogPath = join(outputDir, "prompt-timings.live.jsonl");
    for (let index = 0; index < promptCases.length; index += 1) {
      const item = promptCases[index];
      const promptText = expandScenarioPrompt(item.prompt, scenarioRuntimeContext);
      const expectedExecutionMode = normalizeScenarioExecutionMode(item.executionMode || "agent");
      const expectedApprovalMode = normalizeScenarioApprovalMode(item.approvalMode || scenario.approvalMode || "suggest");
      const expectedReasoningEffort = normalizeScenarioReasoningEffort(item.reasoningEffort || scenario.reasoningEffort || "none");
      const freshSession = item.isolateThread
        ? await startFreshStudioSession(page, requests, item.kind || `prompt-${index}`)
        : { requested: false };
      const modeSelection = await selectStudioExecutionMode(page, requests, expectedExecutionMode);
      const permissionSelection = await selectStudioApprovalMode(page, requests, expectedApprovalMode);
      const reasoningSelection = await selectStudioReasoningEffort(page, expectedReasoningEffort);
      const promptStartedAtMs = Date.now();
      let result;
      let promptFailureError = null;
      try {
        result = await submitPrompt(
          page,
          requests,
          promptText,
          index % 2 === 0 ? "button" : "keyboard",
          promptTimingLogPath,
          {
            assistantVisibleTimeoutMs: item.assistantVisibleTimeoutMs || scenario.assistantVisibleTimeoutMs,
            streamProbeTimeoutMs: item.streamProbeTimeoutMs || scenario.streamProbeTimeoutMs,
            pendingWorklogTimeoutMs: item.pendingWorklogTimeoutMs || scenario.pendingWorklogTimeoutMs,
            requirePendingWorklog: Boolean(item.requirePendingWorklog || scenario.requirePendingWorklog),
            requireAgentFinalStream: Boolean(item.requireAgentFinalStream || scenario.requireAgentFinalStream),
            requireAgentArtifactSourceStream: Boolean(item.requireAgentArtifactSourceStream || scenario.requireAgentArtifactSourceStream),
            requireConversationArtifactProof: Boolean(item.requireConversationArtifactProof || scenario.requireConversationArtifactProof),
            requireMarkdownRenderProof: Boolean(item.requireMarkdownRenderProof || scenario.requireMarkdownRenderProof),
            captureMarkdownRenderProof: Boolean(item.captureMarkdownRenderProof || scenario.captureMarkdownRenderProof),
            requireSourceRowsProof: Boolean(item.requireSourceRowsProof || scenario.requireSourceRowsProof),
            captureSourceRowsProof: Boolean(item.captureSourceRowsProof || scenario.captureSourceRowsProof),
            requiredMarkdownElements: item.requiredMarkdownElements || scenario.requiredMarkdownElements || [],
            capturePendingProjection: index === 0,
            expectedExecutionMode,
            mustMentionAny: item.mustMentionAny || [],
            mustMentionAll: item.mustMentionAll || [],
            outputDir,
            screenshots,
          },
        );
      } catch (error) {
        if (!shouldContinueAfterPromptFailure(scenario, promptText)) {
          throw error;
        }
        promptFailureError = {
          message: error?.message || String(error),
          stack: error?.stack || "",
          timestamp: new Date().toISOString(),
          prompt: promptText,
          expectedTool: toolcatSingleToolFromPrompt(promptText),
        };
        writeFileSync(
          join(outputDir, `prompt-failure-${String(index).padStart(2, "0")}.json`),
          `${JSON.stringify(promptFailureError, null, 2)}\n`,
        );
        await screenshot(page, outputDir, `prompt-failure-${String(index).padStart(2, "0")}.png`, screenshots).catch(() => {});
        result = {
          request: null,
          streamProbe: null,
          assistantText: "",
          modelBackedStreamObserved: false,
          executionMode: expectedExecutionMode,
          completionStatus: "prompt_failure",
          newDocumentedWorkVisible: false,
          documentedWorkCount: 0,
          markdownRenderProof: null,
          sourceRowsProof: null,
          durationMs: Date.now() - promptStartedAtMs,
          timing: {
            prompt: promptText,
            startedAt: new Date(promptStartedAtMs).toISOString(),
            durationMs: Date.now() - promptStartedAtMs,
            promptFailureError,
          },
        };
      }
      promptResults.push({
        kind: item.kind,
        prompt: promptText,
        promptTemplate: item.prompt,
        mustMentionAny: item.mustMentionAny || [],
        mustMentionAll: item.mustMentionAll || [],
        mustNotMentionAny: item.mustNotMentionAny || [],
        requestType: result.request?.requestType,
        executionMode: result.executionMode || "agent",
        expectedExecutionMode,
        approvalMode: normalizeScenarioApprovalMode(result.request?.payload?.approvalMode || result.request?.payload?.approval_mode || expectedApprovalMode),
        expectedApprovalMode,
        freshSession,
        modeSelection,
        permissionSelection,
        reasoningSelection,
        mode: index % 2 === 0 ? "button" : "keyboard",
        streamStatusObserved: result.streamProbe?.status || "not-required-for-agent",
        completionStatusObserved: result.completionStatus,
        firstStreamText: (result.streamProbe?.streamText || result.streamProbe?.thinkingText || "").slice(0, 180),
        firstStreamKind: result.streamProbe?.streamKind || null,
        artifactSourceStreamObserved: Boolean(result.artifactSourceStreamObserved),
        assistantText: result.assistantText,
        modelBackedStreamObserved: result.modelBackedStreamObserved,
        agentFinalStreamObserved: result.agentFinalStreamObserved,
        newDocumentedWorkVisible: result.newDocumentedWorkVisible,
        documentedWorkCount: result.documentedWorkCount,
        pendingProjectionProof: result.pendingProjectionProof || null,
        markdownRenderProof: result.markdownRenderProof || null,
        sourceRowsProof: result.sourceRowsProof || null,
        durationMs: result.durationMs,
        timing: result.timing,
        promptFailureError,
      });
      if (index === 0) {
        await screenshot(page, outputDir, "after-prompt-submission.png", screenshots);
      }
    }
    await screenshot(page, outputDir, "assistant-response.png", screenshots);
    const managedSessionViewportProof = await captureManagedSessionViewportProof(
      page,
      outputDir,
      screenshots,
      { required: Boolean(scenario.requireManagedSessionViewportProof) },
    );
    const conversationArtifactProof = await captureConversationArtifactProof(
      page,
      outputDir,
      screenshots,
      { required: Boolean(scenario.requireConversationArtifactProof) },
    );
    const assistantResponses = promptResults.map((item) => item.assistantText).filter(Boolean);
    const successfulPromptResults = promptResults.filter((item) => !item.promptFailureError);
    const promptFailures = promptResults.filter((item) => item.promptFailureError);
    const uniqueAssistantResponses = [...new Set(assistantResponses)];
    if (promptFailures.length > 0 && !shouldContinueAfterPromptFailure(scenario, "")) {
      throw new Error(`Prompt failures encountered: ${JSON.stringify(promptFailures.map((item) => ({ kind: item.kind, error: item.promptFailureError?.message })))}`);
    }
    if (promptFailures.length === 0 && assistantResponses.length !== promptCases.length) {
      throw new Error(`Expected ${promptCases.length} assistant responses, observed ${assistantResponses.length}.`);
    }
    if ((promptResults[0]?.durationMs ?? 0) > scenario.maxFirstPromptMs) {
      throw new Error(`Simple Agent Studio prompt exceeded latency budget: ${promptResults[0].durationMs}ms.`);
    }
    for (const item of promptResults) {
      if (item.promptFailureError) {
        continue;
      }
      assertNotCannedDaemonProjection(item.assistantText, item.kind);
      assertSemanticModelResponse(item.assistantText, item.kind);
      assertPromptSpecificResponse(item.assistantText, item);
      assertPromptForbiddenTermsAbsent(item.assistantText, item);
    }
    const approvalPauses = approvalPauseSummary(promptResults);
    if (approvalPauses.length > 0 && !scenario.allowApprovalPause && !scenario.allowBlockedResult) {
      throw new Error(`Agent turns paused for approval before satisfying the scenario contract: ${JSON.stringify(approvalPauses)}`);
    }
    const controlledFailureToolNames = new Set(scenario.allowControlledFailureToolNames || []);
    const unexpectedBlockedResults = promptResults.filter((item) =>
      !item.promptFailureError &&
      /blocked|failed|error|paused/i.test(String(item.completionStatusObserved || "")) &&
      !(scenario.allowApprovalPause && isApprovalPauseText(item.assistantText)) &&
      !scenario.allowBlockedResult &&
      !controlledFailureToolNames.has(promptResultToolName(item)),
    );
    if (unexpectedBlockedResults.length > 0) {
      throw new Error(`Agent turns rendered blocked/failure UX for successful prompts: ${JSON.stringify(unexpectedBlockedResults.map((item) => ({ kind: item.kind, completionStatus: item.completionStatusObserved, assistantText: item.assistantText })))}`);
    }
    if (successfulPromptResults.length > 0 && uniqueAssistantResponses.length < scenario.minUniqueAssistantResponses) {
      throw new Error("Assistant responses are not prompt-sensitive; repeated output detected.");
    }
    const modeMismatches = promptResults.filter((item) => item.executionMode !== item.expectedExecutionMode);
    if (modeMismatches.length > 0) {
      throw new Error(`Studio submitted prompts in the wrong execution mode: ${JSON.stringify(modeMismatches.map((item) => ({ kind: item.kind, expected: item.expectedExecutionMode, observed: item.executionMode })))}`);
    }
    const approvalModeMismatches = promptResults.filter((item) => item.approvalMode !== item.expectedApprovalMode);
    if (approvalModeMismatches.length > 0) {
      throw new Error(`Studio submitted prompts with the wrong approval mode: ${JSON.stringify(approvalModeMismatches.map((item) => ({ kind: item.kind, expected: item.expectedApprovalMode, observed: item.approvalMode })))}`);
    }
    const askPromptResults = promptResults.filter((item) => item.expectedExecutionMode === "ask");
    const agentPromptResults = promptResults.filter((item) => item.expectedExecutionMode === "agent");
    const isAllowedAgentStream = (item) =>
      item.modelBackedStreamObserved &&
      (
        (Boolean(scenario.allowAgentArtifactSourceStream) && (item.firstStreamKind === "artifact_source" || item.artifactSourceStreamObserved)) ||
        (Boolean(scenario.requireAgentFinalStream || scenario.allowAgentFinalHandoffStream) &&
          (item.firstStreamKind === "answer" || item.agentFinalStreamObserved))
      );
    if (scenario.requireAskModeStream && askPromptResults.some((item) => !item.modelBackedStreamObserved)) {
      throw new Error("Ask Mode did not expose direct model token streaming.");
    }
    if (scenario.requireAgentArtifactSourceStream && agentPromptResults.some((item) => !item.promptFailureError && item.firstStreamKind !== "artifact_source" && !item.artifactSourceStreamObserved)) {
      throw new Error("Agent artifact generation did not expose a streamed source artifact.");
    }
    if (scenario.requireAgentFinalStream && agentPromptResults.some((item) => !item.promptFailureError && !item.agentFinalStreamObserved)) {
      throw new Error("Agent final handoff did not expose streamed answer deltas.");
    }
    if (scenario.requireAgentModeReply && agentPromptResults.some((item) => !item.promptFailureError && (!item.assistantText || (item.modelBackedStreamObserved && !isAllowedAgentStream(item))))) {
      throw new Error("Agent Mode did not stay on the governed final-reply path.");
    }
    if (askPromptResults.some((item) => item.newDocumentedWorkVisible)) {
      throw new Error("Ask Mode rendered a documented-work card.");
    }
    if (scenario.requireNoDocumentedWorkForAgent && agentPromptResults.some((item) => item.newDocumentedWorkVisible)) {
      throw new Error("Lightweight conversation rendered a documented-work card.");
    }
    const daemonRuntimeTraceSummary = collectDaemonRuntimeTraceSummary({ daemonStateDir, outputDir });
    const requiredAgentTraceToolNames = Array.isArray(scenario.requireAgentTraceToolNames)
      ? scenario.requireAgentTraceToolNames
      : [];
    const missingTraceToolNames = requiredAgentTraceToolNames.filter(
      (toolName) => !daemonRuntimeTraceSummary.observedToolNames.includes(toolName),
    );
    if (missingTraceToolNames.length > 0) {
      throw new Error(`Daemon runtime traces did not include required Agent tool names: ${missingTraceToolNames.join(", ")}`);
    }
    const requiredAgentTraceToolSuccessNames = Array.isArray(scenario.requireAgentTraceToolSuccessNames)
      ? scenario.requireAgentTraceToolSuccessNames
      : [];
    const missingSuccessfulTraceToolNames = requiredAgentTraceToolSuccessNames.filter(
      (toolName) => !daemonRuntimeTraceSummary.completedToolNames.includes(toolName),
    );
    if (missingSuccessfulTraceToolNames.length > 0) {
      throw new Error(`Daemon runtime traces did not include successful completions for required Agent tools: ${missingSuccessfulTraceToolNames.join(", ")}`);
    }
    const requireNoAgentTraceToolFailuresFor = Array.isArray(scenario.requireNoAgentTraceToolFailuresFor)
      ? scenario.requireNoAgentTraceToolFailuresFor
      : [];
    const allowAgentTraceToolFailuresFor = new Set(
      Array.isArray(scenario.allowAgentTraceToolFailuresFor)
        ? scenario.allowAgentTraceToolFailuresFor
        : [],
    );
    const disallowedFailedToolNames = requireNoAgentTraceToolFailuresFor.filter(
      (toolName) =>
        daemonRuntimeTraceSummary.failedToolNames.includes(toolName) &&
        !allowAgentTraceToolFailuresFor.has(toolName),
    );
    if (disallowedFailedToolNames.length > 0) {
      throw new Error(`Daemon runtime traces included failed required Agent tools: ${disallowedFailedToolNames.join(", ")}`);
    }
    const receiptResponse = await fetch(`${daemon.endpoint}/api/v1/receipts`);
    const receiptPayload = receiptResponse.ok ? await receiptResponse.json() : { error: await receiptResponse.text() };
    const receiptItems = Array.isArray(receiptPayload)
      ? receiptPayload
      : Array.isArray(receiptPayload.receipts)
        ? receiptPayload.receipts
        : Array.isArray(receiptPayload.items)
          ? receiptPayload.items
          : [];
    const modelInvocationReceipts = receiptItems.filter((receipt) =>
      /model_invocation/i.test(String(receipt.kind || receipt.type || receipt.id || "")),
    );
    writeFileSync(join(outputDir, "daemon-receipts-after-chat.json"), `${JSON.stringify(receiptPayload, null, 2)}\n`);
    if (modelInvocationReceipts.length === 0 && !scenario.allowNoModelInvocationReceipt) {
      throw new Error("Daemon did not emit model invocation receipts for Studio chat prompts.");
    }

    let postCompletionStopRequestObserved = false;
    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-stop-icon"]').click();
    });
    if (scenario.requirePostCompletionStopRequest) {
      await requireRequest(requests, (request) => request?.requestType === "chat.stop", "chat.stop");
      postCompletionStopRequestObserved = true;
    } else {
      postCompletionStopRequestObserved = Boolean(
        await waitForPredicate(
          async () => requests.some((request) => request?.requestType === "chat.stop"),
          { timeoutMs: 1000, intervalMs: 100 },
        ),
      );
    }

    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-utility-toggle"]').click();
      await frame.locator('[data-testid="studio-tool-timeline"]').waitFor({ state: "visible", timeout: 5000 });
      await frame.locator('[data-testid="studio-receipts-replay"]').waitFor({ state: "visible", timeout: 5000 });
    });

    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);

    const proof = {
      schemaVersion: "ioi.autopilot-agent-studio-live-gui-validation.proof.v1",
      scenarioId: scenario.id,
      scenarioLabel: scenario.label,
      targetStudioChatUxHardened: true,
      targetStudioOperationalChatAchieved: true,
      targetStudioTauriChatUxParityStillPasses: true,
      rootCause: "The previous harness treated daemon turn completion as assistant completion. Studio now streams assistant output through daemon-owned /v1/chat/completions and rejects canned Agentgres projections.",
      textareaKeepsFocusOnClick: true,
      textareaKeepsFocusAcrossBridgePoll: true,
      typingTargetsComposer: true,
      slowTypingStable: true,
      fastTypingStable: true,
      pasteAndSelectionStable: true,
      sendButtonSubmits: promptResults.some((item) => item.mode === "button"),
      keyboardSubmitSubmits: promptResults.some((item) => item.mode === "keyboard"),
      emptyPromptBlocked: true,
      pendingStateAppearsWithinOneSecond: true,
      assistantResponseVisible: true,
      targetStudioModelBackedStreamingAchieved: askPromptResults.length > 0
        ? askPromptResults.every((item) => item.modelBackedStreamObserved && item.assistantText)
        : true,
      targetStudioAgentReplyAchieved: agentPromptResults.length > 0
        ? agentPromptResults.every((item) => item.executionMode === "agent" && item.assistantText)
        : true,
      targetStudioAskModeDirectModelAchieved: askPromptResults.length > 0
        ? askPromptResults.every((item) => item.executionMode === "ask" && item.modelBackedStreamObserved && item.assistantText)
        : true,
      agentFinalReplyAcceptedWithoutStreaming: agentPromptResults.every((item) => item.assistantText && (!item.modelBackedStreamObserved || isAllowedAgentStream(item))),
      agentFinalHandoffStreamingObserved: agentPromptResults.some((item) => item.agentFinalStreamObserved),
      agentArtifactSourceStreamingObserved: agentPromptResults.some((item) => item.firstStreamKind === "artifact_source" || item.artifactSourceStreamObserved),
      askModeDidNotRenderDocumentedWork: askPromptResults.every((item) => !item.newDocumentedWorkVisible),
      modelInvocationReceiptObserved: modelInvocationReceipts.length > 0,
      modelInvocationReceiptCount: modelInvocationReceipts.length,
      cannedDaemonProjectionRejected: true,
      fixtureModelResponseRejected: true,
      semanticModelResponseObserved: true,
      assistantResponses,
      uniqueAssistantResponseCount: uniqueAssistantResponses.length,
      daemonRuntimeTraceSummary,
      managedSessionViewportProof,
      conversationArtifactProof,
      requiredAgentTraceToolNames,
      requiredAgentTraceToolSuccessNames,
      requireNoAgentTraceToolFailuresFor,
      addContextDismissesAndRestoresFocus: true,
      toolsDismissesAndRestoresFocus: true,
      modelSelectorMountedOnly: true,
      postCompletionStopRequestObserved,
      modeSelectorDismissesAndRestoresFocus: true,
      targetSelectorDismissesAndRestoresFocus: true,
      noSeparatorLineBetweenTranscriptAndComposer: true,
      noStuckMenus: true,
      noDuplicateTabsOrSidebarFlashObserved: true,
      noTauriUsage: !read(EXTENSION_JS).includes("@tauri-apps"),
      noWebviewDurableRuntimeAuthority: true,
      noLiveExternalConnectorAction: true,
      queriesTested: promptResults,
      screenshots,
      evidenceDir: outputDir,
      remainingBlockers: "none",
    };
    partialProof = proof;
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    updateGuideStatus({ outputDir, proof });
    return proof;
  } catch (error) {
    if (page && !page.isClosed()) {
      await screenshot(page, outputDir, "failure-state.png", screenshots).catch(() => undefined);
    }
    const failureTraceSummary = collectDaemonRuntimeTraceSummaryBestEffort({ daemonStateDir, outputDir, label: "failure" });
    if (failureTraceSummary && partialProof) {
      partialProof = { ...partialProof, daemonRuntimeTraceSummary: failureTraceSummary };
    }
    writeFileSync(
      join(outputDir, "failure-error.json"),
      `${JSON.stringify({
        message: error?.message || String(error),
        stack: error?.stack || null,
        timestamp: new Date().toISOString(),
      }, null, 2)}\n`,
    );
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    updateGuideStatus({
      outputDir,
      proof: partialProof,
      blocker: error?.message || String(error),
    });
    throw error;
  } finally {
    clearTimeout(validationWatchdog);
    liveBridgeRequestLogPath = null;
    liveBridgeCommandLogPath = null;
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
    if (browserFixture?.server) {
      await closeServer(browserFixture.server).catch(() => undefined);
    }
    await server?.close?.();
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
    cleanupWorkspaceSymlinkProbe(outputDir, workspaceSymlinkProbe);
    cleanupUserWorkspaceFixture(outputDir, userWorkspaceFixture);
    cleanupWorkspaceFixture(outputDir, workspaceFixture);
    await cleanupValidationProcesses({ outputDir, phase: "after-run" });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const scenario = resolveAgentStudioChatScenario(args.scenario);
  const outputDir = join(repoRoot, EVIDENCE_ROOT, timestamp());
  ensureDir(outputDir);
  const preflight = preflightChecks();
  preflight.scenario = {
    id: scenario.id,
    label: scenario.label,
    promptCount: scenario.promptCases.length,
  };
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
  const proof = await runValidation(outputDir, { scenario });
  console.log(JSON.stringify({
    schemaVersion: "ioi.autopilot-agent-studio-live-gui-validation.goal.v1",
    ok: true,
    evidenceDir: outputDir,
    proof,
  }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
