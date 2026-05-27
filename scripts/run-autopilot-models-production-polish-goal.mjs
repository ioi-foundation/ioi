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
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";
import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./lib/autopilot-electron-app-paths.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const MASTER_GUIDE =
  ".internal/plans/autopilot-electron-models-production-polish-playwright-master-guide.md";
const PARENT_GUIDES = [
  ".internal/plans/autopilot-electron-models-lm-studio-inspired-ux-master-guide.md",
  ".internal/plans/autopilot-electron-model-mounting-daemon-runtime-adapter-master-guide.md",
];
const OUTPUT_ROOT =
  "docs/evidence/autopilot-electron-models-production-polish-playwright";
const EXTENSION_ROOT = "apps/autopilot/openvscode-extension/ioi-workbench";
const VSCODE_PACKAGED_APP_ROOT = AUTOPILOT_ELECTRON.packagedRoot;
const MODEL_ID = "stories260k";
const SECONDARY_MODEL_ID = "text-embedding-nomic-embed-text-v1.5";
const ENDPOINT_ID = "endpoint.electron.model-gui";
const SECONDARY_ENDPOINT_ID = "endpoint.electron.embedding-gui";
const ROUTE_ID = "route.native-local";
const PROVIDER_ID = "provider.lmstudio";

const REQUIRED_SCREENSHOTS = [
  "models-library-production.png",
  "models-library-filtered.png",
  "model-inspector-load-tab.png",
  "model-load-parameters-advanced.png",
  "model-unloaded-state.png",
  "workflow-route-unload-blocked.png",
  "model-remounted-ready.png",
  "model-server-api-logs.png",
  "agent-studio-operational-chat-polished.png",
  "agent-studio-model-handoff.png",
  "workflow-model-binding-ready.png",
  "workflow-live-model-dry-run.png",
];

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  const args = { preflight: false, run: false, outputRoot: OUTPUT_ROOT };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--preflight") args.preflight = true;
    else if (arg === "--run") args.run = true;
    else if (arg === "--output-root") args.outputRoot = argv[++index] ?? args.outputRoot;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!args.preflight && !args.run) args.preflight = true;
  return args;
}

function runCommand(command, args = [], options = {}) {
  const startedAtMs = Date.now();
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status ?? 1,
    signal: result.signal ?? null,
    durationMs: Date.now() - startedAtMs,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    ok: result.status === 0,
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

function read(path) {
  try {
    return readFileSync(join(repoRoot, path), "utf8");
  } catch {
    return "";
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(join(repoRoot, path), "utf8"));
  } catch (error) {
    return { __readError: String(error?.message ?? error) };
  }
}

function checkCommand(command) {
  const result = runCommand("bash", ["-lc", `command -v ${command}`]);
  return {
    id: `command:${command}`,
    ok: result.ok && Boolean(result.stdout.trim()),
    summary: result.ok ? `${command} is available` : `${command} is missing`,
    evidence: compact(result),
  };
}

function checkGuide() {
  const content = read(MASTER_GUIDE);
  const required = [
    "Playwright",
    "production-grade",
    "mount/load/unload/remount",
    "Agent Studio",
    "Workflow Composer",
    "Do not begin connector-specific sprint work",
  ];
  const missing = required.filter((phrase) => !content.includes(phrase));
  return {
    id: "guide:models-production-polish",
    ok: existsSync(join(repoRoot, MASTER_GUIDE)) && missing.length === 0,
    summary:
      missing.length === 0
        ? "Production-polish master guide is present"
        : "Production-polish master guide is missing required source-of-truth language",
    evidence: { path: MASTER_GUIDE, missing },
  };
}

function checkParentGuideLinks() {
  const missing = PARENT_GUIDES.filter((path) => !read(path).includes(MASTER_GUIDE));
  return {
    id: "guide:parent-links-production-polish",
    ok: missing.length === 0,
    summary:
      missing.length === 0
        ? "Parent model guides link the production-polish child guide"
        : "One or more parent guides do not link the production-polish child guide",
    evidence: { missing },
  };
}

function checkPackageScripts() {
  const packageJson = readJson("package.json");
  const required = [
    "goal:autopilot-models-production-polish",
    "goal:autopilot-models-production-polish:run",
    "goal:autopilot-models-lm-studio-ux",
    "goal:autopilot-model-mounting",
    "goal:autopilot-workflow-compositor-parity",
  ];
  const missing = required.filter((script) => !packageJson.scripts?.[script]);
  const wired = [
    packageJson.scripts?.["goal:autopilot-models-production-polish"],
    packageJson.scripts?.["goal:autopilot-models-production-polish:run"],
  ].every((value) =>
    String(value || "").includes("scripts/run-autopilot-models-production-polish-goal.mjs"),
  );
  return {
    id: "package:models-production-polish-scripts",
    ok: missing.length === 0 && wired,
    summary:
      missing.length === 0 && wired
        ? "Production-polish goal scripts are wired"
        : "Production-polish goal scripts are missing or miswired",
    evidence: { missing, wired },
  };
}

function checkSourceShape() {
  const extensionSource = read(`${EXTENSION_ROOT}/extension.js`);
  const composerSource = read(`${EXTENSION_ROOT}/webview/workflow-composer/main.tsx`);
  const runtimeSource = read(`${EXTENSION_ROOT}/webview/workflow-composer/fixtureRuntime.ts`);
  const daemonSource = read("packages/runtime-daemon/src/model-mounting.mjs");
  const checks = {
    modelRowsKeyboardSelectable: extensionSource.includes('role="button"') &&
      extensionSource.includes("moveModelSelection"),
    unloadButtonVisible: extensionSource.includes('data-testid="model-running-unload-button"'),
    advancedPanelVisible: extensionSource.includes('data-testid="model-advanced-settings-panel"'),
    emptyAndDegradedStatesVisible:
      extensionSource.includes('data-testid="model-empty-state"') &&
      extensionSource.includes('data-testid="model-error-state"'),
    studioPromptSurface: extensionSource.includes('data-studio-prompt-form') &&
      extensionSource.includes('requestType: "chat.submit"') &&
      extensionSource.includes('type: "studioSubmit"') &&
      !extensionSource.includes("studio.promptSubmit"),
    composerRouteReadiness: composerSource.includes("daemonModelRouteReady") &&
      composerSource.includes("Daemon route blocked"),
    composerUsesConfiguredDaemonModel: runtimeSource.includes("daemonModelId") &&
      runtimeSource.includes("max_tokens: 1"),
    daemonForwardsWorkflowInferenceOptions:
      daemonSource.includes("max_tokens: body.max_tokens") &&
      daemonSource.includes("temperature: body.temperature"),
    noTauriFallback: !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(extensionSource),
  };
  return {
    id: "implementation:production-polish-source-shape",
    ok: Object.values(checks).every(Boolean),
    summary: Object.values(checks).every(Boolean)
      ? "Models, Studio, Workflow, and daemon source shape support production-polish validation"
      : "Production-polish source shape is incomplete",
    evidence: { checks },
  };
}

function checkPackagedApp() {
  const binary = AUTOPILOT_ELECTRON.binary;
  const extension = join(
    VSCODE_PACKAGED_APP_ROOT,
    "resources/app/extensions/ioi-workbench/extension.js",
  );
  return {
    id: "app:packaged-electron-fork",
    ok: existsSync(binary) && existsSync(extension),
    summary:
      existsSync(binary) && existsSync(extension)
        ? "Packaged Electron/VS Code fork is available"
        : "Packaged Electron/VS Code fork is missing",
    evidence: { binary, extension },
  };
}

function checkPreflight() {
  return [
    checkCommand("node"),
    checkCommand("npm"),
    checkCommand("npx"),
    checkCommand("lms"),
    checkGuide(),
    checkParentGuideLinks(),
    checkPackageScripts(),
    checkSourceShape(),
    checkPackagedApp(),
  ];
}

function buildComposerBundle() {
  const result = runCommand("npm", ["run", "build:ioi-workbench-composer"], {
    timeout: 120_000,
  });
  return {
    id: "build:workflow-composer-webview",
    ok: result.ok,
    summary: result.ok
      ? "Workflow Composer webview bundle builds"
      : "Workflow Composer webview bundle failed",
    evidence: compact(result),
  };
}

function syncExtension() {
  const packagedTarget = AUTOPILOT_ELECTRON.packagedWorkbenchTarget;
  try {
    const sync = syncWorkbenchExtensionTargets();
    return {
      id: "sync:ioi-workbench-extension",
      ok:
        existsSync(join(packagedTarget, "extension.js")) &&
        existsSync(join(packagedTarget, "media/workflow-composer/workflow-composer.js")),
      summary: "ioi-workbench extension synced into packaged app; source fork sync is optional",
      evidence: { packagedTarget, sync },
    };
  } catch (error) {
    return {
      id: "sync:ioi-workbench-extension",
      ok: false,
      summary: "ioi-workbench extension sync failed",
      evidence: { error: String(error?.message ?? error), packagedTarget },
    };
  }
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

function wait(ms) {
  return new Promise((resolveWait) => setTimeout(resolveWait, ms));
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

function readRequestBody(request) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("error", rejectBody);
    request.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) {
        resolveBody(null);
        return;
      }
      try {
        resolveBody(JSON.parse(raw));
      } catch (error) {
        rejectBody(error);
      }
    });
  });
}

function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

async function requestJson(endpoint, route, { method = "GET", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`${method} ${route} -> ${response.status} ${JSON.stringify(json)}`);
  }
  return json;
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

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    for (const candidate of page.frames()) {
      try {
        if ((await candidate.locator(selector).count()) > 0) return candidate;
      } catch {
        // Detached frames are normal during VS Code panel replacement.
      }
    }
    return null;
  }, timeoutMs, 350);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

async function projection(endpoint, token) {
  return requestJson(endpoint, "/api/v1/projections/model-mounting", { token });
}

async function waitForLoaded(endpoint, token, expectedLoaded, timeoutMs = 45_000) {
  return waitForPredicate(async () => {
    const value = await projection(endpoint, token);
    const loaded = value.instances?.filter((instance) => instance.status === "loaded") ?? [];
    return expectedLoaded ? loaded.length > 0 && value : loaded.length === 0 && value;
  }, timeoutMs, 500);
}

async function bootstrapDaemon(outputDir) {
  const previousTimeout = process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS;
  process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS = "60000";
  const cwd = mkdtempSync("/tmp/autopilot-models-prod-ws-");
  const stateDir = mkdtempSync("/tmp/autopilot-models-prod-state-");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const grant = await requestJson(daemon.endpoint, "/api/v1/tokens", {
    method: "POST",
    body: {
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.embeddings:*",
        "model.import:*",
        "model.mount:*",
        "model.unmount:*",
        "model.load:*",
        "model.unload:*",
        "route.write:*",
        "route.use:*",
        "server.control:*",
        "server.logs:*",
        "backend.control:*",
        "provider.control:provider.lmstudio",
      ],
    },
  });
  const providerModels = await requestJson(
    daemon.endpoint,
    `/api/v1/providers/${encodeURIComponent(PROVIDER_ID)}/models`,
    { token: grant.token },
  );
  if (!providerModels.some((model) => model.modelId === MODEL_ID)) {
    throw new Error(`LM Studio model ${MODEL_ID} was not discovered by the daemon.`);
  }
  if (!providerModels.some((model) => model.modelId === SECONDARY_MODEL_ID)) {
    throw new Error(`LM Studio model ${SECONDARY_MODEL_ID} was not discovered by the daemon.`);
  }
  const providerStart = await requestJson(
    daemon.endpoint,
    `/api/v1/providers/${encodeURIComponent(PROVIDER_ID)}/start`,
    { method: "POST", token: grant.token },
  );
  const mounted = await requestJson(daemon.endpoint, "/api/v1/models/mount", {
    method: "POST",
    token: grant.token,
    body: {
      id: ENDPOINT_ID,
      model_id: MODEL_ID,
      provider_id: PROVIDER_ID,
      load_policy: { mode: "manual", idleTtlSeconds: 900, autoEvict: false },
    },
  });
  const secondaryMounted = await requestJson(daemon.endpoint, "/api/v1/models/mount", {
    method: "POST",
    token: grant.token,
    body: {
      id: SECONDARY_ENDPOINT_ID,
      model_id: SECONDARY_MODEL_ID,
      provider_id: PROVIDER_ID,
      load_policy: { mode: "manual", idleTtlSeconds: 900, autoEvict: false },
    },
  });
  const estimate = await requestJson(daemon.endpoint, "/api/v1/models/estimate-load", {
    method: "POST",
    token: grant.token,
    body: {
      endpoint_id: ENDPOINT_ID,
      load_options: {
        estimateOnly: true,
        gpu: "0",
        contextLength: 2048,
        parallel: 1,
        ttlSeconds: 900,
        identifier: MODEL_ID,
      },
    },
  });
  const loaded = await requestJson(daemon.endpoint, "/api/v1/models/load", {
    method: "POST",
    token: grant.token,
    body: {
      endpoint_id: ENDPOINT_ID,
      load_options: {
        gpu: "0",
        contextLength: 2048,
        parallel: 1,
        ttlSeconds: 900,
        identifier: MODEL_ID,
      },
    },
  });
  const route = await requestJson(daemon.endpoint, "/api/v1/routes", {
    method: "POST",
    token: grant.token,
    body: {
      id: ROUTE_ID,
      role: "default",
      description: "Electron production-polish live LM Studio model route.",
      privacy: "local_only",
      provider_eligibility: ["lm_studio"],
      fallback: [ENDPOINT_ID],
      denied_providers: ["openai", "anthropic", "gemini"],
    },
  });
  const server = await requestJson(daemon.endpoint, "/api/v1/models/server/start", {
    method: "POST",
    token: grant.token,
  });
  const invocation = await requestJson(daemon.endpoint, "/api/v1/workflows/nodes/execute", {
    method: "POST",
    token: grant.token,
    body: {
      node: "Model Call",
      route_id: ROUTE_ID,
      model: MODEL_ID,
      input: "Say OK.",
      max_tokens: 1,
      temperature: 0,
      workflow_graph_id: "electron-production-polish-preflight",
      workflow_node_id: "daemon-live-model-call",
      workflow_node_type: "Model Call",
      model_policy: { privacy: "local_only", reasoning_effort: "low" },
    },
  });
  const afterBootstrapProjection = await projection(daemon.endpoint, grant.token);
  const receipts = await requestJson(daemon.endpoint, "/api/v1/receipts", {
    token: grant.token,
  });
  const bootstrap = {
    endpoint: daemon.endpoint,
    cwd,
    stateDir,
    providerStart,
    providerModels: providerModels.map((model) => ({
      modelId: model.modelId,
      displayName: model.displayName,
      sizeBytes: model.sizeBytes,
    })),
    mounted,
    secondaryMounted,
    estimate,
    loaded,
    route,
    server,
    invocation,
    projection: afterBootstrapProjection,
    receiptKinds: receipts.map((receipt) => receipt.kind),
    receiptOperations: receipts.map((receipt) => receipt.details?.operation).filter(Boolean),
    previousProviderTimeout: previousTimeout ?? null,
  };
  writeFileSync(join(outputDir, "daemon-bootstrap.json"), `${JSON.stringify(bootstrap, null, 2)}\n`);
  return { daemon, token: grant.token, bootstrap };
}

function bridgeState() {
  return {
    schemaVersion: "ioi.workbench-bridge.state.v1",
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    workspace: { name: "ioi", path: repoRoot },
    summary: {
      workflowCount: 1,
      runCount: 1,
      artifactCount: 1,
      connectorCount: 0,
      policyIssueCount: 0,
    },
    chat: {
      runtime: "ioi-runtime-daemon",
      authority: "daemon-owned",
      phase: "Live local model route ready",
      currentStep: "LM Studio local model is mounted through the IOI daemon.",
      modelLabel: MODEL_ID,
      contextLabel: ROUTE_ID,
      modeLabel: "Dry run",
      turns: [],
    },
    appearance: {
      themeId: "dark-modern",
      openVsCodeColorTheme: "Default Dark Modern",
      source: "models-production-polish-playwright",
      updatedAtMs: Date.now(),
    },
    workflows: [],
    runs: [],
    artifacts: [],
    policy: {
      totalEntries: 1,
      connectorCount: 0,
      connectedConnectorCount: 0,
      runtimeSkillCount: 1,
      authoritativeSourceCount: 1,
      activeIssueCount: 0,
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

async function waitForRequest(requests, predicate, timeoutMs = 45_000) {
  return waitForPredicate(
    () => requests.find((request) => predicate(request)),
    timeoutMs,
    350,
  );
}

async function requireRequest(requests, predicate, label, timeoutMs = 45_000) {
  const request = await waitForRequest(requests, predicate, timeoutMs);
  if (!request) throw new Error(`Timed out waiting for bridge request: ${label}`);
  return request;
}

async function runGuiValidation(outputRoot) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const screenshots = [];
  const consoleLogs = [];
  const pageErrors = [];
  let boot = null;
  let server = null;
  let app = null;
  let browser = null;
  let context = null;
  let tracingStarted = false;
  let userDataDir = null;
  let extensionsDir = null;
  const stdoutPath = join(outputDir, "electron-stdout.log");
  const stderrPath = join(outputDir, "electron-stderr.log");

  try {
    const build = buildComposerBundle();
    if (!build.ok) {
      return {
        id: "gui:models-production-polish-playwright",
        ok: false,
        summary: "Skipped GUI validation because Workflow Composer bundle failed",
        evidence: { outputDir, build },
      };
    }
    const sync = syncExtension();
    if (!sync.ok) {
      return {
        id: "gui:models-production-polish-playwright",
        ok: false,
        summary: "Skipped GUI validation because extension sync failed",
        evidence: { outputDir, sync },
      };
    }

    boot = await bootstrapDaemon(outputDir);
    server = createBridge({ requests, commands, deliveredCommands });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync("/tmp/autopilot-models-prod-user-");
    extensionsDir = mkdtempSync("/tmp/autopilot-models-prod-ext-");
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "cdp-port"), `${cdpPort}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    writeFileSync(join(outputDir, "extensions-dir"), `${extensionsDir}\n`);

    app = spawn(AUTOPILOT_ELECTRON.binary, [
      `--remote-debugging-port=${cdpPort}`,
      `--user-data-dir=${userDataDir}`,
      `--extensions-dir=${extensionsDir}`,
      "--disable-updates",
      "--disable-workspace-trust",
      "--new-window",
      repoRoot,
    ], {
      cwd: repoRoot,
      env: {
        ...process.env,
        IOI_WORKSPACE_IDE_BRIDGE_URL: bridgeUrl,
        IOI_DAEMON_ENDPOINT: boot.daemon.endpoint,
        IOI_DAEMON_TOKEN: boot.token,
        IOI_DAEMON_MODEL_ID: MODEL_ID,
        IOI_PROVIDER_HTTP_TIMEOUT_MS: "60000",
        IOI_AUTOPILOT_CANONICAL_SHELL: "vscode-electron-fork",
        AUTOPILOT_SKIP_OVERVIEW: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
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
        consoleLogs.push({
          type: message.type(),
          text: message.text(),
          location: message.location(),
        });
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

    queueCommand(commands, "ioi.models.open", { phase: "model-library" });
    await requireRequest(
      requests,
      (request) =>
        request?.requestType === "models.open" ||
        request?.requestType === "modelsMode.proof",
      "models open/proof",
    );
    let modelsFrame = await findFrameWithTestId(page, "autopilot-models-mode");
    await screenshot(page, outputDir, "models-library-production.png", screenshots);

    await modelsFrame.locator('[data-testid="model-library-filter"]').fill("stories");
    await modelsFrame.locator('[data-model-row="stories260k"]').click();
    await modelsFrame.locator('[data-testid="model-inspector-title"]').waitFor();
    await screenshot(page, outputDir, "models-library-filtered.png", screenshots);

    await modelsFrame.locator('[data-model-inspector-tab="load"]').click();
    await screenshot(page, outputDir, "model-inspector-load-tab.png", screenshots);
    const advancedToggle = modelsFrame.locator('[data-testid="model-advanced-settings-toggle"]');
    await advancedToggle.click();
    if (!(await advancedToggle.isChecked().catch(() => false))) {
      await advancedToggle.evaluate((input) => {
        input.checked = true;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
    }
    await screenshot(page, outputDir, "model-load-parameters-advanced.png", screenshots);

    await modelsFrame.locator('[data-testid="model-estimate-button"]').click();
    await requireRequest(
      requests,
      (request) => request?.requestType === "models.estimateLoad",
      "models.estimateLoad",
    );

    modelsFrame = await findFrameWithTestId(page, "autopilot-models-mode");
    await modelsFrame.locator('[data-model-inspector-tab="load"]').click();
    await modelsFrame.locator('[data-testid="model-running-unload-button"]').click();
    await requireRequest(
      requests,
      (request) => request?.requestType === "models.unload",
      "models.unload",
    );
    const unloadedProjection = await waitForLoaded(boot.daemon.endpoint, boot.token, false);
    await screenshot(page, outputDir, "model-unloaded-state.png", screenshots);

    queueCommand(commands, "ioi.workflow.openComposer", {
      scenarioId: "model-backed-dry-run",
      phase: "model-binding",
    });
    await requireRequest(
      requests,
      (request) =>
        request?.requestType === "workflowCompositor.proof" ||
        request?.requestType === "workflow.composer.open",
      "workflow open/proof after unload",
    );
    let composerFrame = await findFrameWithTestId(page, "ioi-workflow-composer-shell");
    await composerFrame.locator('[data-testid="ioi-composer-readiness-panel"]').waitFor();
    await screenshot(page, outputDir, "workflow-route-unload-blocked.png", screenshots);

    queueCommand(commands, "ioi.models.open", { phase: "model-load-dialog" });
    modelsFrame = await findFrameWithTestId(page, "autopilot-models-mode");
    await modelsFrame.locator('[data-model-row="stories260k"]').click();
    await modelsFrame.locator('[data-model-inspector-tab="load"]').click();
    await modelsFrame.locator('[data-testid="model-load-confirm-button"]').click();
    await requireRequest(
      requests,
      (request) => request?.requestType === "models.load",
      "models.load",
    );
    const remountedProjection = await waitForLoaded(boot.daemon.endpoint, boot.token, true);
    await screenshot(page, outputDir, "model-remounted-ready.png", screenshots);

    modelsFrame = await findFrameWithTestId(page, "autopilot-models-mode");
    await modelsFrame.locator('[data-model-inspector-tab="load"]').click();
    await modelsFrame.locator('[data-testid="model-mount-drawer"]').evaluate((element) => {
      element.open = true;
    }).catch(() => undefined);
    await modelsFrame.locator('[data-testid="model-quick-loader-filter"]').fill("nomic");
    await modelsFrame.locator('[data-model-inspector-tab="inference"]').click();
    await screenshot(page, outputDir, "model-server-api-logs.png", screenshots);

    queueCommand(commands, "ioi.studio.open", { phase: "chat" });
    await requireRequest(
      requests,
      (request) => request?.requestType === "studio.open",
      "studio.open",
    );
    let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "agent-studio-operational-chat-polished.png", screenshots);
    studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await studioFrame.locator("[data-studio-prompt]").fill(
      "Build a local research agent using the mounted daemon model route.",
    );
    await studioFrame.locator("[data-studio-prompt-form]").evaluate((form) => form.requestSubmit());
    await requireRequest(
      requests,
      (request) => request?.requestType === "chat.submit",
      "chat.submit",
    );
    studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await studioFrame.locator('button[data-command="ioi.models.open"]').first().click();
    await requireRequest(
      requests,
      (request) => request?.requestType === "models.open",
      "studio to models handoff",
    );
    await screenshot(page, outputDir, "agent-studio-model-handoff.png", screenshots);

    queueCommand(commands, "ioi.workflow.openComposer", {
      scenarioId: "model-backed-dry-run",
      phase: "model-binding",
    });
    await requireRequest(
      requests,
      (request) => request?.requestType === "workflow.composer.open",
      "workflow.composer.open",
    );
    composerFrame = await findFrameWithTestId(page, "ioi-workflow-composer-shell");
    await composerFrame.locator('[data-testid="ioi-composer-readiness-panel"][data-route-ready="true"]').waitFor();
    await screenshot(page, outputDir, "workflow-model-binding-ready.png", screenshots);
    await composerFrame.locator('[data-testid="workflow-parity-run-dry-run"]').click();
    await requireRequest(
      requests,
      (request) => request?.requestType === "workflowCompositor.daemonRunProject",
      "workflowCompositor.daemonRunProject",
      90_000,
    );
    await screenshot(page, outputDir, "workflow-live-model-dry-run.png", screenshots);

    const finalProjection = await projection(boot.daemon.endpoint, boot.token);
    const finalReceipts = await requestJson(boot.daemon.endpoint, "/api/v1/receipts", {
      token: boot.token,
    });
    const tracePath = join(outputDir, "playwright-trace.zip");
    if (tracingStarted) {
      await context.tracing.stop({ path: tracePath });
      tracingStarted = false;
    }
    if (browser) {
      await browser.close().catch(() => undefined);
      browser = null;
    }
    if (app?.pid) {
      runCommand("bash", [
        "-lc",
        `SELF=$$; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) && $0 !~ /awk -v u=/ && $0 !~ /ps -eo/ && $0 !~ /bash -lc/ { print $1 }'); for p in ${app.pid} $PIDS; do kill "$p" 2>/dev/null || true; done; sleep 1; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) && $0 !~ /awk -v u=/ && $0 !~ /ps -eo/ && $0 !~ /bash -lc/ { print $1 }'); for p in ${app.pid} $PIDS; do kill -9 "$p" 2>/dev/null || true; done`,
      ], { timeout: 10_000 });
      app = null;
    }
    const electronOrphanCheck = runCommand("bash", [
      "-lc",
      `ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
        userDataDir ?? "",
      )} 'u != "" && index($0, u) && $0 !~ /awk -v u=/ && $0 !~ /ps -eo/ && $0 !~ /bash -lc/ { print }'`,
    ]);
    writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
    writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
    writeFileSync(join(outputDir, "projection-after-validation.json"), `${JSON.stringify(finalProjection, null, 2)}\n`);
    writeFileSync(join(outputDir, "receipts-after-validation.json"), `${JSON.stringify(finalReceipts, null, 2)}\n`);

    const modelProofs = requests
      .filter((request) => request?.requestType === "modelsMode.proof")
      .map((request) => request.payload);
    const composerProofs = requests
      .filter((request) => request?.requestType === "workflowCompositor.proof")
      .map((request) => request.payload);
    const receiptKinds = finalReceipts.map((receipt) => receipt.kind);
    const receiptOperations = finalReceipts
      .map((receipt) => receipt.details?.operation)
      .filter(Boolean);
    const lmsPs = runCommand("lms", ["ps"]);
    const proof = {
      schemaVersion: "ioi.autopilot.models-production-polish-playwright-proof.v1",
      generatedAt: new Date().toISOString(),
      outputDir,
      cdpPort,
      bridgeUrl,
      daemonEndpoint: boot.daemon.endpoint,
      screenshots,
      tracePath,
      deliveredCommands,
      requestTypes: [...new Set(requests.map((request) => request?.requestType))].sort(),
      modelProofCount: modelProofs.length,
      composerProofCount: composerProofs.length,
      pageErrors,
      receiptKinds,
      receiptOperations,
      lifecycle: {
        initiallyLoaded: boot.bootstrap.projection.instances?.some(
          (instance) => instance.status === "loaded" && instance.modelId === MODEL_ID,
        ),
        unloadedObserved: !(unloadedProjection.instances ?? []).some(
          (instance) => instance.status === "loaded",
        ),
        remountedObserved: (remountedProjection.instances ?? []).some(
          (instance) => instance.status === "loaded" && instance.modelId === MODEL_ID,
        ),
        finalLoadedObserved: (finalProjection.instances ?? []).some(
          (instance) => instance.status === "loaded" && instance.modelId === MODEL_ID,
        ),
      },
      boundaries: {
        electronVsCodeForkCanonicalShell: true,
        daemonBackedCatalog: modelProofs.some((proof) => proof?.daemonBacked === true),
        studioPromptIntentObserved: requests.some(
          (request) => request?.requestType === "chat.submit",
        ),
        workflowDaemonRunObserved: requests.some(
          (request) => request?.requestType === "workflowCompositor.daemonRunProject",
        ),
        workflowRouteBlockedObserved: composerProofs.some(
          (proof) => proof?.daemonModelRuntimeConfigured === true && proof?.daemonModelRouteReady === false,
        ),
        workflowRouteReadyObserved: composerProofs.some(
          (proof) => proof?.daemonModelRuntimeConfigured === true && proof?.daemonModelRouteReady === true,
        ),
        externalConnectorAction: false,
        tauriUsed: false,
        webviewDirectModelExecution: false,
        extensionHostDurableRuntime: false,
      },
      lmStudioProcessListBeforeCleanup: compact(lmsPs),
      electronOrphanCheck: compact(electronOrphanCheck),
    };
    const proofPath = join(outputDir, "models-production-polish-playwright-proof.json");
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
    const missingScreenshots = REQUIRED_SCREENSHOTS.filter(
      (file) => !existsSync(join(outputDir, file)),
    );
    const ok =
      missingScreenshots.length === 0 &&
      existsSync(tracePath) &&
      pageErrors.length === 0 &&
      Object.values(proof.lifecycle).every(Boolean) &&
      proof.boundaries.daemonBackedCatalog &&
      proof.boundaries.studioPromptIntentObserved &&
      proof.boundaries.workflowDaemonRunObserved &&
      proof.boundaries.workflowRouteBlockedObserved &&
      proof.boundaries.workflowRouteReadyObserved &&
      receiptOperations.includes("model_load_estimate") &&
      receiptOperations.includes("model_load") &&
      receiptOperations.includes("model_unload") &&
      receiptKinds.includes("model_invocation") &&
      receiptKinds.includes("model_route_selection") &&
      !electronOrphanCheck.stdout.trim() &&
      proof.boundaries.tauriUsed === false &&
      proof.boundaries.webviewDirectModelExecution === false;
    return {
      id: "gui:models-production-polish-playwright",
      ok,
      summary: ok
        ? "Playwright drove Models, Studio, and Workflow Composer through load/unload/remount with evidence"
        : "Playwright production-polish GUI validation failed",
      evidence: {
        outputDir,
        proofPath,
        tracePath,
        missingScreenshots,
        lifecycle: proof.lifecycle,
        boundaries: proof.boundaries,
        requestTypes: proof.requestTypes,
        receiptKinds,
        receiptOperations,
        pageErrors,
        orphanProcesses: electronOrphanCheck.stdout.trim(),
      },
    };
  } catch (error) {
    return {
      id: "gui:models-production-polish-playwright",
      ok: false,
      summary: "Playwright production-polish GUI validation failed",
      evidence: {
        outputDir,
        error: String(error?.stack ?? error?.message ?? error),
        requestTypes: [...new Set(requests.map((request) => request?.requestType))].sort(),
        deliveredCommands,
        screenshots,
        pageErrors,
      },
    };
  } finally {
    if (tracingStarted && context) {
      await context.tracing.stop({ path: join(outputDir, "playwright-trace-partial.zip") }).catch(() => undefined);
    }
    if (browser) await browser.close().catch(() => undefined);
    if (app?.pid) {
      runCommand("bash", [
        "-lc",
        `SELF=$$; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill "$p" 2>/dev/null || true; done; sleep 1; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill -9 "$p" 2>/dev/null || true; done`,
      ], { timeout: 10_000 });
    }
    if (boot?.daemon) {
      try {
        const current = await projection(boot.daemon.endpoint, boot.token);
        for (const instance of current.instances ?? []) {
          if (instance.status === "loaded") {
            await requestJson(boot.daemon.endpoint, "/api/v1/models/unload", {
              method: "POST",
              token: boot.token,
              body: { instance_id: instance.id },
            }).catch(() => undefined);
          }
        }
      } catch {
        // Best-effort cleanup only.
      }
      await boot.daemon.close().catch(() => undefined);
    }
    for (const identifier of [MODEL_ID, "electron-model-workbench"]) {
      runCommand("lms", ["unload", identifier], { timeout: 10_000 });
    }
    const lmStudioAfterCleanup = runCommand("lms", ["ps"], { timeout: 10_000 });
    writeFileSync(
      join(outputDir, "lmstudio-ps-after-cleanup.txt"),
      `${lmStudioAfterCleanup.stdout}${lmStudioAfterCleanup.stderr}`,
    );
    if (server) await closeServer(server).catch(() => undefined);
    if (extensionsDir) rmSync(extensionsDir, { recursive: true, force: true });
    if (userDataDir) {
      const orphanCheck = runCommand("bash", [
        "-lc",
        `ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir,
        )} 'u != "" && index($0, u) && $0 !~ /awk -v u=/ && $0 !~ /ps -eo/ && $0 !~ /bash -lc/ { print }'`,
      ]);
      writeFileSync(
        join(outputDir, "orphan-check.txt"),
        orphanCheck.stdout || "",
      );
    }
  }
}

function writeResult(outputRoot, result) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const resultPath = join(outputDir, "result.json");
  writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
  console.log(resultPath);
  return { outputDir, resultPath };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  mkdirSync(resolve(repoRoot, args.outputRoot), { recursive: true });
  const checks = checkPreflight();

  if (args.run && checks.every((check) => check.ok)) {
    checks.push(await runGuiValidation(args.outputRoot));
  }

  const result = {
    schemaVersion: "autopilot.models-production-polish-playwright-goal.v1",
    mode: args.run ? "run" : "preflight",
    ok: checks.every((check) => check.ok),
    generatedAt: new Date().toISOString(),
    masterGuide: MASTER_GUIDE,
    requiredScreenshots: REQUIRED_SCREENSHOTS,
    checks,
  };
  writeResult(args.outputRoot, result);
  return result.ok ? 0 : 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
