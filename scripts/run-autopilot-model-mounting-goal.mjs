#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import {
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchExtensionTargets,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const MASTER_GUIDE =
  ".internal/plans/autopilot-electron-model-mounting-daemon-runtime-adapter-master-guide.md";
const OUTPUT_ROOT =
  "docs/evidence/autopilot-electron-model-mounting-daemon-runtime-adapter";
const EXTENSION_ROOT =
  "workbench-adapters/ioi-workbench";
const VSCODE_PACKAGED_APP_ROOT = HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedRoot;
const MODEL_ID = "native:electron-gui-model";
const ENDPOINT_ID = "endpoint.electron.model-gui";
const ROUTE_ID = "route.native-local";

const MODEL_SCREENSHOTS = [
  { file: "model-library.png", phase: "model-library", selector: "modelLibrary" },
  { file: "model-mount-drawer.png", phase: "model-mount-drawer", selector: "mountDrawer" },
  { file: "model-runtime-backend.png", phase: "model-runtime-backend", selector: "runtimeBackend" },
  { file: "model-load-estimate.png", phase: "model-load-estimate", selector: "loadEstimate" },
  { file: "model-load-progress.png", phase: "model-load-progress", selector: "loadProgress" },
  { file: "model-instance-ready.png", phase: "model-instance-ready", selector: "instanceReady" },
  { file: "model-server-api.png", phase: "model-server-api", selector: "serverApi" },
  {
    file: "model-invocation-receipts-replay.png",
    phase: "model-invocation-receipts-replay",
    selector: "receiptsReplay",
  },
  {
    file: "model-library-lmstudio-layout.png",
    phase: "model-library",
    selector: "libraryTable",
  },
  {
    file: "model-selected-inspector-info.png",
    phase: "model-selected-inspector",
    selector: "selectedInspector",
  },
  {
    file: "model-selected-inspector-load.png",
    phase: "model-inspector-load-panel",
    selector: "selectedInspector",
  },
  {
    file: "model-quick-loader.png",
    phase: "model-mount-drawer",
    selector: "quickLoaderPopover",
  },
  {
    file: "model-load-dialog.png",
    phase: "model-load-dialog",
    selector: "loadDialog",
  },
  {
    file: "model-discover-download.png",
    phase: "model-discover-view",
    selector: "discoverView",
  },
  {
    file: "model-catalog-sources.png",
    phase: "model-catalog-sources-surface",
    selector: "sourcesView",
  },
  {
    file: "model-running-instance.png",
    phase: "model-instance-ready",
    selector: "instanceReady",
  },
  {
    file: "model-server-logs.png",
    phase: "model-server-api",
    selector: "serverLogs",
  },
  {
    file: "model-receipts-replay-linked.png",
    phase: "model-invocation-receipts-replay",
    selector: "receiptsReplay",
  },
];

const WORKFLOW_SCREENSHOTS = [
  {
    file: "workflow-node-live-model-binding.png",
    scenarioId: "model-backed-dry-run",
    phase: "model-binding",
  },
  {
    file: "workflow-model-loader-binding.png",
    scenarioId: "model-backed-dry-run",
    phase: "model-binding",
  },
  {
    file: "workflow-live-model-dry-run-timeline.png",
    scenarioId: "model-backed-dry-run",
    phase: "run-timeline",
  },
];

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  const args = {
    preflight: false,
    run: false,
    outputRoot: OUTPUT_ROOT,
  };
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

function runCommand(command, options = {}) {
  const startedAtMs = Date.now();
  const result = spawnSync("bash", ["-lc", command], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  return {
    command,
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
    stdoutTail: result.stdout.slice(-3000),
    stderrTail: result.stderr.slice(-3000),
  };
}

function read(path) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    return { __readError: String(error?.message ?? error) };
  }
}

function checkCommand(name) {
  const result = runCommand(`command -v ${name}`);
  return {
    id: `command:${name}`,
    ok: result.ok,
    summary: result.ok ? `${name} is available` : `${name} is missing`,
    evidence: compact(result),
  };
}

function checkMasterGuide() {
  const guidePath = join(repoRoot, MASTER_GUIDE);
  const content = read(guidePath);
  const required = [
    "Observed LM Studio Reference Notes",
    "Workflow Composer De-Fixturing",
    "npm run goal:hypervisor-model-mounting",
    "Connector-specific sprint entry criteria",
  ];
  const missing = required.filter((phrase) => !content.includes(phrase));
  return {
    id: "master-guide:model-mounting-daemon-runtime-adapter",
    ok: existsSync(guidePath) && missing.length === 0,
    summary:
      existsSync(guidePath) && missing.length === 0
        ? "Model mounting master guide is present"
        : "Model mounting master guide is missing required canon",
    evidence: { path: MASTER_GUIDE, missing },
  };
}

function checkPackageScripts() {
  const packageJson = readJson(join(repoRoot, "package.json"));
  const required = [
    "goal:hypervisor-model-mounting",
    "goal:hypervisor-model-mounting:run",
    "goal:hypervisor-workflow-compositor-parity",
    "goal:hypervisor-workflow-compositor-parity:run",
  ];
  const missing = required.filter((script) => !packageJson.scripts?.[script]);
  const wired = required
    .filter((script) => script.includes("model-mounting"))
    .every((script) =>
      packageJson.scripts?.[script]?.includes(
        "scripts/run-autopilot-model-mounting-goal.mjs",
      ),
    );
  return {
    id: "package:model-mounting-scripts",
    ok: missing.length === 0 && wired,
    summary:
      missing.length === 0 && wired
        ? "Model mounting goal scripts are wired"
        : "Model mounting goal scripts are missing",
    evidence: { missing, wired },
  };
}

function checkReferenceEvidence() {
  const required = [
    "docs/evidence/autopilot-electron-model-mounting-lm-studio-reference/2026-05-20T20-49-22-811Z-playwright-ui-nav/02-model-loader-opened.png",
    "docs/evidence/autopilot-electron-model-mounting-lm-studio-reference/2026-05-20T20-49-22-811Z-playwright-ui-nav/05-left-nav-discover-or-models.png",
    "docs/evidence/autopilot-electron-model-mounting-lm-studio-reference/2026-05-20T20-52-34-379Z-playwright-load-params-click/05-developer-surface-after-load-attempt.png",
  ];
  const missing = required.filter((file) => !existsSync(join(repoRoot, file)));
  return {
    id: "reference:lm-studio-observed-surfaces",
    ok: missing.length === 0,
    summary:
      missing.length === 0
        ? "Observed LM Studio reference screenshots are available"
        : "Observed LM Studio reference evidence is missing",
    evidence: { required, missing },
  };
}

function checkWorkbenchImplementation() {
  const extensionSource = read(join(repoRoot, EXTENSION_ROOT, "extension.js"));
  const manifest = readJson(join(repoRoot, EXTENSION_ROOT, "package.json"));
  const composerSource = read(
    join(repoRoot, EXTENSION_ROOT, "webview/workflow-composer/main.tsx"),
  );
  const runtimeSource = read(
    join(repoRoot, EXTENSION_ROOT, "webview/workflow-composer/fixtureRuntime.ts"),
  );
  const scenarioSource = read(
    join(repoRoot, EXTENSION_ROOT, "webview/workflow-composer/fixtureWorkflows.ts"),
  );
  const commands = JSON.stringify(manifest.contributes?.commands ?? []);
  const views = JSON.stringify(manifest.contributes?.views ?? {});
  const activityContainers = manifest.contributes?.viewsContainers?.activitybar ?? [];
  const checks = {
    genericIoiActivityContainerRemoved: !activityContainers.some(
      (container) => container.id === "ioi",
    ),
    dedicatedActivityBarContainers:
      activityContainers.some(
        (container) =>
          container.id === "ioi-studio" &&
          container.icon === "$(sparkle)",
      ) &&
      activityContainers.some(
        (container) =>
          container.id === "ioi-workflows" &&
          container.icon === "media/ioi-workflows.svg",
      ) &&
      activityContainers.some(
        (container) =>
          container.id === "ioi-models" &&
          container.icon === "media/ioi-models.svg",
      ),
    dedicatedActivityBarIcons:
      existsSync(join(repoRoot, EXTENSION_ROOT, "media/ioi-workflows.svg")) &&
      existsSync(join(repoRoot, EXTENSION_ROOT, "media/ioi-models.svg")) &&
      JSON.stringify(activityContainers).includes('"$(sparkle)"'),
    studioModeView: views.includes("ioi.studio"),
    modelsModeView: views.includes("ioi.models"),
    workflowsModeView: views.includes("ioi.workflows"),
    modelsOpenCommand: commands.includes("ioi.models.open"),
    modelSections:
      extensionSource.includes('data-testid="model-library"') &&
      extensionSource.includes('data-testid="model-mount-drawer"') &&
      extensionSource.includes('data-testid="model-server-api"'),
    daemonEndpointProjected: extensionSource.includes("IOI_DAEMON_ENDPOINT"),
    modelProofs: extensionSource.includes("modelsMode.proof"),
    composerDaemonCatalog: runtimeSource.includes("workflowCompositor.daemonModelCatalog"),
    composerDaemonRun: runtimeSource.includes("workflowCompositor.daemonRunProject"),
    composerModelScenario: scenarioSource.includes("model-backed-dry-run"),
    composerDaemonProof: composerSource.includes("daemonModelRuntimeConfigured"),
    noTauriFallback: !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(
      `${extensionSource}\n${composerSource}\n${runtimeSource}`,
    ),
  };
  return {
    id: "ioi-workbench:models-mode-and-daemon-adapter",
    ok: Object.values(checks).every(Boolean),
    summary: Object.values(checks).every(Boolean)
      ? "Workbench exposes Models mode and daemon-backed composer adapter"
      : "Workbench model mounting implementation is incomplete",
    evidence: { checks },
  };
}

function checkDaemonRouteImplementation() {
  const publicRoutes = read(join(repoRoot, "packages/runtime-daemon/src/http/public-runtime-routes.mjs"));
  const requiredPublic = [
    'url.pathname === "/v1/models/artifacts"',
    'url.pathname === "/v1/model-capabilities"',
    'url.pathname === "/v1/models/catalog/search"',
    'url.pathname === "/v1/model-mount/server/status"',
    'url.pathname === "/v1/model-mount/runtime/engines"',
    'url.pathname === "/v1/model-mount/runtime/survey"',
    'url.pathname === "/v1/model-mount/runtime/select"',
    'url.pathname === "/v1/model-mount/routes"',
    'url.pathname === "/v1/model-mount/catalog/import-url"',
    'url.pathname === "/v1/model-mount/artifacts/import"',
    'url.pathname === "/v1/model-mount/endpoints"',
    'url.pathname === "/v1/model-mount/downloads"',
    'url.pathname === "/v1/model-mount/storage/cleanup"',
    'url.pathname === "/v1/model-mount/instances/load"',
    'url.pathname === "/v1/model-mount/instances/unload"',
    'url.pathname === "/v1/model-mount/backends"',
    'url.pathname === "/v1/model-mount/authority"',
    'url.pathname === "/v1/model-mount/server/start"',
    'url.pathname === "/v1/model-mount/server/stop"',
    'segments[2] === "backends"',
    'segments[4] === "health"',
    'segments[4] === "start"',
    'segments[4] === "stop"',
    'segments[2] === "routes"',
    'segments[2] === "artifacts"',
    'segments[2] === "downloads"',
    'segments[2] === "endpoints"',
    'segments[2] === "instances"',
    'segments[5] === "select"',
  ];
  const missing = [
    ...requiredPublic.filter((phrase) => !publicRoutes.includes(phrase)),
  ];
  return {
    id: "daemon:model-mounting-workbench-routes",
    ok: missing.length === 0,
    summary:
      missing.length === 0
        ? "Daemon exposes stable model read, lifecycle, and control routes"
        : "Daemon model mounting route aliases are incomplete",
    evidence: { missing },
  };
}

function checkTauriNotTargeted() {
  const extensionSource = read(join(repoRoot, EXTENSION_ROOT, "extension.js"));
  const composerSource = read(
    join(repoRoot, EXTENSION_ROOT, "webview/workflow-composer/main.tsx"),
  );
  const runtimeSource = read(
    join(repoRoot, EXTENSION_ROOT, "webview/workflow-composer/fixtureRuntime.ts"),
  );
  return {
    id: "tauri:not-revived",
    ok: !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(
      `${extensionSource}\n${composerSource}\n${runtimeSource}`,
    ),
    summary: "Tauri is not referenced by the Electron model mounting target path",
    evidence: {
      checkedPaths: [
        `${EXTENSION_ROOT}/extension.js`,
        `${EXTENSION_ROOT}/webview/workflow-composer/main.tsx`,
        `${EXTENSION_ROOT}/webview/workflow-composer/fixtureRuntime.ts`,
      ],
    },
  };
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

async function bootstrapDaemonModelRuntime(outputDir = null) {
  const cwd = mkdtempSync("/tmp/autopilot-model-workspace-");
  const stateDir = mkdtempSync("/tmp/autopilot-model-state-");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const grant = await requestJson(daemon.endpoint, "/v1/model-mount/tokens", {
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
        "route.use:*",
        "server.control:*",
        "server.logs:*",
        "backend.control:*",
      ],
    },
  });
  const modelPath = join(cwd, "electron-gui-model.Q4_K_M.gguf");
  writeFileSync(
    modelPath,
    [
      "family=electron-gui",
      "quantization=Q4_K_M",
      "format=gguf",
      "context=4096",
      "fixture bytes for daemon-backed Electron model mounting validation",
    ].join("\n"),
  );
  const imported = await requestJson(daemon.endpoint, "/v1/model-mount/artifacts/import", {
    method: "POST",
    token: grant.token,
    body: {
      id: "import.electron-gui-model",
      model_id: MODEL_ID,
      provider_id: "provider.autopilot.local",
      path: modelPath,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "code"],
    },
  });
  const mounted = await requestJson(daemon.endpoint, "/v1/model-mount/endpoints", {
    method: "POST",
    token: grant.token,
    body: {
      id: ENDPOINT_ID,
      model_id: MODEL_ID,
      provider_id: "provider.autopilot.local",
      backend_id: "backend.autopilot.native-local.fixture",
      load_policy: { mode: "on_demand", idle_ttl_seconds: 900, auto_evict: true },
    },
  });
  const estimate = await requestJson(daemon.endpoint, `/v1/model-mount/endpoints/${encodeURIComponent(ENDPOINT_ID)}/load`, {
    method: "POST",
    token: grant.token,
    body: {
      load_options: {
        estimate_only: true,
        gpu: "auto",
        context_length: 4096,
        parallel: 2,
        ttl_seconds: 900,
        identifier: "electron-gui-model-estimate",
      },
    },
  });
  const loaded = await requestJson(
    daemon.endpoint,
    `/v1/model-mount/endpoints/${encodeURIComponent(ENDPOINT_ID)}/load`,
    {
      method: "POST",
      token: grant.token,
      body: {
        id: "instance.electron-gui-model",
        load_options: {
          gpu: "auto",
          context_length: 4096,
          parallel: 2,
          ttl_seconds: 900,
          identifier: "electron-gui-model-live",
        },
      },
    },
  );
  const server = await requestJson(daemon.endpoint, "/v1/model-mount/server/start", {
    method: "POST",
    token: grant.token,
  });
  const invocation = await requestJson(daemon.endpoint, "/v1/model-mount/workflows/nodes/execute", {
    method: "POST",
    token: grant.token,
    body: {
      node: "Model Call",
      route_id: ROUTE_ID,
      model: MODEL_ID,
      input: "Validate Electron model mounting readiness through daemon route.",
      workflow_graph_id: "electron-model-backed-dry-run",
      workflow_node_id: "daemon-model-call",
      workflow_node_type: "Model Call",
      model_policy: { privacy: "local_only", reasoning_effort: "low" },
    },
  });
  const projection = await requestJson(daemon.endpoint, "/v1/model-mount/projection", {
    token: grant.token,
  });
  const receipts = await requestJson(daemon.endpoint, "/v1/model-mount/receipts", {
    token: grant.token,
  });
  const bootstrap = {
    endpoint: daemon.endpoint,
    cwd,
    stateDir,
    imported,
    mounted,
    estimate,
    loaded,
    server,
    invocation,
    projection,
    receiptKinds: receipts.map((receipt) => receipt.kind),
    receiptOperations: receipts.map((receipt) => receipt.details?.operation).filter(Boolean),
  };
  if (outputDir) {
    writeFileSync(join(outputDir, "daemon-bootstrap.json"), `${JSON.stringify(bootstrap, null, 2)}\n`);
  }
  return { daemon, token: grant.token, bootstrap };
}

async function checkDaemonApis() {
  let daemon = null;
  try {
    const boot = await bootstrapDaemonModelRuntime();
    daemon = boot.daemon;
    const projection = boot.bootstrap.projection;
    const checks = {
      artifacts: projection.artifacts?.some((artifact) => artifact.modelId === MODEL_ID),
      endpoint: projection.endpoints?.some((endpoint) => endpoint.id === ENDPOINT_ID),
      instance: projection.instances?.some((instance) => instance.status === "loaded"),
      estimateReceipt: boot.bootstrap.receiptOperations.includes("model_load_estimate"),
      loadReceipt: boot.bootstrap.receiptOperations.includes("model_load"),
      invocationReceipt: boot.bootstrap.receiptKinds.includes("model_invocation"),
      routeReceipt: boot.bootstrap.receiptKinds.includes("model_route_selection"),
    };
    return {
      id: "daemon:live-model-mount-load-invoke",
      ok: Object.values(checks).every(Boolean),
      summary: Object.values(checks).every(Boolean)
        ? "Daemon can import, mount, estimate, load, route, invoke, and receipt a local model"
        : "Daemon live model mounting path is incomplete",
      evidence: { endpoint: boot.daemon.endpoint, checks },
    };
  } catch (error) {
    return {
      id: "daemon:live-model-mount-load-invoke",
      ok: false,
      summary: "Daemon live model mounting path failed",
      evidence: { error: String(error?.message ?? error) },
    };
  } finally {
    if (daemon) await daemon.close();
  }
}

function buildComposerBundle() {
  const result = runCommand(
    "npx vite build --config workbench-adapters/ioi-workbench/vite.workflow-composer.config.ts",
    { timeout: 120_000 },
  );
  return {
    id: "build:workflow-composer-webview",
    ok: result.ok,
    summary: result.ok
      ? "Workflow Composer webview bundle builds"
      : "Workflow Composer webview bundle failed to build",
    evidence: compact(result),
  };
}

function syncExtension() {
  let sync = null;
  let error = null;
  try {
    sync = syncWorkbenchExtensionTargets();
  } catch (caught) {
    error = caught;
  }
  const packagedTarget = HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedWorkbenchTarget;
  return {
    id: "sync:ioi-workbench-extension",
    ok:
      !error &&
      existsSync(join(packagedTarget, "media/workflow-composer/workflow-composer.js")) &&
      existsSync(join(packagedTarget, "extension.js")),
    summary: !error
      ? "ioi-workbench extension synced into packaged app; source fork sync is optional"
      : "ioi-workbench extension sync failed",
    evidence: { packagedTarget, sync, error: error ? String(error?.message ?? error) : null },
  };
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

function bridgeState() {
  return {
    schemaVersion: "ioi.workbench-bridge.state.v1",
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    workspace: { name: "ioi", path: repoRoot },
    summary: {
      workflowCount: 6,
      runCount: 1,
      artifactCount: 1,
      connectorCount: 0,
      policyIssueCount: 0,
    },
    chat: {
      runtime: "ioi-runtime-daemon",
      authority: "daemon-owned",
      phase: "Model runtime ready",
      currentStep: "Daemon-backed local model execution is available.",
      modelLabel: MODEL_ID,
      contextLabel: ROUTE_ID,
      modeLabel: "Dry run",
      turns: [],
    },
    appearance: {
      themeId: "dark-modern",
      themeLabel: "Dark Modern",
      density: "default",
      openVsCodeColorTheme: "Default Dark Modern",
      source: "model-mounting-daemon-runtime-adapter-goal",
      updatedAtMs: Date.now(),
    },
    workflows: [
      {
        workflowId: "workflow:electron-model-backed-dry-run",
        slashCommand: "/workflow model-backed-dry-run",
        stepCount: 3,
        description: "Daemon-backed model dry-run through Workflow Composer",
        relativePath: ".agents/workflows/electron-model-backed-dry-run.workflow.json",
        packageRef: "package:model-mounting-daemon-runtime-adapter",
      },
    ],
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

function captureWindow(windowId, screenshotPath) {
  return runCommand(
    `set +e; for attempt in 1 2 3; do xdotool windowactivate ${windowId} 2>/dev/null || true; sleep 0.35; import -window ${windowId} ${JSON.stringify(
      screenshotPath,
    )} && exit 0; sleep 0.8; done; exit 1`,
    { timeout: 30_000 },
  );
}

function processesContaining(needle) {
  const result = runCommand("ps -eo pid=,cmd=");
  const stdout = result.stdout
    .split("\n")
    .filter((line) => needle && line.includes(needle))
    .join("\n");
  return {
    ...result,
    stdout: stdout ? `${stdout}\n` : "",
  };
}

async function runGuiValidation(outputRoot) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const modelProofs = [];
  const composerProofs = [];
  const errors = [];
  let boot = null;

  const server = createServer(async (request, response) => {
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
        if (body?.requestType === "modelsMode.proof") {
          modelProofs.push(body.payload);
        }
        if (body?.requestType === "workflowCompositor.proof") {
          composerProofs.push(body.payload);
        }
        if (body?.requestType === "workflowCompositor.error") {
          errors.push(body.payload);
        }
        sendJson(response, 200, { ok: true });
        return;
      }
      sendJson(response, 404, { error: "not_found" });
    } catch (error) {
      sendJson(response, 500, { error: String(error?.message ?? error) });
    }
  });

  let app = null;
  let userDataDir = null;
  let serverAddress = null;
  try {
    boot = await bootstrapDaemonModelRuntime(outputDir);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${boot.daemon.endpoint}\n`);

    serverAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${serverAddress.port}`;
    userDataDir = mkdtempSync("/tmp/autopilot-model-user-");
    const extensionsDir = mkdtempSync("/tmp/autopilot-model-ext-");
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    writeFileSync(join(outputDir, "extensions-dir"), `${extensionsDir}\n`);

    const stdoutPath = join(outputDir, "stdout.log");
    const stderrPath = join(outputDir, "stderr.log");
    app = spawn(HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary, [
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
        AUTOPILOT_SKIP_OVERVIEW: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    app.stdout.on("data", (chunk) =>
      writeFileSync(stdoutPath, chunk, { flag: "a" }),
    );
    app.stderr.on("data", (chunk) =>
      writeFileSync(stderrPath, chunk, { flag: "a" }),
    );
    writeFileSync(join(outputDir, "pid"), `${app.pid}\n`);

    const windowId = await waitForPredicate(() => {
      const byName = runCommand(
        `for id in $(xdotool search --name ${JSON.stringify(
          "Hypervisor",
        )} 2>/dev/null); do title=$(xdotool getwindowname "$id" 2>/dev/null || true); case "$title" in *"Hypervisor"*|*"Autopilot"*) echo "$id";; esac; done | tail -n 1`,
      );
      if (byName.ok && byName.stdout.trim()) return byName.stdout.trim();
      const byPid = runCommand(
        `for id in $(xdotool search --pid ${app.pid} 2>/dev/null); do title=$(xdotool getwindowname "$id" 2>/dev/null || true); case "$title" in *"Hypervisor"*|*"Autopilot"*) echo "$id";; esac; done | tail -n 1`,
      );
      return byPid.ok && byPid.stdout.trim() ? byPid.stdout.trim() : null;
    }, 35_000, 1000);
    if (!windowId) throw new Error("No Hypervisor Workbench adapter window found.");
    writeFileSync(join(outputDir, "window-id"), `${windowId}\n`);

    commands.push({
      commandId: "models-open",
      command: "ioi.models.open",
      args: [{ phase: "model-library" }],
    });
    const modelsReady = await waitForPredicate(
      () =>
        requests.find(
          (request) =>
            request?.requestType === "models.open" ||
            request?.requestType === "modelsMode.proof",
        ),
      35_000,
      500,
    );
    if (!modelsReady) throw new Error("Models mode did not report ready.");

    const screenshotResults = [];
    for (const shot of MODEL_SCREENSHOTS) {
      const beforeProofs = modelProofs.length;
      const commandId = `models-${shot.phase}`;
      commands.push({
        commandId,
        command: "ioi.models.capturePhase",
        args: [{ phase: shot.phase }],
      });
      const proof = await waitForPredicate(
        () => modelProofs.slice(beforeProofs).find((candidate) => candidate?.phase === shot.phase),
        25_000,
        500,
      );
      await wait(500);
      const screenshotPath = join(outputDir, shot.file);
      const screenshot = captureWindow(windowId, screenshotPath);
      const selectorName = shot.phase.replace(/-/g, "").replace(/^model/, "model");
      const selectors = proof?.selectors ?? {};
      const requiredSelector = shot.selector
        ? selectors[shot.selector]
        : shot.phase === "model-library"
          ? selectors.modelLibrary
          : shot.phase === "model-mount-drawer"
            ? selectors.mountDrawer
            : shot.phase === "model-runtime-backend"
              ? selectors.runtimeBackend
              : shot.phase === "model-load-estimate"
                ? selectors.loadEstimate
                : shot.phase === "model-load-progress"
                  ? selectors.loadProgress
                  : shot.phase === "model-instance-ready"
                    ? selectors.instanceReady
                    : shot.phase === "model-server-api"
                      ? selectors.serverApi
                      : shot.phase === "model-invocation-receipts-replay"
                        ? selectors.receiptsReplay
                        : selectors[selectorName];
      const ok =
        Boolean(proof) &&
        proof.daemonBacked === true &&
        requiredSelector > 0 &&
        screenshot.ok &&
        existsSync(screenshotPath) &&
        proof.directModelExecution === false &&
        proof.tauriUsed === false;
      screenshotResults.push({
        ...shot,
        commandDelivered: deliveredCommands.some((command) => command.commandId === commandId),
        screenshotPath,
        screenshotCaptured: screenshot.ok && existsSync(screenshotPath),
        proofObserved: Boolean(proof),
        selectors,
        daemonBacked: proof?.daemonBacked,
        boundary: proof
          ? {
              runtimeAuthority: proof.runtimeAuthority,
              webviewOwnsRuntimeState: proof.webviewOwnsRuntimeState,
              directModelExecution: proof.directModelExecution,
              externalConnectorAction: proof.externalConnectorAction,
              tauriUsed: proof.tauriUsed,
            }
          : null,
        ok,
        screenshotCommand: compact(screenshot),
      });
    }

    commands.push({
      commandId: "workflow-model-open",
      command: "ioi.workflow.openComposer",
      args: [{ scenarioId: "model-backed-dry-run", phase: "model-binding" }],
    });
    const composerReady = await waitForPredicate(
      () =>
        requests.find(
          (request) =>
            request?.requestType === "workflowCompositor.webviewReady" ||
            request?.requestType === "workflow.composer.open",
        ),
      35_000,
      500,
    );
    if (!composerReady) throw new Error("Workflow composer did not report ready.");

    for (const shot of WORKFLOW_SCREENSHOTS) {
      const beforeProofs = composerProofs.length;
      const commandId = `workflow-model-${shot.phase}`;
      commands.push({
        commandId,
        command: "ioi.workflow.compositor.runScenario",
        args: [{ scenarioId: shot.scenarioId, phase: shot.phase }],
      });
      const proof = await waitForPredicate(
        () =>
          composerProofs.slice(beforeProofs).find(
            (candidate) =>
              candidate?.scenarioId === shot.scenarioId &&
              candidate?.phase === shot.phase,
          ),
        40_000,
        500,
      );
      if (shot.phase === "run-timeline") {
        await waitForPredicate(
          () =>
            requests.find(
              (request) => request?.requestType === "workflowCompositor.daemonRunProject",
            ),
          20_000,
          500,
        );
      }
      await wait(750);
      const screenshotPath = join(outputDir, shot.file);
      const screenshot = captureWindow(windowId, screenshotPath);
      const selectorChecks = proof?.selectors ?? {};
      const ok =
        Boolean(proof) &&
        proof.daemonModelRuntimeConfigured === true &&
        selectorChecks.composer > 0 &&
        selectorChecks.canvas > 0 &&
        selectorChecks.nodes > 0 &&
        (shot.phase === "model-binding"
          ? selectorChecks.modelBinding > 0
          : selectorChecks.runTimeline > 0) &&
        screenshot.ok &&
        existsSync(screenshotPath) &&
        proof.externalAction === false &&
        proof.tauriUsed === false;
      screenshotResults.push({
        ...shot,
        commandDelivered: deliveredCommands.some((command) => command.commandId === commandId),
        screenshotPath,
        screenshotCaptured: screenshot.ok && existsSync(screenshotPath),
        proofObserved: Boolean(proof),
        selectors: selectorChecks,
        daemonModelRuntimeConfigured: proof?.daemonModelRuntimeConfigured,
        boundary: proof
          ? {
              runtimeAuthority: proof.runtimeAuthority,
              webviewOwnsRuntimeState: proof.webviewOwnsRuntimeState,
              directFileMutation: proof.directFileMutation,
              externalAction: proof.externalAction,
              tauriUsed: proof.tauriUsed,
            }
          : null,
        ok,
        screenshotCommand: compact(screenshot),
      });
    }

    const finalProjection = await requestJson(
      boot.daemon.endpoint,
      "/v1/model-mount/projection",
      { token: boot.token },
    );
    const finalReceipts = await requestJson(boot.daemon.endpoint, "/v1/model-mount/receipts", {
      token: boot.token,
    });
    writeFileSync(join(outputDir, "projection-after-gui.json"), `${JSON.stringify(finalProjection, null, 2)}\n`);
    writeFileSync(join(outputDir, "receipts-after-gui.json"), `${JSON.stringify(finalReceipts, null, 2)}\n`);

    runCommand(`xdotool windowclose ${windowId} 2>/dev/null || true`, {
      timeout: 5000,
    });
    await wait(1500);
    runCommand(
      `SELF=$$; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
        userDataDir,
      )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill -9 "$p" 2>/dev/null || true; done; sleep 1`,
      { timeout: 10_000 },
    );
    const orphanCheck = processesContaining(userDataDir);
    const receiptKinds = finalReceipts.map((receipt) => receipt.kind);
    const receiptOperations = finalReceipts
      .map((receipt) => receipt.details?.operation)
      .filter(Boolean);
    const boundaries = {
      electronVsCodeForkCanonicalShell: true,
      modelsModeVisible: screenshotResults.some((result) => result.file === "model-library.png" && result.ok),
      daemonBackedCatalog: modelProofs.some((proof) => proof?.daemonBacked === true),
      daemonBackedWorkflowRun: requests.some(
        (request) => request?.requestType === "workflowCompositor.daemonRunProject",
      ),
      loadedModelObserved: finalProjection.instances?.some((instance) => instance.status === "loaded"),
      tauriUsed: false,
      externalConnectorAction: false,
      extensionHostDurableRuntime: false,
      webviewDirectModelExecution: false,
    };
    const proof = {
      schemaVersion: "ioi.autopilot.model-mounting-daemon-runtime-adapter-proof.v1",
      generatedAt: new Date().toISOString(),
      outputDir,
      bridgeUrl,
      daemonEndpoint: boot.daemon.endpoint,
      deliveredCommands,
      requestTypes: [...new Set(requests.map((request) => request?.requestType))].sort(),
      composerErrors: errors,
      screenshotResults,
      counts: {
        requests: requests.length,
        deliveredCommands: deliveredCommands.length,
        modelProofs: modelProofs.length,
        composerProofs: composerProofs.length,
        receipts: finalReceipts.length,
      },
      receiptKinds,
      receiptOperations,
      boundaries,
      orphanCheck: compact(orphanCheck),
    };
    const proofPath = join(outputDir, "model-mounting-daemon-runtime-adapter-proof.json");
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
    const ok =
      screenshotResults.length === MODEL_SCREENSHOTS.length + WORKFLOW_SCREENSHOTS.length &&
      screenshotResults.every((result) => result.ok) &&
      screenshotResults.every((result) => result.commandDelivered) &&
      Object.values(boundaries).every((value) => value === true || value === false) &&
      boundaries.daemonBackedCatalog &&
      boundaries.daemonBackedWorkflowRun &&
      boundaries.loadedModelObserved &&
      receiptOperations.includes("model_load_estimate") &&
      receiptOperations.includes("model_load") &&
      receiptKinds.includes("model_invocation") &&
      receiptKinds.includes("model_route_selection") &&
      !orphanCheck.stdout.trim();
    return {
      id: "gui:model-mounting-daemon-runtime-adapter",
      ok,
      summary: ok
        ? "Electron GUI launched, Models mode operated, daemon model route invoked, and evidence captured"
        : "Electron model mounting GUI validation failed",
      evidence: {
        outputDir,
        proofPath,
        screenshotResults,
        requestTypes: proof.requestTypes,
        composerErrors: errors,
        counts: proof.counts,
        receiptKinds,
        receiptOperations,
        boundaries,
        orphanProcesses: orphanCheck.stdout.trim(),
      },
    };
  } catch (error) {
    return {
      id: "gui:model-mounting-daemon-runtime-adapter",
      ok: false,
      summary: "Electron model mounting GUI validation failed",
      evidence: {
        outputDir,
        serverAddress,
        error: String(error?.message ?? error),
        composerErrors: errors,
        requestTypes: [
          ...new Set(requests.map((request) => request?.requestType)),
        ].sort(),
      },
    };
  } finally {
    if (app?.pid) {
      runCommand(
        `SELF=$$; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill "$p" 2>/dev/null || true; done; sleep 1; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          userDataDir ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill -9 "$p" 2>/dev/null || true; done`,
        { timeout: 10_000 },
      );
    }
    if (boot?.daemon) {
      await boot.daemon.close().catch(() => undefined);
    }
    await closeServer(server);
  }
}

function writeResult(outputRoot, result) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const resultPath = join(outputDir, "result.json");
  const summaryPath = join(outputDir, "summary.md");
  writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
  writeFileSync(
    summaryPath,
    [
      "# Autopilot Model Mounting Daemon Runtime Adapter Result",
      "",
      `Status: ${result.ok ? "passed" : "failed"}`,
      `Mode: ${result.mode}`,
      "",
      "## Checks",
      "",
      ...result.checks.map(
        (check) => `- ${check.ok ? "PASS" : "FAIL"} ${check.id}: ${check.summary}`,
      ),
      "",
    ].join("\n"),
  );
  return { outputDir, resultPath, summaryPath };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const checks = [
    checkCommand("node"),
    checkCommand("npm"),
    checkCommand("npx"),
    checkCommand("xdotool"),
    checkCommand("import"),
    checkMasterGuide(),
    checkReferenceEvidence(),
    checkPackageScripts(),
    checkWorkbenchImplementation(),
    checkDaemonRouteImplementation(),
    checkTauriNotTargeted(),
    await checkDaemonApis(),
  ];

  if (args.run && checks.every((check) => check.ok)) {
    checks.push(buildComposerBundle());
    if (checks.at(-1)?.ok) {
      checks.push(syncExtension());
    }
    if (checks.every((check) => check.ok)) {
      checks.push(await runGuiValidation(args.outputRoot));
    }
  }

  const result = {
    schemaVersion: "autopilot.model-mounting-daemon-runtime-adapter-goal.v1",
    mode: args.run ? "run" : "preflight",
    ok: checks.every((check) => check.ok),
    generatedAt: new Date().toISOString(),
    masterGuide: MASTER_GUIDE,
    checks,
  };
  const paths = writeResult(args.outputRoot, result);
  console.log(paths.resultPath);
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
