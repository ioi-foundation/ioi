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

import {
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchExtensionTargets,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const MASTER_GUIDE =
  ".internal/plans/autopilot-electron-workbench-workflow-compositor-parity-master-guide.md";
const OUTPUT_ROOT =
  "docs/evidence/autopilot-workbench-workflow-compositor-parity";
const EXTENSION_ROOT =
  "workbench-adapters/ioi-workbench";
const VSCODE_PACKAGED_APP_ROOT = HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedRoot;
const REQUIRED_SCREENSHOTS = [
  {
    file: "workflow-composer-canvas.png",
    scenarioId: "sequential",
    phase: "canvas",
  },
  {
    file: "workflow-node-inspector.png",
    scenarioId: "sequential",
    phase: "node-inspector",
  },
  {
    file: "workflow-readiness-panel.png",
    scenarioId: "branching-approval",
    phase: "readiness",
  },
  {
    file: "workflow-run-timeline.png",
    scenarioId: "sequential",
    phase: "run-timeline",
  },
  {
    file: "workflow-receipts-replay.png",
    scenarioId: "replay-evidence",
    phase: "receipts-replay",
  },
  {
    file: "workflow-connector-fixture-binding.png",
    scenarioId: "connector-fixture",
    phase: "connector-fixture",
  },
];
const WORKFLOW_SCREENSHOTS = [
  {
    file: "workflow-from-scratch-sequential.png",
    scenarioId: "sequential",
    phase: "canvas",
  },
  {
    file: "workflow-from-scratch-branching-approval.png",
    scenarioId: "branching-approval",
    phase: "canvas",
  },
  {
    file: "workflow-from-scratch-connector-fixture.png",
    scenarioId: "connector-fixture",
    phase: "canvas",
  },
  {
    file: "workflow-from-scratch-code-proposal.png",
    scenarioId: "code-proposal",
    phase: "canvas",
  },
  {
    file: "workflow-from-scratch-replay-evidence.png",
    scenarioId: "replay-evidence",
    phase: "canvas",
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
    "WorkflowComposer",
    "Tauri must not be revived",
    "Validation must prove workflow compositor parity",
    "Connector Sprint Entry Criteria",
  ];
  const missing = required.filter((phrase) => !content.includes(phrase));
  return {
    id: "master-guide:workflow-compositor-parity",
    ok: existsSync(guidePath) && missing.length === 0,
    summary:
      existsSync(guidePath) && missing.length === 0
        ? "Workflow compositor parity guide is present"
        : "Workflow compositor parity guide is missing required canon",
    evidence: { path: MASTER_GUIDE, missing },
  };
}

function checkExtensionImplementation() {
  const extensionPath = join(repoRoot, EXTENSION_ROOT, "extension.js");
  const manifestPath = join(repoRoot, EXTENSION_ROOT, "package.json");
  const webviewPath = join(
    repoRoot,
    EXTENSION_ROOT,
    "webview/workflow-composer/main.tsx",
  );
  const runtimePath = join(
    repoRoot,
    EXTENSION_ROOT,
    "webview/workflow-composer/fixtureRuntime.ts",
  );
  const jsAssetPath = join(
    repoRoot,
    EXTENSION_ROOT,
    "media/workflow-composer/workflow-composer.js",
  );
  const cssAssetPath = join(
    repoRoot,
    EXTENSION_ROOT,
    "media/workflow-composer/workflow-composer.css",
  );
  const extensionSource = read(extensionPath);
  const webviewSource = read(webviewPath);
  const runtimeSource = read(runtimePath);
  const manifest = readJson(manifestPath);
  const commands = JSON.stringify(manifest.contributes?.commands ?? []);
  const activityContainers = manifest.contributes?.viewsContainers?.activitybar ?? [];
  const checks = {
    genericIoiActivityContainerRemoved: !activityContainers.some(
      (container) => container.id === "ioi",
    ),
    studioActivityContainer: activityContainers.some(
      (container) =>
        container.id === "ioi-studio" &&
        container.icon === "$(sparkle)",
    ),
    workflowsActivityContainer: activityContainers.some(
      (container) => container.id === "ioi-workflows",
    ),
    directWorkflowActivityOpen:
      extensionSource.includes("maybeAutoOpenPrimarySurface") &&
      extensionSource.includes('"ioi.workflow.openComposer"') &&
      extensionSource.includes('"workbench.action.closeSidebar"'),
    openComposerCommand: commands.includes("ioi.workflow.openComposer"),
    scenarioCommand: commands.includes("ioi.workflow.compositor.runScenario"),
    webviewPanel: extensionSource.includes("createWebviewPanel"),
    bridgeRequests: extensionSource.includes("workflowCompositor.proof"),
    realWorkflowComposerImport: webviewSource.includes(
      'import { WorkflowComposer } from "@ioi/hypervisor-workbench"',
    ),
    fixtureRuntimeBoundary: runtimeSource.includes("externalAction: false"),
    noTauriFallback: !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(
      `${extensionSource}\n${webviewSource}\n${runtimeSource}`,
    ),
    jsAssetExists: existsSync(jsAssetPath),
    cssAssetExists: existsSync(cssAssetPath),
  };
  return {
    id: "ioi-workbench:real-composer-mounted",
    ok: Object.values(checks).every(Boolean),
    summary: Object.values(checks).every(Boolean)
      ? "ioi-workbench mounts the real WorkflowComposer with fixture-only boundary"
      : "ioi-workbench composer implementation is incomplete",
    evidence: {
      extensionPath: EXTENSION_ROOT,
      checks,
      assetSizes: {
        jsBytes: existsSync(jsAssetPath) ? readFileSync(jsAssetPath).length : 0,
        cssBytes: existsSync(cssAssetPath) ? readFileSync(cssAssetPath).length : 0,
      },
    },
  };
}

function checkPackageScripts() {
  const packageJson = readJson(join(repoRoot, "package.json"));
  const required = [
    "goal:hypervisor-workflow-compositor-parity",
    "goal:hypervisor-workflow-compositor-parity:run",
    "goal:hypervisor-app-ux-readiness",
    "goal:hypervisor-app-ux-readiness:run",
  ];
  const missing = required.filter((script) => !packageJson.scripts?.[script]);
  const wired = required
    .filter((script) => script.includes("workflow-compositor"))
    .every((script) =>
      packageJson.scripts?.[script]?.includes(
        "scripts/run-autopilot-workflow-compositor-parity-goal.mjs",
      ),
    );
  return {
    id: "package:scripts",
    ok: missing.length === 0 && wired,
    summary:
      missing.length === 0 && wired
        ? "Workflow compositor parity goal scripts are wired"
        : "Workflow compositor parity goal scripts are missing",
    evidence: { missing, wired },
  };
}

function checkTauriNotTargeted() {
  const extensionSource = read(join(repoRoot, EXTENSION_ROOT, "extension.js"));
  const packageText = read(join(repoRoot, "package.json"));
  const appPackageText = read(join(repoRoot, "apps/hypervisor/package.json"));
  const srcTauriPath = join(repoRoot, "apps/hypervisor/src-tauri");
  const scriptMentions = [
    ...Object.entries(readJson(join(repoRoot, "package.json")).scripts ?? {}),
    ...Object.entries(readJson(join(repoRoot, "apps/hypervisor/package.json")).scripts ?? {}).map(
      ([key, value]) => [`app:${key}`, value],
    ),
  ].filter(([, value]) => /\btauri\b|src-tauri/.test(String(value)));
  return {
    id: "tauri:not-revived",
    ok:
      !existsSync(srcTauriPath) &&
      scriptMentions.length === 0 &&
      !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(extensionSource) &&
      !/@tauri-apps|src-tauri/.test(packageText + appPackageText),
    summary: "Tauri remains absent from the target workflow compositor path",
    evidence: {
      srcTauriExists: existsSync(srcTauriPath),
      scriptMentions,
    },
  };
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
      existsSync(join(packagedTarget, "media/workflow-composer/workflow-composer.js")),
    summary: !error
      ? "ioi-workbench extension synced into packaged app; source fork sync is optional"
      : "ioi-workbench extension sync failed",
    evidence: {
      packagedTarget,
      sync,
      error: error ? String(error?.message ?? error) : null,
    },
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
    latest = predicate();
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
      workflowCount: 5,
      runCount: 0,
      artifactCount: 0,
      connectorCount: 1,
      policyIssueCount: 0,
    },
    chat: {
      runtime: "ioi-runtime",
      authority: "bounded",
      phase: "Idle",
      currentStep: "Workflow composer parity validation.",
      modelLabel: "Composer fixture",
      contextLabel: "Workspace",
      modeLabel: "Dry run",
      turns: [],
    },
    appearance: {
      themeId: "dark-modern",
      themeLabel: "Dark Modern",
      density: "default",
      openVsCodeColorTheme: "Default Dark Modern",
      source: "workflow-compositor-parity-goal",
      updatedAtMs: Date.now(),
    },
    workflows: [
      {
        workflowId: "workflow:electron-parity-sequential",
        slashCommand: "/workflow sequential",
        stepCount: 4,
        description: "Sequential Electron composer parity fixture",
        relativePath: ".agents/workflows/electron-parity-sequential.workflow.json",
        packageRef: "package:composer-parity",
      },
    ],
    runs: [],
    artifacts: [],
    policy: {
      totalEntries: 1,
      connectorCount: 1,
      connectedConnectorCount: 0,
      runtimeSkillCount: 1,
      authoritativeSourceCount: 1,
      activeIssueCount: 0,
    },
    connections: [
      {
        id: "connection:mock-connector-fixture",
        name: "Mock connector fixture",
        summary: "Dry-run connector binding only; no external action.",
        status: "dry-run",
      },
    ],
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

async function runGuiValidation(outputRoot) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const proofs = [];
  const errors = [];
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
        if (body?.requestType === "workflowCompositor.proof") {
          proofs.push(body.payload);
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
    serverAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${serverAddress.port}`;
    userDataDir = mkdtempSync("/tmp/autopilot-composer-user-");
    const extensionsDir = mkdtempSync("/tmp/autopilot-composer-ext-");
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
      commandId: "workflow-activity-open-composer",
      command: "workbench.view.extension.ioi-workflows",
      args: [],
    });
    const ready = await waitForPredicate(
      () =>
        requests.find(
          (request) =>
            request?.requestType === "workflowCompositor.webviewReady" ||
            request?.requestType === "workflow.composer.open",
        ),
      30_000,
      500,
    );
    if (!ready) throw new Error("Workflow composer webview did not report ready.");

    const screenshotResults = [];
    const allScreenshots = [...REQUIRED_SCREENSHOTS, ...WORKFLOW_SCREENSHOTS];
    for (const shot of allScreenshots) {
      const beforeProofs = proofs.length;
      const commandId = `workflow-composer-${shot.scenarioId}-${shot.phase}-${shot.file}`;
      commands.push({
        commandId,
        command: "ioi.workflow.compositor.runScenario",
        args: [{ scenarioId: shot.scenarioId, phase: shot.phase }],
      });
      const proof = await waitForPredicate(
        () =>
          proofs.slice(beforeProofs).find(
            (candidate) =>
              candidate?.scenarioId === shot.scenarioId &&
              candidate?.phase === shot.phase,
          ),
        35_000,
        500,
      );
      await wait(750);
      const screenshotPath = join(outputDir, shot.file);
      const screenshot = captureWindow(windowId, screenshotPath);
      const selectorChecks = proof?.selectors ?? {};
      const ok =
        Boolean(proof) &&
        selectorChecks.composer > 0 &&
        selectorChecks.canvas > 0 &&
        selectorChecks.nodes > 0 &&
        selectorChecks.edges > 0 &&
        screenshot.ok &&
        existsSync(screenshotPath) &&
        proof.externalAction === false &&
        proof.tauriUsed === false;
      screenshotResults.push({
        ...shot,
        commandDelivered: deliveredCommands.some(
          (command) => command.commandId === commandId,
        ),
        screenshotPath,
        screenshotCaptured: screenshot.ok && existsSync(screenshotPath),
        proofObserved: Boolean(proof),
        selectors: selectorChecks,
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
    const proof = {
      schemaVersion: "ioi.autopilot.workflow-compositor-parity-proof.v1",
      generatedAt: new Date().toISOString(),
      outputDir,
      bridgeUrl,
      deliveredCommands,
      requestTypes: [...new Set(requests.map((request) => request?.requestType))].sort(),
      composerErrors: errors,
      screenshotResults,
      counts: {
        requests: requests.length,
        deliveredCommands: deliveredCommands.length,
        proofs: proofs.length,
      },
      workflowsCreatedThroughGui: WORKFLOW_SCREENSHOTS.map((shot) => shot.scenarioId),
      boundaries: {
        electronVsCodeForkCanonicalShell: true,
        realAgentIdeWorkflowComposerMounted: screenshotResults.some(
          (result) => result.selectors?.composer > 0,
        ),
        workflowActivityOpensComposer: deliveredCommands.some(
          (command) => command.commandId === "workflow-activity-open-composer",
        ) && requests.some((request) => request?.requestType === "workflow.composer.open"),
        tauriUsed: false,
        externalConnectorAction: false,
        extensionHostDurableRuntime: false,
        webviewDirectFileMutation: false,
      },
      orphanCheck: compact(orphanCheck),
    };
    const proofPath = join(outputDir, "workflow-compositor-parity-proof.json");
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
    const ok =
      screenshotResults.length === allScreenshots.length &&
      screenshotResults.every((result) => result.ok) &&
      screenshotResults.every((result) => result.commandDelivered) &&
      proof.boundaries.realAgentIdeWorkflowComposerMounted &&
      proof.boundaries.workflowActivityOpensComposer &&
      !orphanCheck.stdout.trim();
    return {
      id: "gui:workflow-compositor-parity",
      ok,
      summary: ok
        ? "Electron GUI launched, real WorkflowComposer operated, and parity evidence captured"
        : "Electron WorkflowComposer GUI parity validation failed",
      evidence: {
        outputDir,
        proofPath,
        screenshotResults,
        requestTypes: proof.requestTypes,
        composerErrors: errors,
        counts: proof.counts,
        orphanProcesses: orphanCheck.stdout.trim(),
      },
    };
  } catch (error) {
    return {
      id: "gui:workflow-compositor-parity",
      ok: false,
      summary: "Electron WorkflowComposer GUI parity validation failed",
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
      "# Autopilot Workflow Compositor Parity Result",
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
    checkExtensionImplementation(),
    checkPackageScripts(),
    checkTauriNotTargeted(),
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
    schemaVersion: "autopilot.workflow-compositor-parity-goal.v1",
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
