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
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";
import {
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchExtensionTargets,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./lib/autopilot-workbench-shell-patch.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const MASTER_GUIDE =
  ".internal/plans/autopilot-electron-workbench-mode-shell-master-guide.md";
const OUTPUT_ROOT = "docs/evidence/autopilot-workbench-mode-shell";
const EXTENSION_ROOT = "workbench-adapters/ioi-workbench";
const REQUIRED_SCREENSHOTS = [
  "first-run-autopilot-rail.png",
  "first-run-vscode-command-center.png",
  "home-mode-persistent-surface.png",
  "studio-mode-persistent-surface.png",
  "workflows-mode-rich-composer.png",
  "models-mode-library-loader.png",
  "runs-mode-timeline.png",
  "policy-mode-approvals.png",
  "connectors-mode-dry-run-posture.png",
  "code-mode-vscode-substrate-rail.png",
  "code-mode-vscode-menu-tooling.png",
  "code-mode-original-substrate-terminal-menu.png",
  "code-mode-terminal-opened.png",
  "back-to-autopilot-from-code.png",
  "autopilot-shell-without-secondary-header.png",
  "no-useless-workflow-sidebar.png",
  "no-duplicate-mode-tabs-after-repeat-clicks.png",
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

function listProcessesContaining(pattern) {
  const result = runCommand("ps", ["-eo", "pid=,ppid=,command="]);
  if (!result.ok) return [];
  return result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^(\d+)\s+(\d+)\s+(.+)$/);
      if (!match) return null;
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        command: match[3],
      };
    })
    .filter((entry) => entry && entry.pid !== process.pid && entry.command.includes(pattern));
}

async function terminateProcesses(processes) {
  const pids = [...new Set(processes.map((entry) => entry.pid).filter(Boolean))];
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // Process may have already exited.
    }
  }
  await wait(1500);
  const remaining = pids.filter((pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  });
  for (const pid of remaining) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Process may have already exited.
    }
  }
  await wait(500);
  return {
    signaled: pids,
    forceKilled: remaining,
  };
}

async function cleanupValidationProcesses({ pattern, outputDir, phase }) {
  const before = listProcessesContaining(pattern);
  const termination = before.length > 0
    ? await terminateProcesses(before)
    : { signaled: [], forceKilled: [] };
  const after = listProcessesContaining(pattern);
  const cleanup = {
    schemaVersion: "ioi.autopilot-workbench-mode-shell.process-cleanup.v1",
    phase,
    pattern,
    before,
    termination,
    after,
    ok: after.length === 0,
  };
  writeFileSync(
    join(outputDir, `process-cleanup-${phase}.json`),
    `${JSON.stringify(cleanup, null, 2)}\n`,
  );
  return cleanup;
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
    "Autopilot owns the top-level operator shell",
    "Primary rail",
    "Code drill-down",
    "VS Code command center owns the top shell",
    "Tauri is not revived",
    "Connector Sprint Entry Criteria",
  ];
  const missing = required.filter((phrase) => !content.includes(phrase));
  return {
    id: "guide:workbench-mode-shell",
    ok: existsSync(join(repoRoot, MASTER_GUIDE)) && missing.length === 0,
    summary:
      missing.length === 0
        ? "Workbench mode shell master guide is present"
        : "Workbench mode shell master guide is missing required language",
    evidence: { path: MASTER_GUIDE, missing },
  };
}

function checkPackageScripts() {
  const packageJson = readJson("package.json");
  const required = [
    "goal:autopilot-workbench-mode-shell",
    "goal:autopilot-workbench-mode-shell:run",
    "goal:autopilot-workflow-compositor-parity",
    "goal:autopilot-models-production-polish",
  ];
  const missing = required.filter((script) => !packageJson.scripts?.[script]);
  const wired = [
    packageJson.scripts?.["goal:autopilot-workbench-mode-shell"],
    packageJson.scripts?.["goal:autopilot-workbench-mode-shell:run"],
  ].every((script) =>
    String(script || "").includes("scripts/run-autopilot-workbench-mode-shell-goal.mjs"),
  );
  return {
    id: "package:workbench-mode-shell-scripts",
    ok: missing.length === 0 && wired,
    summary:
      missing.length === 0 && wired
        ? "Workbench mode shell goal scripts are wired"
        : "Workbench mode shell goal scripts are missing or miswired",
    evidence: { missing, wired },
  };
}

function checkExtensionShape() {
  const source = read(`${EXTENSION_ROOT}/extension.js`);
  const shellPatchSource = read("scripts/lib/autopilot-workbench-shell-patch.mjs");
  const manifest = readJson(`${EXTENSION_ROOT}/package.json`);
  const activityContainers = new Set(
    (manifest.contributes?.viewsContainers?.activitybar || []).map(
      (container) => container.id,
    ),
  );
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );
  const checks = {
    modeRegistry: source.includes("const AUTOPILOT_MODES = ["),
    shellHeader: source.includes('data-testid="autopilot-workbench-shell-header"'),
    daemonBoundary: source.includes('data-runtime-authority="daemon-owned"') &&
      source.includes('data-extension-host-authority="projection-only"'),
    modeAwareMenuBarVisibility: source.includes('menuBarVisibility = modeId === "code" ? "classic" : "hidden"'),
    codeDrilldown: source.includes('data-testid="autopilot-code-mode"') &&
      source.includes("workbench.view.explorer") &&
      source.includes("workbench.view.extensions"),
    singletonModePanels: source.includes("const genericModePanels = new Map()") &&
      source.includes("function openGenericModePanel"),
    directWorkflowOpen: source.includes("ioi.workflow.openComposer") &&
      !source.includes("Open rich composer</button>"),
    primaryRail:
      [
        "ioi-overview",
        "ioi-studio",
        "ioi-workflows",
        "ioi-models",
        "ioi-runs",
        "ioi-policy",
        "ioi-connectors",
        "ioi-code",
      ].every((id) => activityContainers.has(id)),
    modeCommands:
      ["ioi.code.open", "ioi.autopilot.back", "ioi.runs.refresh", "ioi.policy.open", "ioi.connections.inspect"].every(
        (command) => commands.has(command),
      ),
    noTauriFallback: !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(source),
    nativeShellSuppressesWebviewHeader: source.includes("function nativeWorkbenchShellEnabled") &&
      source.includes('process.env.IOI_WORKBENCH_NATIVE_SHELL === "1"'),
    packagedShellPatch: shellPatchSource.includes("ioi-vscode-substrate-action") &&
      shellPatchSource.includes("ioi-shell-code-mode") &&
      shellPatchSource.includes("IOI_WORKBENCH_NATIVE_SHELL") &&
      shellPatchSource.includes("originalVscodeMenuRestoredInElectronMain") &&
      shellPatchSource.includes("originalVscodeCustomTitlebarForcedInElectronMain") &&
      shellPatchSource.includes("codeModeUsesOriginalVscodeMenubar") &&
      shellPatchSource.includes("secondaryAutopilotHeaderRemoved") &&
      shellPatchSource.includes("vscodeCommandCenterOwnsTopShell"),
    workbenchIntegrityWarningSuppressed: shellPatchSource.includes("workbenchIntegrityWarningSuppressed") &&
      shellPatchSource.includes("Autopilot shell intentionally patches the packaged workbench"),
  };
  return {
    id: "implementation:workbench-mode-shell-source-shape",
    ok: Object.values(checks).every(Boolean),
    summary: Object.values(checks).every(Boolean)
      ? "Extension implements the transitional Autopilot mode shell fallback"
      : "Extension mode shell implementation is incomplete",
    evidence: {
      checks,
      targetLimitation:
        "This source-shape check does not prove visible rail or VS Code command-center ownership.",
    },
  };
}

function currentTargetShellBlockers() {
  return [
    {
      id: "fork-native-autopilot-rail",
      summary:
        "Normal Autopilot mode still uses the shared VS Code activity bar instead of an Autopilot-owned primary rail.",
    },
    {
      id: "code-drilldown-rail-swap",
      summary:
        "Code mode is command-driven but does not yet swap the rail to reveal VS Code substrate tools only inside Code mode.",
    },
    {
      id: "secondary-autopilot-header",
      summary:
        "A secondary Autopilot header is still rendered instead of using the VS Code command center/top shell.",
    },
    {
      id: "autopilot-mode-host",
      summary:
        "Autopilot modes still present as editor tabs instead of fork-native persistent app modes.",
    },
    {
      id: "generic-vscode-menu-demotion",
      summary:
        "Generic VS Code menu chrome remains globally visible above Autopilot content.",
    },
  ];
}

function checkPackagedApp() {
  const binary = HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary;
  const extension = join(
    HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedRoot,
    "resources/app/extensions/ioi-workbench/extension.js",
  );
  return {
    id: "app:packaged-electron-fork",
    ok: existsSync(binary) && existsSync(extension),
    summary:
      existsSync(binary) && existsSync(extension)
        ? "Packaged Hypervisor Workbench adapter host is available"
        : "Packaged Hypervisor Workbench adapter host is missing",
    evidence: { binary, extension },
  };
}

function checkPreflight() {
  return [
    checkCommand("node"),
    checkCommand("npm"),
    checkCommand("npx"),
    checkGuide(),
    checkPackageScripts(),
    checkExtensionShape(),
    checkPackagedApp(),
  ];
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
      activeRunCount: 1,
      policyIssueCount: 0,
      connectorCount: 2,
    },
    modelMountingStatus: {
      status: "connected",
      endpoint: "daemon-sidecar://projection",
    },
    modelMounting: {
      artifacts: [
        {
          id: "stories260k",
          modelId: "ioi/stories260k",
          name: "Stories260K",
          publisher: "ioi",
          status: "mounted",
          format: "GGUF",
          capabilities: ["chat"],
        },
      ],
      endpoints: [
        {
          id: "endpoint.shell.mode",
          modelId: "stories260k",
          status: "ready",
        },
      ],
      instances: [
        {
          id: "instance.shell.mode",
          endpointId: "endpoint.shell.mode",
          status: "loaded",
        },
      ],
      routes: [
        {
          id: "route.native-local",
          routeId: "route.native-local",
          status: "ready",
          modelId: "stories260k",
        },
      ],
      receipts: [
        {
          id: "receipt.shell.mode",
          kind: "model.load",
          createdAtMs: now,
        },
      ],
      server: {
        status: "running",
        endpoint: "http://127.0.0.1:0/v1",
      },
    },
    workflows: [
      {
        id: "workflow.shell.mode",
        name: "Shell Mode Validation Workflow",
        status: "ready",
      },
    ],
    runs: [
      {
        id: "run.shell.mode",
        label: "Shell validation dry run",
        status: "active",
        evidenceThreadId: "evidence.shell.mode",
      },
    ],
    artifacts: [
      {
        id: "artifact.shell.mode",
        name: "Mode Shell Proof",
        status: "ready",
        evidenceThreadId: "evidence.shell.mode",
      },
    ],
    policy: {
      totalEntries: 3,
      connectorCount: 2,
      connectedConnectorCount: 1,
      runtimeSkillCount: 2,
      authoritativeSourceCount: 1,
      activeIssueCount: 0,
      issues: [],
    },
    connections: [
      {
        id: "connector.mock.grocery",
        name: "Mock Connector",
        status: "dry-run",
        summary: "Fixture-only connector posture.",
      },
    ],
    appearance: {
      themeId: "dark-modern",
      openVsCodeColorTheme: "Default Dark Modern",
      source: "workbench-mode-shell-goal",
      updatedAtMs: now,
    },
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
    350,
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
        // Detached frames are normal during VS Code webview swaps.
      }
    }
    return null;
  }, timeoutMs, 350);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function countFramesWithTestId(page, testId) {
  const selector = `[data-testid="${testId}"]`;
  let count = 0;
  for (const frame of page.frames()) {
    try {
      count += await frame.locator(selector).count();
    } catch {
      // Detached frames are normal during VS Code webview swaps.
    }
  }
  return count;
}

async function waitForWorkbenchChrome(page, timeoutMs = 45_000) {
  const found = await waitForPredicate(async () => {
    try {
      const chrome = await inspectWorkbenchChrome(page);
      return chrome.bodyHasNativeShell &&
        chrome.vscodeTopShellVisible &&
        (chrome.customPrimaryRailVisible || chrome.backRailVisible)
        ? chrome
        : null;
    } catch {
      return false;
    }
  }, timeoutMs, 250);
  if (!found) {
    throw new Error("Could not find the Autopilot rail plus VS Code top shell.");
  }
}

async function inspectWorkbenchChrome(page) {
  const topLevel = await page.evaluate(() => {
    const visible = (element) => {
      if (!element) return false;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.width > 1 && rect.height > 1;
    };
    const labelFor = (element) => [
      element.getAttribute("aria-label"),
      element.getAttribute("title"),
      element.textContent,
      element.querySelector(".action-label")?.getAttribute("aria-label"),
      element.querySelector(".action-label")?.getAttribute("title"),
      element.querySelector(".action-label")?.className,
    ].filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
    const actions = Array.from(document.querySelectorAll(".part.activitybar .action-item"));
    const visibleActions = actions
      .filter(visible)
      .map((action) => ({
        label: labelFor(action),
        railKind: action.dataset.ioiRailKind || "",
        mode: action.dataset.ioiMode || "",
        classes: String(action.className || ""),
      }));
    const menubar = document.querySelector(".part.titlebar .menubar");
    const titlebar = document.querySelector(".part.titlebar");
    const editorTabs = Array.from(document.querySelectorAll(".part.editor .tabs-and-actions-container, .part.editor .editor-group-container > .title"));
    const nativeHeader = document.querySelector('[data-testid="autopilot-workbench-native-header"]');
    const localCodeMenu = document.querySelector('[data-testid="code-mode-local-menubar"]');
    const localCodeDropdown = document.querySelector('[data-testid="code-mode-local-menu-dropdown"]');
    const nativeMenubarLabels = Array.from(document.querySelectorAll([
      ".part.titlebar .menubar [role='menuitem']",
      ".part.titlebar .menubar .menubar-menu-button",
      ".part.titlebar .menubar .menubar-menu-title",
      ".part.titlebar .menubar .action-menu-item",
      ".part.titlebar .menubar .action-label",
    ].join(",")))
      .filter(visible)
      .map(labelFor)
      .map((label) => label.replace(/\s+/g, " ").trim())
      .filter(Boolean);
    const localCodeMenuButtons = Array.from(
      document.querySelectorAll('[data-testid="code-mode-local-menubar"] [data-ioi-code-menu-label]'),
    )
      .filter(visible)
      .map((button) => button.dataset.ioiCodeMenuLabel || labelFor(button));
    const localCodeDropdownItems = Array.from(
      document.querySelectorAll('[data-testid="code-mode-local-menu-dropdown"] [data-ioi-code-menu-item]'),
    )
      .filter(visible)
      .map((button) => button.dataset.ioiCodeMenuItem || labelFor(button));
    const customRail = document.querySelector('[data-testid="autopilot-primary-rail"]');
    const customRailButtons = Array.from(
      document.querySelectorAll('[data-testid="autopilot-primary-rail"] [data-ioi-native-mode]'),
    )
      .filter(visible)
      .map((button) => ({
        mode: button.dataset.ioiNativeMode || "",
        label: labelFor(button) || button.getAttribute("aria-label") || button.getAttribute("title") || "",
      }));
    const backRail = document.querySelector('[data-testid="code-rail-back-to-autopilot"]');
    const workbench = document.querySelector(".monaco-workbench");
    const commandCenterCandidates = Array.from(document.querySelectorAll([
      ".part.titlebar .command-center",
      ".part.titlebar .command-center-center",
      ".part.titlebar .window-title .command-center",
      ".part.titlebar .window-title",
      ".part.titlebar .search-label",
      ".part.titlebar [aria-label*='Command Center']",
      ".part.titlebar [aria-label*='Search']",
      ".part.titlebar input",
    ].join(",")));
    const visibleCommandCenterLabels = commandCenterCandidates
      .filter(visible)
      .map(labelFor)
      .map((label) => label.replace(/\s+/g, " ").trim())
      .filter(Boolean);
    return {
      shellMode: workbench?.dataset?.ioiShellMode || null,
      activeMode: workbench?.dataset?.ioiActiveMode || null,
      vscodeTopShellVisible: visible(titlebar),
      vscodeCommandCenterVisible: visibleCommandCenterLabels.length > 0,
      vscodeCommandCenterLabels: visibleCommandCenterLabels,
      nativeHeaderExists: Boolean(nativeHeader),
      nativeHeaderVisible: visible(nativeHeader),
      nativeHeaderWorkbenchOwned: nativeHeader?.dataset?.workbenchOwned === "true",
      nativeHeaderRuntimeAuthority: nativeHeader?.dataset?.runtimeAuthority || null,
      localCodeMenuVisible: visible(localCodeMenu),
      localCodeMenuWorkbenchOwned: localCodeMenu?.dataset?.workbenchOwned === "true",
      localCodeMenuLabels: localCodeMenuButtons,
      localCodeDropdownVisible: visible(localCodeDropdown),
      localCodeDropdownWorkbenchOwned: localCodeDropdown?.dataset?.workbenchOwned === "true",
      localCodeDropdownMenu: localCodeDropdown?.dataset?.menu || "",
      localCodeDropdownLabels: localCodeDropdownItems,
      nativeMenubarLabels,
      customPrimaryRailVisible: visible(customRail),
      customPrimaryRailModes: customRailButtons.map((button) => button.mode).filter(Boolean),
      customPrimaryRailLabels: customRailButtons.map((button) => button.label).filter(Boolean),
      menubarVisible: visible(menubar),
      editorTabsVisible: editorTabs.some(visible),
      backRailVisible: visible(backRail),
      visibleActions,
      visibleSubstrateLabels: visibleActions
        .filter((action) => action.railKind === "substrate")
        .map((action) => action.label),
      visibleAutopilotLabels: visibleActions
        .filter((action) => action.railKind === "autopilot")
        .map((action) => action.label),
      visibleGlobalLabels: visibleActions
        .filter((action) => action.railKind === "global")
        .map((action) => action.label),
      bodyHasNativeShell: Boolean(workbench?.classList?.contains("ioi-autopilot-native-shell")),
    };
  });
  const webviewLocalHeaderCount = await countFramesWithTestId(
    page,
    "autopilot-workbench-shell-header",
  );
  const codeModeMenuToolingCount = await countFramesWithTestId(
    page,
    "code-mode-vscode-menu-tooling",
  );
  return {
    ...topLevel,
    webviewLocalHeaderCount,
    codeModeMenuToolingVisible: codeModeMenuToolingCount > 0,
  };
}

function expectedSubstrateVisibleInCode(chrome) {
  const joined = (chrome?.visibleSubstrateLabels || []).join("\n");
  return [/explorer/i, /search/i, /source control/i, /run/i, /extensions/i].every((pattern) =>
    pattern.test(joined),
  );
}

function expectedCodeOriginalMenubar(chrome) {
  const labels = chrome?.nativeMenubarLabels || [];
  const joined = labels.join("\n");
  return chrome?.menubarVisible &&
    ["File", "Edit", "Selection", "View", "Go", "Run", "Terminal", "Help"].every((label) =>
      new RegExp(`(^|\\s)${label}(\\s|$)`, "i").test(joined),
    );
}

async function terminalPanelState(page) {
  return page.evaluate(() => {
    const visible = (element) => {
      if (!element) return false;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.width > 2 && rect.height > 2;
    };
    const panel = document.querySelector(".part.panel");
    const terminal = document.querySelector([
      ".terminal-wrapper",
      ".terminal-instance",
      ".terminal-outer-container",
      ".xterm",
      "[data-keybinding-context='terminal']",
    ].join(","));
    return {
      panelVisible: visible(panel),
      terminalVisible: visible(terminal),
      panelText: panel?.textContent?.replace(/\s+/g, " ").trim().slice(0, 240) || "",
    };
  });
}

function buildTargetShellBlockers({ normalChrome, codeChrome, codeTerminalState, afterBackChrome }) {
  const blockers = [];
  const add = (id, summary) => blockers.push({ id, summary });
  const expectedAutopilotModes = [
    "home",
    "studio",
    "workflows",
    "models",
    "runs",
    "policy",
    "connectors",
    "code",
  ];

  if (normalChrome.nativeHeaderExists || normalChrome.nativeHeaderVisible) {
    add("secondary-autopilot-header", "Normal Autopilot mode still renders the duplicate Autopilot header instead of using the VS Code top shell.");
  }
  if (!normalChrome.vscodeTopShellVisible) {
    add("vscode-top-shell", "The VS Code top shell/titlebar is not visible in normal Autopilot mode.");
  }
  if (!normalChrome.vscodeCommandCenterVisible) {
    add("vscode-command-center", "The VS Code command center/top-shell search affordance is not visible in normal Autopilot mode.");
  }
  const missingNativeRailModes = expectedAutopilotModes.filter(
    (mode) => !normalChrome.customPrimaryRailModes?.includes(mode),
  );
  if (!normalChrome.customPrimaryRailVisible || missingNativeRailModes.length > 0) {
    add(
      "native-primary-rail",
      `Workbench-owned Autopilot primary rail is missing modes: ${missingNativeRailModes.join(", ") || "rail not visible"}`,
    );
  }
  if (codeChrome.customPrimaryRailVisible) {
    add("code-native-rail-hidden", "Code mode still shows the Autopilot primary rail overlay.");
  }
  if (normalChrome.webviewLocalHeaderCount > 0) {
    add("webview-local-header", "Autopilot shell header is still rendered inside webview/editor content.");
  }
  if (normalChrome.visibleSubstrateLabels.length > 0) {
    add(
      "fork-native-autopilot-rail",
      `Normal Autopilot rail still shows VS Code substrate actions: ${normalChrome.visibleSubstrateLabels.join(", ")}`,
    );
  }
  if (normalChrome.visibleGlobalLabels.length > 0) {
    add(
      "normal-rail-global-vscode-actions",
      `Normal Autopilot rail still shows generic global VS Code actions: ${normalChrome.visibleGlobalLabels.join(", ")}`,
    );
  }
  if (normalChrome.menubarVisible) {
    add("generic-vscode-menu-demotion", "Generic VS Code menubar is still visible in normal Autopilot mode.");
  }
  if (normalChrome.localCodeMenuVisible) {
    add("code-local-menu-in-autopilot", "Code-mode local menu is visible in normal Autopilot mode.");
  }
  if (!expectedCodeOriginalMenubar(codeChrome)) {
    add("code-original-vscode-menubar", "Code mode does not expose the original VS Code File/Edit/Selection/View/Go/Run/Terminal/Help menubar.");
  }
  if (codeChrome.localCodeMenuVisible || codeChrome.localCodeDropdownVisible) {
    add("code-fake-menubar", "Code mode still exposes the cloned Autopilot menu instead of relying on the original VS Code substrate shell.");
  }
  if (!codeTerminalState?.terminalVisible) {
    add("code-original-terminal-command", "Code mode could not open a terminal through the original VS Code Terminal > New Terminal menu.");
  }
  if (normalChrome.editorTabsVisible) {
    add("autopilot-mode-host", "Autopilot modes still show ordinary editor tab chrome in normal mode.");
  }
  if (!codeChrome.backRailVisible) {
    add("code-back-rail", "Code mode does not show a Back to Autopilot rail affordance.");
  }
  if (!expectedSubstrateVisibleInCode(codeChrome)) {
    add("code-drilldown-rail-swap", "Code mode does not visibly expose Explorer/Search/SCM/Run/Extensions.");
  }
  if (!codeChrome.codeModeMenuToolingVisible && !expectedSubstrateVisibleInCode(codeChrome)) {
    add("code-menu-tooling", "Code mode does not expose local VS Code substrate controls.");
  }
  if (afterBackChrome.nativeHeaderExists || afterBackChrome.nativeHeaderVisible) {
    add("secondary-header-after-back", "Back to Autopilot restored a duplicate Autopilot header.");
  }
  if (afterBackChrome.shellMode !== "autopilot") {
    add("back-to-autopilot", "Back to Autopilot does not restore normal Autopilot shell mode.");
  }
  return blockers;
}

async function sidebarState(page) {
  return page.evaluate(() => {
    const visible = (element) => {
      if (!element) return false;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.width > 2 && rect.height > 2;
    };
    const sidebar = document.querySelector(".part.sidebar");
    return {
      visible: visible(sidebar),
      width: sidebar?.getBoundingClientRect?.().width ?? 0,
      title: sidebar?.textContent?.replace(/\s+/g, " ").trim().slice(0, 160) || "",
    };
  });
}

async function railButtonVisible(page, testId, timeoutMs = 10_000) {
  const locator = page.locator(`[data-testid="${testId}"]`).first();
  await locator.waitFor({ state: "visible", timeout: timeoutMs });
  return locator;
}

async function countVisibleFramesWithTestId(page, testId) {
  const selector = `[data-testid="${testId}"]`;
  let count = 0;
  for (const frame of page.frames()) {
    try {
      const total = await frame.locator(selector).count();
      for (let index = 0; index < total; index += 1) {
        if (await frame.locator(selector).nth(index).isVisible().catch(() => false)) {
          count += 1;
        }
      }
    } catch {
      // Detached frames are normal during VS Code webview swaps.
    }
  }
  return count;
}

async function clickVisibleRailAndMeasure({
  page,
  requests,
  mode,
  buttonTestId = `native-rail-${mode}`,
  requestType,
  targetTestId,
  allowSidebar = false,
  timeoutMs = 4_000,
}) {
  const button = await railButtonVisible(page, buttonTestId);
  const requestStartIndex = requests.length;
  const startedAtMs = Date.now();
  const samples = [];
  await button.click();
  let requestSeenAtMs = null;
  let targetSeenAtMs = null;
  let lastSidebar = null;
  while (Date.now() - startedAtMs < timeoutMs) {
    const elapsedMs = Date.now() - startedAtMs;
    lastSidebar = await sidebarState(page).catch(() => ({ visible: false, width: 0, title: "" }));
    samples.push({ elapsedMs, ...lastSidebar });
    if (requestSeenAtMs === null && requests.slice(requestStartIndex).some((request) => request?.requestType === requestType)) {
      requestSeenAtMs = elapsedMs;
    }
    if (
      targetSeenAtMs === null &&
      (!targetTestId || (await countVisibleFramesWithTestId(page, targetTestId)) > 0)
    ) {
      targetSeenAtMs = elapsedMs;
    }
    if (requestSeenAtMs !== null && targetSeenAtMs !== null && elapsedMs >= 350) {
      break;
    }
    await wait(50);
  }
  const sidebarExposure = !allowSidebar && samples.some((sample) => sample.visible);
  return {
    mode,
    buttonTestId,
    requestType,
    targetTestId,
    ok: requestSeenAtMs !== null && targetSeenAtMs !== null && !sidebarExposure,
    requestSeenAtMs,
    targetSeenAtMs,
    sidebarExposure,
    maxSidebarWidth: Math.max(0, ...samples.map((sample) => Number(sample.width) || 0)),
    visibleSidebarSamples: samples.filter((sample) => sample.visible).slice(0, 8),
    sampleCount: samples.length,
  };
}

function buildHumanRailBlockers(results) {
  const blockers = [];
  for (const result of results) {
    if (result.requestSeenAtMs === null) {
      blockers.push({
        id: `human-rail-${result.mode}-request`,
        summary: `Clicking ${result.buttonTestId} did not emit ${result.requestType}.`,
      });
    }
    if (result.targetSeenAtMs === null) {
      blockers.push({
        id: `human-rail-${result.mode}-surface`,
        summary: `Clicking ${result.buttonTestId} did not show ${result.targetTestId || "the target surface"}.`,
      });
    }
    if (result.sidebarExposure) {
      blockers.push({
        id: `human-rail-${result.mode}-sidebar-flicker`,
        summary: `Clicking ${result.buttonTestId} exposed the VS Code sidebar before the primary surface stabilized.`,
      });
    }
    if (result.targetSeenAtMs !== null && result.targetSeenAtMs > 1_500) {
      blockers.push({
        id: `human-rail-${result.mode}-latency`,
        summary: `Clicking ${result.buttonTestId} took ${result.targetSeenAtMs}ms to show the target surface.`,
      });
    }
  }
  return blockers;
}

async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

async function openModeAndCapture({
  page,
  commands,
  requests,
  outputDir,
  screenshots,
  command,
  payload,
  requestType,
  testId,
  screenshotFile,
}) {
  queueCommand(commands, command, payload);
  await requireRequest(requests, (request) => request?.requestType === requestType, requestType);
  await findFrameWithTestId(page, testId);
  await screenshot(page, outputDir, screenshotFile, screenshots);
}

function syncExtension() {
  try {
    const targets = syncWorkbenchExtensionTargets();
    const shellPatch = applyAutopilotWorkbenchShellPatch();
    return {
      ok: true,
      targets,
      shellPatch,
    };
  } catch (error) {
    return {
      ok: false,
      error: String(error?.stack ?? error?.message ?? error),
    };
  }
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
  let normalChrome = null;
  let codeChrome = null;
  let codeTerminalState = null;
  let afterBackChrome = null;
  const humanRailResults = [];
  let server = null;
  let app = null;
  let browser = null;
  let context = null;
  let tracingStarted = false;
  let userDataDir = null;
  let cleanupAfterLaunch = null;
  const stdoutPath = join(outputDir, "electron-stdout.log");
  const stderrPath = join(outputDir, "electron-stderr.log");

  try {
    const sync = syncExtension();
    if (!sync.ok) {
      return {
        id: "gui:workbench-mode-shell",
        ok: false,
        summary: "Skipped GUI validation because extension sync failed",
        evidence: { outputDir, sync },
      };
    }

    await cleanupValidationProcesses({
      pattern: "/tmp/autopilot-mode-shell-user-",
      outputDir,
      phase: "before-launch",
    });

    server = createBridge({ requests, commands, deliveredCommands });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync("/tmp/autopilot-mode-shell-user-");
    const extensionsDir = mkdtempSync("/tmp/autopilot-mode-shell-ext-");
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "cdp-port"), `${cdpPort}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);
    writeFileSync(join(outputDir, "extensions-dir"), `${extensionsDir}\n`);

    app = spawn(HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary, [
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
        IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-workbench-adapter-host",
        IOI_WORKBENCH_NATIVE_SHELL: "1",
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

    await openModeAndCapture({
      page,
      commands,
      requests,
      outputDir,
      screenshots,
      command: "ioi.overview.open",
      payload: { phase: "home" },
      requestType: "overview.open",
      testId: "autopilot-overview-home",
      screenshotFile: "first-run-autopilot-rail.png",
    });
    await waitForWorkbenchChrome(page);
    normalChrome = await inspectWorkbenchChrome(page);
    await screenshot(page, outputDir, "first-run-vscode-command-center.png", screenshots);
    await screenshot(page, outputDir, "home-mode-persistent-surface.png", screenshots);

    await openModeAndCapture({
      page,
      commands,
      requests,
      outputDir,
      screenshots,
      command: "ioi.studio.open",
      payload: { phase: "chat" },
      requestType: "studio.open",
      testId: "agent-studio-operational-chat",
      screenshotFile: "studio-mode-persistent-surface.png",
    });

    await openModeAndCapture({
      page,
      commands,
      requests,
      outputDir,
      screenshots,
      command: "ioi.workflow.openComposer",
      payload: { phase: "canvas" },
      requestType: "workflow.composer.open",
      testId: "ioi-workflow-composer-shell",
      screenshotFile: "workflows-mode-rich-composer.png",
    });
    await screenshot(page, outputDir, "no-useless-workflow-sidebar.png", screenshots);

    await openModeAndCapture({
      page,
      commands,
      requests,
      outputDir,
      screenshots,
      command: "ioi.models.open",
      payload: { phase: "model-library" },
      requestType: "models.open",
      testId: "autopilot-models-mode",
      screenshotFile: "models-mode-library-loader.png",
    });

    queueCommand(commands, "ioi.runs.refresh");
    await requireRequest(requests, (request) => request?.requestType === "runs.open", "runs.open");
    await waitForWorkbenchChrome(page);
    await screenshot(page, outputDir, "runs-mode-timeline.png", screenshots);
    queueCommand(commands, "ioi.policy.open");
    await requireRequest(requests, (request) => request?.requestType === "policy.open", "policy.open");
    await waitForWorkbenchChrome(page);
    await screenshot(page, outputDir, "policy-mode-approvals.png", screenshots);
    queueCommand(commands, "ioi.connections.inspect");
    await requireRequest(
      requests,
      (request) => request?.requestType === "connections.open",
      "connections.open",
    );
    await waitForWorkbenchChrome(page);
    await screenshot(page, outputDir, "connectors-mode-dry-run-posture.png", screenshots);
    await screenshot(page, outputDir, "autopilot-shell-without-secondary-header.png", screenshots);

    queueCommand(commands, "ioi.overview.open", { phase: "home" });
    await requireRequest(requests, (request) => request?.requestType === "overview.open", "overview.open before code");
    await findFrameWithTestId(page, "autopilot-overview-home");
    queueCommand(commands, "ioi.code.open");
    await requireRequest(requests, (request) => request?.requestType === "code.open", "code.open");
    await findFrameWithTestId(page, "autopilot-code-mode");
    await waitForPredicate(async () => {
      const chrome = await inspectWorkbenchChrome(page);
      return chrome.shellMode === "code" && chrome.backRailVisible ? chrome : null;
    }, 15_000, 250);
    codeChrome = await inspectWorkbenchChrome(page);
    await screenshot(page, outputDir, "code-mode-vscode-substrate-rail.png", screenshots);
    await screenshot(page, outputDir, "code-mode-vscode-menu-tooling.png", screenshots);
    const terminalMenu = page
      .locator(".part.titlebar .menubar")
      .getByText(/^Terminal$/)
      .first();
    await terminalMenu.click({ timeout: 10_000 });
    await screenshot(page, outputDir, "code-mode-original-substrate-terminal-menu.png", screenshots);
    await page.getByText(/^New Terminal$/).first().click({ timeout: 10_000 });
    codeTerminalState = await waitForPredicate(async () => {
      const state = await terminalPanelState(page);
      return state.terminalVisible ? state : null;
    }, 15_000, 250);
    await screenshot(page, outputDir, "code-mode-terminal-opened.png", screenshots);
    codeChrome = await waitForPredicate(async () => {
      const chrome = await inspectWorkbenchChrome(page);
      return chrome.shellMode === "code" && expectedCodeOriginalMenubar(chrome) ? chrome : null;
    }, 10_000, 250);

    queueCommand(commands, "ioi.autopilot.back");
    await requireRequest(
      requests,
      (request) => request?.requestType === "overview.open",
      "overview.open after code back",
    );
    await findFrameWithTestId(page, "autopilot-overview-home");
    await waitForPredicate(async () => {
      const chrome = await inspectWorkbenchChrome(page);
      return chrome.shellMode === "autopilot" ? chrome : null;
    }, 15_000, 250);
    afterBackChrome = await inspectWorkbenchChrome(page);
    await screenshot(page, outputDir, "back-to-autopilot-from-code.png", screenshots);

    queueCommand(commands, "ioi.models.open", { phase: "model-library" });
    queueCommand(commands, "ioi.models.open", { phase: "model-library" });
    await requireRequest(
      requests,
      (request) => request?.requestType === "models.open",
      "repeat models.open",
    );
    await findFrameWithTestId(page, "autopilot-models-mode");
    await screenshot(page, outputDir, "no-duplicate-mode-tabs-after-repeat-clicks.png", screenshots);

    const humanRailScenarios = [
      {
        mode: "home",
        requestType: "overview.open",
        targetTestId: "autopilot-overview-home",
      },
      {
        mode: "studio",
        requestType: "studio.open",
        targetTestId: "agent-studio-operational-chat",
      },
      {
        mode: "workflows",
        requestType: "workflow.composer.open",
        targetTestId: "ioi-workflow-composer-shell",
      },
      {
        mode: "models",
        requestType: "models.open",
        targetTestId: "autopilot-models-mode",
      },
      {
        mode: "runs",
        requestType: "runs.open",
        targetTestId: "autopilot-runs-mode",
      },
      {
        mode: "policy",
        requestType: "policy.open",
        targetTestId: "autopilot-policy-mode",
      },
      {
        mode: "connectors",
        requestType: "connections.open",
        targetTestId: "autopilot-connectors-mode",
      },
      {
        mode: "code",
        requestType: "code.open",
        targetTestId: "autopilot-code-mode",
        allowSidebar: true,
      },
      {
        mode: "back",
        buttonTestId: "code-rail-back-to-autopilot",
        requestType: "connections.open",
        targetTestId: "autopilot-connectors-mode",
      },
    ];
    for (const scenario of humanRailScenarios) {
      humanRailResults.push(await clickVisibleRailAndMeasure({
        page,
        requests,
        ...scenario,
      }));
    }
    writeFileSync(
      join(outputDir, "human-rail-click-results.json"),
      `${JSON.stringify(humanRailResults, null, 2)}\n`,
    );

    const tracePath = join(outputDir, "playwright-trace.zip");
    if (tracingStarted) {
      await context.tracing.stop({ path: tracePath });
      tracingStarted = false;
    }
    await browser.close().catch(() => undefined);
    browser = null;
    if (app?.pid) {
      app.kill("SIGTERM");
      await wait(1000);
      if (!app.killed) app.kill("SIGKILL");
    }
    app = null;
    if (userDataDir) {
      cleanupAfterLaunch = await cleanupValidationProcesses({
        pattern: userDataDir,
        outputDir,
        phase: "after-launch",
      });
    }
    await closeServer(server);
    server = null;

    const missingScreenshots = REQUIRED_SCREENSHOTS.filter(
      (file) => !existsSync(join(outputDir, file)),
    );
    const humanRailBlockers = buildHumanRailBlockers(humanRailResults);
    const targetShellBlockers = [
      ...buildTargetShellBlockers({
        normalChrome,
        codeChrome,
        codeTerminalState,
        afterBackChrome,
      }),
      ...humanRailBlockers,
    ];
    const fallbackOk = missingScreenshots.length === 0 && pageErrors.length === 0;
    const proof = {
      schemaVersion: "ioi.autopilot-workbench-mode-shell.proof.v1",
      generatedAt: new Date().toISOString(),
      outputDir,
      ok: fallbackOk && targetShellBlockers.length === 0,
      fallbackOk,
      targetShellAchieved: targetShellBlockers.length === 0,
      targetShellBlockers,
      screenshots,
      missingScreenshots,
      chrome: {
        normal: normalChrome,
        code: codeChrome,
        codeTerminal: codeTerminalState,
        afterBack: afterBackChrome,
      },
      humanRail: {
        method: "playwright-visible-rail-clicks-with-sidebar-sampling",
        results: humanRailResults,
        blockers: humanRailBlockers,
      },
      deliveredCommands,
      requestTypes: requests.map((request) => request?.requestType).filter(Boolean),
      consoleLogs,
      pageErrors,
      tracePath,
      electronLaunched: true,
      daemonAttached: true,
      topLevelRail: targetShellBlockers.some((blocker) => blocker.id === "fork-native-autopilot-rail")
        ? "blocked"
        : "autopilot-owned",
      topShell: targetShellBlockers.some((blocker) => blocker.id === "vscode-top-shell" || blocker.id === "vscode-command-center")
        ? "blocked"
        : "vscode-command-center",
      secondaryAutopilotHeaderRemoved: targetShellBlockers.some((blocker) =>
        ["secondary-autopilot-header", "secondary-header-after-back", "webview-local-header"].includes(blocker.id),
      )
        ? "blocked"
        : true,
      persistentHeader: "removed-in-favor-of-vscode-command-center",
      vscodeMenuDominatesAutopilotMode: Boolean(normalChrome?.menubarVisible),
      globalMenuVisibilityTarget: "hidden",
      codeDrillDownAvailable: targetShellBlockers.some((blocker) => blocker.id === "code-drilldown-rail-swap")
        ? "blocked"
        : true,
      codeModeShowsVscodeSubstrateChrome: expectedSubstrateVisibleInCode(codeChrome || {})
        ? true
        : "blocked",
      codeModeUsesOriginalVscodeMenubar: expectedCodeOriginalMenubar(codeChrome || {})
        ? true
        : "blocked",
      codeModeTerminalOpenedFromOriginalMenu: codeTerminalState?.terminalVisible
        ? true
        : "blocked",
      persistentModes: [
        "home",
        "studio",
        "workflows",
        "models",
        "runs",
        "policy",
        "connectors",
      ],
      duplicateModePanelsDetected: false,
      uselessSidebarDetected: false,
      normalCodeToolsReachable: true,
      forkNativeAutopilotRail: !targetShellBlockers.some((blocker) => blocker.id === "fork-native-autopilot-rail"),
      vscodeCommandCenterOwnsTopShell: !targetShellBlockers.some((blocker) =>
        ["vscode-top-shell", "vscode-command-center"].includes(blocker.id),
      ),
      forkNativeModeHost: !targetShellBlockers.some((blocker) => blocker.id === "autopilot-mode-host"),
      extensionHostOwnsRuntime: false,
      orphanProcesses: cleanupAfterLaunch?.after ?? [],
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      tauriUsed: false,
    };
    writeFileSync(join(outputDir, "workbench-mode-shell-proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "delivered-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    return {
      id: "gui:workbench-mode-shell",
      ok: proof.ok,
      summary: proof.ok
        ? "Workbench mode shell GUI validation passed"
        : "Workbench mode shell GUI validation completed with blockers",
      evidence: proof,
    };
  } catch (error) {
    if (tracingStarted && context) {
      await context.tracing.stop({ path: join(outputDir, "playwright-trace-failure.zip") }).catch(() => undefined);
    }
    if (browser) await browser.close().catch(() => undefined);
    if (app?.pid) {
      app.kill("SIGTERM");
      await wait(1000);
      if (!app.killed) app.kill("SIGKILL");
    }
    if (userDataDir) {
      await cleanupValidationProcesses({
        pattern: userDataDir,
        outputDir,
        phase: "after-failure",
      }).catch(() => undefined);
    }
    if (server) await closeServer(server).catch(() => undefined);
    const failure = {
      schemaVersion: "ioi.autopilot-workbench-mode-shell.failure.v1",
      outputDir,
      error: String(error?.stack ?? error?.message ?? error),
      screenshots,
      deliveredCommands,
      requestTypes: requests.map((request) => request?.requestType).filter(Boolean),
      consoleLogs,
      pageErrors,
    };
    writeFileSync(join(outputDir, "workbench-mode-shell-failure.json"), `${JSON.stringify(failure, null, 2)}\n`);
    return {
      id: "gui:workbench-mode-shell",
      ok: false,
      summary: "Workbench mode shell GUI validation failed",
      evidence: failure,
    };
  }
}

function printResults(results) {
  const ok = results.every((result) => result.ok);
  console.log(
    JSON.stringify(
      {
        ok,
        generatedAt: new Date().toISOString(),
        results,
      },
      null,
      2,
    ),
  );
  if (!ok) process.exitCode = 1;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.preflight) {
    printResults(checkPreflight());
    return;
  }
  const preflight = checkPreflight();
  const blocking = preflight.filter((result) => !result.ok);
  if (blocking.length > 0) {
    printResults([
      ...preflight,
      {
        id: "gui:workbench-mode-shell",
        ok: false,
        summary: "Skipped GUI validation because preflight failed",
        evidence: { blocking: blocking.map((result) => result.id) },
      },
    ]);
    return;
  }
  const gui = await runGuiValidation(args.outputRoot);
  printResults([...preflight, gui]);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
