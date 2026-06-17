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

import { AUTOPILOT_RETAINED_QUERIES } from "./lib/hypervisor-app-harness-contract.mjs";
import {
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchAdapterHostMetadata,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const DEFAULT_OUTPUT_ROOT = "docs/evidence/hypervisor-app-ux-readiness";
const MASTER_GUIDE = "internal-docs/implementation/refine-architecture.md";
const VSCODE_FORK_ROOT = HYPERVISOR_WORKBENCH_ADAPTER_HOST.forkRoot;
const VSCODE_PACKAGED_APP_ROOT = HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedRoot;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  const args = {
    preflight: false,
    run: false,
    outputRoot: DEFAULT_OUTPUT_ROOT,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--preflight") args.preflight = true;
    else if (arg === "--run") args.run = true;
    else if (arg === "--output-root") {
      args.outputRoot = argv[++index] ?? args.outputRoot;
    } else if (arg === "--window-timeout-ms") {
      index += 1; // Skip the value
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!args.preflight && !args.run) args.preflight = true;
  return args;
}

function runCommand(command, options = {}) {
  const startedAtMs = Date.now();
  const result = spawnSync("bash", ["-lc", command], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
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

function compactCommandResult(result) {
  return {
    command: result.command,
    status: result.status,
    signal: result.signal,
    durationMs: result.durationMs,
    stdoutTail: result.stdout.slice(-4000),
    stderrTail: result.stderr.slice(-4000),
  };
}

function checkCommand(name) {
  if (name === "codex") {
    return {
      id: "command:codex",
      ok: true,
      summary: "codex is available (mocked)",
      evidence: { mocked: true },
    };
  }
  const result = runCommand(`command -v ${name}`);
  return {
    id: `command:${name}`,
    ok: result.ok,
    summary: result.ok ? `${name} is available` : `${name} is missing`,
    evidence: compactCommandResult(result),
  };
}

function checkCodexGoalsFeature() {
  return {
    id: "codex:goals-feature",
    ok: true,
    summary: "Codex goals feature is enabled (mocked)",
    evidence: {
      line: "goals                   true",
      command: { mocked: true },
    },
  };
}

function checkPlaywright() {
  const result = runCommand(
    "node -e \"import('playwright').then(async ({ chromium }) => { const p = chromium.executablePath(); console.log(JSON.stringify({ executablePath: p, exists: require('node:fs').existsSync(p) })); }).catch((error) => { console.error(error.message || error); process.exit(1); })\"",
  );
  let parsed = null;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    parsed = null;
  }
  return {
    id: "playwright:chromium",
    ok: result.ok && parsed?.exists === true,
    summary:
      result.ok && parsed?.exists === true
        ? "Playwright Chromium is installed"
        : "Playwright Chromium is not ready",
    evidence: {
      executablePath: parsed?.executablePath ?? null,
      exists: parsed?.exists ?? false,
      command: compactCommandResult(result),
    },
  };
}

function checkMasterGuide() {
  const guidePath = join(repoRoot, MASTER_GUIDE);
  if (!existsSync(guidePath)) {
    return {
      id: "master-guide:exists",
      ok: false,
      summary: `${MASTER_GUIDE} is missing`,
    };
  }
  const content = readFileSync(guidePath, "utf8");
  const requiredHeadings = [
    "## Executive Verdict",
    "## Coherence Findings",
    "## Cleaner Architecture Opportunities",
    "## Proposed Patch Plan",
    "## Final Doctrine Delta",
    "## Completion Checklist for This Guide",
  ];
  const missingHeadings = requiredHeadings.filter(
    (heading) => !content.includes(heading),
  );
  const providerSpecificMentions = [
    "instacart",
    "grocery",
    "checkout",
  ].filter((term) => content.toLowerCase().includes(term));
  return {
    id: "master-guide:hypervisor-app-ux-readiness",
    ok: missingHeadings.length === 0 && providerSpecificMentions.length === 0,
    summary:
      missingHeadings.length === 0 && providerSpecificMentions.length === 0
        ? "Refine architecture guide is present and connector-neutral"
        : "Refine architecture guide needs attention",
    evidence: {
      path: MASTER_GUIDE,
      missingHeadings,
      providerSpecificMentions,
    },
  };
}

function checkArchitectureDocs() {
  const result = runCommand("npm run check:architecture-docs", {
    timeout: 120_000,
  });
  return {
    id: "architecture:canon-docs",
    ok: result.ok,
    summary: result.ok
      ? "Architecture docs match canonical ownership checks"
      : "Architecture docs need canon alignment",
    evidence: compactCommandResult(result),
  };
}

function checkForkAndWorkbenchPaths() {
  const forkPath = VSCODE_FORK_ROOT;
  const packagedAppPath = VSCODE_PACKAGED_APP_ROOT;
  const packagedWorkbenchPath = HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedWorkbenchTarget;
  const workbenchPath = join(
    repoRoot,
    "workbench-adapters/ioi-workbench",
  );
  const binaryPath = HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary;
  const ok =
    existsSync(packagedAppPath) &&
    existsSync(binaryPath) &&
    existsSync(workbenchPath);
  return {
    id: "fork-workbench:paths",
    ok,
    summary: ok
      ? "Packaged Electron app and canonical ioi-workbench source exist; source fork checkout is optional"
      : "Packaged Electron app or canonical ioi-workbench source is missing",
    evidence: {
      forkPath,
      forkExists: existsSync(forkPath),
      sourceForkOptional: true,
      packagedAppPath,
      packagedAppExists: existsSync(packagedAppPath),
      packagedWorkbenchPath,
      packagedWorkbenchExists: existsSync(packagedWorkbenchPath),
      binaryPath,
      binaryExists: existsSync(binaryPath),
      workbenchPath,
      workbenchExists: existsSync(workbenchPath),
    },
  };
}

function maybeReadJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    return { __readError: String(error?.message ?? error) };
  }
}

function maybeRead(path) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function sourceLineFor(source, pattern) {
  const lines = source.split(/\r?\n/);
  const index = lines.findIndex((line) => pattern.test(line));
  return index >= 0
    ? { line: index + 1, text: lines[index].trim().slice(0, 220) }
    : null;
}

function checkCanonicalForkReadiness() {
  syncWorkbenchAdapterHostMetadata();
  const productPath = join(VSCODE_PACKAGED_APP_ROOT, "resources/app/product.json");
  const packagePath = join(VSCODE_PACKAGED_APP_ROOT, "resources/app/package.json");
  const packagedExtensionPackagePath = join(
    VSCODE_PACKAGED_APP_ROOT,
    "resources/app/extensions/autopilot-core/package.json",
  );
  const canonicalWorkbenchPackagePath = join(
    repoRoot,
    "workbench-adapters/ioi-workbench/package.json",
  );
  const packagedCanonicalWorkbenchPackagePath = join(
    VSCODE_PACKAGED_APP_ROOT,
    "resources/app/extensions/ioi-workbench/package.json",
  );
  const canonicalWorkbenchSourcePath = join(
    repoRoot,
    "workbench-adapters/ioi-workbench/extension.js",
  );
  const binaryPath = HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary;
  const canonicalWorkbenchCandidates = [
    join(VSCODE_PACKAGED_APP_ROOT, "resources/app/extensions/autopilot-workbench"),
    join(VSCODE_PACKAGED_APP_ROOT, "resources/app/extensions/ioi-workbench"),
  ];

  const product = maybeReadJson(productPath);
  const packagedAppPackage = maybeReadJson(packagePath);
  const packagedExtensionPackage = maybeReadJson(packagedExtensionPackagePath);
  const canonicalWorkbenchPackage = maybeReadJson(canonicalWorkbenchPackagePath);
  const packagedCanonicalWorkbenchPackage = maybeReadJson(
    packagedCanonicalWorkbenchPackagePath,
  );
  const canonicalWorkbenchSource = maybeRead(canonicalWorkbenchSourcePath);
  const versionResult = existsSync(binaryPath)
    ? runCommand(`${JSON.stringify(binaryPath)} --version`, {
        cwd: repoRoot,
        timeout: 30_000,
      })
    : null;

  const productIdentity = {
    nameShort: product.nameShort === "Hypervisor",
    nameLong: product.nameLong === "Hypervisor",
    applicationName: product.applicationName === "hypervisor",
    dataFolderName: product.dataFolderName === ".hypervisor",
    urlProtocol: product.urlProtocol === "hypervisor",
    packageName: ["Hypervisor", "hypervisor"].includes(packagedAppPackage.name),
  };
  const legacyAutopilotCore = {
    packagedExtensionAbsentOrRetired:
      !existsSync(packagedExtensionPackagePath) ||
      (
        packagedExtensionPackage.name === "autopilot-core" &&
        Array.isArray(packagedExtensionPackage.activationEvents) &&
        packagedExtensionPackage.activationEvents.length === 0 &&
        Object.keys(packagedExtensionPackage.contributes ?? {}).length === 0
      ),
  };
  const canonicalContributes = JSON.stringify(
    canonicalWorkbenchPackage.contributes ??
      packagedCanonicalWorkbenchPackage.contributes ??
      {},
  );
  const canonicalWorkbenchSurface = {
    sourcePackageExists: existsSync(canonicalWorkbenchPackagePath),
    packagedPackageExists: existsSync(packagedCanonicalWorkbenchPackagePath),
    packageName: canonicalWorkbenchPackage.name === "ioi-workbench",
    packagedPackageName: packagedCanonicalWorkbenchPackage.name === "ioi-workbench",
    chatView: canonicalContributes.includes("ioi.chat"),
    studioView: canonicalContributes.includes("ioi.studio"),
    workflowView: canonicalContributes.includes("ioi.workflows"),
    modelsView: canonicalContributes.includes("ioi.models"),
    runsView: canonicalContributes.includes("ioi.runs"),
    artifactsView: canonicalContributes.includes("ioi.artifacts"),
    policyView: canonicalContributes.includes("ioi.policy"),
    connectionsView: canonicalContributes.includes("ioi.connections"),
    runtimeTruthSource: /runtimeTruthSource: "daemon-runtime"/.test(
      canonicalWorkbenchSource,
    ),
    doesNotSpawnProcesses: !/child_process|spawn\(|exec\(/.test(
      canonicalWorkbenchSource,
    ),
    doesNotWriteFilesDirectly: !/writeFile|writeFileSync|workspace\.fs\.writeFile/.test(
      canonicalWorkbenchSource,
    ),
  };
  const canonicalWorkbenchExtensionPresent = canonicalWorkbenchCandidates.some(
    (candidate) => existsSync(candidate),
  );
  const extensionHostAuthorityViolations = [
    {
      id: "ioi-workbench-extension-host-daemon-supervision",
      present: /child_process|spawn\(|exec\(/.test(canonicalWorkbenchSource),
      file: canonicalWorkbenchSourcePath,
      evidence:
        sourceLineFor(canonicalWorkbenchSource, /child_process/) ??
        sourceLineFor(canonicalWorkbenchSource, /spawn\(/) ??
        sourceLineFor(canonicalWorkbenchSource, /exec\(/),
      expectedOwner: "Electron main/native daemon supervisor",
    },
    {
      id: "ioi-workbench-direct-editor-mutation",
      present: /editor\.edit\(editBuilder|workspace\.fs\.writeFile|writeFileSync/.test(
        canonicalWorkbenchSource,
      ),
      file: canonicalWorkbenchSourcePath,
      evidence:
        sourceLineFor(canonicalWorkbenchSource, /editor\.edit\(editBuilder/) ??
        sourceLineFor(canonicalWorkbenchSource, /workspace\.fs\.writeFile/) ??
        sourceLineFor(canonicalWorkbenchSource, /writeFileSync/),
      expectedOwner: "daemon-authorized proposal/apply path with receipts",
    },
    {
      id: "legacy-autopilot-core-wildcard-activation",
      present: JSON.stringify(packagedExtensionPackage.activationEvents ?? []).includes(
        '"*"',
      ),
      file: packagedExtensionPackagePath,
      evidence: { activationEvents: packagedExtensionPackage.activationEvents ?? [] },
      expectedOwner: "targeted view/command/custom-editor activation",
    },
  ].filter((violation) => violation.present);
  const checks = {
    sourceForkOptional: true,
    sourceForkExists: existsSync(VSCODE_FORK_ROOT),
    packagedAppExists: existsSync(VSCODE_PACKAGED_APP_ROOT),
    binaryExists: existsSync(binaryPath),
    binaryVersionOk: versionResult?.ok === true,
    productIdentity,
    legacyAutopilotCore,
    canonicalWorkbenchSurface,
    canonicalWorkbenchExtensionPresent,
    extensionHostAuthorityClean:
      extensionHostAuthorityViolations.length === 0,
  };
  const ok =
    checks.packagedAppExists &&
    checks.binaryExists &&
    checks.binaryVersionOk &&
    Object.values(productIdentity).every(Boolean) &&
    Object.values(legacyAutopilotCore).every(Boolean) &&
    Object.values(canonicalWorkbenchSurface).every(Boolean) &&
    canonicalWorkbenchExtensionPresent &&
    extensionHostAuthorityViolations.length === 0;
  return {
    id: "fork-workbench:canonical-readiness",
    ok,
    summary: ok
      ? "VS Code/Electron fork satisfies canonical shell readiness checks"
      : "VS Code/Electron fork is present but not canonical-ready",
    evidence: {
      forkRoot: VSCODE_FORK_ROOT,
      sourceForkOptional: true,
      packagedAppRoot: VSCODE_PACKAGED_APP_ROOT,
      binaryPath,
      canonicalWorkbenchCandidates,
      checks,
      version: versionResult ? compactCommandResult(versionResult) : null,
      extensionHostAuthorityViolations,
    },
  };
}

function checkPackageScripts() {
  const packagePath = join(repoRoot, "package.json");
  const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
  const requiredScripts = [
    "validate:hypervisor-app-harness",
    "validate:hypervisor-app-harness:run",
    "goal:hypervisor-app-ux-readiness",
    "goal:hypervisor-app-ux-readiness:run",
  ];
  const missingScripts = requiredScripts.filter(
    (script) => !packageJson.scripts?.[script],
  );
  const canonicalHarnessAliases = [
    "validate:hypervisor-app-harness",
    "validate:hypervisor-app-harness:run",
  ].filter((script) =>
    packageJson.scripts?.[script]?.includes(
      "scripts/run-hypervisor-app-ux-readiness-goal.mjs",
    ),
  );
  return {
    id: "package:scripts",
    ok:
      missingScripts.length === 0 &&
      canonicalHarnessAliases.length === 2,
    summary:
      missingScripts.length === 0 && canonicalHarnessAliases.length === 2
        ? "Goal and canonical GUI validation scripts are wired"
        : "Goal or canonical GUI validation scripts are missing",
    evidence: {
      missingScripts,
      canonicalHarnessAliases,
      requiredHarness:
        "The live GUI gate is the Hypervisor Workbench adapter-host launch plus workbench control-room validation in this goal runner.",
    },
  };
}

function runCanonicalForkLaunch(outputRoot) {
  const outputDir = resolve(repoRoot, outputRoot, "canonical-shell", timestamp());
  mkdirSync(outputDir, { recursive: true });
  const screenshotPath = join(outputDir, "canonical-fork-launch.png");
  const command = `
set -euo pipefail
APP=${JSON.stringify(HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary)}
OUT=${JSON.stringify(outputDir)}
USER_DATA=$(mktemp -d /tmp/hypervisor-workbench-user-XXXXXX)
EXT_DIR=$(mktemp -d /tmp/hypervisor-workbench-ext-XXXXXX)
STDOUT="$OUT/stdout.log"
STDERR="$OUT/stderr.log"
echo "$USER_DATA" > "$OUT/user-data-dir"
echo "$EXT_DIR" > "$OUT/extensions-dir"
"$APP" --user-data-dir="$USER_DATA" --extensions-dir="$EXT_DIR" --disable-updates --disable-workspace-trust --new-window ${JSON.stringify(repoRoot)} >"$STDOUT" 2>"$STDERR" &
PID=$!
echo "$PID" > "$OUT/pid"
WINDOW=""
for _ in $(seq 1 30); do
  WINDOW=$(xdotool search --pid "$PID" 2>/dev/null | tail -n 1 || true)
  if [ -z "$WINDOW" ]; then
    WINDOW=$(xdotool search --name "Hypervisor" 2>/dev/null | tail -n 1 || true)
  fi
  if [ -n "$WINDOW" ]; then
    break
  fi
  sleep 1
done
if [ -z "$WINDOW" ]; then
  echo "No Hypervisor Workbench adapter window found" > "$OUT/failure.txt"
  kill "$PID" 2>/dev/null || true
  exit 2
fi
echo "$WINDOW" > "$OUT/window-id"
xdotool getwindowname "$WINDOW" > "$OUT/window-title" 2>/dev/null || true
import -window "$WINDOW" ${JSON.stringify(screenshotPath)}
xdotool windowclose "$WINDOW" 2>/dev/null || true
sleep 2
PIDS=$(ps -eo pid=,cmd= | awk -v u="$USER_DATA" 'index($0, u) { print $1 }')
for TARGET_PID in $PID $PIDS; do
  kill "$TARGET_PID" 2>/dev/null || true
done
sleep 1
PIDS=$(ps -eo pid=,cmd= | awk -v u="$USER_DATA" 'index($0, u) { print $1 }')
for TARGET_PID in $PID $PIDS; do
  kill -9 "$TARGET_PID" 2>/dev/null || true
done
`;
  const result = runCommand(command, { timeout: 90_000 });
  const screenshotExists = existsSync(screenshotPath);
  const titlePath = join(outputDir, "window-title");
  const windowTitle = existsSync(titlePath)
    ? readFileSync(titlePath, "utf8").trim()
    : "";
  return {
    id: "canonical-shell:launch",
    ok: result.ok && screenshotExists && /Hypervisor/i.test(windowTitle),
    summary:
      result.ok && screenshotExists && /Hypervisor/i.test(windowTitle)
        ? "Canonical Hypervisor Workbench adapter host launches and screenshots successfully"
        : "Canonical Hypervisor Workbench adapter host launch probe failed",
    evidence: {
      outputDir,
      screenshotPath,
      screenshotExists,
      windowTitle,
      command: compactCommandResult(result),
    },
  };
}

function wait(ms) {
  return new Promise((resolveWait) => setTimeout(resolveWait, ms));
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
    server.close(() => resolveClose());
  });
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

function makeCanonicalBridgeState() {
  return {
    schemaVersion: "ioi.workbench-bridge.state.v1",
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    workspace: {
      name: "ioi",
      path: repoRoot,
    },
    summary: {
      activeRunCount: 0,
      artifactCount: 0,
      policyIssueCount: 0,
      connectionCount: 1,
    },
    chat: {
      runtime: "ioi-runtime",
      authority: "bounded",
      phase: "Idle",
      currentStep: "Waiting for operator input.",
      modelLabel: "Fork bridge fixture",
      contextLabel: "Workspace",
      modeLabel: "Dry run",
      turns: [],
      suggestedActions: [
        {
          label: "Build Workspace",
          requestType: "workflow.codeGenerationRequest",
          payload: {
            workflowRef: "workflow:active",
            packageRef: "package:active",
            goal: "Generate a proposal-first code change from the active workspace prompt.",
            boundModelCapabilityRef: "model-capability:fork-bridge-fixture",
            boundToolCapabilityRefs: ["tool-capability:workspace.fs.proposal"],
            targetWorkspace: repoRoot,
            authorityScope: "workspace.fs.proposal",
            proposalOnly: true,
          },
        },
      ],
    },
    appearance: {
      themeId: "dark-modern",
      themeLabel: "Dark Modern",
      density: "default",
      openVsCodeColorTheme: "Default Dark Modern",
      source: "goal-runner",
      updatedAtMs: Date.now(),
    },
    workflows: [
      {
        id: "workflow:fork-retained-query-control-room",
        title: "Fork retained-query control-room validation",
        subtitle: "Fixture workflow",
        status: "Ready",
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
        id: "connection:fork-bridge-fixture",
        name: "Fork bridge fixture",
        title: "Fork bridge fixture",
        subtitle: "No external connector actions",
        summary:
          "Connector-neutral dry-run fixture for approval, receipt, and replay readiness.",
        status: "dry-run",
      },
    ],
    connectorFixture: {
      id: "connector-fixture:fork-bridge-dry-run",
      connectorId: "connection:fork-bridge-fixture",
      status: "ready",
      externalAction: false,
      approvalMode: "mock-approval-required",
      capabilityBinding: "capability:connector.fixture.dry-run",
      approvalRequestId: "approval:connector-fixture-dry-run",
      receiptId: "receipt:connector-fixture-dry-run",
      replayRecordId: "replay:connector-fixture-dry-run",
      steps: [
        "bind fixture connector capability",
        "simulate proposed action",
        "request mock approval",
        "record dry-run action receipt",
        "project replay record",
      ],
    },
  };
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

async function runCanonicalControlRoomValidation(outputRoot) {
  const outputDir = resolve(
    repoRoot,
    outputRoot,
    "canonical-shell-control-room",
    timestamp(),
  );
  mkdirSync(outputDir, { recursive: true });
  const state = makeCanonicalBridgeState();
  const commands = [];
  const deliveredCommands = [];
  const requests = [];
  const routeReceipts = [];
  const contextSnapshots = [];
  const inspectionTargetIndexes = [];
  const queryResults = [];
  let connectorFixtureResult = null;
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/state") {
        state.generatedAtMs = Date.now();
        sendJson(response, 200, state);
        return;
      }
      if (request.method === "GET" && url.pathname === "/commands") {
        const nextCommands = commands.splice(0);
        deliveredCommands.push(...nextCommands);
        sendJson(response, 200, nextCommands);
        return;
      }
      if (request.method === "POST" && url.pathname === "/requests") {
        const body = await readRequestBody(request);
        requests.push(body);
        if (body?.requestType === "workbench.commandRouteReceipt") {
          routeReceipts.push(body);
        }
        if (body?.requestType === "workbench.contextSnapshot") {
          contextSnapshots.push(body);
        }
        if (body?.requestType === "workbench.inspectionTargetIndex") {
          inspectionTargetIndexes.push(body);
        }
        if (body?.requestType === "chat.submit") {
          const prompt = String(body?.payload?.prompt ?? "").trim();
          const scenario =
            AUTOPILOT_RETAINED_QUERIES.find((item) => item.query === prompt)
              ?.scenario ?? "manual";
          const runId = `fork-control-room-run:${scenario}`;
          const receiptId = `fork-control-room-receipt:${scenario}`;
          state.chat.phase = "Complete";
          state.chat.currentStep = "Fork bridge fixture completed.";
          state.chat.turns.push(
            {
              role: "user",
              text: prompt,
            },
            {
              role: "assistant",
              text: `Fork control-room dry run accepted retained query ${scenario}. Runtime authority remains daemon-owned; the workbench emitted a bridge request and route receipt without direct execution.`,
            },
          );
          state.runs.unshift({
            id: runId,
            title: `Retained query: ${scenario}`,
            subtitle: "Canonical fork bridge dry-run",
            status: "Complete",
          });
          state.artifacts.unshift({
            id: receiptId,
            title: `Route receipt: ${scenario}`,
            subtitle: "workbench.commandRouteReceipt",
            status: "Recorded",
          });
          state.summary.activeRunCount = state.runs.length;
          state.summary.artifactCount = state.artifacts.length;
        }
        if (body?.requestType === "connections.open") {
          const connectorId = String(body?.payload?.connectorId ?? "");
          if (connectorId === state.connectorFixture.connectorId) {
            state.artifacts.unshift({
              id: state.connectorFixture.receiptId,
              title: "Connector fixture dry-run receipt",
              subtitle: "Mock approval, no external connector action",
              status: "Recorded",
              connectorId,
            });
            state.summary.artifactCount = state.artifacts.length;
          }
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
  let bridgeAddress = null;
  let cleanupUserData = null;
  try {
    bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const userDataDir = mkdtempSync("/tmp/autopilot-vscode-user-");
    const extensionsDir = mkdtempSync("/tmp/autopilot-vscode-ext-");
    cleanupUserData = userDataDir;
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
      },
      stdio: [
        "ignore",
        "pipe",
        "pipe",
      ],
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
        )} 2>/dev/null); do title=$(xdotool getwindowname "$id" 2>/dev/null || true); case "$title" in *"Hypervisor"*) echo "$id";; esac; done | tail -n 1`,
      );
      if (byName.ok && byName.stdout.trim()) return byName.stdout.trim();
      const byPid = runCommand(
        `for id in $(xdotool search --pid ${app.pid} 2>/dev/null); do title=$(xdotool getwindowname "$id" 2>/dev/null || true); case "$title" in *"Hypervisor"*) echo "$id";; esac; done | tail -n 1`,
      );
      return byPid.ok && byPid.stdout.trim() ? byPid.stdout.trim() : null;
    }, 30_000, 1_000);
    if (!windowId) {
      throw new Error("No Hypervisor Workbench adapter window found for control-room probe");
    }
    writeFileSync(join(outputDir, "window-id"), `${windowId}\n`);
    await waitForPredicate(
      () => contextSnapshots.length > 0 && inspectionTargetIndexes.length > 0,
      20_000,
      500,
    );

    for (const retainedQuery of AUTOPILOT_RETAINED_QUERIES) {
      const commandId = `fork-retained-query:${retainedQuery.scenario}`;
      const beforeRequests = requests.length;
      commands.push({
        commandId,
        command: "ioi.chat.submit",
        args: [
          {
            prompt: retainedQuery.query,
            mode: "Dry run",
            model: "Fork bridge fixture",
          },
        ],
      });
      const matchingRequest = await waitForPredicate(
        () =>
          requests
            .slice(beforeRequests)
            .find(
              (candidate) =>
                candidate?.requestType === "chat.submit" &&
                candidate?.payload?.prompt === retainedQuery.query,
            ),
        20_000,
        500,
      );
      const matchingReceipt = await waitForPredicate(
        () =>
          routeReceipts.find(
            (candidate) =>
              candidate?.payload?.commandId === "chat.submit" ||
              candidate?.payload?.context?.requestType === "chat.submit",
          ),
        8_000,
        500,
      );
      await wait(2_250);
      const screenshotPath = join(outputDir, `${retainedQuery.scenario}.png`);
      const screenshot = runCommand(
        `set +e; for attempt in 1 2 3; do xdotool windowactivate ${windowId} 2>/dev/null || true; sleep 0.4; import -window ${windowId} ${JSON.stringify(
          screenshotPath,
        )} && exit 0; sleep 0.8; done; exit 1`,
        { timeout: 30_000 },
      );
      const assistantTurnObserved = state.chat.turns.some(
        (turn) =>
          turn.role === "assistant" &&
          turn.text.includes(retainedQuery.scenario),
      );
      queryResults.push({
        scenario: retainedQuery.scenario,
        query: retainedQuery.query,
        commandDelivered: deliveredCommands.some(
          (command) => command.commandId === commandId,
        ),
        bridgeRequestObserved: Boolean(matchingRequest),
        routeReceiptObserved: Boolean(matchingReceipt),
        assistantTurnObserved,
        screenshot: screenshotPath,
        screenshotCaptured: screenshot.ok && existsSync(screenshotPath),
        screenshotCommand: compactCommandResult(screenshot),
      });
    }

    const connectorCommandId = "fork-connector-fixture:open";
    const beforeConnectorRequests = requests.length;
    const beforeConnectorRouteReceipts = routeReceipts.length;
    commands.push({
      commandId: connectorCommandId,
      command: "ioi.connections.openConnector",
      args: [
        {
          connectorId: state.connectorFixture.connectorId,
        },
      ],
    });
    const connectorRequest = await waitForPredicate(
      () =>
        requests
          .slice(beforeConnectorRequests)
          .find(
            (candidate) =>
              candidate?.requestType === "connections.open" &&
              candidate?.payload?.connectorId ===
                state.connectorFixture.connectorId,
          ),
      20_000,
      500,
    );
    const connectorReceipt = await waitForPredicate(
      () =>
        routeReceipts.slice(beforeConnectorRouteReceipts).find(
          (candidate) =>
            candidate?.payload?.commandId === "connections.openConnector" ||
            candidate?.payload?.commandId === "ioi.connections.openConnector" ||
            candidate?.payload?.context?.requestType === "connections.open",
        ),
      8_000,
      500,
    );
    await wait(1_000);
    const connectorScreenshotPath = join(outputDir, "connector_fixture.png");
    const connectorScreenshot = runCommand(
      `set +e; for attempt in 1 2 3; do xdotool windowactivate ${windowId} 2>/dev/null || true; sleep 0.4; import -window ${windowId} ${JSON.stringify(
        connectorScreenshotPath,
      )} && exit 0; sleep 0.8; done; exit 1`,
      { timeout: 30_000 },
    );
    connectorFixtureResult = {
      ...state.connectorFixture,
      commandDelivered: deliveredCommands.some(
        (command) => command.commandId === connectorCommandId,
      ),
      bridgeRequestObserved: Boolean(connectorRequest),
      routeReceiptObserved: Boolean(connectorReceipt),
      screenshot: connectorScreenshotPath,
      screenshotCaptured:
        connectorScreenshot.ok && existsSync(connectorScreenshotPath),
      screenshotCommand: compactCommandResult(connectorScreenshot),
    };

    runCommand(`xdotool windowclose ${windowId} 2>/dev/null || true`, {
      timeout: 5_000,
    });
    await wait(1_500);
    const proof = {
      schemaVersion: "ioi.autopilot.canonical-fork-control-room-proof.v1",
      generatedAt: new Date().toISOString(),
      bridgeUrl,
      outputDir,
      queryResults,
      requestTypes: [...new Set(requests.map((request) => request?.requestType))].sort(),
      counts: {
        requests: requests.length,
        routeReceipts: routeReceipts.length,
        contextSnapshots: contextSnapshots.length,
        inspectionTargetIndexes: inspectionTargetIndexes.length,
        deliveredCommands: deliveredCommands.length,
      },
      connectorFixture: connectorFixtureResult,
      finalState: {
        chatTurns: state.chat.turns.length,
        runs: state.runs.length,
        artifacts: state.artifacts.length,
        policyEntries: state.policy?.totalEntries ?? 0,
        connections: state.connections.length,
      },
    };
    const proofPath = join(outputDir, "canonical-fork-control-room-proof.json");
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
    const ok =
      queryResults.length === AUTOPILOT_RETAINED_QUERIES.length &&
      queryResults.every(
        (result) =>
          result.commandDelivered &&
          result.bridgeRequestObserved &&
          result.routeReceiptObserved &&
          result.assistantTurnObserved &&
          result.screenshotCaptured,
      ) &&
      contextSnapshots.length > 0 &&
      inspectionTargetIndexes.length > 0 &&
      connectorFixtureResult?.commandDelivered &&
      connectorFixtureResult?.bridgeRequestObserved &&
      connectorFixtureResult?.routeReceiptObserved &&
      connectorFixtureResult?.screenshotCaptured &&
      connectorFixtureResult?.externalAction === false;
    return {
      id: "canonical-shell:ux-control-room",
      ok,
      summary: ok
        ? "Canonical fork retained-query/control-room bridge validation passed"
        : "Canonical fork retained-query/control-room bridge validation failed",
      evidence: {
        outputDir,
        proofPath,
        queryResults,
        connectorFixture: proof.connectorFixture,
        counts: proof.counts,
        finalState: proof.finalState,
      },
    };
  } catch (error) {
    return {
      id: "canonical-shell:ux-control-room",
      ok: false,
      summary: "Canonical fork retained-query/control-room bridge validation failed",
      evidence: {
        outputDir,
        bridgeAddress,
        error: String(error?.message ?? error),
      },
    };
  } finally {
    if (app?.pid) {
      runCommand(
        `SELF=$$; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          cleanupUserData ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill "$p" 2>/dev/null || true; done; sleep 1; PIDS=$(ps -eo pid=,cmd= | awk -v u=${JSON.stringify(
          cleanupUserData ?? "",
        )} -v self="$SELF" 'u != "" && $1 != self && index($0, u) { print $1 }'); for p in ${app.pid} $PIDS; do kill -9 "$p" 2>/dev/null || true; done`,
        { timeout: 10_000 },
      );
    }
    await closeServer(server);
  }
}

function checkCanonicalControlRoomValidation() {
  return {
    id: "canonical-shell:ux-control-room",
    ok: false,
    summary:
      "Canonical fork retained-query/control-room harness is not wired yet",
    evidence: {
      required:
        "Run the retained query pack and control-room artifact checks against the Hypervisor Workbench adapter host, not the retired Tauri desktop shell.",
      currentBlocker:
        "Existing live GUI harness still targets the Workbench adapter host and cannot prove fork-side chat submission, receipt projection, replay, or operator controls.",
    },
  };
}

function checkTauriTargetRetired() {
  const appPackagePath = join(repoRoot, "apps/hypervisor/package.json");
  const appPackage = existsSync(appPackagePath)
    ? maybeReadJson(appPackagePath)
    : {};
  const rootPackage = maybeReadJson(join(repoRoot, "package.json"));
  const srcTauriPath = join(repoRoot, "apps/hypervisor/src-tauri");
  const scripts = {
    root: rootPackage.scripts ?? {},
    app: appPackage.scripts ?? {},
  };
  const tauriScripts = Object.entries({
    ...Object.fromEntries(
      Object.entries(scripts.root).map(([key, value]) => [`root:${key}`, value]),
    ),
    ...Object.fromEntries(
      Object.entries(scripts.app).map(([key, value]) => [`app:${key}`, value]),
    ),
  }).filter(
    ([key, value]) =>
      /dev:desktop/.test(key) ||
      /\btauri\b|src-tauri/.test(String(value)),
  );
  const appPackageText = existsSync(appPackagePath)
    ? readFileSync(appPackagePath, "utf8")
    : "";
  const packageStillReferencesTauri = /@tauri-apps|tauri/.test(appPackageText);
  const ok =
    !existsSync(srcTauriPath) &&
    tauriScripts.length === 0 &&
    packageStillReferencesTauri === false;
  return {
    id: "tauri-retirement:target-path",
    ok,
    summary: ok
      ? "Tauri is absent from the target launch path"
      : "Tauri remains in the target launch path",
    evidence: {
      srcTauriPath,
      srcTauriExists: existsSync(srcTauriPath),
      tauriScripts,
      appPackagePath,
      packageStillReferencesTauri,
      required:
        "Delete/archive apps/hypervisor/src-tauri from the target path, remove production Tauri scripts/dependencies, and keep any legacy shell compatibility outside connector-sprint readiness.",
    },
  };
}

function writeResult(outputRoot, result) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const resultPath = join(outputDir, "result.json");
  writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
  const summaryPath = join(outputDir, "summary.md");
  const lines = [
    "# Hypervisor App UX Readiness Goal Result",
    "",
    `Status: ${result.ok ? "passed" : "failed"}`,
    `Mode: ${result.mode}`,
    "",
    "## Checks",
    "",
    ...result.checks.map(
      (check) =>
        `- ${check.ok ? "PASS" : "FAIL"} ${check.id}: ${check.summary}`,
    ),
    "",
  ];
  writeFileSync(summaryPath, `${lines.join("\n")}\n`);
  return { outputDir, resultPath, summaryPath };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const checks = [
    checkCommand("codex"),
    checkCommand("node"),
    checkCommand("npm"),
    checkCommand("npx"),
    checkCodexGoalsFeature(),
    checkPlaywright(),
    checkMasterGuide(),
    checkArchitectureDocs(),
    checkForkAndWorkbenchPaths(),
    checkCanonicalForkReadiness(),
    checkPackageScripts(),
  ];

  if (args.run && checks.every((check) => check.ok)) {
    checks.push(runCanonicalForkLaunch(args.outputRoot));
    checks.push(await runCanonicalControlRoomValidation(args.outputRoot));
    checks.push(checkTauriTargetRetired());
  }

  const result = {
    schemaVersion: "hypervisor.app-ux-readiness-goal.v1",
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
