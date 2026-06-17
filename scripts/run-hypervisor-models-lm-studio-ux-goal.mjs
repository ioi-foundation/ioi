#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const MASTER_GUIDE =
  ".internal/plans/autopilot-electron-models-lm-studio-inspired-ux-master-guide.md";
const PARENT_GUIDE =
  ".internal/plans/autopilot-electron-model-mounting-daemon-runtime-adapter-master-guide.md";
const OUTPUT_ROOT =
  "docs/evidence/autopilot-electron-models-lm-studio-inspired-ux";
const EXTENSION_ROOT =
  "workbench-adapters/ioi-workbench";

const REQUIRED_SCREENSHOTS = [
  "model-library-lmstudio-layout.png",
  "model-selected-inspector-info.png",
  "model-selected-inspector-load.png",
  "model-quick-loader.png",
  "model-load-dialog.png",
  "model-discover-download.png",
  "model-catalog-sources.png",
  "model-running-instance.png",
  "model-server-logs.png",
  "workflow-model-loader-binding.png",
  "model-receipts-replay-linked.png",
];

const REQUIRED_TESTIDS = [
  "models-lmstudio-shell",
  "models-left-rail",
  "model-library",
  "model-library-table",
  "model-library-row-selected",
  "model-library-footer",
  "model-selected-inspector",
  "model-inspector-info-tab",
  "model-inspector-load-tab",
  "model-inspector-inference-tab",
  "model-inspector-policy-tab",
  "model-inspector-routes-tab",
  "model-inspector-receipts-tab",
  "model-mount-drawer",
  "model-quick-loader-popover",
  "model-load-dialog",
  "model-load-estimate",
  "model-load-confirm-button",
  "model-discovery-surface",
  "model-discover-list",
  "model-discover-search-input",
  "model-discover-search-button",
  "model-discover-staff-picks",
  "model-discover-sort",
  "model-discover-result-row",
  "model-discover-detail",
  "model-discover-stats",
  "model-discover-capabilities",
  "model-discover-readme-title",
  "model-download-options",
  "model-more-from-publisher",
  "model-catalog-sources-surface",
  "model-local-autodiscovery-sources",
  "model-remote-registry-sources",
  "model-catalog-source-config",
  "model-catalog-provider-select",
  "model-catalog-source-configure-button",
  "model-server-api",
  "model-server-view",
  "model-server-status",
  "model-server-endpoints",
  "model-server-loaded-models",
  "model-server-request-log",
  "model-server-backend-logs",
  "model-server-receipts",
  "workflow-node-live-model-binding",
  "workflow-live-model-dry-run-timeline",
  "model-invocation-receipts-replay",
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

function checkMasterGuide() {
  const guidePath = join(repoRoot, MASTER_GUIDE);
  const content = read(guidePath);
  const required = [
    "LM Studio-inspired operational shape",
    "table/inspector-first",
    "Required screenshots",
    "model-library-lmstudio-layout.png",
    "Do not begin real connector-specific sprint work",
  ];
  const missing = required.filter((phrase) => !content.includes(phrase));
  return {
    id: "guide:models-lm-studio-ux",
    ok: existsSync(guidePath) && missing.length === 0,
    summary:
      existsSync(guidePath) && missing.length === 0
        ? "LM Studio-inspired Models UX guide is present"
        : "LM Studio-inspired Models UX guide is missing required source-of-truth language",
    evidence: { path: MASTER_GUIDE, missing },
  };
}

function checkParentGuide() {
  const content = read(join(repoRoot, PARENT_GUIDE));
  const ok = content.includes(MASTER_GUIDE);
  return {
    id: "guide:parent-model-mounting-link",
    ok,
    summary: ok
      ? "Parent model mounting guide links the LM Studio UX child guide"
      : "Parent model mounting guide does not link the LM Studio UX child guide",
    evidence: { path: PARENT_GUIDE },
  };
}

function checkPackageScripts() {
  const packageJson = readJson(join(repoRoot, "package.json"));
  const required = [
    "goal:hypervisor-models-lm-studio-ux",
    "goal:hypervisor-models-lm-studio-ux:run",
    "goal:hypervisor-model-mounting",
    "goal:hypervisor-workflow-compositor-parity",
  ];
  const missing = required.filter((script) => !packageJson.scripts?.[script]);
  const wired = [
    "goal:hypervisor-models-lm-studio-ux",
    "goal:hypervisor-models-lm-studio-ux:run",
  ].every((script) =>
    packageJson.scripts?.[script]?.includes(
      "scripts/run-hypervisor-models-lm-studio-ux-goal.mjs",
    ),
  );
  return {
    id: "package:models-lm-studio-ux-scripts",
    ok: missing.length === 0 && wired,
    summary:
      missing.length === 0 && wired
        ? "LM Studio UX goal scripts are wired"
        : "LM Studio UX goal scripts are missing or miswired",
    evidence: { missing, wired },
  };
}

function checkWorkbenchImplementation() {
  const extensionSource = read(join(repoRoot, EXTENSION_ROOT, "extension.js"));
  const manifest = readJson(join(repoRoot, EXTENSION_ROOT, "package.json"));
  const commands = JSON.stringify(manifest.contributes?.commands ?? []);
  const missingTestIds = REQUIRED_TESTIDS.filter(
    (testId) => !extensionSource.includes(`data-testid="${testId}"`) && !extensionSource.includes(testId),
  );
  const checks = {
    allRequiredTestIds: missingTestIds.length === 0,
    loaderCommand: extensionSource.includes("ioi.models.openLoader") &&
      commands.includes("ioi.models.openLoader"),
    workflowBindingCommand: extensionSource.includes("ioi.models.selectForWorkflow") &&
      commands.includes("ioi.models.selectForWorkflow"),
    catalogSourceCommand: extensionSource.includes("ioi.models.configureCatalogProvider") &&
      commands.includes("ioi.models.configureCatalogProvider"),
    inspectorTabs: extensionSource.includes("data-model-inspector-tab") &&
      extensionSource.includes("activateModelInspectorTab"),
    denseTableInspectorShape:
      extensionSource.includes("models-lmstudio__primary") &&
      extensionSource.includes("models-lmstudio__library") &&
      extensionSource.includes("models-lmstudio__inspector"),
    daemonBoundary:
      extensionSource.includes("runtimeAuthority: \"daemon-owned\"") &&
      extensionSource.includes("webviewExecutesModel: false"),
    noTauriFallback: !/src-tauri|@tauri-apps|tauri:\/\/|tauri\./i.test(extensionSource),
  };
  return {
    id: "implementation:models-lm-studio-ux",
    ok: Object.values(checks).every(Boolean),
    summary: Object.values(checks).every(Boolean)
      ? "Models renderer exposes the LM Studio-inspired table, inspector, loader, dialog, server, and receipt surfaces"
      : "Models renderer is missing one or more LM Studio-inspired UX requirements",
    evidence: { checks, missingTestIds },
  };
}

function checkHarness() {
  const source = read(join(repoRoot, "scripts/run-hypervisor-model-mounting-goal.mjs"));
  const missingScreenshots = REQUIRED_SCREENSHOTS.filter(
    (screenshot) => !source.includes(screenshot),
  );
  const ok =
    missingScreenshots.length === 0 &&
    source.includes("quickLoaderPopover") &&
    source.includes("workflow-model-loader-binding.png");
  return {
    id: "harness:models-lm-studio-ux",
    ok,
    summary: ok
      ? "Model mounting harness captures the UX-specific screenshots"
      : "Model mounting harness is missing UX-specific screenshot capture",
    evidence: { missingScreenshots },
  };
}

function latestEvidenceDir(outputRoot) {
  const root = join(repoRoot, outputRoot);
  if (!existsSync(root)) return null;
  const candidates = readdirSync(root)
    .map((entry) => join(root, entry))
    .filter((entry) => {
      try {
        return statSync(entry).isDirectory();
      } catch {
        return false;
      }
    })
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  return candidates.find((dir) =>
    existsSync(join(dir, "model-mounting-daemon-runtime-adapter-proof.json")),
  );
}

function runPreflight({ outputRoot, write = true }) {
  const checks = [
    checkMasterGuide(),
    checkParentGuide(),
    checkPackageScripts(),
    checkWorkbenchImplementation(),
    checkHarness(),
  ];
  const result = {
    id: "preflight:models-lm-studio-ux",
    ok: checks.every((check) => check.ok),
    summary: checks.every((check) => check.ok)
      ? "LM Studio-inspired Models UX preflight passed"
      : "LM Studio-inspired Models UX preflight failed",
    evidence: { checks },
  };
  if (write) {
    writeResult(outputRoot, result);
  }
  return result;
}

function runGuiValidation(outputRoot) {
  const preflight = runPreflight({ outputRoot, write: false });
  if (!preflight.ok) {
    return {
      id: "gui:models-lm-studio-ux",
      ok: false,
      summary: "Skipped GUI validation because preflight failed",
      evidence: { preflight },
    };
  }

  const delegate = runCommand("node", [
    "scripts/run-hypervisor-model-mounting-goal.mjs",
    "--run",
    "--output-root",
    outputRoot,
  ], {
    timeout: 240_000,
  });
  const delegateResultPath = delegate.stdout
    .trim()
    .split(/\r?\n/)
    .map((line) => line.trim())
    .reverse()
    .find((line) => line.endsWith("/result.json") || line.endsWith("\\result.json"));
  const delegateResult = delegateResultPath ? readJson(delegateResultPath) : null;
  const outputDir =
    delegateResult?.evidence?.outputDir ||
    delegateResult?.outputDir ||
    latestEvidenceDir(outputRoot);
  const missingScreenshots = outputDir
    ? REQUIRED_SCREENSHOTS.filter((file) => !existsSync(join(outputDir, file)))
    : REQUIRED_SCREENSHOTS;
  const delegateProof = outputDir
    ? readJson(join(outputDir, "model-mounting-daemon-runtime-adapter-proof.json"))
    : null;
  const boundary = delegateProof?.evidence?.boundaries ?? delegateProof?.boundaries ?? {};
  const uxProof = {
    schemaVersion: "ioi.autopilot.models-lm-studio-ux-proof.v1",
    generatedAt: new Date().toISOString(),
    outputDir,
    requiredScreenshots: REQUIRED_SCREENSHOTS,
    missingScreenshots,
    delegatedHarness: compact(delegate),
    delegateResultOk: delegateResult?.ok === true,
    boundary,
    assertions: {
      modelsEditorSurface: missingScreenshots.length === 0,
      tableInspectorShape: preflight.evidence.checks.find((check) => check.id === "implementation:models-lm-studio-ux")?.ok === true,
      daemonOwnedRuntime: boundary.daemonBackedCatalog === true && boundary.webviewDirectModelExecution === false,
      workflowRouteBinding: boundary.daemonBackedWorkflowRun === true,
      noTauri: boundary.tauriUsed === false,
    },
  };
  if (outputDir) {
    writeFileSync(
      join(outputDir, "models-lm-studio-ux-proof.json"),
      `${JSON.stringify(uxProof, null, 2)}\n`,
    );
  }
  const ok =
    delegate.ok &&
    delegateResult?.ok === true &&
    missingScreenshots.length === 0 &&
    Object.values(uxProof.assertions).every(Boolean);
  return {
    id: "gui:models-lm-studio-ux",
    ok,
    summary: ok
      ? "Electron Models launched through the harness and captured LM Studio-inspired UX evidence"
      : "Electron Models LM Studio-inspired UX validation failed",
    evidence: {
      outputDir,
      missingScreenshots,
      delegatedHarness: compact(delegate),
      delegateResultPath,
      delegateResultOk: delegateResult?.ok === true,
      assertions: uxProof.assertions,
      proofPath: outputDir ? join(outputDir, "models-lm-studio-ux-proof.json") : null,
    },
  };
}

function writeResult(outputRoot, result) {
  const outputDir = resolve(repoRoot, outputRoot, timestamp());
  mkdirSync(outputDir, { recursive: true });
  const resultPath = join(outputDir, "result.json");
  writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
  const icon = result.ok ? "PASS" : "FAIL";
  console.log(`${icon} ${result.summary}`);
  console.log(`Evidence: ${resultPath}`);
  process.exitCode = result.ok ? 0 : 1;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  mkdirSync(resolve(repoRoot, args.outputRoot), { recursive: true });
  if (args.preflight) {
    runPreflight({ outputRoot: args.outputRoot, write: true });
    return;
  }
  if (args.run) {
    writeResult(args.outputRoot, runGuiValidation(args.outputRoot));
  }
}

main();
