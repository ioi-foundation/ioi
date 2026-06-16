#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const absentForkRoot = mkdtempSync("/tmp/autopilot-vscode-source-absent-");
rmSync(absentForkRoot, { recursive: true, force: true });

process.env.AUTOPILOT_VSCODE_FORK_ROOT = absentForkRoot;

const {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} = await import("./lib/autopilot-electron-app-paths.mjs");

const failures = [];

function fail(message) {
  failures.push(message);
}

function runNodeCheck(script) {
  const result = spawnSync("node", ["--check", script], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      AUTOPILOT_VSCODE_FORK_ROOT: absentForkRoot,
    },
  });
  if (result.status !== 0) {
    fail(`${script} does not parse without source fork env: ${result.stderr || result.stdout}`);
  }
}

if (existsSync(absentForkRoot)) {
  fail(`Absent fork simulation path unexpectedly exists: ${absentForkRoot}`);
}

if (AUTOPILOT_ELECTRON.forkRoot !== absentForkRoot) {
  fail(`Helper did not honor AUTOPILOT_VSCODE_FORK_ROOT=${absentForkRoot}`);
}

if (!existsSync(AUTOPILOT_ELECTRON.binary)) {
  fail(`Packaged Autopilot binary is missing: ${AUTOPILOT_ELECTRON.binary}`);
}

if (!existsSync(AUTOPILOT_ELECTRON.extensionSource)) {
  fail(`Canonical ioi-workbench source is missing: ${AUTOPILOT_ELECTRON.extensionSource}`);
}

let sync = null;
try {
  sync = syncWorkbenchExtensionTargets();
} catch (error) {
  fail(`Packaged extension sync failed without source fork: ${error?.message || error}`);
}

if (sync) {
  const copiedKinds = sync.copied.map((target) => target.kind);
  const skippedKinds = sync.skipped.map((target) => target.kind);
  if (!copiedKinds.includes("packaged-app")) {
    fail(`Packaged app was not synced: ${JSON.stringify(sync)}`);
  }
  if (!skippedKinds.includes("source-fork")) {
    fail(`Source fork was not treated as optional: ${JSON.stringify(sync)}`);
  }
}

const packagedExtension = join(AUTOPILOT_ELECTRON.packagedWorkbenchTarget, "extension.js");
if (!existsSync(packagedExtension)) {
  fail(`Packaged ioi-workbench extension missing after sync: ${packagedExtension}`);
}

for (const script of [
  "scripts/launch-hypervisor-workbench-adapter-host.mjs",
  "scripts/run-autopilot-ux-readiness-goal.mjs",
  "scripts/run-autopilot-workflow-compositor-parity-goal.mjs",
  "scripts/run-autopilot-model-mounting-goal.mjs",
  "scripts/run-autopilot-models-production-polish-goal.mjs",
]) {
  runNodeCheck(script);
}

const launchScript = readFileSync(
  join(repoRoot, "scripts/launch-hypervisor-workbench-adapter-host.mjs"),
  "utf8",
);
const legacySiblingForkPath = ["..", "vscode"].join("/");
if (launchScript.includes(legacySiblingForkPath)) {
  fail("Launch script still directly references a legacy sibling VS Code path instead of the optional path helper.");
}

if (failures.length > 0) {
  console.error("Autopilot Electron source-fork optionality check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      absentForkRoot,
      binary: AUTOPILOT_ELECTRON.binary,
      packagedWorkbenchTarget: AUTOPILOT_ELECTRON.packagedWorkbenchTarget,
      copied: sync?.copied ?? [],
      skipped: sync?.skipped ?? [],
    },
    null,
    2,
  ),
);
