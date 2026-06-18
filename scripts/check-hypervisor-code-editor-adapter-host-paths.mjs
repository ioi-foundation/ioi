#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const absentForkRoot = mkdtempSync(
  "/tmp/hypervisor-vscode-adapter-source-absent-",
);
rmSync(absentForkRoot, { recursive: true, force: true });

process.env.HYPERVISOR_CODE_EDITOR_VSCODE_FORK_ROOT = absentForkRoot;

const { HYPERVISOR_CODE_EDITOR_ADAPTER_HOST, syncCodeEditorExtensionTargets } =
  await import("./lib/hypervisor-code-editor-adapter-host-paths.mjs");

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
      HYPERVISOR_CODE_EDITOR_VSCODE_FORK_ROOT: absentForkRoot,
    },
  });
  if (result.status !== 0) {
    fail(
      `${script} does not parse without source fork env: ${result.stderr || result.stdout}`,
    );
  }
}

if (existsSync(absentForkRoot)) {
  fail(`Absent fork simulation path unexpectedly exists: ${absentForkRoot}`);
}

if (HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.forkRoot !== absentForkRoot) {
  fail(
    `Helper did not honor HYPERVISOR_CODE_EDITOR_VSCODE_FORK_ROOT=${absentForkRoot}`,
  );
}

if (!existsSync(HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.extensionSource)) {
  fail(
    `Canonical ioi-code-editor-adapter source is missing: ${HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.extensionSource}`,
  );
}

let sync = null;
try {
  sync = syncCodeEditorExtensionTargets();
} catch (error) {
  fail(
    `Packaged extension sync failed without source fork: ${error?.message || error}`,
  );
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

const packagedExtension = join(
  HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.packagedCodeEditorTarget,
  "extension.js",
);
if (!existsSync(packagedExtension)) {
  fail(
    `Packaged ioi-code-editor-adapter extension missing after sync: ${packagedExtension}`,
  );
}

if (String(HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.packagedRoot).includes("/ide/")) {
  fail(
    `Packaged root must not fall back to retired root ide/ path: ${HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.packagedRoot}`,
  );
}

if (String(HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.forkRoot).includes("/ide/")) {
  fail(
    `Fork root must not fall back to retired root ide/ path: ${HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.forkRoot}`,
  );
}

for (const script of ["scripts/launch-hypervisor-code-editor-adapter-host.mjs"]) {
  runNodeCheck(script);
}

const launchScript = readFileSync(
  join(repoRoot, "scripts/launch-hypervisor-code-editor-adapter-host.mjs"),
  "utf8",
);
const legacySiblingForkPath = ["..", "vscode"].join("/");
if (launchScript.includes(legacySiblingForkPath)) {
  fail(
    "Launch script still directly references a legacy sibling VS Code path instead of the optional path helper.",
  );
}

if (failures.length > 0) {
  console.error("Hypervisor Code editor adapter host path check failed:");
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
      binary: HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.binary,
      binaryPresent: existsSync(HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.binary),
      packagedCodeEditorTarget:
        HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.packagedCodeEditorTarget,
      copied: sync?.copied ?? [],
      skipped: sync?.skipped ?? [],
    },
    null,
    2,
  ),
);
