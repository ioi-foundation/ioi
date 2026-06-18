#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  envFlag,
  syncWorkbenchExtensionTargets,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

const binary = HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary;
const extensionSyncEnabled = !envFlag("HYPERVISOR_SKIP_EXTENSION_SYNC");
const args = process.argv.slice(2);
const launchArgs = args.length > 0 ? args : [repoRoot];

if (!existsSync(binary)) {
  console.error(
    `Hypervisor Workbench adapter host binary not found at ${binary}. Set HYPERVISOR_WORKBENCH_VSCODE_FORK_BIN to override.`,
  );
  process.exit(1);
}

function syncCodeEditorAdapterExtension() {
  if (!extensionSyncEnabled) return;
  const sync = syncWorkbenchExtensionTargets();
  const copied = sync.copied.map((target) => target.kind).join(", ");
  const skipped = sync.skipped.map((target) => target.kind).join(", ");
  console.log(
    `[Hypervisor Workbench Adapter] Synced ioi-code-editor-adapter extension into ${copied}.` +
      (skipped ? ` Skipped optional ${skipped}.` : ""),
  );
}

syncCodeEditorAdapterExtension();

const child = spawn(binary, launchArgs, {
  cwd: repoRoot,
  env: {
    ...process.env,
    IOI_HYPERVISOR_WORKBENCH_ADAPTER_HOST: "vscode-electron-packaged-host",
    IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-workbench-adapter-host",
  },
  stdio: "inherit",
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
