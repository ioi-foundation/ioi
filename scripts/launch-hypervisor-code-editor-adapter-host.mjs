#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  HYPERVISOR_CODE_EDITOR_ADAPTER_HOST,
  envFlag,
  syncCodeEditorExtensionTargets,
} from "./lib/hypervisor-code-editor-adapter-host-paths.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

const binary = HYPERVISOR_CODE_EDITOR_ADAPTER_HOST.binary;
const extensionSyncEnabled = !envFlag("HYPERVISOR_SKIP_EXTENSION_SYNC");
const args = process.argv.slice(2);
const launchArgs = args.length > 0 ? args : [repoRoot];

if (!existsSync(binary)) {
  console.error(
    `Hypervisor Code editor adapter host binary not found at ${binary}. Set HYPERVISOR_CODE_EDITOR_VSCODE_FORK_BIN to override.`,
  );
  process.exit(1);
}

function syncCodeEditorAdapterExtension() {
  if (!extensionSyncEnabled) return;
  const sync = syncCodeEditorExtensionTargets();
  const copied = sync.copied.map((target) => target.kind).join(", ");
  const skipped = sync.skipped.map((target) => target.kind).join(", ");
  console.log(
    `[Hypervisor Code Editor Adapter] Synced ioi-code-editor-adapter extension into ${copied}.` +
      (skipped ? ` Skipped optional ${skipped}.` : ""),
  );
}

syncCodeEditorAdapterExtension();

const child = spawn(binary, launchArgs, {
  cwd: repoRoot,
  env: {
    ...process.env,
    IOI_HYPERVISOR_CODE_EDITOR_ADAPTER_HOST: "vscode-electron-packaged-host",
    IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-code-editor-adapter-host",
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
