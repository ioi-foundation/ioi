#!/usr/bin/env node
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { validateCursorSdkParity } from "./lib/cursor-sdk-parity-contract.mjs";

const repoRoot = process.cwd();
const evidenceDir = path.join(
  repoRoot,
  "docs",
  "evidence",
  "cursor-sdk-parity",
  new Date().toISOString().replace(/[:.]/g, "-"),
);

run("npm", ["run", "build", "--workspace=@ioi/agent-sdk"]);
const result = await validateCursorSdkParity({ repoRoot, evidenceDir });
writeGuiBlockerIfNeeded(evidenceDir);
console.log(JSON.stringify({ status: result.status, evidenceDir }, null, 2));
if (!result.checks.every((check) => check.pass)) {
  process.exitCode = 1;
}

function run(command, args) {
  const result = childProcess.spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed`);
  }
}

function writeGuiBlockerIfNeeded(targetDir) {
  const guiEvidence = {
    lane: "autopilot_gui_retained_query_validation",
    status: process.env.DISPLAY || process.env.WAYLAND_DISPLAY ? "not_run_by_this_script" : "blocked",
    command:
      "AUTOPILOT_LOCAL_GPU_DEV=1 npm run validate:autopilot-gui-harness:run -- --window-timeout-ms 300000",
    environmentChecked: ["DISPLAY", "WAYLAND_DISPLAY", "AUTOPILOT_LOCAL_GPU_DEV"],
    reason:
      process.env.DISPLAY || process.env.WAYLAND_DISPLAY
        ? "Display appears available; run the GUI command separately for screenshot evidence."
        : "No desktop display variable was available to this non-interactive validation process.",
  };
  fs.writeFileSync(path.join(targetDir, "gui-validation-blocker.json"), `${JSON.stringify(guiEvidence, null, 2)}\n`);
}
