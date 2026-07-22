#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(scriptPath), "..");

const PINNED_RUNTIME_ACTION_GENERATOR_CHECK = Object.freeze({
  id: "runtime-action-generator-check",
  command: process.execPath,
  args: Object.freeze([
    "scripts/generate-runtime-action-contracts.mjs",
    "--check",
  ]),
});

export const PRE_NEXT_LEG_COMMANDS = Object.freeze([
  Object.freeze({
    id: "runtime-action-generator-regressions",
    command: process.execPath,
    args: Object.freeze([
      "--test",
      "scripts/test-runtime-action-contract-generator.mjs",
    ]),
  }),
  Object.freeze({
    id: "pre-next-leg-gate-regressions",
    command: process.execPath,
    args: Object.freeze(["--test", "scripts/test-pre-next-leg-gates.mjs"]),
  }),
  Object.freeze({
    id: "m0-program-control",
    command: "npm",
    args: Object.freeze(["run", "check:m0-program-control"]),
  }),
  Object.freeze({
    id: "architecture-contract-bar",
    command: "npm",
    args: Object.freeze(["run", "check:architecture-contract-bar"]),
  }),
  Object.freeze({
    id: "system-genesis-compiler",
    command: "npm",
    args: Object.freeze(["run", "check:system-genesis-compiler"]),
  }),
  Object.freeze({
    id: "program-state-generator-regressions",
    command: process.execPath,
    args: Object.freeze([
      "--test",
      "scripts/test-generate-program-state.mjs",
    ]),
  }),
  Object.freeze({
    id: "stateless-master-guide",
    command: "npm",
    args: Object.freeze(["run", "check:stateless-master-guide"]),
  }),
  Object.freeze({
    id: "work-items",
    command: "npm",
    args: Object.freeze(["run", "check:work-items"]),
  }),
  Object.freeze({
    id: "architecture-docs",
    command: "npm",
    args: Object.freeze(["run", "check:architecture-docs"]),
  }),
  Object.freeze({
    id: "canon-to-code-delta",
    command: "npm",
    args: Object.freeze(["run", "check:canon-to-code-delta"]),
  }),
  Object.freeze({
    id: "conformance-docs",
    command: "npm",
    args: Object.freeze(["run", "check:conformance-docs"]),
  }),
  Object.freeze({
    id: "readiness",
    command: process.execPath,
    args: Object.freeze(["scripts/check-pre-next-leg-readiness.mjs"]),
  }),
  Object.freeze({
    id: "compositor",
    command: "npm",
    args: Object.freeze(["run", "hypervisor-conformance:compositor"]),
  }),
  Object.freeze({
    id: "runtime-layout",
    command: "npm",
    args: Object.freeze(["run", "check:runtime-layout"]),
  }),
]);

export function runPreNextLeg({
  cwd = root,
  commands = PRE_NEXT_LEG_COMMANDS,
  runCommand = spawnSync,
} = {}) {
  for (const command of [
    PINNED_RUNTIME_ACTION_GENERATOR_CHECK,
    ...commands,
  ]) {
    const result = runCommand(command.command, [...command.args], {
      cwd,
      env: process.env,
      stdio: "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) return result.status ?? 1;
  }
  return 0;
}

if (path.resolve(process.argv[1] ?? "") === scriptPath) {
  process.exitCode = runPreNextLeg();
}
