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
    id: "hypervisor-ported-seed-invariant",
    command: "npm",
    args: Object.freeze(["run", "check:hypervisor-ported-seed"]),
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
    id: "agentgres-ref-minting-boundary",
    command: process.execPath,
    args: Object.freeze(["scripts/check-agentgres-ref-minting.mjs"]),
  }),
  Object.freeze({
    id: "shared-schema-def-byte-identity",
    command: process.execPath,
    args: Object.freeze(["scripts/check-shared-schema-defs.mjs"]),
  }),
  // Wired 2026-08-03. This bar existed for three rounds with NO tracked caller
  // -- a manually retained log is not a per-push control, and a control nobody
  // runs is documentation. That is the written-but-unenforced class this
  // program already filed a successor about
  // (m0-nonenforcing-check-closure-successor), recurring in a bar built inside
  // this very cut.
  Object.freeze({
    id: "attestation-chain-append-only",
    command: process.execPath,
    args: Object.freeze(["scripts/check-attestation-chain.mjs"]),
  }),
  Object.freeze({
    id: "attestation-chain-integration",
    command: process.execPath,
    args: Object.freeze(["scripts/test-attestation-chain-integration.mjs"]),
  }),
  Object.freeze({
    id: "program-state-regeneration-order",
    command: process.execPath,
    args: Object.freeze(["internal-docs/implementation/tools/regenerate-program-state.mjs"]),
  }),
  Object.freeze({
    id: "claims-coverage",
    command: process.execPath,
    args: Object.freeze(["internal-docs/implementation/tools/check-claims-coverage.mjs"]),
  }),
  Object.freeze({
    id: "tracked-caller-census",
    command: process.execPath,
    args: Object.freeze(["internal-docs/implementation/tools/check-tracked-callers.mjs"]),
  }),
  Object.freeze({
    id: "internal-architecture-headers",
    command: process.execPath,
    args: Object.freeze(["scripts/check-internal-architecture-headers.mjs"]),
  }),
  Object.freeze({
    id: "discovery-exclusions",
    command: process.execPath,
    args: Object.freeze(["scripts/check-discovery-exclusions.mjs"]),
  }),
  // Wired the day the census caught it uncalled. The completeness bar is the
  // strongest single claim the QM cut makes -- the adopted tree is upstream
  // bytes, exactly, in both directions -- and an unwired bar making the
  // strongest claim is the worst possible thing to leave as documentation.
  Object.freeze({
    id: "packet-convention-ratchet-integration",
    command: process.execPath,
    args: Object.freeze(["scripts/test-packet-convention-ratchet-integration.mjs"]),
  }),
  Object.freeze({
    id: "adoption-completeness",
    command: process.execPath,
    args: Object.freeze(["scripts/check-adoption-completeness.mjs"]),
  }),
  Object.freeze({
    id: "system-genesis-compiler",
    command: "npm",
    args: Object.freeze(["run", "check:system-genesis-compiler"]),
  }),
  Object.freeze({
    id: "architecture-docs",
    command: "npm",
    args: Object.freeze(["run", "check:architecture-docs"]),
  }),
  Object.freeze({
    id: "work-items",
    command: "npm",
    args: Object.freeze(["run", "check:work-items"]),
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
