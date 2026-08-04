import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  PRE_NEXT_LEG_COMMANDS,
  runPreNextLeg,
} from "./check-pre-next-leg.mjs";

const pinnedRuntimeActionCheck = {
  id: "runtime-action-generator-check",
  command: process.execPath,
  args: ["scripts/generate-runtime-action-contracts.mjs", "--check"],
};

const NODE = process.execPath;

// PIN DATA LIVES HERE, NOT IN THE THING IT PINS.
//
// The previous pin derived its expectations by spreading
// PRE_NEXT_LEG_COMMANDS, and asserted only the ID sequence. Removal therefore
// failed, but REDIRECTION passed: swapping a gate's argv for a successful
// no-op left the ids identical and the derived lookup matched itself. Codex
// proved it by replacing both attestation commands with `node -e` no-ops and
// getting 3/3 green.
//
// A pin computed from its subject is not a pin. These vectors are literal, so
// changing what a gate actually EXECUTES fails here regardless of whether its
// id survives.
const PINNED_GATE_VECTORS = Object.freeze([
  { id: "runtime-action-generator-regressions", command: NODE, args: ["--test","scripts/test-runtime-action-contract-generator.mjs"] },
  { id: "pre-next-leg-gate-regressions", command: NODE, args: ["--test","scripts/test-pre-next-leg-gates.mjs"] },
  { id: "hypervisor-ported-seed-invariant", command: "npm", args: ["run","check:hypervisor-ported-seed"] },
  { id: "m0-program-control", command: "npm", args: ["run","check:m0-program-control"] },
  { id: "architecture-contract-bar", command: "npm", args: ["run","check:architecture-contract-bar"] },
  { id: "agentgres-ref-minting-boundary", command: NODE, args: ["scripts/check-agentgres-ref-minting.mjs"] },
  { id: "shared-schema-def-byte-identity", command: NODE, args: ["scripts/check-shared-schema-defs.mjs"] },
  { id: "attestation-chain-append-only", command: NODE, args: ["scripts/check-attestation-chain.mjs"] },
  { id: "attestation-chain-integration", command: NODE, args: ["scripts/test-attestation-chain-integration.mjs"] },
  { id: "program-state-regeneration-order", command: NODE, args: ["internal-docs/implementation/tools/regenerate-program-state.mjs"] },
  { id: "claims-coverage", command: NODE, args: ["internal-docs/implementation/tools/check-claims-coverage.mjs"] },
  { id: "tracked-caller-census", command: NODE, args: ["internal-docs/implementation/tools/check-tracked-callers.mjs"] },
  { id: "internal-architecture-headers", command: NODE, args: ["scripts/check-internal-architecture-headers.mjs"] },
  { id: "discovery-exclusions", command: NODE, args: ["scripts/check-discovery-exclusions.mjs"] },
  { id: "adoption-completeness", command: NODE, args: ["scripts/check-adoption-completeness.mjs"] },
  { id: "system-genesis-compiler", command: "npm", args: ["run","check:system-genesis-compiler"] },
  { id: "architecture-docs", command: "npm", args: ["run","check:architecture-docs"] },
  { id: "work-items", command: "npm", args: ["run","check:work-items"] },
  { id: "conformance-docs", command: "npm", args: ["run","check:conformance-docs"] },
  { id: "readiness", command: NODE, args: ["scripts/check-pre-next-leg-readiness.mjs"] },
  { id: "compositor", command: "npm", args: ["run","hypervisor-conformance:compositor"] },
  { id: "runtime-layout", command: "npm", args: ["run","check:runtime-layout"] },
]);

test("pre-next-leg gate vectors are pinned independently of the production list", () => {
  const actual = PRE_NEXT_LEG_COMMANDS.map((c) => ({
    id: c.id,
    command: c.command === NODE ? "NODE" : c.command,
    args: [...c.args],
  }));
  const expected = PINNED_GATE_VECTORS.map((c) => ({
    id: c.id,
    command: c.command === NODE ? "NODE" : c.command,
    args: [...c.args],
  }));
  assert.deepEqual(
    actual,
    expected,
    "a gate's executable or argv changed; the pin is literal so redirection to a no-op fails here even when the id survives",
  );
});

test("pre-next-leg propagates a compositor-tier failure", () => {
  const seen = [];
  const expectedCommands = [
    pinnedRuntimeActionCheck,
    ...PRE_NEXT_LEG_COMMANDS,
  ];
  const status = runPreNextLeg({
    commands: PRE_NEXT_LEG_COMMANDS,
    runCommand(command, args) {
      const step = expectedCommands.find(
        (candidate) =>
          candidate.command === command &&
          candidate.args.length === args.length &&
          candidate.args.every((argument, index) => argument === args[index]),
      );
      assert.ok(step, `unrecognized command fixture: ${command} ${args.join(" ")}`);
      seen.push(step.id);
      return { status: step.id === "compositor" ? 23 : 0 };
    },
  });

  assert.equal(status, 23);
  assert.deepEqual(seen, [
    "runtime-action-generator-check",
    "runtime-action-generator-regressions",
    "pre-next-leg-gate-regressions",
    "hypervisor-ported-seed-invariant",
    "m0-program-control",
    "architecture-contract-bar",
    "agentgres-ref-minting-boundary",
    "shared-schema-def-byte-identity",
    "attestation-chain-append-only",
    "attestation-chain-integration",
    "program-state-regeneration-order",
    "claims-coverage",
    "tracked-caller-census",
    "internal-architecture-headers",
    "discovery-exclusions",
    "system-genesis-compiler",
    "architecture-docs",
    "work-items",
    "conformance-docs",
    "readiness",
    "compositor",
  ]);
  assert.equal(seen.includes("runtime-layout"), false);
});

test("pre-next-leg pins check mode ahead of a missing or altered regression flag", () => {
  assert.equal(
    PRE_NEXT_LEG_COMMANDS.some(
      (step) =>
        step.args[0] === "scripts/generate-runtime-action-contracts.mjs",
    ),
    false,
    "the regression command list must not own the pinned generator check",
  );
  const sourceRoot = path.resolve(import.meta.dirname, "..");
  for (const [id, alteredArgs] of [
    ["missing-mode", ["scripts/generate-runtime-action-contracts.mjs"]],
    [
      "write-mode",
      ["scripts/generate-runtime-action-contracts.mjs", "--write"],
    ],
  ]) {
    const temporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), `ioi-pre-next-${id}-`),
    );
    try {
      for (const relativePath of [
        "scripts/generate-runtime-action-contracts.mjs",
        "scripts/lib/repository-path-boundary.mjs",
        "docs/architecture/_meta/schemas/runtime-action-schema.json",
        "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
        "crates/types/src/app/generated/runtime_action_schema.rs",
      ]) {
        const target = path.join(temporaryRoot, relativePath);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(path.join(sourceRoot, relativePath), target);
      }
      const guardedTarget = path.join(
        temporaryRoot,
        "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
      );
      const guardedBytes = Buffer.from("intentionally-stale-generated-bytes\n");
      fs.writeFileSync(guardedTarget, guardedBytes);
      const status = runPreNextLeg({
        cwd: temporaryRoot,
        commands: [
          {
            id: `altered-regression-${id}`,
            command: process.execPath,
            args: alteredArgs,
          },
        ],
        runCommand: spawnSync,
      });
      assert.notEqual(status, 0, `${id}: stale check unexpectedly passed`);
      assert.deepEqual(
        fs.readFileSync(guardedTarget),
        guardedBytes,
        `${id}: altered orchestration reached a write action`,
      );
    } finally {
      fs.rmSync(temporaryRoot, { force: true, recursive: true });
    }
  }
});

test("conformance help cannot mask compositor or unknown flags", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const result = spawnSync(
    process.execPath,
    [
      "scripts/conformance/hypervisor-conformance.mjs",
      "compositor",
      "--help",
      "--bogus",
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stdout}\n${result.stderr}`,
    /Unknown hypervisor conformance tier: --help, --bogus/u,
  );
});
