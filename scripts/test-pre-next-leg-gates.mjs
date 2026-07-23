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
    "m0-program-control",
    "architecture-contract-bar",
    "system-genesis-compiler",
    "program-state-generator-regressions",
    "stateless-master-guide",
    "work-items",
    "architecture-docs",
    "canon-to-code-delta",
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
