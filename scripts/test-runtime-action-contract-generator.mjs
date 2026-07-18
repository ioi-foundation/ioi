import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const generator = "scripts/generate-runtime-action-contracts.mjs";
const generatedTargets = [
  "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
  "crates/types/src/app/generated/runtime_action_schema.rs",
];

test("runtime-action generator rejects every accidental CLI mode before writes", () => {
  const before = new Map(
    generatedTargets.map((relative) => [
      relative,
      fs.readFileSync(path.join(root, relative)),
    ]),
  );
  for (const args of [
    ["--chekc"],
    ["--help"],
    ["--check", "--bogus"],
    ["--check", "--check"],
  ]) {
    const result = spawnSync(process.execPath, [generator, ...args], {
      cwd: root,
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0, `accepted ${args.join(" ")}`);
    assert.match(
      `${result.stdout}\n${result.stderr}`,
      /Unsupported runtime-action generator arguments/u,
    );
    for (const relative of generatedTargets) {
      assert.deepEqual(
        fs.readFileSync(path.join(root, relative)),
        before.get(relative),
        `${relative} changed after rejecting ${args.join(" ")}`,
      );
    }
  }
});

test("runtime-action generator check mode remains deliberate and read-only", () => {
  const before = new Map(
    generatedTargets.map((relative) => [
      relative,
      fs.readFileSync(path.join(root, relative)),
    ]),
  );
  const result = spawnSync(process.execPath, [generator, "--check"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  for (const relative of generatedTargets) {
    assert.deepEqual(
      fs.readFileSync(path.join(root, relative)),
      before.get(relative),
    );
  }
});
