import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
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
    [],
    ["--chekc"],
    ["--help"],
    ["--help", "--bogus"],
    ["--write", "--check"],
    ["--write", "--write"],
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
      /Supported invocations are exactly --write or --check/u,
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

test("runtime-action write rejects a dangling final symlink before external output", () => {
  const temporaryParent = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-runtime-action-dangling-symlink-"),
  );
  const temporaryRoot = path.join(temporaryParent, "repo");
  const externalTarget = path.join(temporaryParent, "external-action-schema.ts");
  try {
    for (const relativePath of [
      generator,
      "scripts/lib/repository-path-boundary.mjs",
      "docs/architecture/_meta/schemas/runtime-action-schema.json",
    ]) {
      const target = path.join(temporaryRoot, relativePath);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(root, relativePath), target);
    }
    const danglingTarget = path.join(temporaryRoot, generatedTargets[0]);
    fs.mkdirSync(path.dirname(danglingTarget), { recursive: true });
    fs.symlinkSync(externalTarget, danglingTarget, "file");

    const result = spawnSync(process.execPath, [generator, "--write"], {
      cwd: temporaryRoot,
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(
      `${result.stdout}\n${result.stderr}`,
      /symlink component/u,
    );
    assert.equal(
      fs.existsSync(externalTarget),
      false,
      "dangling final symlink must not create an external target",
    );
    assert.equal(
      fs.existsSync(path.join(temporaryRoot, generatedTargets[1])),
      false,
      "path preflight must fail before writing another generated target",
    );
  } finally {
    fs.rmSync(temporaryParent, { force: true, recursive: true });
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
