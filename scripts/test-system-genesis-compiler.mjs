import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const sourcePolicyPath = path.join(
  root,
  "crates/types/tests/system_genesis_source_policy.rs",
);

test("syntax-aware purity policy carries alias and fake-marker regressions", () => {
  const source = fs.readFileSync(sourcePolicyPath, "utf8");
  assert.match(source, /use std::\{fs as disk\}/u);
  assert.match(source, /fake_marker/u);
  assert.match(source, /comment text must not truncate production analysis/u);
  assert.match(source, /ALLOWED_PRODUCTION_IMPORTS/u);
});

test("compiler verifier accepts only explicit check mode", () => {
  const verifier = "scripts/check-system-genesis-compiler.mjs";
  for (const args of [[], ["--write"], ["--check", "--bogus"]]) {
    const result = spawnSync(process.execPath, [verifier, ...args], {
      cwd: root,
      encoding: "utf8",
    });
    assert.equal(result.status, 2, `unexpected status for ${args.join(" ")}`);
    assert.match(result.stderr, /Usage:/u);
  }
  const checked = spawnSync(process.execPath, [verifier, "--check"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(checked.status, 0, checked.stderr);
  assert.match(
    checked.stdout,
    /"purity_verifier": "rust_syn_production_item_and_import_analysis"/u,
  );
  assert.match(checked.stdout, /"adversarial_cases": 93/u);
});
