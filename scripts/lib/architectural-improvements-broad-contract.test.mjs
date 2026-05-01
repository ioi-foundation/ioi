import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("architectural improvements broad execution-surface guardrail passes", () => {
  const result = spawnSync("node", ["scripts/check-execution-surface-leg.mjs"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});

test("execution-surface evidence records every master-guide checklist lane", () => {
  const checklistPath = path.join(
    root,
    "docs/evidence/architectural-improvements-broad/checklist.json",
  );
  const report = JSON.parse(fs.readFileSync(checklistPath, "utf8"));
  assert.equal(report.status, "passed");
  const ids = new Set(report.checklist.map((item) => item.id));
  for (const id of [
    "A1",
    "A2",
    "B1",
    "B2",
    "B3",
    "C1",
    "C2",
    "C3",
    "D1",
    "E1",
    "F1",
    "G1",
    "H1",
    "I1",
    "I2",
    "J1",
    "K1",
    "L1",
    "M1",
    "Z1",
    "Z2",
  ]) {
    assert.ok(ids.has(id), `missing checklist lane ${id}`);
  }
});
