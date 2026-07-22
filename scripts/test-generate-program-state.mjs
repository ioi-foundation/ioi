#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";

import { discoverWorkItems } from "./generate-program-state.mjs";

const WORK_ITEM_DIR = "docs/architecture/_meta/work-items";

const git = (repoRoot, ...args) =>
  execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

const writeRecord = (
  repoRoot,
  {
    file = "cut-a.v1.json",
    workItemId = "cut-a",
    status,
    objective = "Exercise current-cut discovery.",
  },
) => {
  const directory = path.join(repoRoot, WORK_ITEM_DIR);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(
    path.join(directory, file),
    `${JSON.stringify(
      {
        evidence_format: "ioi.program.work_item.v1",
        work_item_id: workItemId,
        stage_id: "M1",
        status,
        objective,
        last_status_transaction: "2026-07-22",
      },
      null,
      2,
    )}\n`,
  );
};

const commitAll = (repoRoot, message) => {
  git(repoRoot, "add", WORK_ITEM_DIR);
  git(repoRoot, "commit", "-m", message);
};

test("current-cut discovery accepts zero or multiple ongoing cuts", (t) => {
  const repoRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-program-state-discovery-"),
  );
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));

  git(repoRoot, "init", "--initial-branch=master");
  git(repoRoot, "config", "user.name", "Program State Test");
  git(repoRoot, "config", "user.email", "program-state@example.invalid");

  writeRecord(repoRoot, { status: "proposed" });
  commitAll(repoRoot, "proposed cut");
  assert.deepEqual(discoverWorkItems(repoRoot).current_cuts, []);

  git(repoRoot, "switch", "-c", "feat/cut-a");
  writeRecord(repoRoot, { status: "active" });
  commitAll(repoRoot, "activate cut");
  let discovery = discoverWorkItems(repoRoot);
  assert.equal(discovery.current_cuts[0].record.work_item_id, "cut-a");
  assert.equal(discovery.current_cuts[0].record.status, "active");
  assert.equal(discovery.current_cuts[0].branch, "feat/cut-a");

  writeRecord(repoRoot, { status: "evidence_ready" });
  commitAll(repoRoot, "prepare evidence");
  discovery = discoverWorkItems(repoRoot);
  assert.equal(discovery.current_cuts[0].record.work_item_id, "cut-a");
  assert.equal(discovery.current_cuts[0].record.status, "evidence_ready");

  git(repoRoot, "switch", "-c", "feat/conflict", "master");
  writeRecord(repoRoot, {
    status: "active",
    objective: "A conflicting live body for the same cut.",
  });
  commitAll(repoRoot, "conflicting cut body");
  assert.throws(
    () => discoverWorkItems(repoRoot),
    /ongoing work item cut-a has conflicting record bodies/u,
  );

  git(repoRoot, "switch", "master");
  git(repoRoot, "branch", "-D", "feat/conflict");

  git(repoRoot, "branch", "feat/alias", "feat/cut-a");
  git(repoRoot, "switch", "feat/alias");
  assert.throws(
    () => discoverWorkItems(repoRoot),
    /ongoing work item cut-a is exposed by ambiguous branch names: feat\/alias, feat\/cut-a/u,
  );
  git(repoRoot, "switch", "master");
  git(repoRoot, "branch", "-D", "feat/alias");

  git(repoRoot, "switch", "-c", "feat/other");
  writeRecord(repoRoot, {
    file: "cut-b.v1.json",
    workItemId: "cut-b",
    status: "active",
  });
  commitAll(repoRoot, "second ongoing cut");
  discovery = discoverWorkItems(repoRoot);
  assert.deepEqual(
    discovery.current_cuts.map(({ record, branch }) => ({
      work_item_id: record.work_item_id,
      status: record.status,
      branch,
    })),
    [
      {
        work_item_id: "cut-a",
        status: "evidence_ready",
        branch: "feat/cut-a",
      },
      { work_item_id: "cut-b", status: "active", branch: "feat/other" },
    ],
  );
});

test("descendant refs inheriting an unchanged ongoing record do not reassign it", (t) => {
  const repoRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-program-state-inherited-ref-"),
  );
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));

  git(repoRoot, "init", "--initial-branch=master");
  git(repoRoot, "config", "user.name", "Program State Test");
  git(repoRoot, "config", "user.email", "program-state@example.invalid");
  writeRecord(repoRoot, { status: "proposed" });
  commitAll(repoRoot, "proposed cut");

  git(repoRoot, "switch", "-c", "feat/cut-a");
  writeRecord(repoRoot, { status: "evidence_ready" });
  commitAll(repoRoot, "prepare evidence");
  git(repoRoot, "switch", "master");
  git(repoRoot, "merge", "--ff-only", "feat/cut-a");
  fs.writeFileSync(path.join(repoRoot, "master-followup.txt"), "followup\n");
  git(repoRoot, "add", "master-followup.txt");
  git(repoRoot, "commit", "-m", "advance master without changing the record");

  const discovery = discoverWorkItems(repoRoot);
  assert.equal(discovery.current_cuts.length, 1);
  assert.equal(discovery.current_cuts[0].record.work_item_id, "cut-a");
  assert.equal(discovery.current_cuts[0].branch, "feat/cut-a");
  assert.deepEqual(discovery.current_cuts[0].source_refs, ["feat/cut-a"]);
});
