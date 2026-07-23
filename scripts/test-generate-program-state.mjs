#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  WORK_ITEM_DIR,
  discoverWorkItems,
} from "./generate-program-state.mjs";

const writeRecord = (
  repoRoot,
  {
    file = "cut-a.v1.json",
    workItemId = "cut-a",
    status,
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
        objective: "Exercise private current-cut discovery.",
        last_status_transaction: "2026-07-22",
      },
      null,
      2,
    )}\n`,
  );
};

test("private current-cut discovery accepts zero or multiple ongoing cuts", (t) => {
  const repoRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-private-program-state-"),
  );
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));

  assert.throws(
    () => discoverWorkItems(repoRoot),
    /no private work-item status layer/u,
  );

  writeRecord(repoRoot, { status: "proposed" });
  let discovery = discoverWorkItems(repoRoot);
  assert.deepEqual(discovery.current_cuts, []);
  assert.equal(discovery.status_layer.kind, "private_workspace");

  writeRecord(repoRoot, { status: "active" });
  writeRecord(repoRoot, {
    file: "cut-b.v1.json",
    workItemId: "cut-b",
    status: "evidence_ready",
  });
  discovery = discoverWorkItems(repoRoot);
  assert.deepEqual(
    discovery.current_cuts.map(({ record, branch, source_refs }) => ({
      work_item_id: record.work_item_id,
      status: record.status,
      branch,
      source_refs,
    })),
    [
      {
        work_item_id: "cut-a",
        status: "active",
        branch: "private-workspace",
        source_refs: [],
      },
      {
        work_item_id: "cut-b",
        status: "evidence_ready",
        branch: "private-workspace",
        source_refs: [],
      },
    ],
  );
});

test("private current-cut discovery rejects duplicate work-item identities", (t) => {
  const repoRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-private-program-state-duplicate-"),
  );
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));

  writeRecord(repoRoot, { status: "active" });
  writeRecord(repoRoot, {
    file: "cut-a-copy.v1.json",
    workItemId: "cut-a",
    status: "active",
  });
  assert.throws(
    () => discoverWorkItems(repoRoot),
    /private work-item estate duplicates cut-a/u,
  );
});
