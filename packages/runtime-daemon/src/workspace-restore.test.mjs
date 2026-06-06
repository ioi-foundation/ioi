import assert from "node:assert/strict";
import test from "node:test";

import { workspaceRestoreOperationCounts } from "./workspace-restore.mjs";

test("workspace restore operation counts use canonical operation status fields", () => {
  const counts = workspaceRestoreOperationCounts([
    { status: "ready", apply_status: "applied" },
    { status: "noop", apply_status: "noop" },
    { status: "conflict", applyStatus: "applied" },
    { status: "blocked", apply_status: "failed" },
  ]);

  assert.deepEqual(counts, {
    file_count: 4,
    ready_count: 1,
    noop_count: 1,
    conflict_count: 1,
    blocked_count: 1,
    applied_count: 1,
    apply_noop_count: 1,
    apply_blocked_count: 0,
    failed_count: 1,
  });
  for (const field of [
    "fileCount",
    "readyCount",
    "noopCount",
    "conflictCount",
    "blockedCount",
    "appliedCount",
    "applyNoopCount",
    "applyBlockedCount",
    "failedCount",
  ]) {
    assert.equal(Object.hasOwn(counts, field), false);
  }
});
