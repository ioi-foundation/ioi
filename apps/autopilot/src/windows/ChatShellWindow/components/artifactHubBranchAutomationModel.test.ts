import assert from "node:assert/strict";
import {
  buildBranchLifecycleAutomationPlan,
} from "./artifactHubBranchAutomationModel.ts";
import type {
  SessionBranchSnapshot,
  SessionWorktreeRecord,
} from "../../../types.ts";

function worktree(
  overrides: Partial<SessionWorktreeRecord> = {},
): SessionWorktreeRecord {
  return {
    path: "/repo",
    branchName: "feature/current",
    head: "abc123",
    lastCommit: "abc123 Current commit",
    changedFileCount: 0,
    dirty: false,
    isCurrent: true,
    locked: false,
    lockReason: null,
    prunable: false,
    pruneReason: null,
    statusLabel: "Current workcell",
    statusDetail: "The active session is rooted in this workcell.",
    ...overrides,
  };
}

function snapshot(
  overrides: Partial<SessionBranchSnapshot> = {},
): SessionBranchSnapshot {
  return {
    generatedAtMs: 1,
    sessionId: "session-1",
    workspaceRoot: "/repo",
    isRepo: true,
    repoLabel: "repo",
    currentBranch: "feature/current",
    upstreamBranch: "origin/feature/current",
    lastCommit: "abc123 Current commit",
    aheadCount: 0,
    behindCount: 0,
    changedFileCount: 0,
    dirty: false,
    worktreeRiskLabel: "Clean checkout",
    worktreeRiskDetail: "No tracked file changes are present in this worktree.",
    recentBranches: [],
    worktrees: [worktree()],
    ...overrides,
  };
}

{
  const plan = buildBranchLifecycleAutomationPlan(null);
  assert.equal(plan.tone, "setup");
  assert.equal(plan.actionKind, "none");
  assert.match(plan.detail, /git-backed workspace/i);
}

{
  const plan = buildBranchLifecycleAutomationPlan(
    snapshot({
      dirty: true,
      changedFileCount: 3,
      worktreeRiskLabel: "Dirty checkout",
      worktreeRiskDetail: "3 tracked files are changed.",
      worktrees: [
        worktree({
          dirty: true,
          changedFileCount: 3,
          statusLabel: "Current workcell",
          statusDetail: "Current checkout has tracked edits.",
        }),
        worktree({
          path: "/repo-linked/review",
          branchName: "feature/review-lane",
          isCurrent: false,
          statusLabel: "Ready",
          statusDetail: "Clean linked worktree ready to resume.",
        }),
      ],
    }),
  );

  assert.equal(plan.tone, "review");
  assert.equal(plan.actionKind, "open_commit_view");
  assert.equal(plan.primaryActionLabel, "Review current checkout");
  assert.equal(plan.queuedActions[1]?.kind, "switch_worktree");
  assert.equal(
    plan.queuedActions[1]?.targetWorkspaceRoot,
    "/repo-linked/review",
  );
}

{
  const plan = buildBranchLifecycleAutomationPlan(
    snapshot({
      worktrees: [
        worktree(),
        worktree({
          path: "/repo-linked/stale",
          branchName: "feature/stale",
          isCurrent: false,
          prunable: true,
          pruneReason: "gitdir file points to non-existent location",
          statusLabel: "Prunable",
          statusDetail: "Git marked this linked worktree as prunable.",
        }),
      ],
    }),
  );

  assert.equal(plan.tone, "review");
  assert.equal(plan.actionKind, "remove_worktree");
  assert.equal(plan.primaryActionLabel, "Remove stale workcell");
  assert.equal(
    plan.targetWorkspaceRoot,
    "/repo-linked/stale",
  );
  assert.match(plan.detail, /stale workcell metadata safely/i);
}

{
  const plan = buildBranchLifecycleAutomationPlan(
    snapshot({
      worktrees: [
        worktree(),
        worktree({
          path: "/repo-linked/ready",
          branchName: "feature/ready-lane",
          isCurrent: false,
          statusLabel: "Ready",
          statusDetail: "Clean linked worktree ready to resume.",
        }),
      ],
    }),
  );

  assert.equal(plan.tone, "ready");
  assert.equal(plan.actionKind, "switch_worktree");
  assert.equal(plan.primaryActionLabel, "Resume ready workcell");
  assert.equal(
    plan.targetWorkspaceRoot,
    "/repo-linked/ready",
  );
  assert.match(plan.detail, /clean and ready/i);
}
