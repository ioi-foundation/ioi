import assert from "node:assert/strict";
import { buildCommitOverview } from "./artifactHubCommitModel.ts";
import type { SessionBranchSnapshot } from "../../../types.ts";
import type { WorkspaceSourceControlState } from "@ioi/workspace-substrate";

function branchSnapshot(overrides: Partial<SessionBranchSnapshot> = {}): SessionBranchSnapshot {
  return {
    generatedAtMs: 1,
    sessionId: "session-1",
    workspaceRoot: "/repo",
    isRepo: true,
    repoLabel: "repo",
    currentBranch: "feature/commit-view",
    upstreamBranch: "origin/feature/commit-view",
    lastCommit: "abc123 Previous checkpoint",
    aheadCount: 0,
    behindCount: 0,
    changedFileCount: 0,
    dirty: false,
    worktreeRiskLabel: "Clean checkout",
    worktreeRiskDetail: "No tracked file changes are present in this worktree.",
    recentBranches: [],
    worktrees: [],
    ...overrides,
  };
}

function sourceControlState(
  overrides: Partial<WorkspaceSourceControlState> = {},
): WorkspaceSourceControlState {
  return {
    git: {
      isRepo: true,
      branch: "feature/commit-view",
      dirty: true,
      lastCommit: "abc123 Previous checkpoint",
    },
    entries: [],
    ...overrides,
  };
}

{
  const overview = buildCommitOverview(null, null, null);
  assert.equal(overview.isRepo, false);
  assert.equal(overview.canCommit, false);
  assert.equal(overview.readiness, "blocked");
  assert.match(overview.readinessDetail, /repository-backed workspace/i);
}

{
  const overview = buildCommitOverview(
    sourceControlState({
      entries: [
        { path: "src/commit.ts", originalPath: null, x: "M", y: " " },
        { path: "src/dirty.ts", originalPath: null, x: " ", y: "M" },
        { path: "src/new.ts", originalPath: null, x: "?", y: "?" },
      ],
    }),
    branchSnapshot({ behindCount: 2 }),
    null,
  );

  assert.equal(overview.canCommit, true);
  assert.equal(overview.stagedCount, 1);
  assert.equal(overview.unstagedCount, 2);
  assert.equal(overview.untrackedCount, 1);
  assert.equal(overview.readiness, "attention");
  assert.equal(overview.readinessLabel, "Behind upstream");
  assert.equal(overview.entries[0]?.stage, "staged");
  assert.equal(overview.entries[1]?.stage, "working");
  assert.equal(overview.entries[2]?.stage, "untracked");
}

{
  const overview = buildCommitOverview(
    sourceControlState({
      git: {
        isRepo: true,
        branch: "feature/commit-view",
        dirty: false,
        lastCommit: "def456 Stage success",
      },
      entries: [],
    }),
    branchSnapshot({
      lastCommit: "abc123 Previous checkpoint",
      aheadCount: 1,
      changedFileCount: 0,
      dirty: false,
    }),
    {
      state: sourceControlState({
        git: {
          isRepo: true,
          branch: "feature/commit-view",
          dirty: false,
          lastCommit: "def456 Stage success",
        },
        entries: [],
      }),
      committedFileCount: 2,
      remainingChangeCount: 0,
      commitSummary: "def456 Stage success",
    },
  );

  assert.equal(overview.canCommit, false);
  assert.equal(overview.readiness, "blocked");
  assert.equal(overview.readinessLabel, "Working tree clean");
  assert.equal(overview.lastCommitLabel, "def456 Stage success");
  assert.match(overview.syncLabel, /ahead/i);
}
