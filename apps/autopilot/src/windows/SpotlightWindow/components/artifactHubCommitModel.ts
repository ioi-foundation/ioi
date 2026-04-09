import type {
  WorkspaceCommitResult,
  WorkspaceSourceControlEntry,
  WorkspaceSourceControlState,
} from "@ioi/workspace-substrate";
import type { SessionBranchSnapshot } from "../../../types";

export type CommitReadiness = "blocked" | "attention" | "ready";
export type CommitEntryStage = "staged" | "working" | "mixed" | "untracked";

export interface CommitOverviewEntry {
  path: string;
  originalPath: string | null;
  statusLabel: string;
  stage: CommitEntryStage;
  detail: string;
  canStage: boolean;
  canUnstage: boolean;
  canDiscard: boolean;
}

export interface CommitOverview {
  isRepo: boolean;
  branchLabel: string;
  syncLabel: string;
  changedCount: number;
  stagedCount: number;
  unstagedCount: number;
  untrackedCount: number;
  readiness: CommitReadiness;
  readinessLabel: string;
  readinessDetail: string;
  canCommit: boolean;
  lastCommitLabel: string | null;
  entries: CommitOverviewEntry[];
}

function hasStagedChange(entry: WorkspaceSourceControlEntry): boolean {
  return entry.x !== " " && entry.x !== "?";
}

function hasWorkingChange(entry: WorkspaceSourceControlEntry): boolean {
  return entry.y !== " " || entry.x === "?";
}

function entryStage(entry: WorkspaceSourceControlEntry): CommitEntryStage {
  if (entry.x === "?") {
    return "untracked";
  }
  const staged = hasStagedChange(entry);
  const working = hasWorkingChange(entry);
  if (staged && working) {
    return "mixed";
  }
  if (staged) {
    return "staged";
  }
  return "working";
}

function entryDetail(stage: CommitEntryStage): string {
  switch (stage) {
    case "mixed":
      return "Staged changes exist, and the working tree still differs from the staged version.";
    case "staged":
      return "Staged for the next commit.";
    case "untracked":
      return "New path that is not tracked yet.";
    case "working":
    default:
      return "Working-tree change that is not staged yet.";
  }
}

function syncLabel(branch: SessionBranchSnapshot | null): string {
  if (!branch?.isRepo) {
    return "No upstream configured";
  }
  if (!branch.upstreamBranch) {
    return "No upstream configured";
  }
  if (branch.aheadCount === 0 && branch.behindCount === 0) {
    return `Tracking ${branch.upstreamBranch}`;
  }

  const parts = [`Tracking ${branch.upstreamBranch}`];
  if (branch.aheadCount > 0) {
    parts.push(`${branch.aheadCount} ahead`);
  }
  if (branch.behindCount > 0) {
    parts.push(`${branch.behindCount} behind`);
  }
  return parts.join(" · ");
}

export function buildCommitOverview(
  state: WorkspaceSourceControlState | null,
  branch: SessionBranchSnapshot | null,
  lastReceipt: WorkspaceCommitResult | null = null,
): CommitOverview {
  const entries = state?.entries ?? [];
  const mappedEntries = entries.map((entry) => {
    const stage = entryStage(entry);
    return {
      path: entry.path,
      originalPath: entry.originalPath ?? null,
      statusLabel: `${entry.x}${entry.y}`.trim() || "??",
      stage,
      detail: entryDetail(stage),
      canStage: stage === "working" || stage === "untracked" || stage === "mixed",
      canUnstage: stage === "staged" || stage === "mixed",
      canDiscard: stage !== "staged",
    };
  });

  const stagedCount = mappedEntries.filter(
    (entry) => entry.stage === "staged" || entry.stage === "mixed",
  ).length;
  const untrackedCount = mappedEntries.filter((entry) => entry.stage === "untracked").length;
  const unstagedCount = mappedEntries.filter(
    (entry) =>
      entry.stage === "working" ||
      entry.stage === "mixed" ||
      entry.stage === "untracked",
  ).length;
  const changedCount = mappedEntries.length;
  const isRepo = Boolean(state?.git.isRepo || branch?.isRepo);
  const branchLabel =
    branch?.currentBranch?.trim() || state?.git.branch?.trim() || "Detached HEAD";

  let readiness: CommitReadiness = "blocked";
  let readinessLabel = "Repository unavailable";
  let readinessDetail =
    "Open or resume a repository-backed workspace before using the commit surface.";

  if (isRepo) {
    if (stagedCount > 0 && branch?.behindCount && branch.behindCount > 0) {
      readiness = "attention";
      readinessLabel = "Behind upstream";
      readinessDetail =
        "Staged work is ready, but this branch is behind upstream and may need review before stacking another commit.";
    } else if (stagedCount > 0 && unstagedCount > stagedCount) {
      readiness = "attention";
      readinessLabel = "Unstaged changes remain";
      readinessDetail =
        "Some local edits are still outside the staged commit set. Review them before committing or leave them intentionally for later.";
    } else if (stagedCount > 0) {
      readiness = "ready";
      readinessLabel = "Ready to commit";
      readinessDetail =
        "The staged change set is ready for a commit. Add a headline and optional body to write the next local checkpoint.";
    } else if (changedCount > 0) {
      readiness = "attention";
      readinessLabel = "Stage changes first";
      readinessDetail =
        "Local changes are present, but none are staged yet. Stage the exact files you want in the next commit.";
    } else {
      readiness = "blocked";
      readinessLabel = "Working tree clean";
      readinessDetail =
        "No pending changes are available to commit from this workspace right now.";
    }
  }

  return {
    isRepo,
    branchLabel,
    syncLabel: syncLabel(branch),
    changedCount,
    stagedCount,
    unstagedCount,
    untrackedCount,
    readiness,
    readinessLabel,
    readinessDetail,
    canCommit: isRepo && stagedCount > 0,
    lastCommitLabel:
      lastReceipt?.commitSummary ??
      branch?.lastCommit ??
      state?.git.lastCommit ??
      null,
    entries: mappedEntries,
  };
}
