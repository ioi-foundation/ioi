import type {
  ArtifactHubViewKey,
  SessionBranchSnapshot,
  SessionWorktreeRecord,
} from "../../../types";

export type BranchLifecycleAutomationTone = "setup" | "review" | "ready";
export type BranchLifecycleAutomationActionKind =
  | "open_commit_view"
  | "switch_worktree"
  | "remove_worktree"
  | "none";

export interface BranchLifecycleAutomationQueuedAction {
  kind: Exclude<BranchLifecycleAutomationActionKind, "none">;
  label: string;
  detail: string;
  recommendedView: ArtifactHubViewKey | null;
  targetWorkspaceRoot: string | null;
}

export interface BranchLifecycleAutomationPlan {
  tone: BranchLifecycleAutomationTone;
  statusLabel: string;
  detail: string;
  actionKind: BranchLifecycleAutomationActionKind;
  primaryActionLabel: string | null;
  recommendedView: ArtifactHubViewKey | null;
  targetWorkspaceRoot: string | null;
  checklist: string[];
  queuedActions: BranchLifecycleAutomationQueuedAction[];
}

function syncSummary(snapshot: SessionBranchSnapshot): string {
  if (!snapshot.upstreamBranch) {
    return "No upstream configured";
  }

  const bits = [`Tracking ${snapshot.upstreamBranch}`];
  if (snapshot.aheadCount > 0) {
    bits.push(`${snapshot.aheadCount} ahead`);
  }
  if (snapshot.behindCount > 0) {
    bits.push(`${snapshot.behindCount} behind`);
  }
  return bits.join(" · ");
}

function branchLabel(worktree: SessionWorktreeRecord): string {
  return worktree.branchName?.trim() || "Detached HEAD";
}

function buildCheckoutReviewAction(
  snapshot: SessionBranchSnapshot,
): BranchLifecycleAutomationQueuedAction | null {
  const branch = snapshot.currentBranch?.trim() || "Detached HEAD";

  if (snapshot.dirty) {
    return {
      kind: "open_commit_view",
      label: "Review current checkout",
      detail: `The active workcell on ${branch} still has ${snapshot.changedFileCount} tracked change${
        snapshot.changedFileCount === 1 ? "" : "s"
      }, so commit or discard review should lead before more lifecycle moves.`,
      recommendedView: "commit",
      targetWorkspaceRoot: null,
    };
  }

  if (snapshot.behindCount > 0) {
    return {
      kind: "open_commit_view",
      label: "Review upstream drift",
      detail: `The active workcell on ${branch} is ${snapshot.behindCount} commit${
        snapshot.behindCount === 1 ? "" : "s"
      } behind upstream, so source-control review should lead before more isolated work starts.`,
      recommendedView: "commit",
      targetWorkspaceRoot: null,
    };
  }

  if (snapshot.aheadCount > 0) {
    return {
      kind: "open_commit_view",
      label: "Review unpublished commits",
      detail: `The active workcell on ${branch} is ${snapshot.aheadCount} commit${
        snapshot.aheadCount === 1 ? "" : "s"
      } ahead of upstream, so review the unpublished local checkpoint before widening or cleaning up workcells.`,
      recommendedView: "commit",
      targetWorkspaceRoot: null,
    };
  }

  return null;
}

function firstReadyLinkedWorktree(
  snapshot: SessionBranchSnapshot,
): SessionWorktreeRecord | null {
  return (
    snapshot.worktrees.find(
      (worktree) =>
        !worktree.isCurrent &&
        !worktree.dirty &&
        !worktree.locked &&
        !worktree.prunable,
    ) ?? null
  );
}

function firstPrunableWorktree(
  snapshot: SessionBranchSnapshot,
): SessionWorktreeRecord | null {
  return (
    snapshot.worktrees.find(
      (worktree) =>
        !worktree.isCurrent &&
        !worktree.dirty &&
        !worktree.locked &&
        worktree.prunable,
    ) ?? null
  );
}

export function buildBranchLifecycleAutomationPlan(
  snapshot: SessionBranchSnapshot | null,
): BranchLifecycleAutomationPlan {
  if (!snapshot?.isRepo) {
    return {
      tone: "setup",
      statusLabel: "Repository-backed workspace required",
      detail:
        "Open or resume a git-backed workspace before the shell can automate workcell review, switching, or cleanup.",
      actionKind: "none",
      primaryActionLabel: null,
      recommendedView: "files",
      targetWorkspaceRoot: null,
      checklist: [
        "Current workspace: unavailable",
        "Lifecycle review: waiting for repository state",
      ],
      queuedActions: [],
    };
  }

  const readyLinked = firstReadyLinkedWorktree(snapshot);
  const prunable = firstPrunableWorktree(snapshot);
  const checkoutReview = buildCheckoutReviewAction(snapshot);
  const readyLinkedCount = snapshot.worktrees.filter(
    (worktree) =>
      !worktree.isCurrent &&
      !worktree.dirty &&
      !worktree.locked &&
      !worktree.prunable,
  ).length;
  const prunableCount = snapshot.worktrees.filter(
    (worktree) =>
      !worktree.isCurrent &&
      !worktree.dirty &&
      !worktree.locked &&
      worktree.prunable,
  ).length;

  const queuedActions: BranchLifecycleAutomationQueuedAction[] = [];
  if (checkoutReview) {
    queuedActions.push(checkoutReview);
  }
  if (prunable) {
    queuedActions.push({
      kind: "remove_worktree",
      label: "Remove stale workcell",
      detail: `Git already marked ${branchLabel(prunable)} at ${prunable.path} as prunable, so the shared runtime can clean its stale workcell metadata safely.`,
      recommendedView: null,
      targetWorkspaceRoot: prunable.path,
    });
  }
  if (readyLinked) {
    queuedActions.push({
      kind: "switch_worktree",
      label: "Resume ready workcell",
      detail: `${branchLabel(readyLinked)} at ${readyLinked.path} is clean and ready, so the session can move into that isolated lane without disturbing the active checkout.`,
      recommendedView: null,
      targetWorkspaceRoot: readyLinked.path,
    });
  }

  const primaryAction = queuedActions[0] ?? null;
  const tone: BranchLifecycleAutomationTone = checkoutReview || prunable ? "review" : "ready";
  const statusLabel = primaryAction
    ? primaryAction.kind === "open_commit_view"
      ? "Current workcell review should lead"
      : primaryAction.kind === "remove_worktree"
        ? "Stale workcell cleanup ready"
        : "Ready workcell can be resumed"
    : "Workcell lifecycle aligned";
  const detail =
    primaryAction?.detail ||
    "The active checkout is clean, tracked workcells are healthy, and the branch surface is ready for the next isolated lane when you need one.";

  return {
    tone,
    statusLabel,
    detail,
    actionKind: primaryAction?.kind ?? "none",
    primaryActionLabel: primaryAction?.label ?? null,
    recommendedView: primaryAction?.recommendedView ?? null,
    targetWorkspaceRoot: primaryAction?.targetWorkspaceRoot ?? null,
    checklist: [
      `Current branch: ${snapshot.currentBranch?.trim() || "Detached HEAD"}`,
      `Sync: ${syncSummary(snapshot)}`,
      `Risk: ${snapshot.worktreeRiskLabel}`,
      `Tracked workcells: ${snapshot.worktrees.length}`,
      `${readyLinkedCount} ready linked`,
      `${prunableCount} stale`,
    ],
    queuedActions,
  };
}
