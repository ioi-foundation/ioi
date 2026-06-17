import { useEffect, useMemo, useState } from "react";
import type {
  WorkspaceCommitResult,
  WorkspaceSourceControlState,
} from "@ioi/workspace-substrate";
import type { ArtifactHubViewKey, SessionBranchSnapshot } from "../../../../types";
import type { ChatBranchesStatus } from "../../hooks/useChatBranches";
import type { ChatSourceControlStatus } from "../../hooks/useChatSourceControl";
import { humanizeStatus } from "../ArtifactHubViewHelpers";
import {
  buildCommitOverview,
  type CommitOverviewEntry,
} from "../artifactHubCommitModel";
import {
  buildBranchLifecycleAutomationPlan,
  type BranchLifecycleAutomationQueuedAction,
} from "../artifactHubBranchAutomationModel";

export function branchSyncSummary(snapshot: SessionBranchSnapshot | null): string {
  if (!snapshot?.isRepo) {
    return "No repository";
  }
  if (!snapshot.upstreamBranch) {
    return "No upstream configured";
  }
  if (snapshot.aheadCount === 0 && snapshot.behindCount === 0) {
    return `Tracking ${snapshot.upstreamBranch}`;
  }

  const parts: string[] = [`Tracking ${snapshot.upstreamBranch}`];
  if (snapshot.aheadCount > 0) {
    parts.push(`${snapshot.aheadCount} ahead`);
  }
  if (snapshot.behindCount > 0) {
    parts.push(`${snapshot.behindCount} behind`);
  }
  return parts.join(" · ");
}

export function branchRowSyncSummary(
  aheadCount: number,
  behindCount: number,
  upstreamBranch?: string | null,
): string {
  if (!upstreamBranch) {
    return "No upstream configured";
  }
  if (aheadCount === 0 && behindCount === 0) {
    return `Tracking ${upstreamBranch}`;
  }

  const parts: string[] = [`Tracking ${upstreamBranch}`];
  if (aheadCount > 0) {
    parts.push(`${aheadCount} ahead`);
  }
  if (behindCount > 0) {
    parts.push(`${behindCount} behind`);
  }
  return parts.join(" · ");
}

export function commitEntryActionLabel(entry: CommitOverviewEntry): string {
  switch (entry.stage) {
    case "mixed":
      return "Mixed";
    case "staged":
      return "Staged";
    case "untracked":
      return "Untracked";
    case "working":
    default:
      return "Working";
  }
}

export function CommitView({
  branchSnapshot,
  branchStatus,
  branchError,
  sourceControlState,
  sourceControlStatus,
  sourceControlError,
  sourceControlLastCommitReceipt,
  onRefreshBranches,
  onRefreshSourceControl,
  onStageSourceControlPath,
  onStageAllSourceControl,
  onUnstageSourceControlPath,
  onUnstageAllSourceControl,
  onDiscardSourceControlPath,
  onDiscardAllWorkingSourceControl,
  onCommitSourceControl,
  onOpenView,
}: {
  branchSnapshot: SessionBranchSnapshot | null;
  branchStatus: ChatBranchesStatus;
  branchError: string | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlStatus: ChatSourceControlStatus;
  sourceControlError: string | null;
  sourceControlLastCommitReceipt: WorkspaceCommitResult | null;
  onRefreshBranches?: () => Promise<unknown>;
  onRefreshSourceControl?: () => Promise<unknown>;
  onStageSourceControlPath?: (path: string) => Promise<unknown>;
  onStageAllSourceControl?: () => Promise<unknown>;
  onUnstageSourceControlPath?: (path: string) => Promise<unknown>;
  onUnstageAllSourceControl?: () => Promise<unknown>;
  onDiscardSourceControlPath?: (path: string) => Promise<unknown>;
  onDiscardAllWorkingSourceControl?: () => Promise<unknown>;
  onCommitSourceControl?: (
    headline: string,
    body?: string | null,
  ) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = useMemo(
    () =>
      buildCommitOverview(
        sourceControlState,
        branchSnapshot,
        sourceControlLastCommitReceipt,
      ),
    [branchSnapshot, sourceControlLastCommitReceipt, sourceControlState],
  );
  const [headline, setHeadline] = useState("");
  const [body, setBody] = useState("");

  const isBusy =
    sourceControlStatus === "mutating" || sourceControlStatus === "committing";
  const trimmedHeadline = headline.trim();

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Commit</span>
        <strong>{overview.branchLabel}</strong>
        <p>
          Build the next local commit from the same shared source-control and
          branch posture that already backs Branches and the workspace editor.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(sourceControlStatus)}</span>
          <span>Branch posture: {humanizeStatus(branchStatus)}</span>
          <span>{overview.changedCount} changed paths</span>
          <span>{overview.stagedCount} staged</span>
          <span>{overview.unstagedCount} unstaged</span>
        </div>
      </section>

      {branchError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {branchError}
        </p>
      ) : null}
      {sourceControlError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {sourceControlError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section
          className={`artifact-hub-permissions-card ${
            overview.readiness === "attention"
              ? "artifact-hub-permissions-card--alert"
              : ""
          }`}
        >
          <div className="artifact-hub-permissions-card__head">
            <strong>{overview.readinessLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {overview.syncLabel}
            </span>
          </div>
          <p>{overview.readinessDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{overview.changedCount} total changes</span>
            <span>{overview.stagedCount} staged</span>
            <span>{overview.unstagedCount} unstaged</span>
            <span>{overview.untrackedCount} untracked</span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Latest retained commit</strong>
            <span className="artifact-hub-policy-pill">Head</span>
          </div>
          <p>
            {overview.lastCommitLabel
              ? overview.lastCommitLabel
              : "No retained commit headline is available for this checkout yet."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              {branchSnapshot?.workspaceRoot?.trim() || "No workspace root"}
            </span>
            <span>
              {branchSnapshot?.dirty ? "Dirty checkout" : "Clean checkout"}
            </span>
          </div>
        </section>
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Commit message</strong>
          <span className="artifact-hub-policy-pill">
            {sourceControlStatus === "committing" ? "Committing" : "Compose"}
          </span>
        </div>
        <p>
          Commits only include staged paths. Leave non-staged edits alone if
          they belong to later work.
        </p>
        <div className="artifact-hub-commit-form">
          <label className="artifact-hub-commit-field">
            <span>Headline</span>
            <input
              className="artifact-hub-commit-input"
              type="text"
              value={headline}
              onChange={(event) => setHeadline(event.target.value)}
              placeholder="Summarize the staged checkpoint"
              maxLength={120}
            />
          </label>
          <label className="artifact-hub-commit-field">
            <span>Body</span>
            <textarea
              className="artifact-hub-commit-textarea"
              value={body}
              onChange={(event) => setBody(event.target.value)}
              placeholder="Optional detail for reviewers, future replay, or promotion."
              rows={4}
            />
          </label>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onCommitSourceControl ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={
                isBusy || !overview.canCommit || trimmedHeadline.length === 0
              }
              onClick={() => {
                void onCommitSourceControl(trimmedHeadline, body.trim() || null)
                  .then(() => {
                    setHeadline("");
                    setBody("");
                    void onRefreshBranches?.();
                  })
                  .catch(() => {
                    // Keep the current message draft intact when commit fails.
                  });
              }}
            >
              Write commit
            </button>
          ) : null}
          {onRefreshSourceControl ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => {
                void onRefreshSourceControl();
                void onRefreshBranches?.();
              }}
            >
              Refresh state
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("branch")}
            >
              Manage Branches
            </button>
          ) : null}
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Stage controls</strong>
          <span className="artifact-hub-policy-pill">Current checkout</span>
        </div>
        <p>
          Stage only the paths that belong in the next checkpoint. Unstaged
          edits stay in the working tree and can be committed later.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onStageAllSourceControl && overview.changedCount > 0 ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={isBusy}
              onClick={() => {
                void onStageAllSourceControl();
              }}
            >
              Stage all
            </button>
          ) : null}
          {onUnstageAllSourceControl && overview.stagedCount > 0 ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={isBusy}
              onClick={() => {
                void onUnstageAllSourceControl();
              }}
            >
              Unstage staged
            </button>
          ) : null}
          {onDiscardAllWorkingSourceControl && overview.unstagedCount > 0 ? (
            <button
              type="button"
              className="artifact-hub-open-btn destructive"
              disabled={isBusy}
              onClick={() => {
                void onDiscardAllWorkingSourceControl();
              }}
            >
              Discard unstaged
            </button>
          ) : null}
        </div>
      </section>

      {overview.entries.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Changed paths</span>
            <span>{overview.entries.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {overview.entries.map((entry) => (
              <article className="artifact-hub-generic-row" key={entry.path}>
                <div className="artifact-hub-generic-meta">
                  <span>{commitEntryActionLabel(entry)}</span>
                  <span>{entry.statusLabel}</span>
                  {entry.originalPath ? (
                    <span>{entry.originalPath}</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">{entry.path}</div>
                <p className="artifact-hub-generic-summary">{entry.detail}</p>
                <div className="artifact-hub-generic-actions">
                  {entry.canStage && onStageSourceControlPath ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={isBusy}
                      onClick={() => {
                        void onStageSourceControlPath(entry.path);
                      }}
                    >
                      Stage
                    </button>
                  ) : null}
                  {entry.canUnstage && onUnstageSourceControlPath ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={isBusy}
                      onClick={() => {
                        void onUnstageSourceControlPath(entry.path);
                      }}
                    >
                      Unstage
                    </button>
                  ) : null}
                  {entry.canDiscard && onDiscardSourceControlPath ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn destructive"
                      disabled={isBusy}
                      onClick={() => {
                        void onDiscardSourceControlPath(entry.path);
                      }}
                    >
                      Discard
                    </button>
                  ) : null}
                  {onOpenView ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => onOpenView("files")}
                    >
                      Open Files
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No pending source-control changes are visible for this workspace yet.
        </p>
      )}
    </div>
  );
}

export function BranchesView({
  snapshot,
  status,
  error,
  onRefreshBranches,
  onCreateBranchWorktree,
  onSwitchBranchWorktree,
  onRemoveBranchWorktree,
  onOpenView,
}: {
  snapshot: SessionBranchSnapshot | null;
  status: ChatBranchesStatus;
  error: string | null;
  onRefreshBranches?: () => Promise<unknown>;
  onCreateBranchWorktree?: (
    branchName: string,
    options?: {
      startPoint?: string | null;
      worktreeName?: string | null;
    },
  ) => Promise<unknown>;
  onSwitchBranchWorktree?: (targetWorkspaceRoot: string) => Promise<unknown>;
  onRemoveBranchWorktree?: (targetWorkspaceRoot: string) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const workspaceLabel =
    snapshot?.workspaceRoot?.trim() || "No active workspace";
  const repoLabel = snapshot?.repoLabel?.trim() || "No repository";
  const currentBranch = snapshot?.currentBranch?.trim() || "Detached HEAD";
  const recentBranches = snapshot?.recentBranches ?? [];
  const worktrees = snapshot?.worktrees ?? [];
  const [branchName, setBranchName] = useState("");
  const [worktreeName, setWorktreeName] = useState("");
  const [startPoint, setStartPoint] = useState("");
  const trimmedBranchName = branchName.trim();
  const trimmedWorktreeName = worktreeName.trim();
  const trimmedStartPoint = startPoint.trim();
  const isBusy = status === "loading";
  const lifecyclePlan = useMemo(
    () => buildBranchLifecycleAutomationPlan(snapshot),
    [snapshot],
  );
  const startPointOptions = useMemo(() => {
    const values = new Set<string>();
    const options: string[] = [];
    const push = (value?: string | null) => {
      const trimmed = value?.trim();
      if (!trimmed || values.has(trimmed)) {
        return;
      }
      values.add(trimmed);
      options.push(trimmed);
    };
    push(snapshot?.currentBranch);
    recentBranches.forEach((branch) => push(branch.branchName));
    push("HEAD");
    return options;
  }, [recentBranches, snapshot?.currentBranch]);

  useEffect(() => {
    if (!trimmedStartPoint && startPointOptions.length > 0) {
      setStartPoint(startPointOptions[0] ?? "HEAD");
    }
  }, [startPointOptions, trimmedStartPoint]);

  async function runLifecycleAction(
    action: BranchLifecycleAutomationQueuedAction,
  ) {
    switch (action.kind) {
      case "open_commit_view":
        if (action.recommendedView && onOpenView) {
          onOpenView(action.recommendedView);
        }
        break;
      case "switch_worktree":
        if (action.targetWorkspaceRoot && onSwitchBranchWorktree) {
          await onSwitchBranchWorktree(action.targetWorkspaceRoot);
        }
        break;
      case "remove_worktree":
        if (action.targetWorkspaceRoot && onRemoveBranchWorktree) {
          await onRemoveBranchWorktree(action.targetWorkspaceRoot);
        }
        break;
    }
  }

  function canRunLifecycleAction(
    action: BranchLifecycleAutomationQueuedAction,
  ) {
    switch (action.kind) {
      case "open_commit_view":
        return Boolean(action.recommendedView && onOpenView);
      case "switch_worktree":
        return Boolean(action.targetWorkspaceRoot && onSwitchBranchWorktree);
      case "remove_worktree":
        return Boolean(action.targetWorkspaceRoot && onRemoveBranchWorktree);
    }
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Branches</span>
        <strong>{repoLabel}</strong>
        <p>
          Review the active git checkout, upstream posture, and recent local
          branches for the current session workspace, then spin up or reattach
          isolated workcells over the same shared runtime session.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          <span>Workspace: {workspaceLabel}</span>
          <span>{snapshot?.changedFileCount ?? 0} changed files</span>
          <span>{snapshot?.dirty ? "Dirty checkout" : "Clean checkout"}</span>
          <span>{worktrees.length} tracked workcells</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Lifecycle automation</strong>
          <span className="artifact-hub-policy-pill">
            {lifecyclePlan.statusLabel}
          </span>
        </div>
        <p>{lifecyclePlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {lifecyclePlan.checklist.map((label) => (
            <span key={label}>{label}</span>
          ))}
        </div>
        {lifecyclePlan.queuedActions.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {lifecyclePlan.queuedActions.map((action, index) => (
              <article
                className="artifact-hub-generic-row"
                key={`${action.kind}:${action.targetWorkspaceRoot ?? action.recommendedView ?? index}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{index === 0 ? "Primary" : "Queued"}</span>
                  <span>{humanizeStatus(lifecyclePlan.tone)}</span>
                  <span>
                    {action.recommendedView
                      ? humanizeStatus(action.recommendedView)
                      : humanizeStatus(action.kind)}
                  </span>
                </div>
                <div className="artifact-hub-generic-title">{action.label}</div>
                <p className="artifact-hub-generic-summary">{action.detail}</p>
                {canRunLifecycleAction(action) ? (
                  <div className="artifact-hub-generic-actions">
                    <button
                      type="button"
                      className={`artifact-hub-open-btn ${
                        action.kind === "remove_worktree" ? "destructive" : ""
                      }`.trim()}
                      disabled={isBusy}
                      onClick={() => {
                        void runLifecycleAction(action);
                      }}
                    >
                      {action.label}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-note">
            The current checkout and tracked workcells are already aligned. Use
            the create form below when you need a new isolated lane.
          </p>
        )}
      </section>

      {snapshot?.isRepo ? (
        <>
          <div className="artifact-hub-permissions-grid">
            <section className="artifact-hub-permissions-card">
              <div className="artifact-hub-permissions-card__head">
                <strong>{currentBranch}</strong>
                <span className="artifact-hub-policy-pill">
                  {branchSyncSummary(snapshot)}
                </span>
              </div>
              <p>
                {snapshot.lastCommit
                  ? `Latest commit: ${snapshot.lastCommit}`
                  : "No retained commit headline is available for this checkout yet."}
              </p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                <span>Ahead: {snapshot.aheadCount}</span>
                <span>Behind: {snapshot.behindCount}</span>
                <span>
                  {snapshot.upstreamBranch
                    ? `Upstream: ${snapshot.upstreamBranch}`
                    : "Upstream: not configured"}
                </span>
              </div>
            </section>

            <section className="artifact-hub-permissions-card">
              <div className="artifact-hub-permissions-card__head">
                <strong>{snapshot.worktreeRiskLabel}</strong>
                <span className="artifact-hub-policy-pill">Worktree</span>
              </div>
              <p>{snapshot.worktreeRiskDetail}</p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                <span>{snapshot.changedFileCount} changed files</span>
                <span>
                  {snapshot.dirty
                    ? "Tracked changes present"
                    : "No tracked changes"}
                </span>
              </div>
            </section>
          </div>

          {recentBranches.length > 0 ? (
            <section className="artifact-hub-task-section">
              <div className="artifact-hub-task-section-head">
                <span>Recent branches</span>
                <span>{recentBranches.length}</span>
              </div>
              <div className="artifact-hub-generic-list">
                {recentBranches.map((branch) => (
                  <article
                    className="artifact-hub-generic-row"
                    key={branch.branchName}
                  >
                    <div className="artifact-hub-generic-meta">
                      <span>
                        {branch.isCurrent ? "Current branch" : "Local branch"}
                      </span>
                      <span>
                        {branchRowSyncSummary(
                          branch.aheadCount,
                          branch.behindCount,
                          branch.upstreamBranch,
                        )}
                      </span>
                    </div>
                    <div className="artifact-hub-generic-title">
                      {branch.branchName}
                    </div>
                    <p className="artifact-hub-generic-summary">
                      {branch.lastCommit
                        ? `Latest commit: ${branch.lastCommit}`
                        : "No retained commit headline for this branch yet."}
                    </p>
                    {onCreateBranchWorktree ? (
                      <div className="artifact-hub-generic-actions">
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          disabled={isBusy}
                          onClick={() => {
                            setStartPoint(branch.branchName);
                          }}
                        >
                          Use as start point
                        </button>
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          {worktrees.length > 0 ? (
            <section className="artifact-hub-task-section">
              <div className="artifact-hub-task-section-head">
                <span>Tracked workcells</span>
                <span>{worktrees.length}</span>
              </div>
              <div className="artifact-hub-generic-list">
                {worktrees.map((worktree) => (
                  <article
                    className="artifact-hub-generic-row"
                    key={worktree.path}
                  >
                    <div className="artifact-hub-generic-meta">
                      <span>
                        {worktree.isCurrent
                          ? "Current workcell"
                          : "Linked workcell"}
                      </span>
                      <span>{worktree.statusLabel}</span>
                      <span>
                        {worktree.branchName?.trim() || "Detached HEAD"}
                      </span>
                    </div>
                    <div className="artifact-hub-generic-title">
                      {worktree.path}
                    </div>
                    <p className="artifact-hub-generic-summary">
                      {worktree.lastCommit
                        ? `${worktree.statusDetail} Latest commit: ${worktree.lastCommit}`
                        : worktree.statusDetail}
                    </p>
                    <div className="artifact-hub-generic-actions">
                      {!worktree.isCurrent && onSwitchBranchWorktree ? (
                        <button
                          type="button"
                          className="artifact-hub-open-btn"
                          disabled={isBusy}
                          onClick={() => {
                            void onSwitchBranchWorktree(worktree.path);
                          }}
                        >
                          Switch session here
                        </button>
                      ) : null}
                      {!worktree.isCurrent &&
                      !worktree.dirty &&
                      !worktree.locked &&
                      onRemoveBranchWorktree ? (
                        <button
                          type="button"
                          className="artifact-hub-open-btn destructive"
                          disabled={isBusy}
                          onClick={() => {
                            void onRemoveBranchWorktree(worktree.path);
                          }}
                        >
                          {worktree.prunable
                            ? "Remove stale workcell"
                            : "Remove workcell"}
                        </button>
                      ) : null}
                      {onOpenView && worktree.isCurrent ? (
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          onClick={() => onOpenView("files")}
                        >
                          Open Files
                        </button>
                      ) : null}
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ) : null}
        </>
      ) : (
        <p className="artifact-hub-empty">
          No repository-backed workspace is active yet. Open or resume a session
          rooted in a git checkout, then reopen Branches.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Workcell actions</strong>
          <span className="artifact-hub-policy-pill">
            {isBusy ? "Updating" : "Shared runtime truth"}
          </span>
        </div>
        <p>
          Create a new isolated branch+worktree under the repo-local
          `.ioi-worktrees` directory and move the active session into it.
          Uncommitted edits stay in the current checkout; the new workcell
          starts from the selected branch or commit.
        </p>
        {snapshot?.isRepo && onCreateBranchWorktree ? (
          <div className="artifact-hub-commit-form">
            <label className="artifact-hub-commit-field">
              <span>Start point</span>
              <select
                className="artifact-hub-commit-input"
                value={trimmedStartPoint || ""}
                onChange={(event) => setStartPoint(event.target.value)}
              >
                {startPointOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
            <label className="artifact-hub-commit-field">
              <span>New isolated branch</span>
              <input
                className="artifact-hub-commit-input"
                type="text"
                value={branchName}
                onChange={(event) => setBranchName(event.target.value)}
                placeholder="feature/workcell-review"
                maxLength={120}
              />
            </label>
            <label className="artifact-hub-commit-field">
              <span>Workcell label</span>
              <input
                className="artifact-hub-commit-input"
                type="text"
                value={worktreeName}
                onChange={(event) => setWorktreeName(event.target.value)}
                placeholder="Optional folder suffix"
                maxLength={80}
              />
            </label>
          </div>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {snapshot?.isRepo && onCreateBranchWorktree ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={isBusy || trimmedBranchName.length === 0}
              onClick={() => {
                void onCreateBranchWorktree(trimmedBranchName, {
                  startPoint: trimmedStartPoint || null,
                  worktreeName: trimmedWorktreeName || null,
                })
                  .then(() => {
                    setBranchName("");
                    setWorktreeName("");
                  })
                  .catch(() => {
                    // Keep the form intact when workcell creation fails.
                  });
              }}
            >
              Create isolated workcell
            </button>
          ) : null}
          {onRefreshBranches ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={isBusy}
              onClick={() => {
                void onRefreshBranches();
              }}
            >
              Refresh branch snapshot
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("files")}
            >
              Open Files
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("replay")}
            >
              Review Replay
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}
