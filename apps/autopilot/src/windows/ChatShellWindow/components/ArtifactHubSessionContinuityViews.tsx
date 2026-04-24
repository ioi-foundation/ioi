import { formatSessionTimeAgo } from "@ioi/agent-ide";
import { useMemo } from "react";
import type {
  ArtifactHubViewKey,
  SessionCompactionPolicy,
  SessionCompactionPruneDecision,
  SessionCompactionSnapshot,
  SessionRewindCandidate,
  SessionRewindSnapshot,
  TeamMemorySyncSnapshot,
} from "../../../types";
import {
  buildRetentionReviewAutomationPlan,
  type RetentionReviewAutomationQueuedAction,
} from "../utils/retentionReviewAutomationModel";
import { humanizeStatus } from "./ArtifactHubViewHelpers";
import {
  canCompareFocusedRewindCandidate,
  selectFocusedRewindCandidate,
} from "./artifactHubRewindModel";

const DEFAULT_SESSION_COMPACTION_POLICY: SessionCompactionPolicy = {
  carryPinnedOnly: false,
  preserveChecklistState: true,
  preserveBackgroundTasks: true,
  preserveLatestOutputExcerpt: true,
  preserveGovernanceBlockers: true,
  aggressiveTranscriptPruning: false,
};

function compactionPoliciesMatch(
  left: SessionCompactionPolicy,
  right: SessionCompactionPolicy,
): boolean {
  return (
    left.carryPinnedOnly === right.carryPinnedOnly &&
    left.preserveChecklistState === right.preserveChecklistState &&
    left.preserveBackgroundTasks === right.preserveBackgroundTasks &&
    left.preserveLatestOutputExcerpt === right.preserveLatestOutputExcerpt &&
    left.preserveGovernanceBlockers === right.preserveGovernanceBlockers &&
    left.aggressiveTranscriptPruning === right.aggressiveTranscriptPruning
  );
}

function clipText(value: string, maxChars: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function formatDuration(durationMs: number): string {
  if (!Number.isFinite(durationMs) || durationMs <= 0) return "0s";
  if (durationMs < 60_000)
    return `${Math.max(1, Math.round(durationMs / 1000))}s`;
  if (durationMs < 3_600_000) return `${Math.round(durationMs / 60_000)}m`;
  return `${Math.round(durationMs / 3_600_000)}h`;
}

function compactionDispositionLabel(
  disposition: SessionCompactionPruneDecision["disposition"],
): string {
  switch (disposition) {
    case "carry_forward":
      return "Carry forward";
    case "retained_summary":
      return "Retained in summary";
    case "pruned":
      return "Pruned from resume context";
    default:
      return disposition;
  }
}

function compactionDecisionCounts(
  decisions: SessionCompactionPruneDecision[] | undefined | null,
): Record<SessionCompactionPruneDecision["disposition"], number> {
  return (decisions ?? []).reduce<
    Record<SessionCompactionPruneDecision["disposition"], number>
  >(
    (acc, decision) => {
      acc[decision.disposition] = (acc[decision.disposition] || 0) + 1;
      return acc;
    },
    {
      carry_forward: 0,
      retained_summary: 0,
      pruned: 0,
    },
  );
}

function compactionCarryModeLabel(policy: SessionCompactionPolicy): string {
  return policy.carryPinnedOnly ? "Pinned only" : "Pinned + scoped files";
}

function compactionTranscriptLabel(policy: SessionCompactionPolicy): string {
  return policy.aggressiveTranscriptPruning
    ? "Aggressive prune"
    : "Summary-retained";
}

function compactionPolicySummaryBits(
  policy: SessionCompactionPolicy,
): string[] {
  return [
    `Checklist: ${policy.preserveChecklistState ? "keep" : "prune"}`,
    `Background: ${policy.preserveBackgroundTasks ? "keep" : "prune"}`,
    `Output: ${policy.preserveLatestOutputExcerpt ? "keep" : "prune"}`,
    `Blockers: ${policy.preserveGovernanceBlockers ? "keep" : "prune"}`,
  ];
}

function compactionResumeSafetyLabel(status: "protected" | "degraded"): string {
  return status === "protected"
    ? "Resume safety: Protected"
    : "Resume safety: Degraded";
}

function teamMemorySyncStatusLabel(status: string): string {
  switch (status) {
    case "review_required":
      return "Review required";
    case "redacted":
      return "Redacted";
    case "synced":
      return "Synced";
    default:
      return status;
  }
}

function sessionWorkspaceLabel(workspaceRoot?: string | null): string | null {
  const trimmed = workspaceRoot?.trim();
  if (!trimmed) {
    return null;
  }

  const normalized = trimmed.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? normalized;
}

function sessionRewindSubtitle(
  candidate: SessionRewindCandidate,
): string | null {
  const parts = [
    candidate.phase,
    candidate.currentStep,
    candidate.resumeHint,
    sessionWorkspaceLabel(candidate.workspaceRoot),
  ].filter((value): value is string => Boolean(value?.trim()));
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function CompactView({
  snapshot,
  status,
  error,
  policy,
  teamMemorySnapshot,
  teamMemoryStatus,
  teamMemoryError,
  teamMemoryIncludeGovernanceCritical,
  onRefreshCompaction,
  onCompactSession,
  onSetTeamMemoryIncludeGovernanceCritical,
  onRefreshTeamMemory,
  onSyncTeamMemory,
  onForgetTeamMemoryEntry,
  onUpdateCompactionPolicy,
  onResetCompactionPolicy,
  onOpenView,
}: {
  snapshot: SessionCompactionSnapshot | null;
  status: string;
  error: string | null;
  policy: SessionCompactionPolicy;
  teamMemorySnapshot: TeamMemorySyncSnapshot | null;
  teamMemoryStatus: string;
  teamMemoryError: string | null;
  teamMemoryIncludeGovernanceCritical: boolean;
  onRefreshCompaction?: () => Promise<unknown>;
  onCompactSession?: (
    sessionId?: string | null,
    policy?: SessionCompactionPolicy,
  ) => Promise<unknown>;
  onSetTeamMemoryIncludeGovernanceCritical?: (value: boolean) => void;
  onRefreshTeamMemory?: () => Promise<unknown>;
  onSyncTeamMemory?: () => Promise<unknown>;
  onForgetTeamMemoryEntry?: (entryId: string) => Promise<unknown>;
  onUpdateCompactionPolicy?: (
    policy: SessionCompactionPolicy,
  ) => Promise<unknown>;
  onResetCompactionPolicy?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const activeTitle =
    snapshot?.activeSessionTitle?.trim() || "No active retained session";
  const latest = snapshot?.latestForActive || null;
  const preview = snapshot?.previewForActive || null;
  const activePolicy = preview?.policy ?? snapshot?.policyForActive ?? policy;
  const policyIsDefault = compactionPoliciesMatch(
    activePolicy,
    DEFAULT_SESSION_COMPACTION_POLICY,
  );
  const teamMemoryEntries = teamMemorySnapshot?.entries ?? [];
  const teamMemoryBusy =
    teamMemoryStatus === "syncing" || teamMemoryStatus === "forgetting";
  const teamMemoryScopeLabel =
    teamMemorySnapshot?.activeScopeLabel?.trim() || "Current scope";
  const portfolio = snapshot?.durabilityPortfolio || null;
  const retentionReviewPlan = useMemo(
    () =>
      buildRetentionReviewAutomationPlan({
        compactionSnapshot: snapshot,
        teamMemorySnapshot,
      }),
    [snapshot, teamMemorySnapshot],
  );
  const memoryControls: Array<{
    key: keyof SessionCompactionPolicy;
    label: string;
    description: string;
  }> = [
    {
      key: "carryPinnedOnly",
      label: "Pinned files only",
      description:
        "Prune explicit include and exclude paths from carried-forward state.",
    },
    {
      key: "preserveChecklistState",
      label: "Keep checklist",
      description:
        "Carry the operator checklist into the compacted resume context.",
    },
    {
      key: "preserveBackgroundTasks",
      label: "Keep background tasks",
      description: "Retain labels for parallel work that is still in flight.",
    },
    {
      key: "preserveLatestOutputExcerpt",
      label: "Keep latest output",
      description: "Retain a short output excerpt in the compacted summary.",
    },
    {
      key: "preserveGovernanceBlockers",
      label: "Keep blockers",
      description:
        "Carry pending approvals or governance blockers forward explicitly.",
    },
    {
      key: "aggressiveTranscriptPruning",
      label: "Aggressive transcript pruning",
      description:
        "Drop conversational texture from the summary and keep only the compacted anchor.",
    },
  ];
  const records = snapshot?.records ?? [];
  const recommendation = snapshot?.recommendationForActive || null;
  const recommendedPolicy = recommendation?.recommendedPolicy ?? null;
  const recommendedPolicyMatches = recommendedPolicy
    ? compactionPoliciesMatch(activePolicy, recommendedPolicy)
    : false;
  const autoStateLabel = recommendation?.shouldCompact
    ? "Recommended now"
    : latest?.mode === "auto"
      ? "Recently auto-compacted"
      : "Monitoring";
  const latestModeLabel =
    latest?.mode === "auto" ? "Auto compaction" : "Manual compaction";
  const reasonLabels = recommendation?.reasonLabels ?? [];
  const memoryClassCounts = latest?.carriedForwardState.memoryItems.reduce<
    Record<string, number>
  >((acc, item) => {
    acc[item.memoryClass] = (acc[item.memoryClass] || 0) + 1;
    return acc;
  }, {});
  const previewDecisionCounts = compactionDecisionCounts(
    preview?.pruneDecisions,
  );
  const latestDecisionCounts = compactionDecisionCounts(latest?.pruneDecisions);

  async function runRetentionReviewAction(
    action: RetentionReviewAutomationQueuedAction,
  ) {
    switch (action.kind) {
      case "compact_active_session":
        if (onCompactSession) {
          await onCompactSession(
            snapshot?.activeSessionId || null,
            activePolicy,
          );
        }
        break;
      case "sync_team_memory":
        if (onSyncTeamMemory) {
          await onSyncTeamMemory();
        }
        break;
      case "open_view":
        if (action.recommendedView && onOpenView) {
          onOpenView(action.recommendedView);
        }
        break;
    }
  }

  function canRunRetentionReviewAction(
    action: RetentionReviewAutomationQueuedAction,
  ) {
    switch (action.kind) {
      case "compact_active_session":
        return Boolean(onCompactSession);
      case "sync_team_memory":
        return Boolean(onSyncTeamMemory);
      case "open_view":
        return Boolean(action.recommendedView && onOpenView);
    }
  }

  return (
    <div className="artifact-hub-rewind">
      <section className="artifact-hub-files-identity artifact-hub-rewind__identity">
        <span className="artifact-hub-files-kicker">Compact</span>
        <strong>Conversation compaction</strong>
        <p>
          Capture a resumable session summary with carried-forward file context,
          blockers, and resume anchors so long-running work stays reloadable
          across Chat, retained sessions, and the standalone REPL.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Status: {humanizeStatus(status)}</span>
          <span>{snapshot?.recordCount ?? 0} retained compaction records</span>
          <span>Active: {activeTitle}</span>
          <span>Auto policy: {autoStateLabel}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Retention review automation</strong>
          <span className="artifact-hub-policy-pill">
            {retentionReviewPlan.statusLabel}
          </span>
        </div>
        <p>{retentionReviewPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {retentionReviewPlan.checklist.map((label) => (
            <span key={label}>{label}</span>
          ))}
        </div>
        {retentionReviewPlan.queuedActions.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {retentionReviewPlan.queuedActions.map((action, index) => (
              <article
                className="artifact-hub-generic-row"
                key={`${action.kind}:${action.recommendedView ?? index}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{index === 0 ? "Primary" : "Queued"}</span>
                  <span>{humanizeStatus(retentionReviewPlan.tone)}</span>
                  <span>
                    {action.recommendedView
                      ? humanizeStatus(action.recommendedView)
                      : humanizeStatus(action.kind)}
                  </span>
                </div>
                <div className="artifact-hub-generic-title">{action.label}</div>
                <p className="artifact-hub-generic-summary">{action.detail}</p>
                {canRunRetentionReviewAction(action) ? (
                  <div className="artifact-hub-generic-actions">
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      onClick={() => {
                        void runRetentionReviewAction(action);
                      }}
                    >
                      {action.label}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        ) : null}
      </section>

      {portfolio ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Cross-session durability</strong>
            <span className="artifact-hub-policy-pill">
              {portfolio.replayReadySessionCount}/
              {portfolio.retainedSessionCount} replay-ready
            </span>
          </div>
          <p>{portfolio.coverageSummary}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Compacted: {portfolio.compactedSessionCount}</span>
            <span>Uncompacted: {portfolio.uncompactedSessionCount}</span>
            <span>Stale: {portfolio.staleCompactionCount}</span>
            <span>Degraded: {portfolio.degradedCompactionCount}</span>
            <span>Recommended now: {portfolio.recommendedCompactionCount}</span>
          </div>
          <p className="artifact-hub-note">{portfolio.teamMemorySummary}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              Team memory sessions: {portfolio.teamMemoryCoveredSessionCount}
            </span>
            <span>Entries: {portfolio.teamMemoryEntryCount}</span>
            <span>
              Review required: {portfolio.teamMemoryReviewRequiredSessionCount}
            </span>
            <span>
              Redacted sessions: {portfolio.teamMemoryRedactedSessionCount}
            </span>
            <span>
              Missing sync: {portfolio.compactedWithoutTeamMemoryCount}
            </span>
          </div>
          {portfolio.attentionLabels.length > 0 ? (
            <>
              <p className="artifact-hub-note">{portfolio.attentionSummary}</p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                {portfolio.attentionLabels.map((label) => (
                  <span key={label}>{label}</span>
                ))}
              </div>
            </>
          ) : (
            <p className="artifact-hub-note">
              Fresh protected compaction records and scoped team-memory coverage
              are aligned across the retained portfolio.
            </p>
          )}
        </section>
      ) : null}

      {recommendation ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Auto compaction policy</strong>
            <span className="artifact-hub-policy-pill">{autoStateLabel}</span>
          </div>
          <p>
            Conservative auto mode watches session scale, carried-forward file
            context, and blocker or idle age before capturing a resumable
            summary.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>History: {recommendation.historyCount}</span>
            <span>Events: {recommendation.eventCount}</span>
            <span>Artifacts: {recommendation.artifactCount}</span>
            <span>Includes: {recommendation.explicitIncludeCount}</span>
            <span>Idle: {formatDuration(recommendation.idleAgeMs)}</span>
          </div>
          {reasonLabels.length > 0 ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              {reasonLabels.map((reason) => (
                <span key={reason}>{reason}</span>
              ))}
            </div>
          ) : (
            <p className="artifact-hub-note">
              No compaction threshold is active right now.
            </p>
          )}
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Memory controls</strong>
          <span className="artifact-hub-policy-pill">
            {policyIsDefault ? "Default manual policy" : "Custom manual policy"}
          </span>
        </div>
        <p>
          Tune what the preview and the next manual compaction pass will carry
          forward. Conservative auto compaction keeps using the default policy.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Carry mode: {compactionCarryModeLabel(activePolicy)}</span>
          <span>Transcript: {compactionTranscriptLabel(activePolicy)}</span>
          {compactionPolicySummaryBits(activePolicy).map((label) => (
            <span key={label}>{label}</span>
          ))}
        </div>
        <div className="artifact-hub-compact-policy-list">
          {memoryControls.map((control) => (
            <label
              className="artifact-hub-compact-policy-toggle"
              key={control.key}
            >
              <input
                type="checkbox"
                checked={activePolicy[control.key]}
                disabled={!onUpdateCompactionPolicy || status === "compacting"}
                onChange={() => {
                  if (!onUpdateCompactionPolicy) {
                    return;
                  }
                  void onUpdateCompactionPolicy({
                    ...activePolicy,
                    [control.key]: !activePolicy[control.key],
                  });
                }}
              />
              <span className="artifact-hub-compact-policy-copy">
                <strong>{control.label}</strong>
                <span>{control.description}</span>
              </span>
            </label>
          ))}
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {recommendedPolicy && onUpdateCompactionPolicy ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={recommendedPolicyMatches || status === "compacting"}
              onClick={() => {
                void onUpdateCompactionPolicy(recommendedPolicy);
              }}
            >
              {recommendedPolicyMatches
                ? "Recommended policy active"
                : "Apply recommended policy"}
            </button>
          ) : null}
          {onResetCompactionPolicy ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={policyIsDefault || status === "compacting"}
              onClick={() => {
                void onResetCompactionPolicy();
              }}
            >
              Reset defaults
            </button>
          ) : null}
        </div>
      </section>

      {recommendation ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recommended manual policy</strong>
            <span className="artifact-hub-policy-pill">
              {recommendedPolicyMatches
                ? "Recommendation applied"
                : recommendation.recommendedPolicyLabel}
            </span>
          </div>
          <p>
            Use the recommended policy when you want the preview and the next
            manual compaction pass to follow the safest current resume posture.
          </p>
          {recommendedPolicy ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              <span>
                Carry mode: {compactionCarryModeLabel(recommendedPolicy)}
              </span>
              <span>
                Transcript: {compactionTranscriptLabel(recommendedPolicy)}
              </span>
              {compactionPolicySummaryBits(recommendedPolicy).map((label) => (
                <span key={`recommended-${label}`}>{label}</span>
              ))}
            </div>
          ) : null}
          {recommendation.recommendedPolicyReasonLabels.length > 0 ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              {recommendation.recommendedPolicyReasonLabels.map((reason) => (
                <span key={reason}>{reason}</span>
              ))}
            </div>
          ) : null}
          {recommendation.resumeSafeguardLabels.length > 0 ? (
            <>
              <p className="artifact-hub-note">
                Resume safeguards the recommendation is protecting:
              </p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                {recommendation.resumeSafeguardLabels.map((label) => (
                  <span key={label}>{label}</span>
                ))}
              </div>
            </>
          ) : null}
        </section>
      ) : null}

      {preview ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Compaction preview</strong>
            <span className="artifact-hub-policy-pill">If compacted now</span>
          </div>
          <p>
            Preview what the active session would keep, summarize, and prune
            from the carried-forward resume context. Pruned here means omitted
            from the compacted resume context, not deleted from retained
            evidence.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Carry forward: {previewDecisionCounts.carry_forward}</span>
            <span>
              Summary-retained: {previewDecisionCounts.retained_summary}
            </span>
            <span>Pruned: {previewDecisionCounts.pruned}</span>
            <span>
              {compactionResumeSafetyLabel(preview.resumeSafety.status)}
            </span>
            <span>{preview.preCompactionSpan}</span>
          </div>
          {preview.resumeSafety.reasons.length > 0 ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              {preview.resumeSafety.reasons.map((reason) => (
                <span key={reason}>{reason}</span>
              ))}
            </div>
          ) : null}
          <div className="artifact-hub-generic-list">
            {preview.pruneDecisions.map((decision) => (
              <article className="artifact-hub-generic-row" key={decision.key}>
                <div className="artifact-hub-generic-meta">
                  <span>{decision.label}</span>
                  <span>
                    {compactionDispositionLabel(decision.disposition)}
                  </span>
                  <span>{decision.detailCount} item(s)</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {decision.summary}
                </div>
                <p className="artifact-hub-generic-summary">
                  {decision.rationale}
                </p>
                {decision.examples.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {decision.examples.map((example) => (
                      <span key={`${decision.key}:${example}`}>
                        {clipText(example, 72)}
                      </span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Team memory sync</strong>
          <span className="artifact-hub-policy-pill">
            {teamMemoryBusy
              ? "Updating"
              : teamMemorySnapshot
                ? `${teamMemorySnapshot.entryCount} in scope`
                : "No scope"}
          </span>
        </div>
        <p>
          Promote carried-forward session memory into a scoped multi-actor
          ledger that preserves runtime truth, keeps governance-critical items
          local by default, and redacts sensitive values before shared sync.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Scope: {teamMemoryScopeLabel}</span>
          <span>Entries: {teamMemorySnapshot?.entryCount ?? 0}</span>
          <span>Redacted: {teamMemorySnapshot?.redactedEntryCount ?? 0}</span>
          <span>
            Review required: {teamMemorySnapshot?.reviewRequiredCount ?? 0}
          </span>
        </div>
        <p className="artifact-hub-note">
          {teamMemorySnapshot?.summary ||
            "Sync the active retained session to create the first shared team-memory entry."}
        </p>
        <label className="artifact-hub-compact-policy-toggle">
          <input
            type="checkbox"
            checked={teamMemoryIncludeGovernanceCritical}
            disabled={
              !onSetTeamMemoryIncludeGovernanceCritical || teamMemoryBusy
            }
            onChange={() =>
              onSetTeamMemoryIncludeGovernanceCritical?.(
                !teamMemoryIncludeGovernanceCritical,
              )
            }
          />
          <span className="artifact-hub-compact-policy-copy">
            <strong>Include governance-critical blockers</strong>
            <span>
              Keep this off for the safer default. When enabled, blocker and
              approval context sync into team memory but stay flagged for
              review.
            </span>
          </span>
        </label>
        {teamMemoryError ? (
          <p className="artifact-hub-error">{teamMemoryError}</p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onSyncTeamMemory ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={teamMemoryBusy}
              onClick={() => {
                void onSyncTeamMemory();
              }}
            >
              Sync active session
            </button>
          ) : null}
          {onRefreshTeamMemory ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={teamMemoryBusy}
              onClick={() => {
                void onRefreshTeamMemory();
              }}
            >
              Refresh team memory
            </button>
          ) : null}
        </div>
        {teamMemoryEntries.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {teamMemoryEntries.map((entry) => (
              <article className="artifact-hub-generic-row" key={entry.entryId}>
                <div className="artifact-hub-generic-meta">
                  <span>{entry.scopeLabel}</span>
                  <span>{entry.actorLabel}</span>
                  <span>{formatSessionTimeAgo(entry.syncedAtMs)}</span>
                  <span>{teamMemorySyncStatusLabel(entry.syncStatus)}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {entry.resumeAnchor}
                </div>
                <p className="artifact-hub-generic-summary">{entry.summary}</p>
                <p className="artifact-hub-generic-summary">
                  {entry.reviewSummary}
                </p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>Redactions: {entry.redaction.redactionCount}</span>
                  <span>
                    Governance held local: {entry.omittedGovernanceItemCount}
                  </span>
                  <span>Shared items: {entry.sharedMemoryItems.length}</span>
                  {entry.redaction.redactedFields.map((field) => (
                    <span key={`${entry.entryId}:${field}`}>{field}</span>
                  ))}
                </div>
                {entry.sharedMemoryItems.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {entry.sharedMemoryItems.slice(0, 4).map((item) => (
                      <span key={`${entry.entryId}:${item.key}`}>
                        {item.label}: {item.values.join(" | ")}
                      </span>
                    ))}
                  </div>
                ) : null}
                {onForgetTeamMemoryEntry ? (
                  <div className="artifact-hub-permissions-card__actions">
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={teamMemoryBusy}
                      onClick={() => {
                        void onForgetTeamMemoryEntry(entry.entryId);
                      }}
                    >
                      Forget entry
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            No scoped team-memory entries are stored yet. Sync the active
            session after a meaningful run to retain shared memory with runtime
            redaction and governance posture.
          </p>
        )}
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Manual compaction</strong>
          <span className="artifact-hub-policy-pill">
            {latest
              ? formatSessionTimeAgo(latest.compactedAtMs)
              : "Not compacted yet"}
          </span>
        </div>
        <p>
          Run one manual compaction pass against the active retained session,
          then use the stored resume anchor and carried-forward state from any
          shell.
        </p>
        {latest ? (
          <div className="artifact-hub-generic-list">
            <article className="artifact-hub-generic-row">
              <div className="artifact-hub-generic-meta">
                <span>{latest.title}</span>
                <span>{latestModeLabel}</span>
                <span>{latest.preCompactionSpan}</span>
              </div>
              <div className="artifact-hub-generic-title">
                {latest.resumeAnchor}
              </div>
              <p className="artifact-hub-generic-summary">{latest.summary}</p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                <span>
                  Memory classes:{" "}
                  {Object.keys(memoryClassCounts ?? {}).length || 0}
                </span>
                <span>
                  Governance: {memoryClassCounts?.governance_critical || 0}
                </span>
                <span>Pinned: {memoryClassCounts?.pinned || 0}</span>
                <span>
                  Carry-forward: {memoryClassCounts?.carry_forward || 0}
                </span>
                <span>
                  Summary-retained: {latestDecisionCounts.retained_summary}
                </span>
                <span>Pruned: {latestDecisionCounts.pruned}</span>
                <span>
                  {compactionResumeSafetyLabel(latest.resumeSafety.status)}
                </span>
              </div>
              {latest.resumeSafety.reasons.length > 0 ? (
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  {latest.resumeSafety.reasons.map((reason) => (
                    <span key={reason}>{reason}</span>
                  ))}
                </div>
              ) : null}
            </article>
          </div>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onCompactSession ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onCompactSession(
                  snapshot?.activeSessionId || null,
                  activePolicy,
                );
              }}
            >
              Compact active session
            </button>
          ) : null}
          {onRefreshCompaction ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => {
                void onRefreshCompaction();
              }}
            >
              Refresh compaction state
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("repl")}
            >
              Open REPL
            </button>
          ) : null}
        </div>
      </section>

      {records.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Retained compaction records</span>
            <span>{records.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {records.map((record) => (
              <article
                className="artifact-hub-generic-row"
                key={record.compactionId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{record.title}</span>
                  <span>{formatSessionTimeAgo(record.compactedAtMs)}</span>
                  <span>{record.mode === "auto" ? "Auto" : "Manual"}</span>
                  {record.phase ? <span>{record.phase}</span> : null}
                </div>
                <div className="artifact-hub-generic-title">
                  {record.resumeAnchor}
                </div>
                <p className="artifact-hub-generic-summary">
                  {record.preCompactionSpan}
                </p>
                <p className="artifact-hub-generic-summary">{record.summary}</p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Root:{" "}
                    {record.carriedForwardState.workspaceRoot || "No workspace"}
                  </span>
                  <span>
                    Pins: {record.carriedForwardState.pinnedFiles.length}
                  </span>
                  <span>
                    Includes:{" "}
                    {record.carriedForwardState.explicitIncludes.length}
                  </span>
                  <span>
                    Memory items:{" "}
                    {record.carriedForwardState.memoryItems.length}
                  </span>
                  <span>
                    {compactionResumeSafetyLabel(record.resumeSafety.status)}
                  </span>
                  <span>
                    Pruned:{" "}
                    {compactionDecisionCounts(record.pruneDecisions).pruned}
                  </span>
                  <span>
                    Summary-retained:{" "}
                    {
                      compactionDecisionCounts(record.pruneDecisions)
                        .retained_summary
                    }
                  </span>
                  <span>
                    Blocker: {record.carriedForwardState.blockedOn || "None"}
                  </span>
                </div>
                {record.resumeSafety.reasons.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {record.resumeSafety.reasons.map((reason) => (
                      <span key={`${record.compactionId}:${reason}`}>
                        {reason}
                      </span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No compaction records are stored yet. Run a session, then compact it
          to retain a resumable long-session summary and carry-forward state.
        </p>
      )}
    </div>
  );
}

export function RewindView({
  snapshot,
  status,
  error,
  onLoadSession,
  onRefreshRewind,
  selectedSessionId,
  onSelectSession,
  onOpenCompareForSession,
}: {
  snapshot: SessionRewindSnapshot | null;
  status: string;
  error: string | null;
  onLoadSession?: (sessionId: string) => void;
  onRefreshRewind?: () => Promise<unknown>;
  selectedSessionId: string | null;
  onSelectSession?: (sessionId: string | null) => void;
  onOpenCompareForSession?: (sessionId: string | null) => void;
}) {
  const candidates = snapshot?.candidates ?? [];
  const activeTitle =
    snapshot?.activeSessionTitle?.trim() || "No active retained session";
  const focusedCandidate = selectFocusedRewindCandidate(
    snapshot,
    selectedSessionId,
  );
  const compareReady = canCompareFocusedRewindCandidate(
    snapshot?.activeSessionId,
    focusedCandidate,
  );
  const focusBadge = focusedCandidate?.isCurrent
    ? "Current"
    : focusedCandidate?.isLastStable
      ? "Last stable"
      : "Retained checkpoint";

  return (
    <div className="artifact-hub-rewind">
      <section className="artifact-hub-files-identity artifact-hub-rewind__identity">
        <span className="artifact-hub-files-kicker">Rewind</span>
        <strong>Retained session rewind</strong>
        <p>
          Review retained checkpoints, compare their discard surface against the
          active run, and reopen the selected session without deleting stored
          evidence or other session history.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Status: {humanizeStatus(status)}</span>
          <span>{candidates.length} retained checkpoints</span>
          <span>Active: {activeTitle}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      {focusedCandidate ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Focused rewind checkpoint</strong>
            <span className="artifact-hub-policy-pill">
              {formatSessionTimeAgo(focusedCandidate.timestamp)}
            </span>
          </div>
          <p>{focusedCandidate.previewHeadline}</p>
          <div className="artifact-hub-generic-list">
            <article className="artifact-hub-generic-row">
              <div className="artifact-hub-generic-meta">
                <span>{focusedCandidate.title}</span>
                <span>{focusBadge}</span>
                <span>
                  {sessionRewindSubtitle(focusedCandidate) ||
                    "Retained checkpoint"}
                </span>
              </div>
              <p className="artifact-hub-generic-summary">
                {focusedCandidate.previewDetail}
              </p>
              <p className="artifact-hub-generic-summary">
                {focusedCandidate.discardSummary}
              </p>
            </article>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onLoadSession ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => onLoadSession(focusedCandidate.sessionId)}
              >
                {focusedCandidate.actionLabel}
              </button>
            ) : null}
            {compareReady && onOpenCompareForSession ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() =>
                  onOpenCompareForSession(focusedCandidate.sessionId)
                }
              >
                Review discard preview
              </button>
            ) : null}
            {onRefreshRewind ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => {
                  void onRefreshRewind();
                }}
              >
                Refresh rewind points
              </button>
            ) : null}
          </div>
        </section>
      ) : null}

      {candidates.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Retained checkpoints</span>
            <span>{candidates.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {candidates.map((candidate) => (
              <article
                className="artifact-hub-generic-row"
                key={candidate.sessionId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{candidate.title}</span>
                  <span>{formatSessionTimeAgo(candidate.timestamp)}</span>
                  {candidate.isCurrent ? <span>Current</span> : null}
                  {!candidate.isCurrent && candidate.isLastStable ? (
                    <span>Last stable</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">
                  {candidate.previewHeadline}
                </div>
                <p className="artifact-hub-generic-summary">
                  {sessionRewindSubtitle(candidate) || candidate.previewDetail}
                </p>
                <p className="artifact-hub-generic-summary">
                  {candidate.discardSummary}
                </p>
                {onLoadSession ? (
                  <div className="artifact-hub-generic-actions">
                    {onSelectSession ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        onClick={() => onSelectSession(candidate.sessionId)}
                        type="button"
                      >
                        {candidate.sessionId === focusedCandidate?.sessionId
                          ? "Selected"
                          : "Select"}
                      </button>
                    ) : null}
                    {onOpenCompareForSession &&
                    candidate.sessionId !== snapshot?.activeSessionId ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        onClick={() =>
                          onOpenCompareForSession(candidate.sessionId)
                        }
                        type="button"
                      >
                        Compare
                      </button>
                    ) : null}
                    <button
                      className="artifact-hub-open-btn"
                      onClick={() => onLoadSession(candidate.sessionId)}
                      type="button"
                    >
                      {candidate.actionLabel}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No retained session checkpoints are available yet. Finish or stop a
          run, then reopen Rewind to preview the stored checkpoints.
        </p>
      )}
    </div>
  );
}
