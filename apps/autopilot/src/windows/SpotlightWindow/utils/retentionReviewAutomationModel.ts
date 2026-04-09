import type {
  ArtifactHubViewKey,
  SessionCompactionSnapshot,
  TeamMemorySyncSnapshot,
} from "../../../types";

export type RetentionReviewAutomationTone = "setup" | "review" | "ready";
export type RetentionReviewAutomationActionKind =
  | "compact_active_session"
  | "sync_team_memory"
  | "open_view"
  | "none";

export interface RetentionReviewAutomationQueuedAction {
  kind: Exclude<RetentionReviewAutomationActionKind, "none">;
  label: string;
  detail: string;
  recommendedView: ArtifactHubViewKey | null;
}

export interface RetentionReviewAutomationPlan {
  tone: RetentionReviewAutomationTone;
  statusLabel: string;
  detail: string;
  actionKind: RetentionReviewAutomationActionKind;
  primaryActionLabel: string | null;
  recommendedView: ArtifactHubViewKey | null;
  checklist: string[];
  queuedActions: RetentionReviewAutomationQueuedAction[];
}

export function buildRetentionReviewAutomationPlan(input: {
  compactionSnapshot?: SessionCompactionSnapshot | null;
  teamMemorySnapshot?: TeamMemorySyncSnapshot | null;
}): RetentionReviewAutomationPlan {
  const snapshot = input.compactionSnapshot ?? null;
  const teamMemory = input.teamMemorySnapshot ?? null;
  const latest = snapshot?.latestForActive ?? null;
  const recommendation = snapshot?.recommendationForActive ?? null;
  const portfolio = snapshot?.durabilityPortfolio ?? null;
  const activeSessionId = snapshot?.activeSessionId?.trim();
  const checklist = [
    `Active session: ${snapshot?.activeSessionTitle?.trim() || "No retained session"}`,
    `Compaction records: ${snapshot?.recordCount ?? 0}`,
    `Replay-ready: ${portfolio?.replayReadySessionCount ?? 0}/${portfolio?.retainedSessionCount ?? 0}`,
    `Portfolio attention: ${portfolio?.attentionLabels.length ?? 0}`,
    `Team-memory entries: ${teamMemory?.entryCount ?? portfolio?.teamMemoryEntryCount ?? 0}`,
    `Team-memory review required: ${teamMemory?.reviewRequiredCount ?? portfolio?.teamMemoryReviewRequiredSessionCount ?? 0}`,
  ];

  if (!activeSessionId) {
    return {
      tone: "setup",
      statusLabel: "Retained session required",
      detail:
        "Open or retain a session before the shell can automate compaction, team-memory sync, or retained-portfolio review.",
      actionKind: "none",
      primaryActionLabel: null,
      recommendedView: "replay",
      checklist,
      queuedActions: [],
    };
  }

  const queuedActions: RetentionReviewAutomationQueuedAction[] = [];
  if (!latest || recommendation?.shouldCompact) {
    queuedActions.push({
      kind: "compact_active_session",
      label: latest ? "Refresh protected compaction" : "Compact active session",
      recommendedView: null,
      detail: latest
        ? `The runtime is still recommending ${recommendation?.recommendedPolicyLabel?.toLowerCase() || "another"} compaction pass for the active retained session before wider review or export.`
        : "The active retained session does not have a compaction record yet, so capture one before wider review or export.",
    });
  }

  if (
    (teamMemory?.entryCount ?? 0) === 0 ||
    (portfolio?.compactedWithoutTeamMemoryCount ?? 0) > 0
  ) {
    queuedActions.push({
      kind: "sync_team_memory",
      label: "Sync team memory",
      recommendedView: null,
      detail:
        "At least one compacted retained session is missing team-memory coverage, so sync the active session before wider handoff or promotion.",
    });
  }

  if (
    (teamMemory?.reviewRequiredCount ?? 0) > 0 ||
    (portfolio?.attentionLabels.length ?? 0) > 0
  ) {
    queuedActions.push({
      kind: "open_view",
      label: "Review retained portfolio",
      recommendedView: "review",
      detail:
        portfolio?.attentionSummary ||
        teamMemory?.summary ||
        "Retained durability posture still needs review before the next handoff.",
    });
  }

  if (queuedActions.length === 0) {
    queuedActions.push({
      kind: "open_view",
      label: "Continue to Export",
      recommendedView: "export",
      detail:
        "Protected compaction, retained portfolio posture, and team-memory coverage are aligned enough to continue into the export and promotion lane.",
    });
  }

  const primaryAction = queuedActions[0];
  return {
    tone:
      primaryAction.kind === "open_view" &&
      primaryAction.recommendedView === "export"
        ? "ready"
        : "review",
    statusLabel:
      primaryAction.kind === "compact_active_session"
        ? "Compaction should lead retention review"
        : primaryAction.kind === "sync_team_memory"
          ? "Team-memory sync should lead retention review"
          : primaryAction.recommendedView === "export"
            ? "Retention review is ready to hand off"
            : "Retained portfolio review should lead",
    detail: primaryAction.detail,
    actionKind: primaryAction.kind,
    primaryActionLabel: primaryAction.label,
    recommendedView: primaryAction.recommendedView,
    checklist,
    queuedActions,
  };
}
