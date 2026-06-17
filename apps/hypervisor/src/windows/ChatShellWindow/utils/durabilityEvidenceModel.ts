import type {
  SessionCompactionSnapshot,
  TeamMemorySyncSnapshot,
} from "../../../types";

export interface DurabilityEvidenceOverview {
  statusLabel: string;
  detail: string;
  compactionSummary: string;
  teamMemorySummary: string;
}

export function buildDurabilityEvidenceOverview(input: {
  activeSessionId?: string | null;
  compactionSnapshot?: SessionCompactionSnapshot | null;
  teamMemorySnapshot?: TeamMemorySyncSnapshot | null;
}): DurabilityEvidenceOverview {
  const latestCompaction = input.compactionSnapshot?.latestForActive || null;
  const recommendation = input.compactionSnapshot?.recommendationForActive || null;
  const portfolio = input.compactionSnapshot?.durabilityPortfolio || null;
  const teamMemory = input.teamMemorySnapshot || null;
  const hasActiveSession = Boolean(input.activeSessionId?.trim());

  const compactionSummary = latestCompaction
    ? `${latestCompaction.mode === "auto" ? "Auto compaction" : "Manual compaction"} · ${
        latestCompaction.resumeSafety.status === "protected"
          ? "Protected resume"
          : "Degraded resume"
      } · ${latestCompaction.resumeAnchor}`
    : recommendation?.shouldCompact
      ? `Compaction recommended · ${recommendation.recommendedPolicyLabel}`
      : portfolio?.coverageSummary
        ? portfolio.coverageSummary
        : hasActiveSession
          ? "No retained compaction record yet"
          : "Open a retained session to inspect compaction posture";

  const teamMemorySummary = teamMemory
    ? `${teamMemory.entryCount} synced entries · ${teamMemory.reviewRequiredCount} review required · ${teamMemory.redactedEntryCount} redacted`
    : portfolio?.teamMemorySummary
      ? portfolio.teamMemorySummary
    : hasActiveSession
      ? "No team-memory snapshot yet"
      : "No team-memory scope selected";

  if (portfolio?.attentionLabels.length) {
    return {
      statusLabel: "Durability review pending",
      detail: portfolio.attentionSummary,
      compactionSummary,
      teamMemorySummary,
    };
  }

  if (latestCompaction?.resumeSafety.status === "protected") {
    return {
      statusLabel: "Replay-safe durability",
      detail:
        "The latest retained compaction record keeps a protected resume posture, and export/share can carry that same long-session context forward.",
      compactionSummary,
      teamMemorySummary,
    };
  }

  if (recommendation?.shouldCompact || teamMemory?.reviewRequiredCount) {
    return {
      statusLabel: "Durability review pending",
      detail:
        "The retained session can already be exported, but compaction or team-memory review still deserves attention before wider handoff or promotion.",
      compactionSummary,
      teamMemorySummary,
    };
  }

  return {
    statusLabel: hasActiveSession ? "Durability baseline" : "Durability pending",
    detail: hasActiveSession
      ? "Export and share can still use the canonical trace bundle even before a retained compaction record or team-memory sync is captured."
      : "Run or reopen a retained session to attach compaction and team-memory posture to the evidence path.",
    compactionSummary,
    teamMemorySummary,
  };
}
