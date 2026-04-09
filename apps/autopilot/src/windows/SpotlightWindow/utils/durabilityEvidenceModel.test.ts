import assert from "node:assert/strict";
import type {
  SessionCompactionSnapshot,
  TeamMemorySyncSnapshot,
} from "../../../types";
import { buildDurabilityEvidenceOverview } from "./durabilityEvidenceModel.ts";

const protectedCompactionSnapshot: SessionCompactionSnapshot = {
  generatedAtMs: Date.parse("2026-04-05T23:55:00.000Z"),
  activeSessionId: "session-123",
  activeSessionTitle: "Long-running session",
  policyForActive: {
    carryPinnedOnly: false,
    preserveChecklistState: true,
    preserveBackgroundTasks: true,
    preserveLatestOutputExcerpt: true,
    preserveGovernanceBlockers: true,
    aggressiveTranscriptPruning: false,
  },
  recordCount: 1,
  latestForActive: {
    compactionId: "session-123:1",
    sessionId: "session-123",
    title: "Long-running session",
    compactedAtMs: Date.parse("2026-04-05T23:54:00.000Z"),
    mode: "auto",
    phase: "Complete",
    policy: {
      carryPinnedOnly: false,
      preserveChecklistState: true,
      preserveBackgroundTasks: true,
      preserveLatestOutputExcerpt: true,
      preserveGovernanceBlockers: true,
      aggressiveTranscriptPruning: false,
    },
    preCompactionSpan: "120 turns",
    summary: "Compact summary",
    resumeAnchor: "Resume from final validation",
    carriedForwardState: {
      workspaceRoot: "/repo",
      pinnedFiles: [],
      explicitIncludes: [],
      explicitExcludes: [],
      checklistLabels: [],
      backgroundTaskLabels: [],
      blockedOn: null,
      pendingDecisionContext: null,
      latestArtifactOutcome: null,
      executionTargets: [],
      latestOutputExcerpt: null,
      memoryItems: [],
    },
    resumeSafety: {
      status: "protected",
      reasons: ["Checklist retained"],
    },
    pruneDecisions: [],
  },
  previewForActive: null,
  recommendationForActive: null,
  durabilityPortfolio: {
    retainedSessionCount: 1,
    compactedSessionCount: 1,
    replayReadySessionCount: 1,
    uncompactedSessionCount: 0,
    staleCompactionCount: 0,
    degradedCompactionCount: 0,
    recommendedCompactionCount: 0,
    compactedWithoutTeamMemoryCount: 0,
    teamMemoryEntryCount: 1,
    teamMemoryCoveredSessionCount: 1,
    teamMemoryRedactedSessionCount: 0,
    teamMemoryReviewRequiredSessionCount: 0,
    coverageSummary: "1 of 1 retained sessions are replay-ready.",
    teamMemorySummary: "1 retained session is represented in team memory.",
    attentionSummary: "Cross-session durability coverage is healthy.",
    attentionLabels: [],
  },
  records: [],
};

const teamMemorySnapshot: TeamMemorySyncSnapshot = {
  generatedAtMs: Date.parse("2026-04-05T23:56:00.000Z"),
  activeSessionId: "session-123",
  activeScopeId: "workspace:/repo",
  activeScopeKind: "workspace",
  activeScopeLabel: "repo",
  entryCount: 3,
  redactedEntryCount: 1,
  reviewRequiredCount: 1,
  summary: "Team memory summary",
  entries: [],
};

{
  const overview = buildDurabilityEvidenceOverview({
    activeSessionId: "session-123",
    compactionSnapshot: protectedCompactionSnapshot,
    teamMemorySnapshot,
  });

  assert.equal(overview.statusLabel, "Replay-safe durability");
  assert.match(overview.compactionSummary, /Protected resume/);
  assert.match(overview.teamMemorySummary, /3 synced entries/);
}

{
  const overview = buildDurabilityEvidenceOverview({
    activeSessionId: "session-123",
    compactionSnapshot: {
      ...protectedCompactionSnapshot,
      latestForActive: null,
      recommendationForActive: {
        shouldCompact: true,
        reasonLabels: ["Long session"],
        recommendedPolicy: protectedCompactionSnapshot.policyForActive,
        recommendedPolicyLabel: "Lean carry-forward",
        recommendedPolicyReasonLabels: ["Large transcript"],
        resumeSafeguardLabels: ["Checklist retained"],
        historyCount: 120,
        eventCount: 240,
        artifactCount: 12,
        pinnedFileCount: 2,
        explicitIncludeCount: 1,
        idleAgeMs: 5_000,
        blockedAgeMs: null,
      },
    },
    teamMemorySnapshot: {
      ...teamMemorySnapshot,
      reviewRequiredCount: 2,
    },
  });

  assert.equal(overview.statusLabel, "Durability review pending");
  assert.match(overview.compactionSummary, /Lean carry-forward/);
  assert.match(overview.detail, /review still deserves attention/i);
}

{
  const overview = buildDurabilityEvidenceOverview({
    activeSessionId: "session-123",
    compactionSnapshot: {
      ...protectedCompactionSnapshot,
      durabilityPortfolio: {
        ...protectedCompactionSnapshot.durabilityPortfolio!,
        retainedSessionCount: 3,
        replayReadySessionCount: 1,
        staleCompactionCount: 1,
        attentionSummary:
          "1 retained session has new activity since the latest compaction record.",
        attentionLabels: [
          "1 retained session has new activity since the latest compaction record.",
        ],
      },
    },
  });

  assert.equal(overview.statusLabel, "Durability review pending");
  assert.match(overview.detail, /new activity since the latest compaction/i);
  assert.match(overview.compactionSummary, /Protected resume/);
  assert.match(overview.teamMemorySummary, /represented in team memory/i);
}
