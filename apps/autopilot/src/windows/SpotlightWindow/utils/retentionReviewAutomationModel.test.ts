import assert from "node:assert/strict";
import {
  buildRetentionReviewAutomationPlan,
} from "./retentionReviewAutomationModel.ts";
import type {
  SessionCompactionPolicy,
  SessionCompactionRecord,
  SessionCompactionRecommendation,
  SessionCompactionSnapshot,
  SessionDurabilityPortfolio,
  TeamMemorySyncSnapshot,
} from "../../../types.ts";

const policy: SessionCompactionPolicy = {
  carryPinnedOnly: false,
  preserveChecklistState: true,
  preserveBackgroundTasks: true,
  preserveLatestOutputExcerpt: true,
  preserveGovernanceBlockers: true,
  aggressiveTranscriptPruning: false,
};

function latestRecord(
  overrides: Partial<SessionCompactionRecord> = {},
): SessionCompactionRecord {
  return {
    compactionId: "session-1:1",
    sessionId: "session-1",
    title: "Retained proof session",
    compactedAtMs: 1,
    mode: "manual",
    phase: "Complete",
    policy,
    preCompactionSpan: "12m active span",
    summary: "Compacted summary",
    resumeAnchor: "Resume from protected anchor",
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
      reasons: ["Protected resume anchor retained."],
    },
    pruneDecisions: [],
    ...overrides,
  };
}

function recommendation(
  overrides: Partial<SessionCompactionRecommendation> = {},
): SessionCompactionRecommendation {
  return {
    shouldCompact: false,
    reasonLabels: [],
    recommendedPolicy: policy,
    recommendedPolicyLabel: "Balanced carry-forward",
    recommendedPolicyReasonLabels: [],
    resumeSafeguardLabels: [],
    historyCount: 10,
    eventCount: 25,
    artifactCount: 2,
    pinnedFileCount: 0,
    explicitIncludeCount: 0,
    idleAgeMs: 1000,
    blockedAgeMs: null,
    ...overrides,
  };
}

function portfolio(
  overrides: Partial<SessionDurabilityPortfolio> = {},
): SessionDurabilityPortfolio {
  return {
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
    coverageSummary: "1/1 replay-ready.",
    teamMemorySummary: "1 team-memory entry.",
    attentionSummary: "Retention review is healthy.",
    attentionLabels: [],
    ...overrides,
  };
}

function snapshot(
  overrides: Partial<SessionCompactionSnapshot> = {},
): SessionCompactionSnapshot {
  return {
    generatedAtMs: 1,
    activeSessionId: "session-1",
    activeSessionTitle: "Retained proof session",
    policyForActive: policy,
    recordCount: 1,
    latestForActive: latestRecord(),
    previewForActive: null,
    recommendationForActive: recommendation(),
    durabilityPortfolio: portfolio(),
    records: [latestRecord()],
    ...overrides,
  };
}

function teamMemory(
  overrides: Partial<TeamMemorySyncSnapshot> = {},
): TeamMemorySyncSnapshot {
  return {
    generatedAtMs: 1,
    activeSessionId: "session-1",
    activeScopeId: "workspace:/repo",
    activeScopeKind: "workspace",
    activeScopeLabel: "Current workspace",
    entryCount: 1,
    redactedEntryCount: 0,
    reviewRequiredCount: 0,
    summary: "1 synced entry.",
    entries: [],
    ...overrides,
  };
}

{
  const plan = buildRetentionReviewAutomationPlan({});
  assert.equal(plan.tone, "setup");
  assert.equal(plan.actionKind, "none");
  assert.match(plan.detail, /retain a session/i);
}

{
  const plan = buildRetentionReviewAutomationPlan({
    compactionSnapshot: snapshot({
      latestForActive: null,
      recordCount: 0,
      records: [],
      recommendationForActive: recommendation({
        shouldCompact: true,
        recommendedPolicyLabel: "Lean carry-forward",
      }),
      durabilityPortfolio: portfolio({
        replayReadySessionCount: 0,
        compactedSessionCount: 0,
        uncompactedSessionCount: 1,
        attentionLabels: ["No retained sessions have compaction records yet."],
        attentionSummary: "Compaction still needs to run.",
      }),
    }),
    teamMemorySnapshot: teamMemory({ entryCount: 0 }),
  });

  assert.equal(plan.tone, "review");
  assert.equal(plan.actionKind, "compact_active_session");
  assert.equal(plan.primaryActionLabel, "Compact active session");
  assert.equal(plan.queuedActions[1]?.kind, "sync_team_memory");
}

{
  const plan = buildRetentionReviewAutomationPlan({
    compactionSnapshot: snapshot({
      durabilityPortfolio: portfolio({
        compactedWithoutTeamMemoryCount: 1,
        teamMemoryEntryCount: 0,
      }),
    }),
    teamMemorySnapshot: teamMemory({ entryCount: 0, summary: "No entries yet." }),
  });

  assert.equal(plan.actionKind, "sync_team_memory");
  assert.equal(plan.primaryActionLabel, "Sync team memory");
}

{
  const plan = buildRetentionReviewAutomationPlan({
    compactionSnapshot: snapshot({
      durabilityPortfolio: portfolio({
        attentionLabels: ["1 retained session still needs review."],
        attentionSummary: "1 retained session still needs review.",
      }),
    }),
    teamMemorySnapshot: teamMemory({ reviewRequiredCount: 1 }),
  });

  assert.equal(plan.actionKind, "open_view");
  assert.equal(plan.primaryActionLabel, "Review retained portfolio");
  assert.equal(plan.recommendedView, "review");
}

{
  const plan = buildRetentionReviewAutomationPlan({
    compactionSnapshot: snapshot(),
    teamMemorySnapshot: teamMemory(),
  });

  assert.equal(plan.tone, "ready");
  assert.equal(plan.actionKind, "open_view");
  assert.equal(plan.primaryActionLabel, "Continue to Export");
  assert.equal(plan.recommendedView, "export");
}
