import assert from "node:assert/strict";
import type { CanonicalTraceBundle } from "../../../types";
import { buildPromotionStageDraft } from "./promotionStageModel.ts";
import { buildRetainedPortfolioDossier } from "./retainedPortfolioDossierModel.ts";

function baseBundle(): CanonicalTraceBundle {
  return {
    schemaVersion: 1,
    sessionId: "session-12345678",
    threadId: "thread-abcdef12",
    exportedAtUtc: "2026-04-05T23:30:00.000Z",
    latestAnswerMarkdown:
      "The service candidate is ready for replay-safe promotion with receipts attached.",
    sessionSummary: {
      session_id: "session-12345678",
      title: "Launch the new service candidate",
      timestamp: Date.parse("2026-04-05T23:30:00.000Z"),
      current_step: "Complete",
    },
    history: [],
    events: [],
    interventions: [],
    artifacts: [],
    artifactPayloads: [],
    assistantNotifications: [],
    assistantWorkbenchActivities: [],
    stats: {
      eventCount: 12,
      receiptCount: 4,
      artifactCount: 3,
      runBundleCount: 0,
      reportArtifactCount: 0,
      interventionCount: 2,
      assistantNotificationCount: 0,
      assistantWorkbenchActivityCount: 0,
      includedArtifactPayloads: true,
      includedArtifactPayloadCount: 1,
    },
  };
}

{
  const dossier = buildRetainedPortfolioDossier({
    bundle: baseBundle(),
    portfolio: {
      retainedSessionCount: 3,
      compactedSessionCount: 3,
      replayReadySessionCount: 2,
      uncompactedSessionCount: 0,
      staleCompactionCount: 1,
      degradedCompactionCount: 0,
      recommendedCompactionCount: 1,
      compactedWithoutTeamMemoryCount: 0,
      teamMemoryEntryCount: 3,
      teamMemoryCoveredSessionCount: 3,
      teamMemoryRedactedSessionCount: 1,
      teamMemoryReviewRequiredSessionCount: 0,
      coverageSummary: "2 of 3 retained sessions are replay-ready.",
      teamMemorySummary: "3 synced team-memory entries.",
      attentionSummary: "1 retained session is stale.",
      attentionLabels: ["1 retained session is stale."],
    },
    exportVariant: "operator_share",
    privacyStatusLabel: "Redaction-aware sharing",
    privacyRecommendationLabel: "Share the operator evidence pack.",
    durabilityStatusLabel: "Replay-safe durability",
  });
  const draft = buildPromotionStageDraft({
    target: "sas.xyz",
    bundle: baseBundle(),
    exportVariant: "operator_share",
    exportPath: "/tmp/autopilot-share.zip",
    durabilitySummary: "Replay-safe durability · Auto compaction · 3 synced entries",
    privacySummary: "Redaction-aware sharing · 1 redacted overrides",
    dossier,
  });

  assert.equal(draft.subjectKind, "service_candidate");
  assert.equal(draft.operation, "promote");
  assert.equal(draft.subjectId, "sas.xyz");
  assert.equal(draft.sourceUri, "trace-bundle:thread-abcdef12");
  assert.match(draft.notes, /operator evidence pack/);
  assert.match(draft.notes, /Dossier:/);
  assert.match(draft.notes, /Retained portfolio:/);
  assert.match(draft.notes, /12 events, 4 receipts, 3 artifacts, 1 payloads/);
  assert.match(draft.notes, /Replay-safe durability/);
  assert.match(draft.notes, /Redaction-aware sharing/);
}

{
  const draft = buildPromotionStageDraft({
    target: "IOI CLI",
    sessionId: "session-12345678",
    threadId: "thread-abcdef12",
    bundle: baseBundle(),
  });

  assert.equal(draft.subjectKind, "ioi_cli_domain_release");
  assert.equal(draft.subjectId, "IOI CLI");
  assert.match(draft.notes, /IOI CLI domain productionization review/);
}
