import assert from "node:assert/strict";
import type {
  CanonicalTraceBundle,
  SessionDurabilityPortfolio,
} from "../../../types";
import { buildRetainedPortfolioDossier } from "./retainedPortfolioDossierModel.ts";

const readyBundle = {
  sessionId: "session-abcdef12",
  threadId: "thread-abcdef12",
  exportedAtUtc: "2026-04-05T23:59:00.000Z",
  sessionSummary: {
    title: "Launch the service candidate",
  },
  stats: {
    eventCount: 12,
    receiptCount: 4,
    artifactCount: 3,
    includedArtifactPayloadCount: 1,
  },
  artifactPayloads: [],
} as unknown as CanonicalTraceBundle;

const alignedPortfolio = {
  retainedSessionCount: 3,
  compactedSessionCount: 3,
  replayReadySessionCount: 3,
  uncompactedSessionCount: 0,
  staleCompactionCount: 0,
  degradedCompactionCount: 0,
  recommendedCompactionCount: 0,
  compactedWithoutTeamMemoryCount: 0,
  teamMemoryEntryCount: 6,
  teamMemoryCoveredSessionCount: 3,
  teamMemoryRedactedSessionCount: 0,
  teamMemoryReviewRequiredSessionCount: 0,
  coverageSummary: "All retained sessions are replay-ready.",
  teamMemorySummary: "Team memory is aligned.",
  attentionSummary: "No retained attention required.",
  attentionLabels: [],
} as SessionDurabilityPortfolio;

{
  const dossier = buildRetainedPortfolioDossier({
    bundle: readyBundle,
    portfolio: alignedPortfolio,
    exportVariant: "operator_share",
    privacyStatusLabel: "Operator review allowed",
    privacyRecommendationLabel: "Share the operator evidence pack.",
    durabilityStatusLabel: "Replay-safe durability",
  });

  assert.equal(dossier.readiness, "ready");
  assert.equal(dossier.recommendedVariant, "operator_share");
  assert.equal(dossier.latestExportMatchesRecommendation, true);
  assert.match(dossier.title, /Operator review dossier/i);
  assert.match(dossier.portfolioSummary, /3\/3 replay-ready/i);
}

{
  const dossier = buildRetainedPortfolioDossier({
    bundle: readyBundle,
    portfolio: {
      ...alignedPortfolio,
      staleCompactionCount: 1,
      attentionLabels: ["A retained session is stale."],
    },
    exportVariant: "trace_bundle",
    privacyStatusLabel: "Pending review",
    privacyRecommendationLabel: "Prefer the redacted review pack until privacy review clears.",
    durabilityStatusLabel: "Replay-safe durability",
  });

  assert.equal(dossier.readiness, "review");
  assert.equal(dossier.recommendedVariant, "redacted_share");
  assert.equal(dossier.latestExportMatchesRecommendation, false);
  assert.match(dossier.summary, /still deserves one more pass/i);
  assert.match(dossier.checklist.join(" "), /Redacted review pack/i);
}

{
  const dossier = buildRetainedPortfolioDossier({
    sessionTitle: "No replay yet",
    bundle: null,
    portfolio: null,
    exportVariant: null,
    privacyStatusLabel: "Operator review allowed",
    privacyRecommendationLabel: "Share the operator evidence pack.",
    durabilityStatusLabel: "Replay-safe durability",
  });

  assert.equal(dossier.readiness, "setup");
  assert.match(dossier.summary, /Load the canonical replay bundle/i);
  assert.match(dossier.portfolioSummary, /Active-session posture only/i);
}
