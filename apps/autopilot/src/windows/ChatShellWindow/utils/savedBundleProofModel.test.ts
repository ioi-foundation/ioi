import assert from "node:assert/strict";
import type { CanonicalTraceBundle } from "../../../types";
import { buildRetainedPortfolioDossier } from "./retainedPortfolioDossierModel.ts";
import { buildSavedBundleProofOverview } from "./savedBundleProofModel.ts";

const bundle: CanonicalTraceBundle = {
  schemaVersion: 1,
  sessionId: "session-proof",
  threadId: "thread-proof",
  exportedAtUtc: "2026-04-05T23:40:00.000Z",
  latestAnswerMarkdown: "Ready to export.",
  sessionSummary: {
    session_id: "session-proof",
    title: "Saved bundle review",
    timestamp: Date.parse("2026-04-05T23:40:00.000Z"),
    phase: "Completed",
    current_step: "Review evidence",
    resume_hint: "ready",
    workspace_root: "/tmp/ioi",
  },
  stats: {
    eventCount: 12,
    receiptCount: 4,
    artifactCount: 3,
    runBundleCount: 1,
    reportArtifactCount: 0,
    interventionCount: 0,
    assistantNotificationCount: 0,
    assistantWorkbenchActivityCount: 0,
    includedArtifactPayloads: true,
    includedArtifactPayloadCount: 1,
  },
  history: [],
  events: [],
  artifacts: [],
  artifactPayloads: [],
  interventions: [],
  assistantNotifications: [],
  assistantWorkbenchActivities: [],
};

function dossier(exportVariant: "operator_share" | "redacted_share" | null) {
  return buildRetainedPortfolioDossier({
    sessionTitle: "Saved bundle review",
    bundle,
    portfolio: null,
    exportVariant,
    privacyStatusLabel:
      exportVariant === "redacted_share"
        ? "Privacy review pending"
        : "Operator review ready",
    privacyRecommendationLabel:
      exportVariant === "redacted_share"
        ? "Prefer the redacted review pack until privacy review clears."
        : "Operator evidence pack is aligned.",
    durabilityStatusLabel: "Durability aligned",
  });
}

{
  const overview = buildSavedBundleProofOverview({
    dossier: dossier(null),
    exportPath: null,
    exportTimestampMs: null,
    exportVariant: null,
    bundle,
  });

  assert.equal(overview.tone, "setup");
  assert.equal(overview.statusLabel, "Saved bundle proof not retained yet");
}

{
  const overview = buildSavedBundleProofOverview({
    dossier: dossier("redacted_share"),
    exportPath: "/tmp/autopilot-share.zip",
    exportTimestampMs: Date.parse("2026-04-05T23:45:00.000Z"),
    exportVariant: "operator_share",
    bundle,
  });

  assert.equal(overview.tone, "review");
  assert.match(overview.detail, /recommends redacted review pack/i);
}

{
  const overview = buildSavedBundleProofOverview({
    dossier: dossier("operator_share"),
    exportPath: "/tmp/autopilot-share.zip",
    exportTimestampMs: Date.parse("2026-04-05T23:45:00.000Z"),
    exportVariant: "operator_share",
    bundle,
  });

  assert.equal(overview.tone, "ready");
  assert.equal(overview.statusLabel, "Saved bundle proof retained");
}
