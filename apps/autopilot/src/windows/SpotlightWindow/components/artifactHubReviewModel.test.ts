import assert from "node:assert/strict";
import { buildReviewOverview } from "./artifactHubReviewModel.ts";

{
  const overview = buildReviewOverview({
    sessionTitle: "Ship the shared runtime review hub",
    branchLabel: "feature/review-hub",
    changedPathCount: 6,
    stagedPathCount: 6,
    unstagedPathCount: 0,
    evidenceEventCount: 18,
    evidenceArtifactCount: 5,
    visibleSourceCount: 4,
    screenshotCount: 1,
    substrateReceiptCount: 3,
    verifierState: "passed",
    verifierOutcome: "pass",
    approvalState: "approved",
    prReadiness: "ready",
    prReadinessLabel: "Ready for reviewer handoff",
    prReadinessDetail: "Drafts and evidence are aligned.",
    privacyStatusLabel: "Redacted export allowed",
    privacyDetail: "The current share posture is already redaction-aware.",
    privacyRecommendationLabel: "Use the redacted review pack for wider handoff.",
    durabilityStatusLabel: "Replay-safe durability",
    durabilityDetail: "Compaction and team memory are already aligned.",
    exportStatus: "success",
    exportVariant: "redacted_review",
    replayReady: true,
  });

  assert.equal(overview.tone, "ready");
  assert.equal(overview.reviewCount, 0);
  assert.equal(overview.cards[0].value, "Runtime evidence aligned");
  assert.equal(overview.cards[1].actionView, "pr_comments");
  assert.equal(overview.cards[3].tone, "ready");
}

{
  const overview = buildReviewOverview({
    sessionTitle: "Investigate the blocker",
    branchLabel: "feature/review-hub",
    changedPathCount: 2,
    stagedPathCount: 1,
    unstagedPathCount: 1,
    evidenceEventCount: 3,
    evidenceArtifactCount: 1,
    visibleSourceCount: 1,
    screenshotCount: 0,
    substrateReceiptCount: 1,
    verifierState: "running",
    verifierOutcome: "blocked",
    approvalState: "pending",
    blockerTitle: "Approval gate waiting",
    blockerDetail: "A governed write path still needs operator approval.",
    prReadiness: "attention",
    prReadinessLabel: "Follow-up needed before review",
    prReadinessDetail: "The reviewer handoff should stay conditional.",
    privacyStatusLabel: "Privacy review pending",
    privacyDetail: "A privacy posture change is still waiting for review.",
    privacyRecommendationLabel: "Prefer the redacted review pack until approved.",
    durabilityStatusLabel: "Durability review pending",
    durabilityDetail: "Compaction or team-memory review is still pending.",
    exportStatus: "idle",
    exportVariant: null,
    replayReady: true,
  });

  assert.equal(overview.tone, "attention");
  assert.equal(overview.reviewCount, 4);
  assert.equal(overview.cards[0].actionView, "tasks");
  assert.equal(overview.cards[2].actionView, "privacy");
  assert.equal(overview.cards[3].tone, "attention");
}
