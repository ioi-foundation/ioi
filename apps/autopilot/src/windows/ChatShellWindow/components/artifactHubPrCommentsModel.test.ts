import assert from "node:assert/strict";
import { buildPrCommentsOverview } from "./artifactHubPrCommentsModel.ts";

{
  const overview = buildPrCommentsOverview({
    sessionTitle: "Autopilot validation run",
    branchLabel: "feature/mobile",
    lastCommitLabel: "abc123 Add mobile handoff drawer",
    progressSummary: "Validation passed and artifacts retained.",
    currentStage: "verification",
    selectedRoute: "coding",
    changedPathCount: 5,
    stagedPathCount: 5,
    unstagedPathCount: 0,
    evidenceEventCount: 12,
    evidenceArtifactCount: 4,
    visibleSourceCount: 3,
    screenshotCount: 1,
    substrateReceiptCount: 2,
    verifierState: "passed",
    verifierOutcome: "pass",
    approvalState: "clear",
    verificationNotes: ["Verifier state: Passed · Outcome: Pass · Approval: Clear"],
  });

  assert.equal(overview.readiness, "ready");
  assert.equal(overview.readinessLabel, "Ready for reviewer handoff");
  assert.equal(overview.draftCount, 3);
  assert.match(overview.drafts[0].markdown, /abc123 Add mobile handoff drawer/);
  assert.match(overview.drafts[1].markdown, /ready for focused review/i);
}

{
  const overview = buildPrCommentsOverview({
    sessionTitle: "Autopilot validation run",
    branchLabel: "feature/review",
    lastCommitLabel: null,
    progressSummary: "Awaiting clarification.",
    currentStage: "review",
    selectedRoute: "coding",
    changedPathCount: 2,
    stagedPathCount: 1,
    unstagedPathCount: 1,
    evidenceEventCount: 3,
    evidenceArtifactCount: 1,
    visibleSourceCount: 1,
    screenshotCount: 0,
    substrateReceiptCount: 1,
    verifierState: "blocked",
    verifierOutcome: "blocked",
    approvalState: "pending",
    blockerTitle: "Clarification required",
    blockerDetail: "Need the final API shape before landing the patch.",
  });

  assert.equal(overview.readiness, "attention");
  assert.match(overview.readinessDetail, /follow-up explicitly/i);
  assert.match(overview.drafts[2].markdown, /Clarification required/);
  assert.match(overview.drafts[2].markdown, /final API shape/i);
}

{
  const overview = buildPrCommentsOverview({
    sessionTitle: null,
    branchLabel: null,
    lastCommitLabel: null,
    progressSummary: null,
    currentStage: null,
    selectedRoute: null,
    changedPathCount: 0,
    stagedPathCount: 0,
    unstagedPathCount: 0,
    evidenceEventCount: 0,
    evidenceArtifactCount: 0,
    visibleSourceCount: 0,
    screenshotCount: 0,
    substrateReceiptCount: 0,
    verifierState: "queued",
    verifierOutcome: null,
    approvalState: "pending",
  });

  assert.equal(overview.readiness, "draft");
  assert.match(overview.drafts[0].markdown, /current change set/i);
}
