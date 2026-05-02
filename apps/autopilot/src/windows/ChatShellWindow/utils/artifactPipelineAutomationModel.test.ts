import assert from "node:assert/strict";
import { buildArtifactPipelineAutomationPlan } from "./artifactPipelineAutomationModel.ts";
import type { RetainedPortfolioDossier } from "./retainedPortfolioDossierModel";
import type { SavedBundleProofOverview } from "./savedBundleProofModel";

const baseDossier: RetainedPortfolioDossier = {
  title: "Operator review dossier · Session",
  readiness: "ready",
  readinessLabel: "Dossier ready",
  summary: "Ready",
  recommendedVariant: "operator_share",
  recommendedVariantLabel: "Operator evidence pack",
  latestExportLabel: "Operator evidence pack",
  latestExportMatchesRecommendation: true,
  portfolioSummary: "2/2 replay-ready",
  checklist: [],
};

const readyProof: SavedBundleProofOverview = {
  tone: "ready",
  statusLabel: "Saved bundle proof retained",
  detail: "Ready",
  meta: [],
  checklist: [],
};

{
  const plan = buildArtifactPipelineAutomationPlan({
    dossier: {
      ...baseDossier,
      latestExportMatchesRecommendation: false,
    },
    savedBundleProof: {
      ...readyProof,
      tone: "review",
      statusLabel: "Saved bundle proof needs review",
    },
    privacyOverview: {
      statusLabel: "Operator-ready sharing",
      detail: "Ready",
      exportSummary: "Ready",
      recommendationLabel: "Operator evidence pack is allowed.",
    },
    durabilityOverview: {
      statusLabel: "Replay-safe durability",
      detail: "Ready",
      compactionSummary: "Ready",
      teamMemorySummary: "Ready",
    },
  });

  assert.equal(plan.actionKind, "export_recommended_pack");
  assert.equal(plan.queuedActions.length, 1);
}

{
  const plan = buildArtifactPipelineAutomationPlan({
    dossier: {
      ...baseDossier,
      recommendedVariant: "redacted_share",
      recommendedVariantLabel: "Redacted review pack",
    },
    savedBundleProof: readyProof,
    privacyOverview: {
      statusLabel: "Redaction-aware sharing",
      detail: "Review privacy",
      exportSummary: "Ready",
      recommendationLabel: "Prefer redacted review pack.",
    },
    durabilityOverview: {
      statusLabel: "Replay-safe durability",
      detail: "Ready",
      compactionSummary: "Ready",
      teamMemorySummary: "Ready",
    },
  });

  assert.equal(plan.actionKind, "review_privacy");
  assert.equal(plan.recommendedView, "privacy");
  assert.equal(plan.queuedActions.length, 1);
}

{
  const plan = buildArtifactPipelineAutomationPlan({
    dossier: {
      ...baseDossier,
      readiness: "review",
      readinessLabel: "Portfolio review recommended",
    },
    savedBundleProof: readyProof,
    privacyOverview: {
      statusLabel: "Operator-ready sharing",
      detail: "Ready",
      exportSummary: "Ready",
      recommendationLabel: "Operator evidence pack is allowed.",
    },
    durabilityOverview: {
      statusLabel: "Durability review pending",
      detail: "Review durability",
      compactionSummary: "Pending",
      teamMemorySummary: "Pending",
    },
  });

  assert.equal(plan.actionKind, "review_durability");
  assert.equal(plan.recommendedView, "compact");
  assert.equal(plan.queuedActions.length, 1);
}

{
  const plan = buildArtifactPipelineAutomationPlan({
    dossier: baseDossier,
    savedBundleProof: readyProof,
    privacyOverview: {
      statusLabel: "Operator-ready sharing",
      detail: "Ready",
      exportSummary: "Ready",
      recommendationLabel: "Operator evidence pack is allowed.",
    },
    durabilityOverview: {
      statusLabel: "Replay-safe durability",
      detail: "Ready",
      compactionSummary: "Ready",
      teamMemorySummary: "Ready",
    },
    stagedOperations: [],
  });

  assert.equal(plan.actionKind, "stage_promotion");
  assert.equal(plan.promotionTarget, "sas.xyz");
  assert.equal(plan.queuedActions.length, 2);
  assert.equal(plan.queuedActions[1].promotionTarget, "IOI CLI");
}

{
  const plan = buildArtifactPipelineAutomationPlan({
    dossier: baseDossier,
    savedBundleProof: readyProof,
    privacyOverview: {
      statusLabel: "Operator-ready sharing",
      detail: "Ready",
      exportSummary: "Ready",
      recommendationLabel: "Operator evidence pack is allowed.",
    },
    durabilityOverview: {
      statusLabel: "Replay-safe durability",
      detail: "Ready",
      compactionSummary: "Ready",
      teamMemorySummary: "Ready",
    },
    stagedOperations: [
      {
        operationId: "op-1",
        subjectKind: "service_candidate",
        operation: "promote",
        title: "sas.xyz",
        sourceUri: "trace-bundle:thread-1",
        subjectId: "sas.xyz",
        notes: null,
        createdAtMs: 1,
        status: "staged",
      },
    ],
  });

  assert.equal(plan.actionKind, "stage_promotion");
  assert.equal(plan.promotionTarget, "IOI CLI");
  assert.equal(plan.queuedActions.length, 1);
}

{
  const plan = buildArtifactPipelineAutomationPlan({
    dossier: baseDossier,
    savedBundleProof: readyProof,
    privacyOverview: {
      statusLabel: "Operator-ready sharing",
      detail: "Ready",
      exportSummary: "Ready",
      recommendationLabel: "Operator evidence pack is allowed.",
    },
    durabilityOverview: {
      statusLabel: "Replay-safe durability",
      detail: "Ready",
      compactionSummary: "Ready",
      teamMemorySummary: "Ready",
    },
    stagedOperations: [
      {
        operationId: "op-1",
        subjectKind: "service_candidate",
        operation: "promote",
        title: "sas.xyz",
        sourceUri: "trace-bundle:thread-1",
        subjectId: "sas.xyz",
        notes: null,
        createdAtMs: 1,
        status: "staged",
      },
      {
        operationId: "op-2",
        subjectKind: "ioi_cli_domain_release",
        operation: "promote",
        title: "IOI CLI",
        sourceUri: "trace-bundle:thread-1",
        subjectId: "IOI CLI",
        notes: null,
        createdAtMs: 2,
        status: "staged",
      },
    ],
  });

  assert.equal(plan.actionKind, "none");
  assert.equal(plan.recommendedView, "thoughts");
  assert.equal(plan.queuedActions.length, 0);
}
