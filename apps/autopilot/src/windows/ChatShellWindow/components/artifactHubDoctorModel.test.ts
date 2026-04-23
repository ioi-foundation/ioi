import assert from "node:assert/strict";
import {
  buildDoctorOverview,
  type BuildDoctorOverviewInput,
} from "./artifactHubDoctorModel.ts";

function baseInput(): BuildDoctorOverviewInput {
  return {
    runtime: {
      status: "ready",
      error: null,
      pendingApprovalCount: 0,
      pendingControlCount: 0,
      activeIssueCount: 0,
      liveJobCount: 0,
      backendCount: 2,
      healthyBackendCount: 2,
      degradedBackendCount: 0,
    },
    authority: {
      permissionsStatus: "ready",
      permissionsError: null,
      pendingGovernance: false,
      activeOverrideCount: 0,
      rememberedApprovalCount: 0,
      requiresPrivacyReview: false,
      redactedOverrideCount: 0,
    },
    extensions: {
      pluginCount: 3,
      blockedPluginCount: 0,
      reviewRequiredPluginCount: 0,
      criticalUpdateCount: 0,
      refreshFailedCount: 0,
      updateAvailableCount: 0,
      nonconformantChannelCount: 0,
      nonconformantSourceCount: 0,
    },
    workspace: {
      isRepo: true,
      changedFileCount: 0,
      dirty: false,
      aheadCount: 0,
      behindCount: 0,
      worktreeRiskLabel: "Checkout clean",
    },
    durability: {
      status: "ready",
      error: null,
      activeSession: true,
      recordCount: 2,
      shouldCompact: false,
      recommendedPolicyLabel: null,
      recommendationReasons: [],
      resumeSafetyStatus: "protected",
    },
    automation: {
      remoteEnvStatus: "ready",
      remoteEnvError: null,
      bindingCount: 4,
      redactedBindingCount: 0,
      secretBindingCount: 1,
      hooksStatus: "ready",
      hooksError: null,
      activeHookCount: 2,
      disabledHookCount: 0,
      hookReceiptCount: 3,
    },
  };
}

function readyOverviewStaysReady(): void {
  const overview = buildDoctorOverview(baseInput());

  assert.equal(overview.tone, "ready");
  assert.equal(overview.reviewCount, 0);
  assert.equal(overview.watchCount, 0);
  assert.equal(overview.headline, "Tracked shell diagnostics look healthy");
  assert.equal(
    overview.cards.find((card) => card.id === "workspace")?.tone,
    "ready",
  );
}

function runtimeAndWorkspaceIssuesEscalateToAttention(): void {
  const overview = buildDoctorOverview({
    ...baseInput(),
    runtime: {
      ...baseInput().runtime,
      activeIssueCount: 2,
      degradedBackendCount: 1,
      healthyBackendCount: 1,
    },
    workspace: {
      ...baseInput().workspace,
      dirty: true,
      changedFileCount: 7,
      behindCount: 2,
    },
  });

  assert.equal(overview.tone, "attention");
  assert.equal(overview.reviewCount, 2);
  assert.equal(overview.watchCount, 0);
  assert.equal(
    overview.headline,
    "2 areas need review",
  );
  assert.equal(
    overview.cards.find((card) => card.id === "runtime")?.tone,
    "attention",
  );
  assert.equal(
    overview.cards.find((card) => card.id === "workspace")?.tone,
    "attention",
  );
}

function rememberedAuthorityAndCompactionRecommendationStayInSetupAndAttention(): void {
  const overview = buildDoctorOverview({
    ...baseInput(),
    authority: {
      ...baseInput().authority,
      activeOverrideCount: 1,
      rememberedApprovalCount: 2,
    },
    durability: {
      ...baseInput().durability,
      shouldCompact: true,
      recommendedPolicyLabel: "Carry pinned only",
      recommendationReasons: ["Long thread", "Pinned files retained"],
    },
    automation: {
      ...baseInput().automation,
      redactedBindingCount: 2,
    },
  });

  assert.equal(overview.tone, "attention");
  assert.equal(overview.reviewCount, 1);
  assert.equal(overview.watchCount, 2);
  assert.equal(
    overview.cards.find((card) => card.id === "authority")?.tone,
    "setup",
  );
  assert.equal(
    overview.cards.find((card) => card.id === "durability")?.tone,
    "attention",
  );
  assert.equal(
    overview.cards.find((card) => card.id === "automation")?.actionView,
    "remote_env",
  );
}

readyOverviewStaysReady();
runtimeAndWorkspaceIssuesEscalateToAttention();
rememberedAuthorityAndCompactionRecommendationStayInSetupAndAttention();
