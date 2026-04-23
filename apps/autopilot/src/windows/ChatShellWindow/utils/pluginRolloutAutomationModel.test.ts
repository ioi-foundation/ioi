import assert from "node:assert/strict";
import type { SessionPluginSnapshot } from "../../../types";
import { buildPluginRolloutAutomationPlan } from "./pluginRolloutAutomationModel.ts";

const baseSnapshot: SessionPluginSnapshot = {
  generatedAtMs: Date.parse("2026-04-06T02:10:00.000Z"),
  sessionId: "plugins-automation",
  workspaceRoot: "/repo",
  pluginCount: 2,
  enabledPluginCount: 1,
  disabledPluginCount: 1,
  trustedPluginCount: 1,
  untrustedPluginCount: 1,
  blockedPluginCount: 0,
  reloadablePluginCount: 1,
  managedPackageCount: 1,
  updateAvailableCount: 0,
  installablePackageCount: 0,
  verifiedPluginCount: 2,
  unverifiedPluginCount: 0,
  signatureMismatchPluginCount: 0,
  recommendedPluginCount: 1,
  reviewRequiredPluginCount: 0,
  staleCatalogCount: 0,
  expiredCatalogCount: 0,
  criticalUpdateCount: 0,
  refreshAvailableCount: 0,
  refreshFailedCount: 0,
  catalogChannelCount: 1,
  nonconformantChannelCount: 0,
  catalogSourceCount: 1,
  localCatalogSourceCount: 0,
  remoteCatalogSourceCount: 1,
  failedCatalogSourceCount: 0,
  nonconformantSourceCount: 0,
  hookContributionCount: 0,
  filesystemSkillCount: 0,
  recentReceiptCount: 0,
  recentReceipts: [],
  catalogSources: [],
  catalogChannels: [],
  plugins: [
    {
      pluginId: "plugin-a",
      entryId: "plugin:plugin-a",
      label: "Plugin A",
      description: null,
      version: "1.0.0",
      sourceEnabled: true,
      enabled: true,
      statusLabel: "Enabled",
      sourceLabel: "Remote catalog",
      sourceKind: "catalog",
      sourceUri: "https://example.com/catalog.json",
      category: null,
      marketplaceDisplayName: null,
      marketplaceInstallationPolicy: null,
      marketplaceAuthenticationPolicy: null,
      marketplaceProducts: [],
      authenticityState: "verified",
      authenticityLabel: "Verified",
      authenticityDetail: "Signed and verified.",
      operatorReviewState: "approved",
      operatorReviewLabel: "Approved",
      operatorReviewReason: "Approved for runtime load.",
      catalogStatus: "healthy",
      catalogStatusLabel: "Healthy",
      catalogStatusDetail: "Catalog aligned.",
      requestedCapabilities: [],
      trustPosture: "trusted",
      governedProfile: "guided_default",
      authorityTierLabel: "Workspace",
      availabilityLabel: "Available",
      sessionScopeLabel: "Session",
      reloadable: true,
      reloadabilityLabel: "Reloadable",
      contributionCount: 1,
      hookContributionCount: 0,
      filesystemSkillCount: 0,
      capabilityCount: 1,
      runtimeTrustState: "trusted",
      runtimeTrustLabel: "Trusted",
      runtimeLoadState: "enabled",
      runtimeLoadLabel: "Enabled",
      runtimeStatusDetail: "Running.",
      trustRemembered: true,
      packageManaged: true,
      packageInstallState: "installed",
      packageInstallLabel: "Installed",
      packageInstallDetail: "Managed package installed.",
      updateAvailable: false,
      whyAvailable: "Healthy plugin.",
    },
    {
      pluginId: "plugin-b",
      entryId: "plugin:plugin-b",
      label: "Plugin B",
      description: null,
      version: "1.0.0",
      sourceEnabled: true,
      enabled: false,
      statusLabel: "Available",
      sourceLabel: "Remote catalog",
      sourceKind: "catalog",
      sourceUri: "https://example.com/catalog.json",
      category: null,
      marketplaceDisplayName: null,
      marketplaceInstallationPolicy: null,
      marketplaceAuthenticationPolicy: null,
      marketplaceProducts: [],
      authenticityState: "verified",
      authenticityLabel: "Verified",
      authenticityDetail: "Signed and verified.",
      operatorReviewState: "available",
      operatorReviewLabel: "Available",
      operatorReviewReason: "Awaiting trust.",
      catalogStatus: "healthy",
      catalogStatusLabel: "Healthy",
      catalogStatusDetail: "Catalog aligned.",
      requestedCapabilities: [],
      trustPosture: "review",
      governedProfile: "guided_default",
      authorityTierLabel: "Workspace",
      availabilityLabel: "Available",
      sessionScopeLabel: "Session",
      reloadable: false,
      reloadabilityLabel: "Load after trust",
      contributionCount: 1,
      hookContributionCount: 0,
      filesystemSkillCount: 0,
      capabilityCount: 1,
      runtimeTrustState: "untrusted",
      runtimeTrustLabel: "Needs trust",
      runtimeLoadState: "disabled",
      runtimeLoadLabel: "Disabled",
      runtimeStatusDetail: "Awaiting trust.",
      trustRemembered: false,
      packageManaged: false,
      packageInstallState: "available",
      packageInstallLabel: "Available",
      packageInstallDetail: "Can be installed.",
      updateAvailable: false,
      whyAvailable: "Awaiting trust.",
    },
  ],
};

{
  const plan = buildPluginRolloutAutomationPlan({
    ...baseSnapshot,
    refreshAvailableCount: 1,
    plugins: baseSnapshot.plugins.map((plugin) =>
      plugin.pluginId === "plugin-a"
        ? {
            ...plugin,
            catalogStatus: "refresh_available",
          }
        : plugin,
    ),
  });

  assert.equal(plan.primaryActionKind, "refresh_catalog");
  assert.equal(plan.pluginId, "plugin-a");
  assert.deepEqual(
    plan.queuedActions.map((action) => action.kind),
    ["refresh_catalog", "install_package", "trust_and_enable"],
  );
  assert.equal(plan.governanceNotes.length, 0);
}

{
  const plan = buildPluginRolloutAutomationPlan({
    ...baseSnapshot,
    updateAvailableCount: 1,
    plugins: baseSnapshot.plugins.map((plugin) =>
      plugin.pluginId === "plugin-a"
        ? {
            ...plugin,
            updateAvailable: true,
          }
        : plugin,
      ),
  });

  assert.equal(plan.primaryActionKind, "apply_update");
  assert.equal(plan.pluginId, "plugin-a");
  assert.deepEqual(
    plan.queuedActions.map((action) => action.kind),
    ["apply_update", "install_package", "trust_and_enable"],
  );
}

{
  const plan = buildPluginRolloutAutomationPlan(baseSnapshot);

  assert.equal(plan.primaryActionKind, "install_package");
  assert.equal(plan.pluginId, "plugin-b");
  assert.deepEqual(
    plan.queuedActions.map((action) => action.kind),
    ["install_package", "trust_and_enable"],
  );
  assert.equal(plan.governanceNotes.length, 0);
}

{
  const plan = buildPluginRolloutAutomationPlan({
    ...baseSnapshot,
    reviewRequiredPluginCount: 1,
    plugins: baseSnapshot.plugins.map((plugin) =>
      plugin.pluginId === "plugin-b"
        ? {
            ...plugin,
            operatorReviewState: "review_required",
            operatorReviewLabel: "Review required",
            operatorReviewReason:
              "Package integrity is proven, but the publisher chain is not yet rooted in trusted marketplace authority.",
            publisherTrustState: "unknown_root",
            publisherTrustLabel: "Publisher unknown root",
            trustRecommendation:
              "Package integrity is proven, but the publisher chain is not yet rooted in trusted marketplace authority.",
            packageInstallState: "installable",
            packageInstallLabel: "Ready for managed install",
          }
        : plugin,
    ),
  });

  assert.equal(plan.primaryActionKind, "install_package");
  assert.deepEqual(
    plan.queuedActions.map((action) => action.kind),
    ["install_package", "stage_review"],
  );
  assert.equal(plan.governanceNotes.length, 1);
  assert.equal(plan.governanceNotes[0].severity, "review");
  assert.match(plan.governanceNotes[0].label, /Review Plugin B before trust and enable/);
}

{
  const plan = buildPluginRolloutAutomationPlan({
    ...baseSnapshot,
    blockedPluginCount: 1,
    plugins: baseSnapshot.plugins.map((plugin) =>
      plugin.pluginId === "plugin-b"
        ? {
            ...plugin,
            operatorReviewState: "blocked",
            operatorReviewLabel: "Blocked",
            operatorReviewReason:
              "The marketplace catalog has expired. Refresh the signed catalog before trusting updates from this feed.",
            catalogStatus: "expired",
            catalogStatusLabel: "Catalog expired",
            catalogStatusDetail:
              "The marketplace catalog has expired. Refresh the signed catalog before trusting updates from this feed.",
            updateSeverity: "blocked",
            updateSeverityLabel: "Blocked update channel",
            packageInstallState: "installable",
            packageInstallLabel: "Ready for managed install",
          }
        : plugin,
    ),
  });

  assert.equal(plan.primaryActionKind, "stage_review");
  assert.deepEqual(
    plan.queuedActions.map((action) => action.kind),
    ["stage_review"],
  );
  assert.ok(
    plan.governanceNotes.some(
      (note) =>
        note.severity === "blocked" &&
        note.label === "Trust Plugin B is blocked",
    ),
  );
}
