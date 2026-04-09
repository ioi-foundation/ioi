import assert from "node:assert/strict";
import type { SessionPluginSnapshot } from "../../../types";
import {
  buildPluginRolloutDossier,
  buildPluginRolloutStageDraft,
} from "./pluginRolloutModel.ts";

const healthySnapshot: SessionPluginSnapshot = {
  generatedAtMs: Date.parse("2026-04-06T01:20:00.000Z"),
  sessionId: "session-plugins-1",
  workspaceRoot: "/repo",
  pluginCount: 3,
  enabledPluginCount: 2,
  disabledPluginCount: 1,
  trustedPluginCount: 3,
  untrustedPluginCount: 0,
  blockedPluginCount: 0,
  reloadablePluginCount: 2,
  managedPackageCount: 2,
  updateAvailableCount: 0,
  installablePackageCount: 1,
  verifiedPluginCount: 3,
  unverifiedPluginCount: 0,
  signatureMismatchPluginCount: 0,
  recommendedPluginCount: 2,
  reviewRequiredPluginCount: 0,
  staleCatalogCount: 0,
  expiredCatalogCount: 0,
  criticalUpdateCount: 0,
  refreshAvailableCount: 0,
  refreshFailedCount: 0,
  catalogChannelCount: 2,
  nonconformantChannelCount: 0,
  catalogSourceCount: 2,
  localCatalogSourceCount: 1,
  remoteCatalogSourceCount: 1,
  failedCatalogSourceCount: 0,
  nonconformantSourceCount: 0,
  hookContributionCount: 1,
  filesystemSkillCount: 2,
  recentReceiptCount: 1,
  recentReceipts: [],
  catalogSources: [],
  catalogChannels: [],
  plugins: [],
};

{
  const dossier = buildPluginRolloutDossier(healthySnapshot);

  assert.equal(dossier.readiness, "ready");
  assert.match(dossier.title, /Plugin rollout dossier/i);
  assert.match(dossier.sourceSummary, /1 remote source/i);
}

{
  const dossier = buildPluginRolloutDossier({
    ...healthySnapshot,
    reviewRequiredPluginCount: 1,
    blockedPluginCount: 1,
    criticalUpdateCount: 2,
    nonconformantChannelCount: 1,
  });

  assert.equal(dossier.readiness, "review");
  assert.match(dossier.summary, /still deserve attention/i);
  assert.match(dossier.checklist.join(" "), /critical updates/i);
}

{
  const dossier = buildPluginRolloutDossier(healthySnapshot);
  const draft = buildPluginRolloutStageDraft({
    dossier,
    snapshot: healthySnapshot,
  });

  assert.equal(draft.subjectKind, "plugin_rollout");
  assert.equal(draft.operation, "review");
  assert.equal(draft.sourceUri, "plugin-rollout:/repo");
  assert.match(draft.notes, /Plugin rollout dossier/i);
  assert.match(draft.notes, /Preserve remote catalog authority/i);
}
