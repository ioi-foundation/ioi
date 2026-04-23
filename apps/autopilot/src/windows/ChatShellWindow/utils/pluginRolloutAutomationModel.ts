import type {
  SessionPluginRecord,
  SessionPluginSnapshot,
} from "../../../types";

export type PluginRolloutAutomationTone = "ready" | "review" | "setup";

export type PluginRolloutAutomationActionKind =
  | "none"
  | "refresh_inventory"
  | "refresh_catalog"
  | "install_package"
  | "apply_update"
  | "trust_and_enable"
  | "stage_review";

export interface PluginRolloutAutomationQueuedAction {
  kind: PluginRolloutAutomationActionKind;
  label: string;
  pluginId: string | null;
  detail: string;
}

export interface PluginRolloutAutomationGovernanceNote {
  pluginId: string | null;
  label: string;
  detail: string;
  severity: "review" | "blocked";
}

export interface PluginRolloutAutomationPlan {
  tone: PluginRolloutAutomationTone;
  statusLabel: string;
  detail: string;
  primaryActionKind: PluginRolloutAutomationActionKind;
  primaryActionLabel: string | null;
  pluginId: string | null;
  checklist: string[];
  queuedActions: PluginRolloutAutomationQueuedAction[];
  governanceNotes: PluginRolloutAutomationGovernanceNote[];
}

const INSTALLABLE_PACKAGE_STATES = new Set(["available", "installable", "removed"]);
const REVIEW_OPERATOR_STATES = new Set(["review_required"]);
const BLOCKED_OPERATOR_STATES = new Set(["blocked"]);
const REVIEW_PUBLISHER_TRUST_STATES = new Set([
  "unknown",
  "unknown_root",
  "unknown_authority_bundle",
]);
const BLOCKED_PUBLISHER_TRUST_STATES = new Set([
  "revoked",
  "revoked_by_root",
  "revoked_by_authority_bundle",
  "expired_authority_bundle",
]);
const REVIEW_AUTHENTICITY_STATES = new Set([
  "unsigned",
  "unverified",
  "catalog_metadata_only",
]);
const BLOCKED_AUTHENTICITY_STATES = new Set(["signature_mismatch"]);
const REVIEW_CATALOG_STATES = new Set(["stale", "timing_unavailable", "refresh_failed"]);
const BLOCKED_CATALOG_STATES = new Set(["expired"]);
const REVIEW_UPDATE_STATES = new Set([
  "critical_review",
  "review_stale_feed",
  "review_refresh_failure",
]);
const BLOCKED_UPDATE_STATES = new Set(["blocked"]);

function describeInstallGovernanceRisk(plugin: SessionPluginRecord): string {
  if (plugin.catalogStatus === "expired") {
    return (
      plugin.catalogStatusDetail ||
      "The signed marketplace catalog has expired, so a managed package install should wait for refresh."
    );
  }
  if (BLOCKED_PUBLISHER_TRUST_STATES.has(plugin.publisherTrustState ?? "")) {
    return (
      plugin.publisherTrustDetail ||
      plugin.trustRecommendation ||
      "Marketplace trust is currently revoked or expired, so a managed package install should not proceed."
    );
  }
  if (REVIEW_AUTHENTICITY_STATES.has(plugin.authenticityState)) {
    return (
      plugin.authenticityDetail ||
      "Package authenticity metadata is incomplete, so managed install should wait for review."
    );
  }
  if (BLOCKED_AUTHENTICITY_STATES.has(plugin.authenticityState)) {
    return (
      plugin.authenticityDetail ||
      "Package verification failed, so managed install is blocked."
    );
  }
  return (
    plugin.packageInstallDetail ||
    plugin.operatorReviewReason ||
    "Managed package install should wait for rollout review."
  );
}

function describeTrustGovernanceRisk(plugin: SessionPluginRecord): string {
  return (
    plugin.operatorReviewReason ||
    plugin.trustRecommendation ||
    plugin.publisherTrustDetail ||
    plugin.catalogStatusDetail ||
    plugin.authenticityDetail ||
    "Review the package trust chain, feed freshness, and requested capabilities before trusting runtime load."
  );
}

function describeUpdateGovernanceRisk(plugin: SessionPluginRecord): string {
  return (
    plugin.updateDetail ||
    plugin.operatorReviewReason ||
    plugin.catalogStatusDetail ||
    plugin.trustRecommendation ||
    "This packaged update should wait for explicit rollout review."
  );
}

function installGovernanceSeverity(
  plugin: SessionPluginRecord,
): "review" | "blocked" | null {
  if (plugin.packageManaged) {
    return null;
  }
  if (!INSTALLABLE_PACKAGE_STATES.has(plugin.packageInstallState)) {
    return null;
  }
  if (
    BLOCKED_OPERATOR_STATES.has(plugin.operatorReviewState ?? "") ||
    BLOCKED_PUBLISHER_TRUST_STATES.has(plugin.publisherTrustState ?? "") ||
    BLOCKED_AUTHENTICITY_STATES.has(plugin.authenticityState) ||
    BLOCKED_CATALOG_STATES.has(plugin.catalogStatus)
  ) {
    return "blocked";
  }
  if (
    REVIEW_AUTHENTICITY_STATES.has(plugin.authenticityState) ||
    Boolean(plugin.packageError)
  ) {
    return "review";
  }
  return null;
}

function trustGovernanceSeverity(
  plugin: SessionPluginRecord,
): "review" | "blocked" | null {
  if (
    plugin.runtimeTrustState === "trusted" ||
    plugin.runtimeLoadState === "enabled"
  ) {
    return null;
  }
  if (
    BLOCKED_OPERATOR_STATES.has(plugin.operatorReviewState ?? "") ||
    BLOCKED_PUBLISHER_TRUST_STATES.has(plugin.publisherTrustState ?? "") ||
    BLOCKED_AUTHENTICITY_STATES.has(plugin.authenticityState) ||
    BLOCKED_CATALOG_STATES.has(plugin.catalogStatus) ||
    BLOCKED_UPDATE_STATES.has(plugin.updateSeverity ?? "")
  ) {
    return "blocked";
  }
  if (
    REVIEW_OPERATOR_STATES.has(plugin.operatorReviewState ?? "") ||
    REVIEW_PUBLISHER_TRUST_STATES.has(plugin.publisherTrustState ?? "") ||
    REVIEW_AUTHENTICITY_STATES.has(plugin.authenticityState) ||
    REVIEW_CATALOG_STATES.has(plugin.catalogStatus) ||
    REVIEW_UPDATE_STATES.has(plugin.updateSeverity ?? "")
  ) {
    return "review";
  }
  return null;
}

function updateGovernanceSeverity(
  plugin: SessionPluginRecord,
): "review" | "blocked" | null {
  if (!plugin.packageManaged || !plugin.updateAvailable) {
    return null;
  }
  if (
    BLOCKED_OPERATOR_STATES.has(plugin.operatorReviewState ?? "") ||
    BLOCKED_PUBLISHER_TRUST_STATES.has(plugin.publisherTrustState ?? "") ||
    BLOCKED_AUTHENTICITY_STATES.has(plugin.authenticityState) ||
    BLOCKED_CATALOG_STATES.has(plugin.catalogStatus) ||
    BLOCKED_UPDATE_STATES.has(plugin.updateSeverity ?? "")
  ) {
    return "blocked";
  }
  if (
    REVIEW_OPERATOR_STATES.has(plugin.operatorReviewState ?? "") ||
    REVIEW_PUBLISHER_TRUST_STATES.has(plugin.publisherTrustState ?? "") ||
    REVIEW_AUTHENTICITY_STATES.has(plugin.authenticityState) ||
    REVIEW_CATALOG_STATES.has(plugin.catalogStatus) ||
    REVIEW_UPDATE_STATES.has(plugin.updateSeverity ?? "")
  ) {
    return "review";
  }
  return null;
}

function pushGovernanceNote(
  notes: PluginRolloutAutomationGovernanceNote[],
  note: PluginRolloutAutomationGovernanceNote,
): void {
  if (
    notes.some(
      (existing) =>
        existing.pluginId === note.pluginId &&
        existing.label === note.label &&
        existing.detail === note.detail,
    )
  ) {
    return;
  }
  notes.push(note);
}

export function buildPluginRolloutAutomationPlan(
  snapshot: SessionPluginSnapshot | null,
): PluginRolloutAutomationPlan {
  if (!snapshot || snapshot.pluginCount === 0) {
    const queuedActions: PluginRolloutAutomationQueuedAction[] = [
      {
        kind: "refresh_inventory",
        label: "Refresh plugin inventory",
        pluginId: null,
        detail:
          "Load the tracked runtime plugin inventory before wider rollout automation can reason about catalogs, packages, or trust state.",
      },
    ];
    return {
      tone: "setup",
      statusLabel: "Plugin rollout automation waiting on inventory",
      detail:
        "Load the tracked plugin inventory before the shell can recommend the next rollout action.",
      primaryActionKind: queuedActions[0].kind,
      primaryActionLabel: queuedActions[0].label,
      pluginId: null,
      checklist: ["Inventory: load runtime snapshot first"],
      queuedActions,
      governanceNotes: [],
    };
  }

  const governanceNotes: PluginRolloutAutomationGovernanceNote[] = [];
  const baseChecklist = [
    `${snapshot.refreshAvailableCount} refreshes ready`,
    `${snapshot.updateAvailableCount} managed updates`,
    `${snapshot.reviewRequiredPluginCount} review required`,
    `${snapshot.blockedPluginCount} blocked`,
  ];
  const queuedActions: PluginRolloutAutomationQueuedAction[] = [
    ...snapshot.plugins
      .filter((plugin) => plugin.catalogStatus === "refresh_available")
      .map((plugin) => ({
        kind: "refresh_catalog" as const,
        label: `Refresh ${plugin.label} catalog`,
        pluginId: plugin.pluginId,
        detail:
          "Refresh the signed catalog source before wider rollout review so the queued package and trust decisions use the latest authority state.",
      })),
    ...snapshot.plugins
      .filter((plugin) => plugin.updateAvailable && plugin.packageManaged)
      .filter((plugin) => updateGovernanceSeverity(plugin) === null)
      .map((plugin) => ({
        kind: "apply_update" as const,
        label: `Apply ${plugin.label} update`,
        pluginId: plugin.pluginId,
        detail:
          "Apply the managed package update so the runtime package matches the latest retained rollout posture.",
      })),
    ...snapshot.plugins
      .filter(
        (plugin) =>
          !plugin.packageManaged &&
          INSTALLABLE_PACKAGE_STATES.has(plugin.packageInstallState) &&
          installGovernanceSeverity(plugin) === null,
      )
      .map((plugin) => ({
        kind: "install_package" as const,
        label: `Install ${plugin.label} managed package`,
        pluginId: plugin.pluginId,
        detail:
          "Capture a profile-local managed package copy before wider rollout or runtime trust so updates and removal stay governed against a retained artifact.",
      })),
    ...snapshot.plugins
      .filter(
        (plugin) =>
          plugin.runtimeTrustState !== "trusted" &&
          plugin.runtimeLoadState !== "enabled" &&
          trustGovernanceSeverity(plugin) === null,
      )
      .map((plugin) => ({
        kind: "trust_and_enable" as const,
        label: `Trust and enable ${plugin.label}`,
        pluginId: plugin.pluginId,
        detail:
          plugin.packageManaged
            ? "Promote the retained plugin into runtime load now that the managed package and trust posture are aligned."
            : "Promote the retained plugin into runtime load once its current trust posture is ready. Install the managed package first when you want rollout state retained separately from the tracked source.",
      })),
  ];

  for (const plugin of snapshot.plugins) {
    const installSeverity = installGovernanceSeverity(plugin);
    if (installSeverity) {
      pushGovernanceNote(governanceNotes, {
        pluginId: plugin.pluginId,
        label:
          installSeverity === "blocked"
            ? `Install ${plugin.label} is blocked`
            : `Review ${plugin.label} install before automation`,
        detail: describeInstallGovernanceRisk(plugin),
        severity: installSeverity,
      });
    }

    const updateSeverity = updateGovernanceSeverity(plugin);
    if (updateSeverity) {
      pushGovernanceNote(governanceNotes, {
        pluginId: plugin.pluginId,
        label:
          updateSeverity === "blocked"
            ? `Update ${plugin.label} is blocked`
            : `Review ${plugin.label} update before automation`,
        detail: describeUpdateGovernanceRisk(plugin),
        severity: updateSeverity,
      });
    }

    const trustSeverity = trustGovernanceSeverity(plugin);
    if (trustSeverity) {
      pushGovernanceNote(governanceNotes, {
        pluginId: plugin.pluginId,
        label:
          trustSeverity === "blocked"
            ? `Trust ${plugin.label} is blocked`
            : `Review ${plugin.label} before trust and enable`,
        detail: describeTrustGovernanceRisk(plugin),
        severity: trustSeverity,
      });
    }
  }

  if (
    governanceNotes.length > 0 ||
    snapshot.reviewRequiredPluginCount > 0 ||
    snapshot.blockedPluginCount > 0 ||
    snapshot.criticalUpdateCount > 0 ||
    snapshot.failedCatalogSourceCount > 0 ||
    snapshot.nonconformantChannelCount > 0 ||
    snapshot.nonconformantSourceCount > 0
  ) {
    queuedActions.push({
      kind: "stage_review",
      label:
        governanceNotes.length > 0
          ? "Stage governed rollout review"
          : "Stage rollout review",
      pluginId: null,
      detail:
        governanceNotes.length > 0
          ? `Stage the shared rollout dossier so ${governanceNotes.length} higher-risk trust, install, or update decisions keep their review context as governed product evidence.`
          : "Stage the shared rollout dossier so the remaining review-required, blocked, or nonconformant posture is preserved as governed product evidence.",
    });
  }

  const checklist = [...baseChecklist];
  if (governanceNotes.length > 0) {
    checklist.push(`${governanceNotes.length} governed review gates`);
  }

  const [primaryAction] = queuedActions;
  if (!primaryAction) {
    return {
      tone: "ready",
      statusLabel: "Rollout automation has no pending action",
      detail:
        "Tracked plugin trust, packages, and catalogs are aligned, so rollout automation does not need a follow-up action right now.",
      primaryActionKind: "none",
      primaryActionLabel: null,
      pluginId: null,
      checklist,
      queuedActions,
      governanceNotes,
    };
  }

  const actionableQueueLength = queuedActions.filter(
    (action) => action.kind !== "stage_review",
  ).length;
  const reviewOnlyQueue =
    actionableQueueLength === 0 &&
    queuedActions.every((action) => action.kind === "stage_review");

  return {
    tone: "review",
    statusLabel: reviewOnlyQueue
      ? "Governed review required"
      : governanceNotes.length > 0
        ? "Governed rollout queue ready"
        : queuedActions.length > 1
          ? "Rollout queue ready"
        : primaryAction.kind === "refresh_catalog"
          ? "Catalog refresh recommended"
          : primaryAction.kind === "install_package"
            ? "Managed package install recommended"
          : primaryAction.kind === "apply_update"
            ? "Managed package update ready"
            : primaryAction.kind === "trust_and_enable"
              ? "Trust review can advance one plugin"
              : "Rollout review should be staged",
    detail: reviewOnlyQueue
      ? `There are ${governanceNotes.length} higher-risk rollout decisions that still need explicit review before automation should continue.`
      : governanceNotes.length > 0
        ? `There are ${actionableQueueLength} safe rollout steps ready and ${governanceNotes.length} governed review items still need explicit operator attention. Start with ${primaryAction.label.toLowerCase()} so retained rollout state stays ahead of trust and update decisions.`
        : queuedActions.length > 1
          ? `There are ${queuedActions.length} governed rollout steps ready. Start with ${primaryAction.label.toLowerCase()} and work down the retained queue without losing review context.`
          : primaryAction.detail,
    primaryActionKind: primaryAction.kind,
    primaryActionLabel: primaryAction.label,
    pluginId: primaryAction.pluginId,
    checklist,
    queuedActions,
    governanceNotes,
  };
}
