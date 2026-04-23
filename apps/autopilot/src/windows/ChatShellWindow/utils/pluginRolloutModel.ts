import type { SessionPluginSnapshot } from "../../../types";

export type PluginRolloutTone = "ready" | "review" | "setup";

export interface PluginRolloutDossier {
  title: string;
  readiness: PluginRolloutTone;
  readinessLabel: string;
  summary: string;
  sourceSummary: string;
  checklist: string[];
}

export interface PluginRolloutStageDraft {
  subjectKind: string;
  operation: string;
  sourceUri: string;
  subjectId: string;
  notes: string;
}

function workspaceLabel(snapshot: SessionPluginSnapshot | null): string {
  return snapshot?.workspaceRoot?.trim() || snapshot?.sessionId || "session scope";
}

function pluralize(value: number, noun: string): string {
  return `${value} ${noun}${value === 1 ? "" : "s"}`;
}

export function buildPluginRolloutDossier(
  snapshot: SessionPluginSnapshot | null,
): PluginRolloutDossier {
  const scope = workspaceLabel(snapshot);
  const sourceSummary = snapshot
    ? [
        pluralize(snapshot.remoteCatalogSourceCount, "remote source"),
        pluralize(snapshot.localCatalogSourceCount, "local source"),
        pluralize(snapshot.catalogChannelCount, "catalog channel"),
      ].join(" · ")
    : "No plugin inventory loaded yet.";
  const reviewNeeded =
    !snapshot ||
    snapshot.pluginCount === 0
      ? false
      : snapshot.reviewRequiredPluginCount > 0 ||
          snapshot.blockedPluginCount > 0 ||
          snapshot.criticalUpdateCount > 0 ||
          snapshot.failedCatalogSourceCount > 0 ||
          snapshot.nonconformantChannelCount > 0 ||
          snapshot.nonconformantSourceCount > 0 ||
          snapshot.staleCatalogCount > 0 ||
          snapshot.expiredCatalogCount > 0;
  const readiness: PluginRolloutTone = !snapshot || snapshot.pluginCount === 0
    ? "setup"
    : reviewNeeded
      ? "review"
      : "ready";
  const readinessLabel =
    readiness === "setup"
      ? "Plugin inventory still loading"
      : readiness === "review"
        ? "Rollout review recommended"
        : "Rollout ready";
  const summary =
    readiness === "setup"
      ? "Load the tracked plugin inventory before staging a rollout review dossier."
      : readiness === "review"
        ? `Remote source health, operator review posture, or pending updates still deserve attention before ${scope} should be treated as rollout-ready.`
        : `Remote catalog health, trust posture, and rollout state are aligned for ${scope}.`;
  const checklist = snapshot
    ? [
        `${snapshot.pluginCount} tracked · ${snapshot.trustedPluginCount} trusted · ${snapshot.enabledPluginCount} enabled`,
        `${snapshot.verifiedPluginCount} verified · ${snapshot.unverifiedPluginCount} unverified · ${snapshot.signatureMismatchPluginCount} mismatched`,
        `${snapshot.reviewRequiredPluginCount} review required · ${snapshot.blockedPluginCount} blocked · ${snapshot.criticalUpdateCount} critical updates`,
        `${snapshot.refreshAvailableCount} refresh available · ${snapshot.refreshFailedCount} refresh failed · ${snapshot.updateAvailableCount} updates ready`,
        `${snapshot.nonconformantChannelCount} nonconformant channels · ${snapshot.nonconformantSourceCount} nonconformant sources · ${snapshot.failedCatalogSourceCount} failed sources`,
      ]
    : ["Plugin inventory: load runtime snapshot first"];

  return {
    title: `Plugin rollout dossier · ${scope}`,
    readiness,
    readinessLabel,
    summary,
    sourceSummary,
    checklist,
  };
}

export function buildPluginRolloutStageDraft(input: {
  dossier: PluginRolloutDossier;
  snapshot: SessionPluginSnapshot | null;
}): PluginRolloutStageDraft {
  const scope = workspaceLabel(input.snapshot);
  const sourceUri = input.snapshot?.workspaceRoot?.trim()
    ? `plugin-rollout:${input.snapshot.workspaceRoot}`
    : `plugin-rollout:${input.snapshot?.sessionId || "session"}`;
  const subjectId = input.snapshot?.sessionId || scope;
  const notes = [
    `${input.dossier.title} (${input.dossier.readinessLabel}).`,
    input.dossier.summary,
    `Sources: ${input.dossier.sourceSummary}.`,
    `Checklist: ${input.dossier.checklist.join(" · ")}.`,
    "Preserve remote catalog authority, conformance, and package verification context during rollout review.",
  ].join(" ");

  return {
    subjectKind: "plugin_rollout",
    operation: "review",
    sourceUri,
    subjectId,
    notes,
  };
}
