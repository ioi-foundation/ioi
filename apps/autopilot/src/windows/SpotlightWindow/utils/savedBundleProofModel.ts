import type { CanonicalTraceBundle } from "../../../types";
import type { RetainedPortfolioDossier } from "./retainedPortfolioDossierModel";
import {
  traceBundleExportVariantLabel,
  type TraceBundleExportVariant,
} from "./traceBundleExportModel";

export type SavedBundleProofTone = "ready" | "review" | "setup";

export interface SavedBundleProofOverview {
  tone: SavedBundleProofTone;
  statusLabel: string;
  detail: string;
  meta: string[];
  checklist: string[];
}

function trimOrNull(value?: string | null): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function payloadModeLabel(variant?: TraceBundleExportVariant | null): string {
  return variant === "redacted_share" ? "Payloads omitted" : "Payloads included";
}

export function buildSavedBundleProofOverview(input: {
  dossier: RetainedPortfolioDossier;
  exportPath?: string | null;
  exportTimestampMs?: number | null;
  exportVariant?: TraceBundleExportVariant | null;
  bundle?: CanonicalTraceBundle | null;
}): SavedBundleProofOverview {
  const exportPath = trimOrNull(input.exportPath);
  const latestVariantLabel = traceBundleExportVariantLabel(input.exportVariant);
  const hasTimestamp =
    typeof input.exportTimestampMs === "number" &&
    Number.isFinite(input.exportTimestampMs);
  const zipRetained = Boolean(exportPath?.toLowerCase().endsWith(".zip"));
  const bundleLoaded = Boolean(input.bundle);
  const recommendedLabel = input.dossier.recommendedVariantLabel;
  const latestLabel = latestVariantLabel ?? "Not packaged yet";
  const matchesRecommendation = latestVariantLabel === recommendedLabel;

  const meta = [
    `Recommended: ${recommendedLabel}`,
    `Latest: ${latestLabel}`,
    hasTimestamp ? "Saved timestamp retained" : "No saved timestamp",
    exportPath ? "Saved path retained" : "No saved path",
  ];

  const checklist = [
    exportPath ? `Saved path: ${exportPath}` : "Saved path: export a local zip",
    hasTimestamp
      ? `Saved at: ${new Date(input.exportTimestampMs!).toLocaleString()}`
      : "Saved at: retain a packaged timestamp",
    `Variant: ${latestLabel}`,
    payloadModeLabel(input.exportVariant),
    bundleLoaded
      ? `Replay evidence: ${input.bundle?.stats.eventCount ?? 0} events retained`
      : "Replay evidence: load the canonical bundle before relying on the saved pack",
  ];

  if (!exportPath || !hasTimestamp || !latestVariantLabel) {
    return {
      tone: "setup",
      statusLabel: "Saved bundle proof not retained yet",
      detail:
        "Export the recommended review pack so the dossier keeps a concrete local path, package variant, and saved timestamp beside the canonical replay evidence.",
      meta,
      checklist,
    };
  }

  if (!zipRetained || !matchesRecommendation) {
    return {
      tone: "review",
      statusLabel: "Saved bundle proof needs review",
      detail: !matchesRecommendation
        ? `The latest packaged bundle is ${latestLabel.toLowerCase()} while the dossier recommends ${recommendedLabel.toLowerCase()}.`
        : "A packaged artifact is retained, but its saved proof metadata still needs review before it should be treated as the canonical handoff bundle.",
      meta,
      checklist,
    };
  }

  return {
    tone: "ready",
    statusLabel: "Saved bundle proof retained",
    detail:
      "The latest packaged bundle matches the dossier recommendation and retains the local proof metadata needed for evidence-preserving handoff.",
    meta,
    checklist,
  };
}
