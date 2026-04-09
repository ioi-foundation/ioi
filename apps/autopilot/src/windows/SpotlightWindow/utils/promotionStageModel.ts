import type { CanonicalTraceBundle } from "../../../types";
import {
  traceBundleExportVariantLabel,
  type TraceBundleExportVariant,
} from "./traceBundleExportModel";
import type { RetainedPortfolioDossier } from "./retainedPortfolioDossierModel";

export type PromotionTarget = "sas.xyz" | "Forge";

export interface PromotionStageDraft {
  subjectKind: string;
  operation: string;
  sourceUri: string;
  subjectId: string;
  notes: string;
}

function promotionSubjectKind(target: PromotionTarget): string {
  return target === "sas.xyz" ? "service_candidate" : "forge_release";
}

function promotionIntentLabel(target: PromotionTarget): string {
  return target === "sas.xyz"
    ? "service candidate review"
    : "productionization review";
}

export function buildPromotionStageDraft(input: {
  target: PromotionTarget;
  sessionId?: string | null;
  threadId?: string | null;
  bundle?: CanonicalTraceBundle | null;
  exportPath?: string | null;
  exportVariant?: TraceBundleExportVariant | null;
  durabilitySummary?: string | null;
  privacySummary?: string | null;
  dossier?: RetainedPortfolioDossier | null;
}): PromotionStageDraft {
  const sessionId = input.bundle?.sessionId || input.sessionId || "unknown-session";
  const threadId = input.bundle?.threadId || input.threadId || sessionId;
  const sessionTitle =
    input.bundle?.sessionSummary?.title?.trim() || `Session ${sessionId.slice(0, 8)}`;
  const stats = input.bundle?.stats;
  const evidenceBits = [
    `${stats?.eventCount ?? 0} events`,
    `${stats?.receiptCount ?? 0} receipts`,
    `${stats?.artifactCount ?? 0} artifacts`,
    `${stats?.includedArtifactPayloadCount ?? input.bundle?.artifactPayloads.length ?? 0} payloads`,
  ];
  const variantLabel = traceBundleExportVariantLabel(input.exportVariant)?.toLowerCase() || null;
  const notes = [
    `Canonical evidence for '${sessionTitle}' (${sessionId}) via thread ${threadId}.`,
    `Retained bundle stats: ${evidenceBits.join(", ")}.`,
    input.dossier
      ? `Dossier: ${input.dossier.title} (${input.dossier.readinessLabel}).`
      : null,
    input.dossier
      ? `Dossier recommendation: ${input.dossier.recommendedVariantLabel}.`
      : null,
    input.dossier
      ? `Retained portfolio: ${input.dossier.portfolioSummary}.`
      : null,
    variantLabel ? `Latest export: ${variantLabel}.` : null,
    input.exportPath ? `Latest export path: ${input.exportPath}.` : null,
    input.durabilitySummary
      ? `Durability posture: ${input.durabilitySummary}.`
      : null,
    input.privacySummary ? `Privacy posture: ${input.privacySummary}.` : null,
    `Route this run into ${input.target} ${promotionIntentLabel(input.target)} while preserving replay context.`,
  ]
    .filter((entry): entry is string => Boolean(entry))
    .join(" ");

  return {
    subjectKind: promotionSubjectKind(input.target),
    operation: "promote",
    sourceUri: `trace-bundle:${threadId}`,
    subjectId: input.target,
    notes,
  };
}
