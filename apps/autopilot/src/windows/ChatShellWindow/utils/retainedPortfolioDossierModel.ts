import type {
  CanonicalTraceBundle,
  SessionDurabilityPortfolio,
} from "../../../types";
import {
  traceBundleExportVariantLabel,
  type TraceBundleExportVariant,
} from "./traceBundleExportModel";

export type RetainedPortfolioDossierTone = "ready" | "review" | "setup";

export interface RetainedPortfolioDossier {
  title: string;
  readiness: RetainedPortfolioDossierTone;
  readinessLabel: string;
  summary: string;
  recommendedVariant: TraceBundleExportVariant;
  recommendedVariantLabel: string;
  latestExportLabel: string | null;
  latestExportMatchesRecommendation: boolean;
  portfolioSummary: string;
  checklist: string[];
}

function trimOrNull(value?: string | null): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function isAttentionLabel(value?: string | null): boolean {
  return /pending|review required|local-only|degraded/i.test(value ?? "");
}

function recommendedVariant(input: {
  privacyStatusLabel: string;
  privacyRecommendationLabel: string;
}): TraceBundleExportVariant {
  return isAttentionLabel(input.privacyStatusLabel) ||
    /redacted/i.test(input.privacyRecommendationLabel)
    ? "redacted_share"
    : "operator_share";
}

function portfolioSummary(portfolio: SessionDurabilityPortfolio | null): string {
  if (!portfolio) {
    return "Active-session posture only until the retained cross-session portfolio is loaded.";
  }

  const bits = [
    `${portfolio.replayReadySessionCount}/${portfolio.retainedSessionCount} replay-ready`,
  ];

  if (portfolio.staleCompactionCount > 0) {
    bits.push(`${portfolio.staleCompactionCount} stale`);
  }
  if (portfolio.degradedCompactionCount > 0) {
    bits.push(`${portfolio.degradedCompactionCount} degraded`);
  }
  if (portfolio.recommendedCompactionCount > 0) {
    bits.push(`${portfolio.recommendedCompactionCount} recommended now`);
  }
  if (portfolio.teamMemoryReviewRequiredSessionCount > 0) {
    bits.push(
      `${portfolio.teamMemoryReviewRequiredSessionCount} team-memory review`,
    );
  }
  if (portfolio.compactedWithoutTeamMemoryCount > 0) {
    bits.push(
      `${portfolio.compactedWithoutTeamMemoryCount} missing sync`,
    );
  }
  if (bits.length === 1) {
    bits.push("cross-session portfolio aligned");
  }

  return bits.join(" · ");
}

function checklist(input: {
  bundle: CanonicalTraceBundle | null;
  portfolio: SessionDurabilityPortfolio | null;
  privacyStatusLabel: string;
  durabilityStatusLabel: string;
  recommendedVariantLabel: string;
}): string[] {
  const bundle = input.bundle;
  const stats = bundle?.stats;
  return [
    bundle
      ? `Replay bundle: ${stats?.eventCount ?? 0} events, ${stats?.receiptCount ?? 0} receipts, ${stats?.artifactCount ?? 0} artifacts`
      : "Replay bundle: load the canonical bundle before wider review",
    `Recommended pack: ${input.recommendedVariantLabel}`,
    `Durability: ${input.durabilityStatusLabel}`,
    `Privacy: ${input.privacyStatusLabel}`,
    input.portfolio
      ? `Portfolio: ${portfolioSummary(input.portfolio)}`
      : "Portfolio: cross-session retained coverage still loading",
  ];
}

export function buildRetainedPortfolioDossier(input: {
  sessionTitle?: string | null;
  bundle?: CanonicalTraceBundle | null;
  portfolio?: SessionDurabilityPortfolio | null;
  exportVariant?: TraceBundleExportVariant | null;
  privacyStatusLabel: string;
  privacyRecommendationLabel: string;
  durabilityStatusLabel: string;
}): RetainedPortfolioDossier {
  const baseTitle =
    trimOrNull(input.sessionTitle) ||
    trimOrNull(input.bundle?.sessionSummary?.title) ||
    (input.bundle?.sessionId
      ? `Session ${input.bundle.sessionId.slice(0, 8)}`
      : "Current session");
  const recommended = recommendedVariant({
    privacyStatusLabel: input.privacyStatusLabel,
    privacyRecommendationLabel: input.privacyRecommendationLabel,
  });
  const recommendedLabel =
    traceBundleExportVariantLabel(recommended) || "Review pack";
  const latestLabel = traceBundleExportVariantLabel(input.exportVariant);
  const portfolio = input.portfolio ?? null;
  const portfolioNeedsReview =
    Boolean(portfolio?.attentionLabels.length) ||
    (portfolio?.staleCompactionCount ?? 0) > 0 ||
    (portfolio?.degradedCompactionCount ?? 0) > 0 ||
    (portfolio?.recommendedCompactionCount ?? 0) > 0 ||
    (portfolio?.teamMemoryReviewRequiredSessionCount ?? 0) > 0;
  const readiness: RetainedPortfolioDossierTone = !input.bundle
    ? "setup"
    : isAttentionLabel(input.privacyStatusLabel) ||
        isAttentionLabel(input.durabilityStatusLabel) ||
        portfolioNeedsReview
      ? "review"
      : "ready";
  const readinessLabel =
    readiness === "setup"
      ? "Replay bundle still loading"
      : readiness === "review"
        ? "Portfolio review recommended"
        : "Dossier ready";
  const summary =
    readiness === "setup"
      ? "Load the canonical replay bundle before packaging or staging a saved review dossier."
      : readiness === "review"
        ? `Retained replay, privacy, or cross-session durability posture still deserves one more pass before ${baseTitle} is treated as promotion-ready.`
        : `Replay, privacy, and retained-portfolio posture are aligned for an evidence-preserving dossier for ${baseTitle}.`;

  return {
    title: `${recommended === "redacted_share" ? "Redacted" : "Operator"} review dossier · ${baseTitle}`,
    readiness,
    readinessLabel,
    summary,
    recommendedVariant: recommended,
    recommendedVariantLabel: recommendedLabel,
    latestExportLabel: latestLabel,
    latestExportMatchesRecommendation: latestLabel === recommendedLabel,
    portfolioSummary: portfolioSummary(portfolio),
    checklist: checklist({
      bundle: input.bundle ?? null,
      portfolio,
      privacyStatusLabel: input.privacyStatusLabel,
      durabilityStatusLabel: input.durabilityStatusLabel,
      recommendedVariantLabel: recommendedLabel,
    }),
  };
}
