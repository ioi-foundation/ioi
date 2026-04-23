import type { ArtifactHubViewKey } from "../../../types";

export type ReviewTone = "ready" | "setup" | "attention";

export interface ReviewWorkflowCard {
  id: "run" | "handoff" | "privacy" | "promotion";
  label: string;
  tone: ReviewTone;
  value: string;
  detail: string;
  meta: string[];
  actionView?: ArtifactHubViewKey;
}

export interface BuildReviewOverviewInput {
  sessionTitle?: string | null;
  branchLabel?: string | null;
  changedPathCount: number;
  stagedPathCount: number;
  unstagedPathCount: number;
  evidenceEventCount: number;
  evidenceArtifactCount: number;
  visibleSourceCount: number;
  screenshotCount: number;
  substrateReceiptCount: number;
  verifierState?: string | null;
  verifierOutcome?: string | null;
  approvalState?: string | null;
  blockerTitle?: string | null;
  blockerDetail?: string | null;
  prReadiness: "draft" | "ready" | "attention";
  prReadinessLabel: string;
  prReadinessDetail: string;
  privacyStatusLabel: string;
  privacyDetail: string;
  privacyRecommendationLabel: string;
  durabilityStatusLabel: string;
  durabilityDetail: string;
  exportStatus: string;
  exportVariant?: string | null;
  replayReady: boolean;
}

export interface ReviewOverview {
  tone: ReviewTone;
  headline: string;
  detail: string;
  reviewCount: number;
  watchCount: number;
  cards: ReviewWorkflowCard[];
}

const REVIEW_TONE_RANK: Record<ReviewTone, number> = {
  ready: 0,
  setup: 1,
  attention: 2,
};

function trimOrNull(value?: string | null): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function humanizeStatus(value?: string | null): string {
  const text = trimOrNull(value)?.replace(/[_-]+/g, " ") ?? "unknown";
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

function strongestTone(values: ReviewTone[]): ReviewTone {
  return values.reduce<ReviewTone>((current, candidate) => {
    return REVIEW_TONE_RANK[candidate] > REVIEW_TONE_RANK[current]
      ? candidate
      : current;
  }, "ready");
}

function isPendingReview(label: string): boolean {
  return /pending|review required/i.test(label);
}

function runReviewCard(
  input: BuildReviewOverviewInput,
): ReviewWorkflowCard {
  const blockerTitle = trimOrNull(input.blockerTitle);
  const blockerDetail = trimOrNull(input.blockerDetail);
  const verifierBlocked =
    input.verifierOutcome === "blocked" || input.approvalState === "denied";
  const verifierPassed =
    input.verifierOutcome === "pass" || input.verifierState === "passed";
  const tone: ReviewTone = blockerTitle || verifierBlocked
    ? "attention"
    : verifierPassed &&
        input.evidenceEventCount > 0 &&
        input.evidenceArtifactCount > 0
      ? "ready"
      : "setup";

  return {
    id: "run",
    label: "Run review",
    tone,
    value: blockerTitle
      ? blockerTitle
      : verifierPassed
        ? "Runtime evidence aligned"
        : "Review still assembling",
    detail: blockerTitle
      ? blockerDetail || "The current run still has an explicit blocker."
      : verifierPassed
        ? "Verification, approvals, and retained evidence are already strong enough for a focused operator review pass."
        : "Use the shared task, replay, and evidence surfaces to close the remaining review gaps before wider handoff.",
    meta: [
      `${input.changedPathCount} changed path(s)`,
      `${input.stagedPathCount} staged`,
      `${input.substrateReceiptCount} runtime receipt(s)`,
      `Verifier: ${humanizeStatus(input.verifierOutcome || input.verifierState)}`,
    ],
    actionView: blockerTitle ? "tasks" : "replay",
  };
}

function handoffCard(
  input: BuildReviewOverviewInput,
): ReviewWorkflowCard {
  const tone: ReviewTone =
    input.prReadiness === "attention"
      ? "attention"
      : input.prReadiness === "ready"
        ? "ready"
        : "setup";
  return {
    id: "handoff",
    label: "Reviewer handoff",
    tone,
    value: input.prReadinessLabel,
    detail: input.prReadinessDetail,
    meta: [
      trimOrNull(input.branchLabel) || "No retained branch label",
      `${input.stagedPathCount} staged · ${input.unstagedPathCount} unstaged`,
      `${input.visibleSourceCount} evidence source(s)`,
    ],
    actionView: "pr_comments",
  };
}

function privacyCard(
  input: BuildReviewOverviewInput,
): ReviewWorkflowCard {
  const tone: ReviewTone = isPendingReview(input.privacyStatusLabel)
    ? "attention"
    : /local-only/i.test(input.privacyStatusLabel)
      ? "setup"
      : "ready";
  return {
    id: "privacy",
    label: "Privacy review",
    tone,
    value: input.privacyStatusLabel,
    detail: input.privacyDetail,
    meta: [
      input.privacyRecommendationLabel,
      `${input.screenshotCount} screenshot receipt(s)`,
      `${input.evidenceArtifactCount} retained artifact(s)`,
    ],
    actionView: tone === "attention" ? "privacy" : "share",
  };
}

function promotionCard(
  input: BuildReviewOverviewInput,
): ReviewWorkflowCard {
  const blocked =
    !input.replayReady ||
    isPendingReview(input.durabilityStatusLabel) ||
    isPendingReview(input.privacyStatusLabel) ||
    input.prReadiness === "attention";
  const exportReady = input.exportStatus === "success" || input.exportStatus === "idle";
  const tone: ReviewTone = !input.replayReady
    ? "setup"
    : blocked
      ? "attention"
      : exportReady
        ? "ready"
        : "setup";
  const exportLabel = trimOrNull(input.exportVariant)?.replace(/_/g, " ");

  return {
    id: "promotion",
    label: "Promotion review",
    tone,
    value: !input.replayReady
      ? "Replay bundle not loaded"
      : tone === "ready"
        ? "Evidence-preserving promotion ready"
        : "Promotion still needs review",
    detail: !input.replayReady
      ? "Load the canonical replay bundle before staging service-candidate or Forge promotion from shared runtime truth."
      : tone === "ready"
        ? "Replay, privacy, durability, and reviewer handoff posture are aligned for evidence-preserving promotion."
        : "Promotion can already stay on the canonical evidence path, but privacy, durability, or reviewer posture still deserves one more pass.",
    meta: [
      input.durabilityStatusLabel,
      exportLabel ? `Latest export: ${exportLabel}` : "Latest export: not packaged yet",
      `${input.evidenceEventCount} events · ${input.evidenceArtifactCount} artifacts`,
    ],
    actionView: input.replayReady ? "share" : "export",
  };
}

export function buildReviewOverview(
  input: BuildReviewOverviewInput,
): ReviewOverview {
  const cards = [
    runReviewCard(input),
    handoffCard(input),
    privacyCard(input),
    promotionCard(input),
  ];
  const tone = strongestTone(cards.map((card) => card.tone));
  const reviewCount = cards.filter((card) => card.tone === "attention").length;
  const watchCount = cards.filter((card) => card.tone === "setup").length;
  const scopeLabel =
    trimOrNull(input.sessionTitle) ||
    trimOrNull(input.branchLabel) ||
    "the current retained session";

  return {
    tone,
    headline:
      tone === "attention"
        ? "Review follow-up required"
        : tone === "setup"
          ? "Review workflow assembling"
          : "Review workflow aligned",
    detail:
      tone === "attention"
        ? `One or more review lanes still need attention before ${scopeLabel} should be treated as fully ready for wider handoff or promotion.`
        : tone === "setup"
          ? `The shared runtime already has enough state to start reviewing ${scopeLabel}, but at least one lane is still assembling.`
          : `Run review, reviewer handoff, privacy posture, and promotion readiness are all aligned for ${scopeLabel}.`,
    reviewCount,
    watchCount,
    cards,
  };
}
