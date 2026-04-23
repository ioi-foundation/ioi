export type PrCommentsReadiness = "draft" | "ready" | "attention";

export interface BuildPrCommentsInput {
  sessionTitle?: string | null;
  branchLabel?: string | null;
  lastCommitLabel?: string | null;
  progressSummary?: string | null;
  currentStage?: string | null;
  selectedRoute?: string | null;
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
  verificationNotes?: string[];
}

export interface PrCommentDraft {
  id: "status_update" | "review_ready" | "follow_up";
  label: string;
  description: string;
  markdown: string;
}

export interface PrCommentsOverview {
  readiness: PrCommentsReadiness;
  readinessLabel: string;
  readinessDetail: string;
  evidenceLabel: string;
  draftCount: number;
  drafts: PrCommentDraft[];
}

function trimOrNull(value?: string | null): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function humanizeStatus(value?: string | null): string {
  const text = trimOrNull(value)?.replace(/[_-]+/g, " ") ?? "unknown";
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

function joinLines(lines: Array<string | null | undefined>): string {
  return lines.filter((line): line is string => Boolean(line?.trim())).join("\n");
}

function bulletList(lines: Array<string | null | undefined>): string {
  return lines
    .filter((line): line is string => Boolean(line?.trim()))
    .map((line) => `- ${line}`)
    .join("\n");
}

function reviewScopeLabel(input: BuildPrCommentsInput): string {
  return (
    trimOrNull(input.sessionTitle) ||
    trimOrNull(input.branchLabel) ||
    "the current change set"
  );
}

function verificationHeadline(input: BuildPrCommentsInput): string {
  const firstNote = trimOrNull(input.verificationNotes?.[0]);
  if (firstNote) {
    return firstNote;
  }
  return [
    `Verifier: ${humanizeStatus(input.verifierState)}`,
    input.verifierOutcome
      ? `Outcome: ${humanizeStatus(input.verifierOutcome)}`
      : null,
    input.approvalState
      ? `Approval: ${humanizeStatus(input.approvalState)}`
      : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function buildPrCommentsOverview(
  input: BuildPrCommentsInput,
): PrCommentsOverview {
  const blockerTitle = trimOrNull(input.blockerTitle);
  const blockerDetail = trimOrNull(input.blockerDetail);
  const verification = verificationHeadline(input);
  const scopeLabel = reviewScopeLabel(input);
  const evidenceLabel = `${input.evidenceEventCount} events · ${input.evidenceArtifactCount} artifacts · ${input.substrateReceiptCount} receipts`;
  const routeLabel =
    trimOrNull(input.selectedRoute) ||
    trimOrNull(input.currentStage) ||
    trimOrNull(input.progressSummary) ||
    "Execution in progress";

  const readiness: PrCommentsReadiness = blockerTitle
    ? "attention"
    : input.verifierOutcome === "blocked" || input.approvalState === "denied"
      ? "attention"
      : (input.verifierState === "passed" || input.verifierOutcome === "pass") &&
          input.changedPathCount > 0 &&
          input.approvalState !== "pending"
        ? "ready"
        : "draft";

  const readinessLabel =
    readiness === "ready"
      ? "Ready for reviewer handoff"
      : readiness === "attention"
        ? "Follow-up needed before review"
        : "Draft reviewer update";
  const readinessDetail =
    readiness === "ready"
      ? "Verification and evidence are strong enough to draft a reviewer-facing update from shared runtime truth."
      : readiness === "attention"
        ? "The change set still has an open blocker or review gate, so reviewer comments should call out the follow-up explicitly."
        : "The change set is still moving, but you can already draft a status comment without leaving the runtime-backed evidence flow.";

  const statusUpdate = joinLines([
    "## Status update",
    "",
    `Working on ${scopeLabel}.`,
    "",
    bulletList([
      `Route: ${routeLabel}`,
      verification,
      input.lastCommitLabel
        ? `Latest retained commit: ${input.lastCommitLabel}`
        : "Latest retained commit: not recorded yet",
      `${input.changedPathCount} changed path(s) · ${input.stagedPathCount} staged · ${input.unstagedPathCount} unstaged`,
      `${input.visibleSourceCount} evidence source(s) · ${input.screenshotCount} screenshot receipt(s)`,
      `Evidence thread summary: ${evidenceLabel}`,
      blockerTitle ? `Open blocker: ${blockerTitle}` : null,
    ]),
  ]);

  const reviewReady = joinLines([
    "## Ready for review",
    "",
    readiness === "ready"
      ? `This update is ready for focused review on ${scopeLabel}.`
      : `This update is approaching review readiness for ${scopeLabel}, but it still needs follow-up before sign-off.`,
    "",
    bulletList([
      `Branch scope: ${trimOrNull(input.branchLabel) || "No branch retained yet"}`,
      verification,
      `${input.changedPathCount} changed path(s) are in scope for this review`,
      `${input.evidenceArtifactCount} retained artifact(s) and ${input.substrateReceiptCount} runtime receipt(s) support the current state`,
      blockerTitle
        ? `Review blocker: ${blockerTitle}${blockerDetail ? ` · ${blockerDetail}` : ""}`
        : null,
    ]),
  ]);

  const followUp = joinLines([
    "## Follow-up requested",
    "",
    blockerTitle
      ? `Please hold final review on ${scopeLabel} until the blocker below is resolved.`
      : `Please keep review focused on the next validation and staging steps for ${scopeLabel}.`,
    "",
    bulletList([
      blockerTitle
        ? `${blockerTitle}${blockerDetail ? ` · ${blockerDetail}` : ""}`
        : `Verification posture: ${verification}`,
      input.unstagedPathCount > 0
        ? `${input.unstagedPathCount} path(s) are still unstaged and may belong to later work`
        : null,
      input.stagedPathCount > 0
        ? `${input.stagedPathCount} staged path(s) are ready for the next reviewer checkpoint`
        : null,
      `Evidence available: ${evidenceLabel}`,
    ]),
  ]);

  return {
    readiness,
    readinessLabel,
    readinessDetail,
    evidenceLabel,
    draftCount: 3,
    drafts: [
      {
        id: "status_update",
        label: "Status update",
        description:
          "Compact reviewer-facing status note with route, verification, and retained evidence context.",
        markdown: statusUpdate,
      },
      {
        id: "review_ready",
        label: "Review-ready note",
        description:
          "Focused handoff comment for reviewers checking the current staged change set.",
        markdown: reviewReady,
      },
      {
        id: "follow_up",
        label: "Follow-up request",
        description:
          "Explicit blocker or next-step comment when review should stay conditional.",
        markdown: followUp,
      },
    ],
  };
}
