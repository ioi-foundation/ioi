import type { ChatPrivacySnapshot } from "../hooks/useChatPrivacySettings";
import type { TraceBundleExportVariant } from "./traceBundleExportModel";

export interface PrivacyEvidenceOverview {
  statusLabel: string;
  detail: string;
  exportSummary: string;
  recommendationLabel: string;
}

export function buildPrivacyEvidenceOverview(input: {
  snapshot: ChatPrivacySnapshot;
  exportVariant?: TraceBundleExportVariant | null;
}): PrivacyEvidenceOverview {
  const wantsRedacted =
    input.exportVariant === "redacted_share" ||
    input.snapshot.redactedOverrideCount > 0 ||
    input.snapshot.focusedDataHandlingLabel.toLowerCase().includes("redacted");

  const exportSummary = `${input.snapshot.redactedOverrideCount} redacted overrides · ${input.snapshot.localOnlyOverrideCount} local-only overrides · ${input.snapshot.exportSurfaceLabel}`;

  if (input.snapshot.pendingGovernanceSummary) {
    return {
      statusLabel: "Privacy review pending",
      detail: input.snapshot.sessionReviewDetail,
      exportSummary,
      recommendationLabel:
        "Prefer the redacted review pack until the pending governance request is resolved.",
    };
  }

  if (wantsRedacted) {
    return {
      statusLabel: "Redaction-aware sharing",
      detail: input.snapshot.sessionReviewDetail,
      exportSummary,
      recommendationLabel:
        "The redacted review pack is aligned with the current runtime data-handling posture.",
    };
  }

  if (input.snapshot.localOnlyOverrideCount > 0) {
    return {
      statusLabel: "Local-only evidence",
      detail: input.snapshot.sessionReviewDetail,
      exportSummary,
      recommendationLabel:
        "Keep the export local to the operator path unless permissions or governance widen the share posture.",
    };
  }

  return {
    statusLabel: input.snapshot.sessionReviewLabel,
    detail: input.snapshot.sessionReviewDetail,
    exportSummary,
    recommendationLabel:
      "The operator evidence pack is allowed under the current runtime posture.",
  };
}
