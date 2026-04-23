import assert from "node:assert/strict";
import type { ChatPrivacySnapshot } from "../hooks/useChatPrivacySettings";
import { buildPrivacyEvidenceOverview } from "./privacyEvidenceModel.ts";

const baseSnapshot: ChatPrivacySnapshot = {
  generatedAtMs: Date.parse("2026-04-06T00:10:00.000Z"),
  focusedScopeLabel: "Mail",
  focusedDataHandlingLabel: "Local redacted",
  focusedDataHandlingDetail: "Artifacts leave the runtime only after redaction.",
  sessionReviewLabel: "Redacted export allowed",
  sessionReviewDetail: "Use redaction before artifacts leave the runtime.",
  exportSurfaceLabel: "Canonical local export",
  exportSurfaceDetail: "Exports stay operator initiated.",
  governingSourceLabel: "Connector policy override",
  activeOverrideCount: 2,
  redactedOverrideCount: 1,
  localOnlyOverrideCount: 0,
  pendingGovernanceSummary: null,
  governanceHistoryLabel: "Recent governance review retained",
  governanceHistoryDetail: "Remembered approvals stay attached to privacy posture.",
  recentGovernanceReceipts: [],
  connectors: [],
};

{
  const overview = buildPrivacyEvidenceOverview({
    snapshot: baseSnapshot,
    exportVariant: "operator_share",
  });

  assert.equal(overview.statusLabel, "Redaction-aware sharing");
  assert.match(overview.recommendationLabel, /redacted review pack/i);
}

{
  const overview = buildPrivacyEvidenceOverview({
    snapshot: {
      ...baseSnapshot,
      pendingGovernanceSummary: "Redacted export requested for Mail.",
      sessionReviewLabel: "Privacy posture change pending",
    },
    exportVariant: "operator_share",
  });

  assert.equal(overview.statusLabel, "Privacy review pending");
  assert.match(overview.recommendationLabel, /Prefer the redacted review pack/i);
}
