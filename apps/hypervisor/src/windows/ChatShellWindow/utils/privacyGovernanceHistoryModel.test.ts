import assert from "node:assert/strict";
import { buildPrivacyGovernanceHistoryOverview } from "./privacyGovernanceHistoryModel.ts";

{
  const overview = buildPrivacyGovernanceHistoryOverview({
    governanceRequest: null,
    rememberedApprovals: null,
  });

  assert.equal(overview.label, "No recent governance review retained");
}

{
  const overview = buildPrivacyGovernanceHistoryOverview({
    governanceRequest: {
      requestId: "request-1",
      createdAtMs: 1,
      status: "pending",
      action: "widen",
      capabilityEntryId: "capability-1",
      capabilityLabel: "Mail",
      capabilityKind: "connector",
      governingEntryId: null,
      governingLabel: "Mail policy",
      governingKind: "policy",
      connectorId: "mail.primary",
      connectorLabel: "Mail",
      sourceLabel: "Policy center",
      authorityTierLabel: "Governed",
      governedProfileLabel: "Automation bridge",
      leaseModeLabel: "Governed",
      whySelectable: "Review required",
      headline: "Redacted export requested",
      detail: "A redacted export path is pending review for Mail.",
      requestedState: {
        version: 1,
        global: {
          reads: "auto",
          writes: "confirm",
          admin: "confirm",
          expert: "block",
          automations: "confirm_on_create",
          dataHandling: "local_redacted",
        },
        overrides: {},
      },
    },
    rememberedApprovals: null,
  });

  assert.equal(overview.label, "Governance change pending");
  assert.match(overview.detail, /pending review/i);
}

{
  const overview = buildPrivacyGovernanceHistoryOverview({
    governanceRequest: null,
    rememberedApprovals: {
      generatedAtMs: 1,
      activeDecisionCount: 1,
      recentReceiptCount: 1,
      decisions: [],
      recentReceipts: [
        {
          receiptId: "receipt-1",
          timestampMs: 1,
          hookKind: "pre_run_approval_hook",
          status: "matched",
          summary: "Matched remembered approval for Mail read.",
          connectorId: "mail.primary",
          actionId: "mail.read_latest",
          decisionId: "decision-1",
        },
      ],
    },
  });

  assert.equal(overview.label, "Recent governance review retained");
  assert.equal(overview.recentReceipts.length, 1);
}
