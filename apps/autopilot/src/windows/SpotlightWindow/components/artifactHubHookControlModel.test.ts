import assert from "node:assert/strict";
import type { SessionHookSnapshot } from "../../../types";
import { buildHookControlOverview } from "./artifactHubHookControlModel.ts";

function makeSnapshot(
  overrides: Partial<SessionHookSnapshot> = {},
): SessionHookSnapshot {
  return {
    generatedAtMs: Date.now(),
    sessionId: "session-hook-control",
    workspaceRoot: "/tmp/ioi",
    activeHookCount: 0,
    disabledHookCount: 0,
    runtimeReceiptCount: 0,
    approvalReceiptCount: 0,
    hooks: [],
    recentReceipts: [],
    ...overrides,
  };
}

{
  const overview = buildHookControlOverview(null);

  assert.equal(overview.tone, "setup");
  assert.equal(overview.statusLabel, "No hook sources retained");
  assert.equal(overview.recommendedView, "plugins");
}

{
  const overview = buildHookControlOverview(
    makeSnapshot({
      activeHookCount: 1,
      approvalReceiptCount: 2,
      hooks: [
        {
          hookId: "hook-1",
          entryId: "plugin:mail",
          label: "Mail read hook",
          ownerLabel: "Mail tools",
          sourceLabel: "Mail connector",
          sourceKind: "connector",
          sourceUri: null,
          contributionPath: null,
          triggerLabel: "read",
          enabled: true,
          statusLabel: "Active",
          trustPosture: "trusted",
          governedProfile: "guided_default",
          authorityTierLabel: "Connector",
          availabilityLabel: "Runtime",
          sessionScopeLabel: "Session",
          whyActive: "Connector receipts feed hook state.",
        },
      ],
    }),
  );

  assert.equal(overview.tone, "attention");
  assert.equal(overview.statusLabel, "Approval-sensitive automation active");
  assert.equal(overview.recommendedView, "permissions");
}

{
  const overview = buildHookControlOverview(
    makeSnapshot({
      activeHookCount: 2,
      runtimeReceiptCount: 3,
      hooks: [
        {
          hookId: "hook-1",
          entryId: "plugin:mail",
          label: "Mail read hook",
          ownerLabel: "Mail tools",
          sourceLabel: "Mail connector",
          sourceKind: "connector",
          sourceUri: null,
          contributionPath: null,
          triggerLabel: "read",
          enabled: true,
          statusLabel: "Active",
          trustPosture: "trusted",
          governedProfile: "guided_default",
          authorityTierLabel: "Connector",
          availabilityLabel: "Runtime",
          sessionScopeLabel: "Session",
          whyActive: "Connector receipts feed hook state.",
        },
        {
          hookId: "hook-2",
          entryId: "plugin:google",
          label: "Calendar hook",
          ownerLabel: "Calendar tools",
          sourceLabel: "Google Workspace",
          sourceKind: "connector",
          sourceUri: null,
          contributionPath: null,
          triggerLabel: "write",
          enabled: true,
          statusLabel: "Active",
          trustPosture: "trusted",
          governedProfile: "guided_default",
          authorityTierLabel: "Connector",
          availabilityLabel: "Runtime",
          sessionScopeLabel: "Session",
          whyActive: "Workspace automation is enabled.",
        },
      ],
    }),
  );

  assert.equal(overview.tone, "ready");
  assert.equal(overview.statusLabel, "Hooks active and reporting");
  assert.equal(overview.recommendedView, null);
}
