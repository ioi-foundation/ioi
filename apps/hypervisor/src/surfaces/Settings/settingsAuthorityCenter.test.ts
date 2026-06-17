import assert from "node:assert/strict";
import test from "node:test";

import { buildAuthorityCenterProjection } from "../Policy/authorityCenter";
import { createDefaultShieldPolicyState } from "../Policy/policyCenter";
import { summarizeSettingsAuthorityCenter } from "./settingsAuthorityCenter";

test("settings authority center summarizes shared runtime projection", () => {
  const projection = buildAuthorityCenterProjection({
    policyState: createDefaultShieldPolicyState(),
    modelSnapshot: {
      modelCapabilities: [
        {
          id: "model-capability:route.local-first",
          routeId: "route.local-first",
          capability: "chat",
          credentialReadiness: { status: "ready" },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          receiptBehavior: { requiredReceiptTypes: ["model_invocation"] },
        },
      ],
    },
    toolCatalog: [
      {
        stableToolId: "gmail.send",
        displayName: "Send email",
        credentialReadiness: { status: "missing" },
        effectClass: "external_write",
      },
    ],
  });

  const summary = summarizeSettingsAuthorityCenter(projection);

  assert.equal(summary.tone, "warning");
  assert.equal(summary.label, "Needs review");
  assert.equal(summary.checklist.includes("1/2 capabilities ready"), true);
  assert.equal(summary.checklist.includes("1 capability blocker"), true);
  assert.equal(
    summary.failClosedReasons.some((reason) => reason.includes("Send email")),
    true,
  );
  assert.equal(summary.topCapabilities.length, 2);
  assert.deepEqual(
    summary.topCapabilities[1]?.repairActions.map((action) => action.kind),
    ["requestGrant", "openConnectorCredential", "openWorkflowPreflight"],
  );
});

console.log("settingsAuthorityCenter.test.ts: ok");
