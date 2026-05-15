import assert from "node:assert/strict";
import test from "node:test";

import type { ConnectorSummary } from "@ioi/agent-ide";
import { buildAuthorityCenterProjection } from "./authorityCenter";
import { createDefaultShieldPolicyState } from "./policyCenter";

const connector: ConnectorSummary = {
  id: "google-workspace",
  pluginId: "google_workspace",
  name: "Google Workspace",
  provider: "Google",
  category: "productivity",
  description: "Read and draft workspace data.",
  status: "connected",
  authMode: "oauth",
  scopes: ["scope:google.readonly"],
};

test("authority center projection aggregates readiness without leaking raw secrets", () => {
  const projection = buildAuthorityCenterProjection({
    policyState: createDefaultShieldPolicyState(),
    connectors: [connector],
    modelSnapshot: {
      providers: [{ secretRef: "sk-rawshouldnotescape123456" }],
      modelCapabilities: [
        {
          id: "model-capability:route.local-first",
          routeId: "route.local-first",
          capability: "chat",
          policyTarget: "model.route.local-first",
          privacyTier: "local_private",
          authorityScopeRequirements: [
            "model.chat:*",
            "route.use:route.local-first",
          ],
          credentialReadiness: { status: "ready" },
          receiptBehavior: {
            requiredReceiptTypes: ["model_route_selection", "model_invocation"],
          },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          fallbackPolicy: {
            selectedEndpointId: "endpoint.local-auto",
          },
        },
      ],
      tokens: [
        {
          id: "token.public",
          grantId: "wallet.grant.test",
          allowed: ["model.chat:*"],
          denied: ["shell.exec:*"],
          vaultRefs: { model: { redacted: true, hash: "abc123" } },
          receiptId: "receipt_permission_token_test",
          expiresAt: "2026-05-15T00:00:00Z",
        },
      ],
      vaultRefs: [
        {
          vaultRefHash: "abc123",
          label: "OpenAI provider key",
          purpose: "model.provider.auth",
          state: "material bound",
          lastResolvedAt: "2026-05-15T00:00:00Z",
        },
      ],
    },
    toolCatalog: [
      {
        stableToolId: "sys.exec",
        displayName: "Shell command",
        credentialReadiness: { status: "not_required" },
        effectClass: "local_command",
        riskDomain: "host",
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        receiptBehavior: { requiredReceiptTypes: ["shell_receipt"] },
      },
    ],
  });

  assert.equal(projection.status, "ready");
  assert.equal(projection.summary.rawSecretLeakSuspected, false);
  assert.equal(projection.summary.readyCapabilities, 3);
  assert.equal(projection.summary.activeGrants, 1);
  assert.equal(projection.summary.vaultRefs, 1);
  assert.equal(
    JSON.stringify(projection).includes("sk-rawshouldnotescape"),
    false,
  );
  assert.equal(
    projection.capabilities.some(
      (capability) => capability.policyTarget === "model.route.local-first",
    ),
    true,
  );
});

test("authority center projection degrades when live capabilities are blocked", () => {
  const projection = buildAuthorityCenterProjection({
    policyState: createDefaultShieldPolicyState(),
    modelSnapshot: {
      modelCapabilities: [
        {
          id: "model-capability:route.hosted",
          routeId: "route.hosted",
          capability: "chat",
          policyTarget: "model.route.hosted",
          privacyTier: "hosted",
          authorityScopeRequirements: ["model.chat:*"],
          credentialReadiness: { status: "missing" },
          receiptBehavior: {
            requiredReceiptTypes: ["model_route_selection", "model_invocation"],
          },
          workflowAvailability: { available: false },
          agentAvailability: { available: false },
          fallbackPolicy: {},
        },
      ],
    },
    toolCatalog: [
      {
        stableToolId: "gmail.send",
        displayName: "Send email",
        credentialReadiness: { status: "missing" },
        effectClass: "external_write",
        riskDomain: "communication",
      },
    ],
  });

  assert.equal(projection.status, "degraded");
  assert.equal(projection.summary.blockedCapabilities, 2);
  assert.equal(
    projection.blockers.includes("2 live capabilities are blocked."),
    true,
  );
});

console.log("authorityCenter.test.ts: ok");
