import assert from "node:assert/strict";
import test from "node:test";

import type { ConnectorSummary } from "@ioi/agent-ide";
import {
  buildAuthorityCenterProjection,
  buildAuthorityGrantRequestPayload,
} from "./authorityCenter";
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
  assert.deepEqual(projection.grants[0]?.receiptRefs, [
    "receipt_permission_token_test",
  ]);
  assert.equal(projection.grants[0]?.canRevoke, true);
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

test("authority center builds scoped grant payloads from capability rows", () => {
  const projection = buildAuthorityCenterProjection({
    policyState: createDefaultShieldPolicyState(),
    modelSnapshot: {
      modelCapabilities: [
        {
          id: "model-capability:route.local-first",
          routeId: "route.local-first",
          capability: "chat",
          authorityScopeRequirements: [
            "model.chat:*",
            "route.use:route.local-first",
          ],
          credentialReadiness: { status: "ready" },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
        },
      ],
    },
  });

  const payload = buildAuthorityGrantRequestPayload(
    projection.capabilities[0],
    {
      generatedAtMs: Date.parse("2026-05-15T12:00:00Z"),
      expiresInMs: 30 * 60 * 1000,
    },
  );

  assert.equal(payload.audience, "autopilot-authority-center");
  assert.deepEqual(payload.allowed, [
    "model.chat:*",
    "route.use:route.local-first",
  ]);
  assert.equal(payload.expiresAt, "2026-05-15T12:30:00.000Z");
  assert.equal(
    payload.grantId,
    "wallet.grant.authority-center.model.model-capability-route-local-first",
  );
  assert.equal(JSON.stringify(payload).includes("provider."), false);
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

test("authority center prefers wallet authority snapshots for grants and vault refs", () => {
  const projection = buildAuthorityCenterProjection({
    policyState: createDefaultShieldPolicyState(),
    authoritySnapshot: {
      grants: [
        {
          id: "token.authority",
          grantId: "wallet.grant.authority",
          allowed: ["model.chat:*"],
          denied: [],
          expiresAt: "2026-05-15T13:00:00Z",
          revokedAt: null,
          receiptId: "receipt_authority_grant",
        },
      ],
      vaultRefs: [
        {
          vaultRefHash: "vault-authority",
          label: "Authority vault",
          purpose: "model.provider.auth",
          configured: true,
          lastResolvedAt: "2026-05-15T12:00:00Z",
        },
      ],
    },
    modelSnapshot: {
      tokens: [
        {
          id: "token.model-snapshot",
          grantId: "wallet.grant.model-snapshot",
          allowed: ["model.chat:*"],
          denied: [],
          expiresAt: "2026-05-15T13:00:00Z",
          revokedAt: null,
          receiptId: "receipt_model_snapshot",
        },
      ],
    },
  });

  assert.equal(projection.grants.length, 1);
  assert.equal(projection.grants[0]?.id, "token.authority");
  assert.equal(projection.vaultRefs.length, 1);
  assert.equal(projection.vaultRefs[0]?.id, "vault-authority");
});

test("authority center accepts canonical endpoint wrappers and snake case contracts", () => {
  const projection = buildAuthorityCenterProjection({
    policyState: createDefaultShieldPolicyState(),
    modelSnapshot: {
      capabilities: [
        {
          model_capability_ref: "model-capability:route.autopilot",
          route_id: "route.autopilot",
          capability: "chat",
          policy_target: "model.route.autopilot",
          privacy_tier: "local_private",
          authority_scope_requirements: ["model.chat:*"],
          credential_readiness: { status: "ready" },
          receipt_behavior: {
            required_receipt_types: ["model_invocation"],
          },
          workflow_availability: { available: true },
          agent_availability: { available: true },
          fallback_policy: {
            selected_endpoint_id: "endpoint.local",
          },
        },
      ],
    },
    toolCatalog: {
      tools: [
        {
          stable_tool_id: "tool://gmail.send",
          display_name: "Send Gmail message",
          credential_readiness: { status: "ready" },
          effect_class: "external_message",
          risk_class: "external_message",
          authority_scope_requirements: ["scope:gmail.send"],
          receipt_behavior: {
            required_receipt_types: ["request_preview", "provider_response"],
          },
        },
      ],
    },
  });

  assert.equal(projection.status, "ready");
  assert.equal(projection.summary.readyCapabilities, 2);
  assert.equal(
    projection.capabilities[0]?.id,
    "model-capability:route.autopilot",
  );
  assert.deepEqual(projection.capabilities[0]?.receiptTypes, [
    "model_invocation",
  ]);
  assert.equal(projection.capabilities[1]?.id, "tool://gmail.send");
  assert.deepEqual(projection.capabilities[1]?.requiredScopes, [
    "scope:gmail.send",
  ]);
});

console.log("authorityCenter.test.ts: ok");
