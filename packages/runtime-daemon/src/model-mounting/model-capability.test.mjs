import assert from "node:assert/strict";
import test from "node:test";

import { modelCapabilities } from "./model-capability.mjs";

test("model capability contracts emit canonical protocol fields without retired aliases", () => {
  const [contract] = modelCapabilities({
    routes: [
      {
        id: "route.local-first",
        role: "reasoning",
        privacy: "local_private",
        providerEligibility: ["provider.local"],
        fallback: ["endpoint.local"],
        deniedProviders: ["provider.denied"],
        status: "active",
        maxCostUsd: 0.01,
        maxLatencyMs: 1_500,
      },
    ],
    endpoints: [
      {
        id: "endpoint.local",
        providerId: "provider.local",
        modelId: "model.local",
        status: "mounted",
        capabilities: ["chat"],
        privacyClass: "local_private",
        lastReceiptId: "receipt.endpoint",
        evidenceRefs: ["endpoint.evidence"],
      },
    ],
    providers: [
      {
        id: "provider.local",
        kind: "ioi_native_local",
        status: "available",
        privacyClass: "local_private",
        lastReceiptId: "receipt.provider",
        evidenceRefs: ["provider.evidence"],
      },
    ],
    artifacts: [
      {
        modelId: "model.local",
        capabilities: ["chat"],
        lastReceiptId: "receipt.artifact",
      },
    ],
    instances: [{ endpointId: "endpoint.local", status: "loaded" }],
  });

  assert.equal(contract.schema_version, "ioi.model-capability.v1");
  assert.equal(contract.route_id, "route.local-first");
  assert.equal(contract.model_role, "reasoning");
  assert.equal(contract.primitive_capability, "prim:model.chat");
  assert.deepEqual(contract.authority_scope_requirements, [
    "route.use:route.local-first",
    "model.chat:*",
  ]);
  assert.equal(contract.policy_target, "model.route.local-first");
  assert.equal(contract.privacy_tier, "local_private");
  assert.deepEqual(contract.provider_priority, ["provider.local"]);
  assert.deepEqual(contract.fallback_policy, {
    allowed: false,
    endpoint_ids: ["endpoint.local"],
    denied_providers: ["provider.denied"],
    selected_endpoint_id: "endpoint.local",
    deterministic_order: true,
  });
  assert.deepEqual(contract.fallback_evidence, [
    {
      endpoint_id: "endpoint.local",
      provider_id: "provider.local",
      status: "ready",
      reason: "Endpoint, provider, and credential posture are ready.",
      vault_required: false,
      vault_ready: true,
    },
  ]);
  assert.deepEqual(contract.cost_estimate_visibility, {
    visible: true,
    max_cost_usd: 0.01,
    max_latency_ms: 1_500,
    source: "model_route_policy",
  });
  assert.deepEqual(contract.credential_readiness.evidence_refs, [
    "receipt.endpoint",
    "receipt.provider",
    "receipt.artifact",
    "endpoint.evidence",
    "provider.evidence",
  ]);
  assert.deepEqual(contract.vault_readiness, {
    status: "ready",
    required_count: 0,
    configured_count: 0,
    missing_count: 0,
  });
  assert.equal(contract.byok_required, false);
  assert.deepEqual(contract.receipt_behavior, {
    receipt_required: true,
    required_receipt_types: ["model_route_selection", "model_invocation"],
  });
  assert.deepEqual(contract.workflow_availability.config_fields, [
    "model_ref",
    "route_id",
    "model_binding",
  ]);
  assert.equal(contract.agent_availability.available, true);
  assert.equal(contract.candidates[0].endpoint_id, "endpoint.local");
  assert.equal(contract.candidates[0].provider_id, "provider.local");
  assert.equal(contract.candidates[0].privacy_tier, "local_private");
  assert.equal(contract.candidates[0].vault_required, false);
  assert.equal(contract.candidates[0].vault_ready, true);

  for (const retiredField of [
    "schemaVersion",
    "routeId",
    "modelRole",
    "primitiveCapability",
    "authorityScopeRequirements",
    "policyTarget",
    "privacyTier",
    "providerPriority",
    "fallbackPolicy",
    "fallbackEvidence",
    "costEstimateVisibility",
    "credentialReadiness",
    "vaultReadiness",
    "byokRequired",
    "receiptBehavior",
    "workflowAvailability",
    "agentAvailability",
  ]) {
    assert.equal(Object.hasOwn(contract, retiredField), false);
  }

  for (const retiredField of [
    "endpointId",
    "modelId",
    "providerId",
    "providerKind",
    "privacyTier",
    "vaultRequired",
    "vaultReady",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(contract.candidates[0], retiredField), false);
  }
});
