import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeGraphModelBinding,
  normalizeWorkflowModelBinding,
  workflowModelBindingIsReady,
} from "./workflow-model-capability-binding";

test("raw graph model ids do not mint legacy model capability refs", () => {
  const binding = normalizeGraphModelBinding("reasoning", {
    modelId: "openai/gpt-5.4-mini",
    required: true,
  });

  assert.equal(
    binding.modelCapabilityRef,
    "model-capability:route.local-first",
  );
  assert.equal(binding.routeId, "route.local-first");
  assert.deepEqual(binding.authorityScopes, [
    "route.use:route.local-first",
    "model.chat:*",
  ]);
  assert.equal(binding.receiptBehavior?.receiptRequired, true);
  assert.equal(binding.credentialReadiness?.status, "unknown");
  assert.equal(
    (binding.policyPosture as { status?: unknown })?.status,
    "unknown",
  );
  assert.equal(workflowModelBindingIsReady(binding), false);
  assert.equal(
    Object.values(binding).some(
      (value) => typeof value === "string" && value.includes("model-capability:legacy"),
    ),
    false,
  );
});

test("canonical graph model capability readiness remains executable", () => {
  const binding = normalizeGraphModelBinding("reasoning", {
    modelCapabilityRef: "model-capability:route.local-first",
    routeId: "route.local-first",
    credentialReadiness: { status: "ready" },
    grantReadiness: { status: "ready" },
    policyPosture: { status: "allowed" },
    workflowAvailability: { available: true },
    agentAvailability: { available: true },
  });

  assert.equal(binding.modelCapabilityRef, "model-capability:route.local-first");
  assert.equal(binding.credentialReadiness?.status, "ready");
  assert.equal(workflowModelBindingIsReady(binding), true);
});

test("live workflow model binding without readiness fails closed", () => {
  const binding = normalizeWorkflowModelBinding({
    modelRef: "reasoning",
    modelCapabilityRef: "model-capability:route.local-first",
    routeId: "route.local-first",
    mockBinding: false,
    credentialReady: false,
    credentialReadiness: { status: "unknown" },
    workflowAvailability: { available: false },
    agentAvailability: { available: false },
    grantReadiness: { status: "unknown" },
    policyPosture: { status: "unknown" },
    capabilityScope: ["chat"],
    sideEffectClass: "none",
    requiresApproval: false,
  });

  assert.equal(workflowModelBindingIsReady(binding), false);
  assert.equal(binding.receiptBehavior?.receiptRequired, true);
  assert.deepEqual(binding.authorityScopes, [
    "route.use:route.local-first",
    "model.chat:*",
  ]);
});

console.log("workflow-model-capability-binding.test.ts: ok");
