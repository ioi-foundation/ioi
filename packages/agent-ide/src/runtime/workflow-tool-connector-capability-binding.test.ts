import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingIsReady,
  workflowToolBindingIsReady,
} from "./workflow-tool-connector-capability-binding";

test("legacy tool refs project to canonical tool capability contracts", () => {
  const binding = normalizeWorkflowToolBinding({
    toolRef: "file.apply_patch",
    bindingKind: "coding_tool_pack",
    mockBinding: false,
    credentialReady: true,
    capabilityScope: ["file.apply_patch"],
    sideEffectClass: "write",
    requiresApproval: true,
  });

  assert.equal(binding.toolCapabilityRef, "tool-capability:file.apply_patch");
  assert.deepEqual(binding.authorityScopes, ["scope:workspace.write"]);
  assert.equal(binding.riskClass, "local_write");
  assert.equal(binding.receiptBehavior?.receiptRequired, true);
  assert.equal(binding.idempotencyBehavior?.required, true);
  assert.equal(binding.credentialReadiness?.status, "ready");
  assert.equal((binding.policyPosture as { status?: unknown })?.status, "allowed");
  assert.equal(workflowToolBindingIsReady(binding), true);
});

test("live tool bindings without readiness fail closed", () => {
  const binding = normalizeWorkflowToolBinding({
    toolRef: "external.crm.write",
    bindingKind: "plugin_tool",
    mockBinding: false,
    credentialReady: false,
    credentialReadiness: { status: "unknown" },
    workflowAvailability: { available: false },
    agentAvailability: { available: false },
    grantReadiness: { status: "unknown" },
    policyPosture: { status: "unknown" },
    capabilityScope: ["write"],
    sideEffectClass: "external_write",
    requiresApproval: true,
  });

  assert.equal(binding.toolCapabilityRef, "tool-capability:external.crm.write");
  assert.deepEqual(binding.authorityScopes, ["tool.invoke:external.crm.write"]);
  assert.equal(workflowToolBindingIsReady(binding), false);
});

test("legacy connector refs project to canonical connector capability contracts", () => {
  const binding = normalizeWorkflowConnectorBinding({
    connectorRef: "google.workspace.mail",
    mockBinding: false,
    credentialReady: true,
    capabilityScope: ["draft"],
    sideEffectClass: "external_write",
    requiresApproval: true,
    operation: "draft_email",
  });

  assert.equal(
    binding.connectorCapabilityRef,
    "connector-capability:google.workspace.mail",
  );
  assert.deepEqual(binding.authorityScopes, [
    "connector.invoke:google.workspace.mail",
  ]);
  assert.equal(binding.riskClass, "external_write");
  assert.equal(binding.receiptBehavior?.receiptRequired, true);
  assert.equal(binding.idempotencyBehavior?.required, true);
  assert.equal(workflowConnectorBindingIsReady(binding), true);
});

console.log("workflow-tool-connector-capability-binding.test.ts: ok");
