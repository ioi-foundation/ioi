import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeWorkflowConnectorCatalog,
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolCatalog,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingCatalogFallback,
  workflowConnectorBindingIsReady,
  workflowToolBindingCatalogFallback,
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

test("tool catalog fallback hydrates canonical capability metadata", () => {
  const catalog = workflowToolBindingCatalogFallback();
  const nativeCatalog = catalog.find(
    (binding) =>
      binding.toolCapabilityRef ===
      "tool-capability:agent.runtime.native-tool.catalog.read",
  );

  assert.ok(nativeCatalog);
  assert.equal(nativeCatalog.mockBinding, false);
  assert.equal(nativeCatalog.credentialReadiness?.status, "ready");
  assert.equal(nativeCatalog.workflowAvailability?.available, true);
  assert.equal(nativeCatalog.agentAvailability?.available, true);
  assert.equal(nativeCatalog.receiptBehavior?.receiptRequired, true);
  assert.deepEqual(nativeCatalog.authorityScopeRequirements, []);
});

test("connector catalog fallback hydrates canonical authority and receipt metadata", () => {
  const catalog = workflowConnectorBindingCatalogFallback();
  const ticketing = catalog.find(
    (binding) =>
      binding.connectorCapabilityRef ===
      "connector-capability:it_ticketing",
  );

  assert.ok(ticketing);
  assert.equal(ticketing.mockBinding, true);
  assert.equal(ticketing.riskClass, "external_write");
  assert.deepEqual(ticketing.authorityScopes, [
    "connector.invoke:it_ticketing",
  ]);
  assert.equal(ticketing.receiptBehavior?.receiptRequired, true);
  assert.equal(ticketing.idempotencyBehavior?.required, true);
});

test("runtime catalog rows normalize and dedupe by capability ref", () => {
  const catalog = normalizeWorkflowToolCatalog([
    {
      toolRef: "file.apply_patch",
      toolCapabilityRef: "tool-capability:file.apply_patch",
      bindingKind: "coding_tool_pack",
      mockBinding: false,
      credentialReady: true,
      sideEffectClass: "write",
      capabilityScope: ["file.apply_patch"],
      requiresApproval: true,
    },
    {
      toolRef: "file.apply_patch",
      toolCapabilityRef: "tool-capability:file.apply_patch",
      bindingKind: "coding_tool_pack",
      mockBinding: false,
      credentialReady: true,
      sideEffectClass: "write",
      capabilityScope: ["file.apply_patch"],
      requiresApproval: true,
    },
  ]);

  assert.equal(catalog.length, 1);
  assert.equal(catalog[0].riskClass, "local_write");
  assert.deepEqual(catalog[0].authorityScopeRequirements, [
    "scope:workspace.write",
  ]);
});

test("missing catalog input falls back to canonical offline presets", () => {
  assert.ok(normalizeWorkflowToolCatalog(null).length >= 1);
  assert.ok(normalizeWorkflowConnectorCatalog(undefined).length >= 1);
});

console.log("workflow-tool-connector-capability-binding.test.ts: ok");
