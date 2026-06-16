import assert from "node:assert/strict";
import test from "node:test";

import {
  TOOL_CAPABILITY_BINDING_ENDPOINT,
  normalizeWorkflowConnectorCatalog,
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolCatalog,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingCatalogFallback,
  workflowConnectorBindingIsReady,
  workflowWithCatalogBinding,
  workflowToolBindingCatalogFallback,
  workflowToolBindingIsReady,
} from "./workflow-tool-connector-capability-binding";
import { makeDefaultWorkflow } from "./workflow-defaults";
import { makeWorkflowNode } from "./workflow-node-registry";

test("tool capability catalog uses stable Rust daemon protocol route", () => {
  assert.equal(TOOL_CAPABILITY_BINDING_ENDPOINT, "/v1/tools");
});

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

test("runtime tool contracts project to workflow capability bindings", () => {
  const [binding] = normalizeWorkflowToolCatalog([
    {
      schemaVersion: "ioi.runtime-tool-contract.v1",
      tool_id: "tool://gmail.send",
      display_name: "Send Gmail message",
      input_schema: { type: "object", required: ["to", "body"] },
      output_schema: { type: "object", required: ["messageId"] },
      risk_class: "external_message",
      effect_class: "external_message",
      primitive_capabilities_required: ["prim:net.request"],
      authority_scopes_required: ["scope:gmail.send"],
      approval_required: true,
      evidence_required: ["request_preview", "provider_response"],
      credential_readiness: {
        status: "ready",
        evidenceRefs: ["credential:gmail"],
      },
      rate_limit_profile: {
        policy: "gmail_user_window",
        maxCalls: 10,
        windowMs: 60000,
      },
      idempotency_behavior: {
        required: true,
        strategy: "message_draft_hash",
      },
      workflow_availability: {
        available: true,
        nodeType: "plugin_tool",
        configFields: ["toolBinding"],
      },
      agent_availability: {
        available: true,
      },
      marketplace_exposure: {
        eligible: false,
        reason: "External messages require explicit approval.",
      },
      owner: "connector://gmail",
      version: "1.0.0",
    } as any,
  ]);

  assert.equal(binding.toolRef, "gmail.send");
  assert.equal(binding.toolCapabilityRef, "tool-capability:gmail.send");
  assert.equal(binding.bindingKind, "plugin_tool");
  assert.equal(binding.sideEffectClass, "external_write");
  assert.equal(binding.riskClass, "external_message");
  assert.deepEqual(binding.primitiveCapabilities, ["prim:net.request"]);
  assert.deepEqual(binding.authorityScopeRequirements, ["scope:gmail.send"]);
  assert.deepEqual(binding.evidenceRequirements, [
    "request_preview",
    "provider_response",
  ]);
  assert.equal(binding.receiptBehavior?.receiptRequired, true);
  assert.deepEqual(binding.receiptBehavior?.requiredReceiptTypes, [
    "request_preview",
    "provider_response",
  ]);
  assert.equal(binding.idempotencyBehavior?.required, true);
  assert.equal(binding.workflowAvailability?.available, true);
  assert.equal(binding.agentAvailability?.available, true);
  assert.equal(
    (binding.runtimeToolContract as { owner?: string } | undefined)?.owner,
    "connector://gmail",
  );
  assert.equal(workflowToolBindingIsReady(binding), true);
});

test("missing catalog input falls back to canonical offline presets", () => {
  assert.ok(normalizeWorkflowToolCatalog(null).length >= 1);
  assert.ok(normalizeWorkflowConnectorCatalog(undefined).length >= 1);
});

test("catalog binding projection updates workflow nodes deterministically", () => {
  const workflow = {
    ...makeDefaultWorkflow("Catalog binding projection"),
    nodes: [
      makeWorkflowNode("catalog-tool", "plugin_tool", "Catalog tool", 100, 100),
    ],
  };
  const [toolBinding] = normalizeWorkflowToolCatalog([
    {
      toolRef: "file.apply_patch",
      bindingKind: "coding_tool_pack",
      mockBinding: false,
      credentialReady: true,
      sideEffectClass: "write",
      capabilityScope: ["file.apply_patch"],
      requiresApproval: true,
    },
  ]);

  const result = workflowWithCatalogBinding(workflow, "catalog-tool", {
    kind: "tool",
    value: toolBinding,
  });

  assert.equal(result.applied, true);
  assert.equal(
    result.node?.config?.logic.toolBinding?.toolCapabilityRef,
    "tool-capability:file.apply_patch",
  );
  assert.equal(result.node?.config?.logic.connectorBinding, undefined);
  assert.equal(
    result.workflow.nodes[0].config?.logic.toolBinding?.receiptBehavior
      ?.receiptRequired,
    true,
  );
});

console.log("workflow-tool-connector-capability-binding.test.ts: ok");
