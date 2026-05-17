import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject } from "../types/graph";
import {
  workflowCapabilityPreflight,
  workflowCapabilityPreflightValidationResult,
  workflowCapabilityRunLaunchAnnotation,
} from "./workflow-capability-preflight";

const workflow = {
  version: "1",
  nodes: [],
  edges: [],
  global_config: {
    env: "test",
    modelBindings: {},
    requiredCapabilities: {},
    policy: {
      maxBudget: 1,
      maxSteps: 4,
      timeoutMs: 1_000,
    },
    contract: {
      developerBond: 1,
      adjudicationRubric: "test",
    },
    meta: {
      name: "Capability preflight",
      description: "Capability preflight",
    },
  },
  metadata: {
    id: "workflow.capability-preflight",
    name: "Capability preflight",
    slug: "workflow-capability-preflight",
    workflowKind: "agent_workflow",
    executionMode: "mock",
  },
} as unknown as WorkflowProject;

test("workflow capability preflight preserves old local workflows", () => {
  const oldWorkflow = {
    ...workflow,
    nodes: [
      {
        id: "model",
        type: "model_call",
        name: "Model",
        x: 0,
        y: 0,
        config: {
          kind: "model_call",
          logic: { modelRef: "reasoning" },
          law: {},
        },
      },
    ],
  } as unknown as WorkflowProject;

  assert.equal(workflowCapabilityPreflight(oldWorkflow), null);
});

test("workflow capability preflight blocks unready live capability bindings", () => {
  const liveWorkflow = {
    ...workflow,
    nodes: [
      {
        id: "tool",
        type: "plugin_tool",
        name: "External writer",
        x: 0,
        y: 0,
        config: {
          kind: "plugin_tool",
          logic: {
            toolBinding: {
              toolRef: "external.crm.write",
              toolCapabilityRef: "tool-capability:external.crm.write",
              bindingKind: "plugin_tool",
              mockBinding: false,
              credentialReady: false,
              credentialReadiness: { status: "unknown" },
              grantReadiness: { status: "unknown" },
              policyPosture: { status: "unknown" },
              workflowAvailability: { available: false },
              agentAvailability: { available: false },
              receiptBehavior: {
                receiptRequired: false,
                requiredReceiptTypes: [],
              },
              authorityScopes: [],
              authorityScopeRequirements: [],
              capabilityScope: ["write"],
              sideEffectClass: "external_write",
              requiresApproval: true,
            },
          },
          law: {},
        },
      },
    ],
  } as unknown as WorkflowProject;

  const preflight = workflowCapabilityPreflight(liveWorkflow);
  assert.equal(preflight?.status, "blocked");
  assert.deepEqual(preflight?.targetNodeIds, ["tool"]);
  assert.deepEqual(preflight?.capabilityRefs, [
    "tool-capability:external.crm.write",
  ]);
  assert.equal(
    preflight?.blockerReasons.includes("missing_credential_readiness"),
    true,
  );
  assert.equal(
    preflight?.blockerReasons.includes("missing_receipt_behavior"),
    true,
  );

  const annotation = workflowCapabilityRunLaunchAnnotation(preflight);
  assert.equal(
    annotation?.schemaVersion,
    "ioi.workflow.capability-preflight.v1",
  );
  assert.equal(annotation?.rows[0]?.nodeId, "tool");
  assert.deepEqual(
    annotation?.rows[0]?.repairActions.map((action) => action.kind),
    [
      "open_capability_binding",
      "request_authority_grant",
      "attach_ready_capability",
      "review_receipt_policy",
    ],
  );
  assert.equal(
    annotation?.rows[0]?.repairActions.find(
      (action) => action.kind === "request_authority_grant",
    )?.authorityEndpoint,
    "/api/v1/authority",
  );

  const validation = workflowCapabilityPreflightValidationResult(preflight!);
  assert.equal(validation.status, "blocked");
  assert.deepEqual(validation.blockedNodes, ["tool"]);
  assert.equal(
    validation.errors.some(
      (issue) => issue.code === "workflow_capability_preflight_blocked",
    ),
    true,
  );
});

test("workflow capability preflight clears after canonical repair config is persisted", () => {
  const repairedWorkflow = {
    ...workflow,
    nodes: [
      {
        id: "tool",
        type: "plugin_tool",
        name: "External writer",
        x: 0,
        y: 0,
        config: {
          kind: "plugin_tool",
          logic: {
            toolBinding: {
              toolRef: "external.crm.write",
              toolCapabilityRef: "tool-capability:external.crm.write",
              bindingKind: "plugin_tool",
              mockBinding: false,
              credentialReady: true,
              credentialReadiness: { status: "ready" },
              grantReadiness: { status: "ready" },
              policyPosture: { status: "allowed" },
              workflowAvailability: { available: true },
              agentAvailability: { available: true },
              receiptBehavior: {
                receiptRequired: true,
                requiredReceiptTypes: ["tool_invocation", "tool_verification"],
              },
              authorityScopes: ["tool.invoke:external.crm.write"],
              authorityScopeRequirements: ["tool.invoke:external.crm.write"],
              capabilityScope: ["write"],
              sideEffectClass: "external_write",
              requiresApproval: true,
            },
          },
          law: {},
        },
      },
    ],
  } as unknown as WorkflowProject;

  assert.equal(workflowCapabilityPreflight(repairedWorkflow), null);
});
