import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject } from "../types/graph";
import { workflowCapabilityPreflight } from "./workflow-capability-preflight";
import {
  WORKFLOW_CAPABILITY_GRANT_REQUEST_SCHEMA_VERSION,
  workflowCapabilityGrantRequestFromRepairAction,
} from "./workflow-capability-grant-request";

const baseWorkflow = {
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
      name: "Capability grant workflow",
      description: "Capability grant workflow",
    },
  },
  metadata: {
    id: "workflow.capability-grant",
    name: "Capability grant workflow",
    slug: "workflow-capability-grant",
    workflowKind: "agent_workflow",
    executionMode: "live",
  },
} as unknown as WorkflowProject;

test("workflow capability grant request is canonical and redacted", () => {
  const workflow = {
    ...baseWorkflow,
    nodes: [
      {
        id: "model",
        type: "model_call",
        name: "Reasoning model",
        x: 0,
        y: 0,
        config: {
          kind: "model_call",
          logic: {
            modelRef: "reasoning",
            modelBinding: {
              modelRef: "reasoning",
              modelId: "local:model",
              modelCapabilityRef: "model-capability:route.local-first",
              routeId: "route.local-first",
              mockBinding: false,
              credentialReadiness: { status: "ready" },
              grantReadiness: { status: "missing" },
              policyPosture: { status: "unknown" },
              receiptBehavior: {
                receiptRequired: true,
                requiredReceiptTypes: ["model_invocation"],
              },
              authorityScopes: ["model.invoke:route.local-first"],
              sideEffectClass: "none",
              requiresApproval: false,
            },
          },
          law: {},
        },
      },
    ],
  } as unknown as WorkflowProject;

  const requestAction = workflowCapabilityPreflight(workflow)?.rows[0]
    ?.repairActions.find((action) => action.kind === "request_authority_grant");
  assert.ok(requestAction);

  const request = workflowCapabilityGrantRequestFromRepairAction(
    workflow,
    requestAction,
    {
      nowMs: 42,
      requestId: "grant-request-test",
    },
  );
  assert.ok(request);
  assert.equal(
    request.schemaVersion,
    WORKFLOW_CAPABILITY_GRANT_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(request.workflowNodeId, "model");
  assert.equal(request.policyTarget.kind, "model_capability");
  assert.equal(request.policyTarget.ref, "model-capability:route.local-first");
  assert.deepEqual(request.authorityScopes, ["model.invoke:route.local-first"]);
  assert.deepEqual(request.receiptBehavior.requiredReceiptTypes, [
    "authority_grant_request",
    "policy_decision",
    "capability_grant_receipt",
  ]);
  assert.equal(request.failClosedUntil, "grant_readiness_ready_and_policy_allowed");
  assert.deepEqual(request.redaction, {
    containsSecretMaterial: false,
    credentialValuesIncluded: false,
  });
  assert.equal(JSON.stringify(request).includes("apiKey"), false);
  assert.equal(JSON.stringify(request).includes("secret"), false);
});

test("workflow capability grant request requires explicit authority scopes", () => {
  const workflow = {
    ...baseWorkflow,
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
              toolRef: "external.crm.read",
              toolCapabilityRef: "tool-capability:external.crm.read",
              bindingKind: "plugin_tool",
              mockBinding: false,
              credentialReadiness: { status: "ready" },
              grantReadiness: { status: "missing" },
              policyPosture: { status: "unknown" },
              workflowAvailability: { available: true },
              agentAvailability: { available: true },
              receiptBehavior: {
                receiptRequired: true,
                requiredReceiptTypes: ["tool_invocation"],
              },
              authorityScopes: [],
              authorityScopeRequirements: [],
              sideEffectClass: "read",
              requiresApproval: false,
            },
          },
          law: {},
        },
      },
    ],
  } as unknown as WorkflowProject;

  const requestAction = workflowCapabilityPreflight(workflow)?.rows[0]
    ?.repairActions.find((action) => action.kind === "request_authority_grant");
  assert.ok(requestAction);
  assert.deepEqual(requestAction.authorityScopes, []);
  assert.equal(
    workflowCapabilityGrantRequestFromRepairAction(workflow, requestAction),
    null,
  );
});
