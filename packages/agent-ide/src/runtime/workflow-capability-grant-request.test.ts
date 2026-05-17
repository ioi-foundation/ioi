import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject } from "../types/graph";
import { workflowCapabilityPreflight } from "./workflow-capability-preflight";
import {
  WORKFLOW_CAPABILITY_GRANT_REQUEST_SCHEMA_VERSION,
  applyApprovedWorkflowCapabilityGrantRequestToWorkflow,
  workflowCapabilityGrantRequestFromRepairAction,
  type WorkflowCapabilityGrantRequest,
  type WorkflowCapabilityGrantRequestResult,
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

test("workflow capability grant lifecycle only unblocks after approved grant is applied", () => {
  const workflow = toolGrantWorkflow();
  const requestAction = workflowCapabilityPreflight(workflow)?.rows[0]
    ?.repairActions.find((action) => action.kind === "request_authority_grant");
  assert.ok(requestAction);
  const request = workflowCapabilityGrantRequestFromRepairAction(
    workflow,
    requestAction,
    {
      nowMs: 99,
      requestId: "grant-lifecycle",
    },
  );
  assert.ok(request);

  const drafted = grantResult(request, "drafted");
  assert.equal(
    applyApprovedWorkflowCapabilityGrantRequestToWorkflow(workflow, drafted)
      .status,
    "blocked",
  );
  assert.equal(workflowCapabilityPreflight(workflow)?.status, "blocked");

  const denied = grantResult(request, "denied");
  assert.equal(
    applyApprovedWorkflowCapabilityGrantRequestToWorkflow(workflow, denied)
      .status,
    "blocked",
  );

  const expired = grantResult(request, "expired");
  assert.equal(
    applyApprovedWorkflowCapabilityGrantRequestToWorkflow(workflow, expired)
      .status,
    "blocked",
  );

  const approved = grantResult(request, "approved");
  const applied = applyApprovedWorkflowCapabilityGrantRequestToWorkflow(
    workflow,
    approved,
  );
  assert.equal(applied.status, "applied");
  assert.equal(applied.bindingKey, "toolBinding");
  assert.equal(workflowCapabilityPreflight(applied.workflow), null);
  const appliedBinding = applied.workflow.nodes[0]?.config?.logic
    .toolBinding as any;
  assert.equal(appliedBinding?.grantReadiness?.status, "ready");
  assert.equal(appliedBinding?.policyPosture?.status, "allowed");
  assert.deepEqual(appliedBinding?.authorityScopes, [
    "tool.invoke:external.crm.write",
  ]);
  assert.deepEqual(appliedBinding?.grantReceiptRefs, [
    "receipt_workflow_capability_grant_request_grant-lifecycle",
  ]);
});

function toolGrantWorkflow(): WorkflowProject {
  return {
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
              toolRef: "external.crm.write",
              toolCapabilityRef: "tool-capability:external.crm.write",
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
              authorityScopes: ["tool.invoke:external.crm.write"],
              authorityScopeRequirements: ["tool.invoke:external.crm.write"],
              sideEffectClass: "external_write",
              requiresApproval: true,
            },
          },
          law: {},
        },
      },
    ],
  } as unknown as WorkflowProject;
}

function grantResult(
  request: WorkflowCapabilityGrantRequest,
  status: WorkflowCapabilityGrantRequestResult["status"],
): WorkflowCapabilityGrantRequestResult {
  return {
    schemaVersion: "ioi.workflow.capability-grant-request-result.v1",
    requestId: request.requestId,
    status,
    capabilityRef: request.capabilityRef,
    workflowNodeId: request.workflowNodeId,
    authorityScopes: request.authorityScopes,
    policyDecisionRefs:
      status === "approved"
        ? [`policy_workflow_capability_grant_request_${request.requestId}`]
        : [],
    receiptRefs:
      status === "approved"
        ? [`receipt_workflow_capability_grant_request_${request.requestId}`]
        : [],
    evidenceRef: `authority-grant-request-${request.requestId}`,
    workflowRemainsFailClosed: status !== "approved",
    secretMaterialPresent: false,
    message: `Grant ${status}`,
    issues: [],
    request,
    resolvedAtMs: status === "drafted" || status === "blocked" ? null : 100,
    resolution:
      status === "drafted" || status === "blocked"
        ? null
        : {
            decision:
              status === "approved"
                ? "approve"
                : status === "denied"
                  ? "deny"
                  : "expire",
            reason: null,
            actor: "test",
            resolvedAtMs: 100,
          },
    appliedAtMs: null,
  };
}
