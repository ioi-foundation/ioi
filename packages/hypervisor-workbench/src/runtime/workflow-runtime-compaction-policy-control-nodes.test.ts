import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_COMPACTION_POLICY_COMPONENT_KIND,
  RUNTIME_COMPACTION_POLICY_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
  RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION,
  RUNTIME_COMPACTION_POLICY_SOURCE,
  RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND,
  RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION,
  createRuntimeCompactionPolicyControlRequestFromWorkflowNode,
} from "./workflow-runtime-compaction-policy-control-nodes";

test("runtime_compaction_policy workflow node builds a daemon policy request", () => {
  const node = makeWorkflowNode(
    "compaction-policy",
    "runtime_compaction_policy",
    "Compaction policy",
    100,
    120,
  );
  const contextBudget = {
    status: "blocked",
    policyDecision: { status: "blocked" },
    receiptRefs: ["receipt_context_budget_thread_abc"],
  };
  const request = createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-compaction-policy-1",
      turnId: "turn-compaction-policy-1",
      runtimeContextBudget: contextBudget,
    },
    { workflowGraphId: "workflow.react-flow.compaction-policy-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_COMPACTION_POLICY_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_compaction_policy");
  assert.equal(request.nodeId, "compaction-policy");
  assert.equal(request.threadId, "thread-compaction-policy-1");
  assert.equal(request.turnId, "turn-compaction-policy-1");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-compaction-policy-1/compaction-policy",
  );
  assert.equal(request.method, "POST");
  assert.equal(request.body.source, RUNTIME_COMPACTION_POLICY_SOURCE);
  assert.equal(request.body.actor, "operator");
  assert.equal(request.body.eventKind, RUNTIME_COMPACTION_POLICY_SOURCE_EVENT_KIND);
  assert.equal(
    request.body.componentKind,
    RUNTIME_COMPACTION_POLICY_COMPONENT_KIND,
  );
  assert.equal(
    request.body.payloadSchemaVersion,
    RUNTIME_COMPACTION_POLICY_PAYLOAD_SCHEMA_VERSION,
  );
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.compaction-policy-proof",
  );
  assert.equal(
    request.body.workflowNodeId,
    RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID,
  );
  assert.equal(request.body.contextBudgetStatus, "blocked");
  assert.deepEqual(request.body.contextBudget, contextBudget);
  assert.equal(request.body.policy.okAction, "noop");
  assert.equal(request.body.policy.warnAction, "warn");
  assert.equal(request.body.policy.blockedAction, "compact");
  assert.equal(request.body.policy.approvalRequired, false);
  assert.equal(request.body.policy.approvalGranted, false);
  assert.equal(request.body.policy.executeCompaction, false);
  assert.equal(
    request.body.policy.compactWorkflowNodeId,
    RUNTIME_COMPACTION_POLICY_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
  );
});

test("runtime_compaction_policy helper supports approval and execution fields", () => {
  const node = makeWorkflowNode(
    "compaction-policy-configured",
    "runtime_compaction_policy",
    "Compaction policy",
    100,
    120,
    {
      runtimeCompactionPolicyEndpoint: "/runtime/{threadId}/compaction-policy",
      runtimeCompactionPolicyThreadIdField: "runtime.threadId",
      runtimeCompactionPolicyTurnIdField: "runtime.turnId",
      runtimeCompactionPolicyContextBudgetField: "policy.contextBudget",
      runtimeCompactionPolicyBlockedAction: "approval_required",
      runtimeCompactionPolicyApprovalRequired: true,
      runtimeCompactionPolicyApprovalGrantedField: "operator.approved",
      runtimeCompactionPolicyExecuteCompactionField: "operator.execute",
      runtimeCompactionPolicyCompactReasonField: "operator.reason",
      runtimeCompactionPolicyCompactScope: "thread",
      runtimeCompactionPolicyCompactWorkflowNodeId: "runtime.context-compact.policy",
      runtimeCompactionPolicyWorkflowNodeId: "runtime.compaction-policy.configured",
      runtimeCompactionPolicyActor: "workflow-author",
    },
  );
  const request = createRuntimeCompactionPolicyControlRequestFromWorkflowNode(node, {
    runtime: { threadId: "thread with space", turnId: "turn-1" },
    policy: { contextBudget: { status: "blocked" } },
    operator: {
      approved: "true",
      execute: "true",
      reason: "compact after approved context budget block",
    },
  });

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn-1");
  assert.equal(request.endpoint, "/runtime/thread%20with%20space/compaction-policy");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.workflowNodeId, "runtime.compaction-policy.configured");
  assert.equal(request.body.policy.blockedAction, "approval_required");
  assert.equal(request.body.policy.approvalRequired, true);
  assert.equal(request.body.policy.approvalGranted, true);
  assert.equal(request.body.policy.executeCompaction, true);
  assert.equal(
    request.body.policy.compactReason,
    "compact after approved context budget block",
  );
  assert.equal(
    request.body.policy.compactWorkflowNodeId,
    "runtime.context-compact.policy",
  );
});

test("runtime_compaction_policy helper maps warning budgets to configurable actions", () => {
  const node = makeWorkflowNode(
    "compaction-policy-warn",
    "runtime_compaction_policy",
    "Compaction policy",
    100,
    120,
    {
      runtimeCompactionPolicyWarnActionField: "policy.warnAction",
      runtimeCompactionPolicyContextBudgetStatusField: "budget.status",
    },
  );
  const request = createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-compaction-policy-warn",
      budget: { status: "warn" },
      policy: { warnAction: "compact" },
    },
    { workflowGraphId: "workflow.react-flow.compaction-policy-proof" },
  );

  assert.equal(request.body.contextBudgetStatus, "warn");
  assert.equal(request.body.policy.warnAction, "compact");
  assert.equal(request.body.policy.blockedAction, "compact");
  assert.equal(request.body.policy.okAction, "noop");
});
