import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-budget-recovery-control-nodes";
import { createWorkflowRuntimeCodingToolBudgetRecoverySubflow } from "./workflow-runtime-coding-tool-budget-recovery-subflow";
import type { WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor } from "./workflow-runtime-event-projection";

function codingToolBudgetRecoverySeed(): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor {
  return {
    id: "coding-tool-budget-recovery:thread:event-blocked:request_approval",
    schemaVersion: "ioi.workflow.coding-tool-budget-recovery.v1",
    action: "request_approval",
    label: "Request approval",
    summary: "Request approval before retry.",
    status: "available",
    executable: true,
    runId: "run-budget-blocked",
    threadId: "thread-budget",
    workflowGraphId: "workflow.graph",
    workflowNodeId: "node.apply_patch",
    eventId: "event-blocked",
    sourceEventId: "event-blocked",
    approvalId: null,
    approvalRequestEventId: null,
    approvalDecisionEventId: null,
    targetNodeIds: ["node.apply_patch"],
    receiptRefs: ["receipt-budget"],
    policyDecisionRefs: ["policy-budget"],
    recoveryPolicy: {
      schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
      source: "react_flow",
      approvalScope: "target_nodes",
      targetNodeIds: ["node.apply_patch"],
      sourceNodeIds: ["node.apply_patch"],
      retryLimit: 1,
      ttlMs: 900000,
      operatorRole: "budget_operator",
      requiresApproval: true,
      allowOverride: true,
    },
  };
}

test("creates a prewired coding-tool budget recovery subflow from blocked evidence", () => {
  const seed = codingToolBudgetRecoverySeed();
  const subflow = createWorkflowRuntimeCodingToolBudgetRecoverySubflow(seed, {
    idPrefix: "budget-recovery-proof",
    origin: { x: 100, y: 200 },
  });

  assert.equal(
    subflow.schemaVersion,
    "ioi.workflow.runtime-coding-tool-budget-recovery-subflow.v1",
  );
  assert.equal(subflow.runId, "run-budget-blocked");
  assert.equal(subflow.nodes.length, 4);
  assert.deepEqual(
    subflow.nodes.map((node) => node.config?.logic.runtimeCodingToolBudgetRecoveryAction),
    [
      "request_approval",
      "approve_override",
      "reject_override",
      "retry_approved",
    ],
  );
  assert.deepEqual(
    subflow.nodes.map((node) => node.config?.logic.runtimeCodingToolBudgetRecoveryRunId),
    [
      "run-budget-blocked",
      "run-budget-blocked",
      "run-budget-blocked",
      "run-budget-blocked",
    ],
  );
  assert.deepEqual(
    subflow.nodes.map(
      (node) => node.config?.logic.runtimeCodingToolBudgetRecoveryWorkflowNodeId,
    ),
    subflow.nodes.map((node) => node.id),
  );
  assert.deepEqual(
    subflow.edges.map((edge) => [edge.from, edge.to, edge.data?.path]),
    [
      [subflow.requestNodeId, subflow.approveNodeId, "approval_path"],
      [subflow.requestNodeId, subflow.rejectNodeId, "rejection_path"],
      [subflow.approveNodeId, subflow.retryNodeId, "approved_retry"],
    ],
  );
});

test("generated coding-tool budget recovery subflow nodes compile into daemon requests", () => {
  const subflow = createWorkflowRuntimeCodingToolBudgetRecoverySubflow(
    codingToolBudgetRecoverySeed(),
    {
      idPrefix: "budget-recovery-executable-proof",
      origin: { x: 100, y: 200 },
    },
  );
  const requests = subflow.nodes.map((node) =>
    createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(node, {}, {
      workflowGraphId: subflow.workflowGraphId,
    }),
  );

  assert.deepEqual(
    requests.map((request) => request.action),
    [
      "request_approval",
      "approve_override",
      "reject_override",
      "retry_approved",
    ],
  );
  assert.deepEqual(
    requests.map((request) => request.endpoint),
    [
      "/v1/runs/run-budget-blocked/coding-tool-budget-recovery",
      "/v1/runs/run-budget-blocked/coding-tool-budget-recovery",
      "/v1/runs/run-budget-blocked/coding-tool-budget-recovery",
      "/v1/runs/run-budget-blocked/coding-tool-budget-recovery",
    ],
  );
  assert.deepEqual(
    requests.map((request) => request.body.workflowNodeId),
    subflow.nodes.map((node) => node.id),
  );
  assert.deepEqual(
    requests.map((request) => request.body.workflowGraphId),
    [
      "workflow.graph",
      "workflow.graph",
      "workflow.graph",
      "workflow.graph",
    ],
  );
  assert.equal(requests[0]?.body.approvalId, requests[1]?.body.approvalId);
  assert.equal(requests[1]?.body.approvalId, requests[3]?.body.approvalId);
  assert.equal(requests[3]?.body.recoveryPolicy.operatorRole, "budget_operator");
  assert.deepEqual(requests[3]?.body.targetNodeIds, ["node.apply_patch"]);
});
