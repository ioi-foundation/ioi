import assert from "node:assert/strict";
import test from "node:test";

import { createWorkflowRuntimeCodingToolBudgetRecoverySubflow } from "./workflow-runtime-coding-tool-budget-recovery-subflow";
import type { WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor } from "./workflow-runtime-event-projection";

test("creates a prewired coding-tool budget recovery subflow from blocked evidence", () => {
  const seed: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor = {
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
