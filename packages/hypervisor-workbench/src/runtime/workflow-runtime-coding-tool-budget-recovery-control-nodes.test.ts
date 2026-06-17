import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND,
  RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND,
  RUNTIME_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_CONTROL_SCHEMA_VERSION,
  createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode,
} from "./workflow-runtime-coding-tool-budget-recovery-control-nodes";

test("runtime_coding_tool_budget_recovery workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "budget-recovery-control",
    "runtime_coding_tool_budget_recovery",
    "Budget recovery",
    100,
    120,
  );
  const request =
    createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
      node,
      {
        runId: "run-react-flow-1",
        threadId: "thread-react-flow-1",
        action: "request_approval",
        approvalId: "approval-budget-recovery",
        sourceEventId: "event-budget-blocked",
        targetNodeIds: ["node-write"],
        recoveryPolicy: {
          schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
          source: "react_flow_test",
          approvalScope: "target_nodes",
          operatorRole: "budget_operator",
          retryLimit: 2,
          ttlMs: 300000,
          requiresApproval: true,
          allowOverride: true,
          targetNodeIds: ["node-write"],
          sourceNodeIds: ["node-write"],
        },
      },
      { workflowGraphId: "workflow.react-flow.budget-recovery-proof" },
    );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_coding_tool_budget_recovery");
  assert.equal(request.nodeId, "budget-recovery-control");
  assert.equal(request.runId, "run-react-flow-1");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.action, "request_approval");
  assert.equal(
    request.endpoint,
    "/v1/runs/run-react-flow-1/coding-tool-budget-recovery",
  );
  assert.equal(request.method, "POST");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(request.body.eventKind, RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND);
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.budget-recovery-proof",
  );
  assert.equal(
    request.body.workflowNodeId,
    RUNTIME_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID,
  );
  assert.equal(request.body.approvalId, "approval-budget-recovery");
  assert.equal(request.body.sourceEventId, "event-budget-blocked");
  assert.deepEqual(request.body.targetNodeIds, ["node-write"]);
  assert.equal(request.body.recoveryPolicy.operatorRole, "budget_operator");
  assert.equal(request.body.recoveryPolicy.retryLimit, 2);
});

test("runtime_coding_tool_budget_recovery helper supports configurable fields and encoded routes", () => {
  const node = makeWorkflowNode(
    "budget-recovery-configured",
    "runtime_coding_tool_budget_recovery",
    "Budget recovery",
    100,
    120,
    {
      runtimeCodingToolBudgetRecoveryEndpoint:
        "/runtime/runs/{runId}/budget-recovery/{approvalId}",
      runtimeCodingToolBudgetRecoveryRunIdField: "runtime.run.id",
      runtimeCodingToolBudgetRecoveryThreadIdField: "runtime.thread.id",
      runtimeCodingToolBudgetRecoveryActionField: "recovery.action",
      runtimeCodingToolBudgetRecoveryApprovalIdField: "recovery.approval.id",
      runtimeCodingToolBudgetRecoverySourceEventIdField: "recovery.sourceEventId",
      runtimeCodingToolBudgetRecoveryTargetNodeIdsField: "recovery.targets",
      runtimeCodingToolBudgetRecoveryPolicyInputField: "recovery.policy",
      runtimeCodingToolBudgetRecoveryWorkflowNodeId:
        "runtime.budget-recovery.configured",
      runtimeCodingToolBudgetRecoveryActor: "workflow-author",
    },
  );
  const request =
    createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
      node,
      {
        runtime: {
          run: { id: "run with space" },
          thread: { id: "thread configured" },
        },
        recovery: {
          action: "retry-approved",
          approval: { id: "approval/with/slash" },
          sourceEventId: "event configured",
          targets: "node-a,node-b",
          policy: {
            approvalScope: "target_nodes",
            operatorRole: "workflow_author",
            retryLimit: 3,
            ttlMs: 600000,
            requiresApproval: false,
            allowOverride: true,
          },
        },
      },
    );

  assert.equal(request.runId, "run with space");
  assert.equal(request.threadId, "thread configured");
  assert.equal(request.action, "retry_approved");
  assert.equal(
    request.endpoint,
    "/runtime/runs/run%20with%20space/budget-recovery/approval%2Fwith%2Fslash",
  );
  assert.equal(request.body.approval_id, "approval/with/slash");
  assert.deepEqual(request.body.target_node_ids, ["node-a", "node-b"]);
  assert.equal(request.body.recovery_policy.retryLimit, 3);
  assert.equal(request.body.recovery_policy.requiresApproval, false);
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.workflowNodeId, "runtime.budget-recovery.configured");
});
