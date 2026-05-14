import assert from "node:assert/strict";
import test from "node:test";

import { makeDefaultWorkflow } from "./workflow-defaults";
import { createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-budget-recovery-control-nodes";
import {
  bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence,
  workflowRuntimeCodingToolBudgetRecoveryBindingIssue,
  workflowRuntimeCodingToolBudgetRecoveryEvidenceAction,
  workflowRuntimeCodingToolBudgetRecoveryEvidenceActionsFromProjection,
} from "./workflow-runtime-coding-tool-budget-recovery-binding";
import { createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow } from "./workflow-runtime-coding-tool-budget-recovery-subflow";
import type { WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor } from "./workflow-runtime-event-projection";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./workflow-validation";

function codingToolBudgetRecoverySeed(
  action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor["action"] =
    "request_approval",
): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor {
  return {
    id: `coding-tool-budget-recovery:thread:event-blocked:${action}`,
    schemaVersion: "ioi.workflow.coding-tool-budget-recovery.v1",
    action,
    label: "Request approval",
    summary: "Request approval before retry.",
    status: "available",
    executable: true,
    runId: "run-budget-blocked",
    threadId: "thread-budget",
    workflowGraphId: "workflow.template",
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

test("coding-tool budget recovery binding quick-fix wires selected evidence into template nodes", () => {
  const baseWorkflow = makeDefaultWorkflow();
  const subflow = createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow({
    idPrefix: "budget-recovery-template",
    workflowGraphId: "workflow.template",
    sourceWorkflowNodeId: "node.apply_patch",
  });
  const workflow = {
    ...baseWorkflow,
    metadata: {
      ...baseWorkflow.metadata,
      id: "workflow.template",
    },
    nodes: [...baseWorkflow.nodes, ...subflow.nodes],
  };
  const validation = validateWorkflowProject(workflow, []);
  const readiness = evaluateWorkflowActivationReadiness(workflow, [], validation);
  const issue = readiness.executionReadinessIssues?.find((candidate) =>
    workflowRuntimeCodingToolBudgetRecoveryBindingIssue(candidate),
  );

  assert(issue);
  const result = bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence(
    workflow,
    codingToolBudgetRecoverySeed(),
    { issue },
  );
  assert.equal(result.status, "bound");
  assert.deepEqual(
    result.boundNodeIds,
    [
      subflow.requestNodeId,
      subflow.approveNodeId,
      subflow.rejectNodeId,
      subflow.retryNodeId,
    ],
  );
  const boundRetry = result.workflow.nodes.find(
    (node) => node.id === subflow.retryNodeId,
  )!;
  const logic = boundRetry.config?.logic ?? {};
  assert.equal(logic.runtimeCodingToolBudgetRecoveryRunId, "run-budget-blocked");
  assert.equal(
    logic.runtimeCodingToolBudgetRecoveryApprovalId,
    "approval_workflow_run_coding_tool_budget_run-budget-blocked_event-blocked",
  );
  assert.deepEqual(logic.runtimeCodingToolBudgetRecoveryTargetNodeIds, [
    "node.apply_patch",
  ]);
  assert.equal(
    logic.fieldMappings?.runId?.source,
    "{{runtime.codingToolBudgetRecoveryEvidence.event-blocked}}",
  );
  assert.equal(logic.fieldMappings?.recoveryPolicy?.path, "recoveryPolicy");
  assert.equal(
    (logic.runtimeCodingToolBudgetRecovery as any)?.evidenceBinding
      ?.schemaVersion,
    "ioi.workflow.runtime-coding-tool-budget-recovery-binding.v1",
  );

  const nextValidation = validateWorkflowProject(result.workflow, []);
  const nextReadiness = evaluateWorkflowActivationReadiness(
    result.workflow,
    [],
    nextValidation,
  );
  assert.equal(
    (nextReadiness.executionReadinessIssues ?? []).some((candidate) =>
      workflowRuntimeCodingToolBudgetRecoveryBindingIssue(candidate),
    ),
    false,
  );

  const request = createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
    boundRetry,
    {},
    { workflowGraphId: result.workflow.metadata.id },
  );
  assert.equal(request.action, "retry_approved");
  assert.equal(
    request.endpoint,
    "/v1/runs/run-budget-blocked/coding-tool-budget-recovery",
  );
  assert.equal(request.body.threadId, "thread-budget");
  assert.equal(request.body.recoveryPolicy.operatorRole, "budget_operator");
});

test("coding-tool budget recovery binding helper selects blocked-run evidence actions", () => {
  const review = codingToolBudgetRecoverySeed("review_receipt");
  const approve = codingToolBudgetRecoverySeed("approve_override");
  const request = codingToolBudgetRecoverySeed("request_approval");
  assert.equal(
    workflowRuntimeCodingToolBudgetRecoveryEvidenceAction([review, approve, request])
      ?.action,
    "request_approval",
  );
  assert.equal(
    workflowRuntimeCodingToolBudgetRecoveryEvidenceActionsFromProjection({
      reactFlowNodes: [
        { data: { codingToolBudgetRecoveryActions: [review, request] } },
        { data: { codingToolBudgetRecoveryActions: [request, approve] } },
      ],
    }).length,
    3,
  );
});

test("coding-tool budget recovery binding quick-fix blocks without run evidence", () => {
  const baseWorkflow = makeDefaultWorkflow();
  const subflow = createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow({
    idPrefix: "budget-recovery-template",
    workflowGraphId: "workflow.template",
  });
  const result = bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence(
    { ...baseWorkflow, nodes: [...baseWorkflow.nodes, ...subflow.nodes] },
    { ...codingToolBudgetRecoverySeed(), runId: null },
    { issue: { nodeId: subflow.requestNodeId, code: "missing_runtime_coding_tool_budget_recovery_run_binding", message: "" } },
  );

  assert.equal(result.status, "blocked");
  assert.deepEqual(result.boundNodeIds, []);
  assert(result.blockers.includes("coding_tool_budget_recovery_evidence_missing"));
});
