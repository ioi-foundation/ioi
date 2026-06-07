import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  WORKFLOW_RUNTIME_POLICY_STACK_SCHEMA_VERSION,
  workflowRuntimePolicyStackFromEvents,
} from "./workflow-runtime-policy-stack";

function event(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:test:${seq}`,
    seq,
    threadId: "thread-test",
    turnId: "turn-test",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: `2026-05-14T00:00:0${seq}.000Z`,
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId: "workflow.policy-stack",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

test("builds an ordered runtime policy stack from daemon events", () => {
  const stack = workflowRuntimePolicyStackFromEvents(
    [
      event("trust-warning", 2, {
        type: "workspace_trust_warning",
        eventKind: "workspace.trust_warning",
        sourceEventKind: "WorkspaceTrust.Warning",
        status: "warning",
        componentKind: "workspace_trust",
        workflowNodeId: "runtime.thread-mode.yolo.workspace-trust",
        receiptRefs: ["receipt-trust"],
        policyDecisionRefs: ["policy-trust"],
        payload: {
          warning_id: "warning-1",
          mode: "yolo",
          approval_mode: "never_prompt",
        },
      }),
      event("trust-ack", 3, {
        type: "workspace_trust_acknowledged",
        eventKind: "workspace.trust_acknowledged",
        sourceEventKind: "WorkspaceTrust.Acknowledged",
        componentKind: "workspace_trust",
        workflowNodeId: "runtime.thread-mode.yolo.workspace-trust",
        receiptRefs: ["receipt-trust-ack"],
        policyDecisionRefs: ["policy-trust-ack"],
        payload: {
          warning_id: "warning-1",
          source_event_id: "trust-warning",
        },
      }),
      event("approval-required", 4, {
        type: "approval_required",
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        status: "waiting_for_approval",
        componentKind: "approval_gate",
        workflowNodeId: "workflow.coding.file.apply_patch",
        approvalId: "approval-1",
        receiptRefs: ["receipt-approval-required"],
        policyDecisionRefs: ["policy-approval-required"],
        payload: { approval_id: "approval-1" },
      }),
      event("approval-approved", 5, {
        type: "approval_decision",
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        status: "approved",
        componentKind: "approval_gate",
        workflowNodeId: "workflow.coding.file.apply_patch",
        approvalId: "approval-1",
        receiptRefs: ["receipt-approval-approved"],
        policyDecisionRefs: ["policy-approval-approved"],
        payload: {
          approval_id: "approval-1",
          decision: "approve",
          approval_request_event_id: "approval-required",
        },
      }),
      event("tool-completed", 6, {
        type: "tool_completed",
        eventKind: "tool.completed",
        sourceEventKind: "CodingTool.FileApplyPatch",
        status: "completed",
        componentKind: "coding_tool",
        workflowNodeId: "workflow.coding.file.apply_patch",
        toolCallId: "tool-call-1",
        toolName: "file.apply_patch",
        receiptRefs: ["receipt-tool"],
        policyDecisionRefs: ["policy-tool"],
        payload: {
          approval_id: "approval-1",
          approval_satisfied: true,
          approval_decision_event_id: "approval-approved",
        },
      }),
    ],
    { workflowGraphId: "workflow.policy-stack" },
  );

  assert.equal(stack.schemaVersion, WORKFLOW_RUNTIME_POLICY_STACK_SCHEMA_VERSION);
  assert.equal(stack.status, "completed");
  assert.equal(stack.approvalId, "approval-1");
  assert.equal(stack.warningId, "warning-1");
  assert.equal(stack.toolCallId, "tool-call-1");
  assert.deepEqual(
    stack.stages.map((stage) => [stage.kind, stage.status, stage.eventId]),
    [
      ["workspace_trust_warning", "completed", "trust-warning"],
      ["workspace_trust_acknowledgement", "completed", "trust-ack"],
      ["approval_requirement", "completed", "approval-required"],
      ["approval_decision", "completed", "approval-approved"],
      ["approved_retry", "completed", "tool-completed"],
    ],
  );
  assert.deepEqual(stack.workflowNodeIds, [
    "runtime.thread-mode.yolo.workspace-trust",
    "workflow.coding.file.apply_patch",
  ]);
  assert.deepEqual(stack.receiptRefs, [
    "receipt-trust",
    "receipt-trust-ack",
    "receipt-approval-required",
    "receipt-approval-approved",
    "receipt-tool",
  ]);
});

test("marks the stack waiting while trust or approval gates are unresolved", () => {
  const waitingForTrust = workflowRuntimePolicyStackFromEvents([
    event("trust-warning", 1, {
      type: "workspace_trust_warning",
      eventKind: "workspace.trust_warning",
      sourceEventKind: "WorkspaceTrust.Warning",
      componentKind: "workspace_trust",
      status: "warning",
      payload: { warning_id: "warning-1" },
    }),
  ]);

  assert.equal(waitingForTrust.status, "waiting");
  assert.deepEqual(
    waitingForTrust.stages.map((stage) => [stage.kind, stage.status]),
    [
      ["workspace_trust_warning", "completed"],
      ["workspace_trust_acknowledgement", "waiting"],
      ["approval_requirement", "not_required"],
      ["approval_decision", "not_required"],
      ["approved_retry", "not_required"],
    ],
  );

  const waitingForApproval = workflowRuntimePolicyStackFromEvents([
    event("trust-warning", 1, {
      type: "workspace_trust_warning",
      eventKind: "workspace.trust_warning",
      sourceEventKind: "WorkspaceTrust.Warning",
      componentKind: "workspace_trust",
      payload: { warning_id: "warning-1" },
    }),
    event("trust-ack", 2, {
      type: "workspace_trust_acknowledged",
      eventKind: "workspace.trust_acknowledged",
      sourceEventKind: "WorkspaceTrust.Acknowledged",
      componentKind: "workspace_trust",
      payload: { warning_id: "warning-1" },
    }),
    event("approval-required", 3, {
      type: "approval_required",
      eventKind: "approval.required",
      sourceEventKind: "OperatorApproval.Request",
      componentKind: "approval_gate",
      approvalId: "approval-1",
      payload: { approval_id: "approval-1" },
    }),
  ]);

  assert.equal(waitingForApproval.status, "waiting");
  assert.equal(waitingForApproval.stages[3]?.status, "waiting");
  assert.equal(waitingForApproval.stages[4]?.status, "not_required");
});

test("recognizes daemon coding-budget approved retry events", () => {
  const stack = workflowRuntimePolicyStackFromEvents([
    event("approval-required", 1, {
      type: "approval_required",
      eventKind: "approval.required",
      sourceEventKind: "OperatorApproval.Request",
      componentKind: "approval_gate",
      approvalId: "approval-budget",
      payload: {
        approval_id: "approval-budget",
        reason: "coding_tool_budget_preflight_blocked",
      },
    }),
    event("approval-approved", 2, {
      type: "approval_decision",
      eventKind: "approval.approved",
      sourceEventKind: "OperatorApproval.Approve",
      componentKind: "approval_gate",
      approvalId: "approval-budget",
      payload: {
        approval_id: "approval-budget",
        decision: "approve",
      },
    }),
    event("approved-retry", 3, {
      type: "tool_completed",
      eventKind: "workflow.run.retry_completed",
      sourceEventKind: "WorkflowRunCodingToolBudgetApprovedRetry",
      componentKind: "coding_tool",
      workflowNodeId: "runtime.coding-tool-budget-recovery",
      approvalId: "approval-budget",
      toolCallId: "retry-budget",
      receiptRefs: ["receipt-retry"],
      policyDecisionRefs: ["policy-retry"],
      payload: {
        approval_id: "approval-budget",
        approval_satisfied: true,
        approval_decision_event_id: "approval-approved",
      },
    }),
  ]);

  assert.equal(stack.status, "completed");
  assert.deepEqual(stack.stages[4], {
    kind: "approved_retry",
    status: "completed",
    label: "Approved retry",
    eventId: "approved-retry",
    eventSeq: 3,
    workflowGraphId: "workflow.policy-stack",
    workflowNodeId: "runtime.coding-tool-budget-recovery",
    threadId: "thread-test",
    approvalId: "approval-budget",
    warningId: null,
    toolCallId: "retry-budget",
    receiptRefs: ["receipt-retry"],
    policyDecisionRefs: ["policy-retry"],
  });
});

test("runtime policy stack ignores retired payload identity aliases", () => {
  const warningOnly = workflowRuntimePolicyStackFromEvents([
    event("trust-warning", 1, {
      type: "workspace_trust_warning",
      eventKind: "workspace.trust_warning",
      sourceEventKind: "WorkspaceTrust.Warning",
      componentKind: "workspace_trust",
      payload: { warningId: "warning-retired" },
    }),
    event("trust-ack", 2, {
      type: "workspace_trust_acknowledged",
      eventKind: "workspace.trust_acknowledged",
      sourceEventKind: "WorkspaceTrust.Acknowledged",
      componentKind: "workspace_trust",
      payload: {
        warningId: "warning-retired",
        sourceEventId: "trust-warning",
      },
    }),
  ]);

  assert.equal(warningOnly.warningId, "trust-warning");
  assert.equal(warningOnly.status, "waiting");
  assert.equal(warningOnly.stages[1]?.eventId, null);

  const approvalOnly = workflowRuntimePolicyStackFromEvents([
    event("approval-required", 1, {
      type: "approval_required",
      eventKind: "approval.required",
      sourceEventKind: "OperatorApproval.Request",
      componentKind: "approval_gate",
      payload: {
        approval_id: "approval-canonical",
        approvalId: "approval-retired",
      },
    }),
    event("approval-approved", 2, {
      type: "approval_decision",
      eventKind: "approval.approved",
      sourceEventKind: "OperatorApproval.Approve",
      componentKind: "approval_gate",
      status: "approved",
      payload: {
        approval_id: "approval-canonical",
        approvalId: "approval-retired",
        decision: "approve",
      },
    }),
    event("approved-retry", 3, {
      type: "tool_completed",
      eventKind: "workflow.run.retry_completed",
      sourceEventKind: "WorkflowRunCodingToolBudgetApprovedRetry",
      componentKind: "coding_tool",
      workflowNodeId: "runtime.coding-tool-budget-recovery",
      toolCallId: "retry-budget",
      payload: {
        approvalId: "approval-retired",
        approvalSatisfied: true,
        approvalDecisionEventId: "approval-approved",
      },
    }),
  ]);

  assert.equal(approvalOnly.approvalId, "approval-canonical");
  assert.equal(approvalOnly.status, "waiting");
  assert.equal(approvalOnly.stages[4]?.eventId, null);
});
