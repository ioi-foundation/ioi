import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  WORKFLOW_RUNTIME_EDIT_PROPOSAL_POLICY_SCHEMA_VERSION,
  workflowRuntimeEditProposalPolicyStackFromEvents,
} from "./workflow-runtime-edit-proposal-policy";

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
    workflowGraphId: "workflow.edit-policy",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

test("builds a workflow edit proposal policy stack through approved apply", () => {
  const stack = workflowRuntimeEditProposalPolicyStackFromEvents(
    [
      event("proposal", 1, {
        type: "workflow_edit_proposed",
        eventKind: "workflow.edit_proposed",
        sourceEventKind: "WorkflowEdit.Proposed",
        status: "waiting_for_approval",
        componentKind: "workflow_edit_proposal",
        workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
        approvalId: "approval-a",
        receiptRefs: ["receipt-proposal"],
        policyDecisionRefs: ["policy-proposal"],
        payload: {
          proposal_id: "proposal-a",
          approval_id: "approval-a",
          target_workflow_node_ids: ["node-a"],
        },
      }),
      event("approval-required", 2, {
        type: "approval_required",
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        componentKind: "approval_gate",
        approvalId: "approval-a",
        receiptRefs: ["receipt-approval"],
        payload: { approval_id: "approval-a" },
      }),
      event("approval-approved", 3, {
        type: "approval_decision",
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        componentKind: "approval_gate",
        approvalId: "approval-a",
        status: "approved",
        receiptRefs: ["receipt-approved"],
        payload: { approval_id: "approval-a", decision: "approve" },
      }),
      event("apply", 4, {
        type: "workflow_edit_applied",
        eventKind: "workflow.edit_applied",
        sourceEventKind: "WorkflowEdit.Applied",
        componentKind: "workflow_edit_proposal",
        workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
        approvalId: "approval-a",
        receiptRefs: ["receipt-apply"],
        policyDecisionRefs: ["policy-apply"],
        payload: {
          proposal_id: "proposal-a",
          proposal_event_id: "proposal",
          approval_id: "approval-a",
          mutation_executed: true,
        },
      }),
    ],
    { workflowGraphId: "workflow.edit-policy" },
  );

  assert.equal(
    stack.schemaVersion,
    WORKFLOW_RUNTIME_EDIT_PROPOSAL_POLICY_SCHEMA_VERSION,
  );
  assert.equal(stack.status, "completed");
  assert.equal(stack.proposalId, "proposal-a");
  assert.equal(stack.approvalId, "approval-a");
  assert.equal(stack.mutationExecuted, true);
  assert.deepEqual(stack.targetWorkflowNodeIds, ["node-a"]);
  assert.deepEqual(
    stack.stages.map((stage) => [stage.kind, stage.status, stage.eventId]),
    [
      ["proposal_created", "completed", "proposal"],
      ["approval_requirement", "completed", "approval-required"],
      ["approval_decision", "completed", "approval-approved"],
      ["proposal_apply", "completed", "apply"],
    ],
  );
  assert.deepEqual(stack.receiptRefs, [
    "receipt-proposal",
    "receipt-approval",
    "receipt-approved",
    "receipt-apply",
  ]);
});

test("marks rejected or unapplied workflow edit proposals as blocked or waiting", () => {
  const rejected = workflowRuntimeEditProposalPolicyStackFromEvents([
    event("proposal", 1, {
      type: "workflow_edit_proposed",
      eventKind: "workflow.edit_proposed",
      sourceEventKind: "WorkflowEdit.Proposed",
      approvalId: "approval-a",
      payload: { proposal_id: "proposal-a", approval_id: "approval-a" },
    }),
    event("approval-required", 2, {
      type: "approval_required",
      eventKind: "approval.required",
      sourceEventKind: "OperatorApproval.Request",
      approvalId: "approval-a",
      payload: { approval_id: "approval-a" },
    }),
    event("approval-rejected", 3, {
      type: "approval_decision",
      eventKind: "approval.rejected",
      sourceEventKind: "OperatorApproval.Reject",
      approvalId: "approval-a",
      status: "rejected",
      payload: { approval_id: "approval-a", decision: "reject" },
    }),
  ]);

  assert.equal(rejected.status, "blocked");
  assert.deepEqual(
    rejected.stages.map((stage) => [stage.kind, stage.status]),
    [
      ["proposal_created", "completed"],
      ["approval_requirement", "completed"],
      ["approval_decision", "blocked"],
      ["proposal_apply", "blocked"],
    ],
  );

  const waitingForApply = workflowRuntimeEditProposalPolicyStackFromEvents([
    event("proposal", 1, {
      type: "workflow_edit_proposed",
      eventKind: "workflow.edit_proposed",
      sourceEventKind: "WorkflowEdit.Proposed",
      approvalId: "approval-a",
      payload: { proposal_id: "proposal-a", approval_id: "approval-a" },
    }),
    event("approval-required", 2, {
      type: "approval_required",
      eventKind: "approval.required",
      sourceEventKind: "OperatorApproval.Request",
      approvalId: "approval-a",
      payload: { approval_id: "approval-a" },
    }),
    event("approval-approved", 3, {
      type: "approval_decision",
      eventKind: "approval.approved",
      sourceEventKind: "OperatorApproval.Approve",
      approvalId: "approval-a",
      status: "approved",
      payload: { approval_id: "approval-a", decision: "approve" },
    }),
  ]);

  assert.equal(waitingForApply.status, "waiting");
  assert.equal(waitingForApply.stages[3]?.status, "waiting");
});
