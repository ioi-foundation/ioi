import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowRuntimePolicyLeasePanel } from "./workflow-runtime-policy-lease-panel";

type RuntimeEventFixtureOverrides =
  Partial<WorkflowRuntimeThreadEventLike> & Record<string, unknown>;

function event(
  id: string,
  seq: number,
  overrides: RuntimeEventFixtureOverrides = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:test:${seq}`,
    seq,
    thread_id: "thread-test",
    threadId: "thread-test",
    turn_id: "turn-test",
    turnId: "turn-test",
    type: "approval_required",
    eventKind: "approval.required",
    sourceEventKind: "OperatorApproval.Request",
    status: "waiting_for_approval",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    component_kind: "approval_gate",
    componentKind: "approval_gate",
    workflow_node_id: "workflow.policy-lease",
    workflowNodeId: "workflow.policy-lease",
    workflow_graph_id: "workflow.policy-lease",
    workflowGraphId: "workflow.policy-lease",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

test("policy lease panel reads canonical lease fields", () => {
  const panel = buildWorkflowRuntimePolicyLeasePanel([
    event("approval-required", 1, {
      receipt_refs: ["receipt-canonical"],
      policy_decision_refs: ["policy-canonical"],
      payload: {
        approval_id: "approval-canonical",
        approval_lease: {
          lease_id: "lease-canonical",
          policy_hash: "policy-hash-canonical",
          ttl_ms: 120_000,
          expires_at: "2026-06-07T00:10:00.000Z",
          expected_receipt_refs: ["receipt-expected-canonical"],
          authority_scope_requirements: ["scope:workspace.write"],
          revoke_endpoint: "/v1/threads/thread-test/approvals/approval-canonical/revoke",
        },
      },
    }),
  ], { now: "2026-06-07T00:00:00.000Z" });

  assert.equal(panel.pendingCount, 1);
  assert.equal(panel.rows[0]?.approvalId, "approval-canonical");
  assert.equal(panel.rows[0]?.leaseId, "lease-canonical");
  assert.equal(panel.rows[0]?.policyHash, "policy-hash-canonical");
  assert.equal(panel.rows[0]?.ttlMs, 120_000);
  assert.deepEqual(panel.rows[0]?.receiptRefs, ["receipt-canonical"]);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, ["policy-canonical"]);
  assert.deepEqual(panel.rows[0]?.expectedReceiptRefs, ["receipt-expected-canonical"]);
  assert.deepEqual(panel.rows[0]?.authorityScopeRequirements, ["scope:workspace.write"]);
});

test("policy lease panel reads canonical event identity fields", () => {
  const panel = buildWorkflowRuntimePolicyLeasePanel([
    event("approval-required-identity", 1, {
      approval_id: "approval-canonical-event",
      thread_id: "thread-canonical-event",
      turn_id: "turn-canonical-event",
      workflow_graph_id: "workflow-canonical-event",
      workflow_node_id: "workflow.policy-lease-canonical",
      payload: {
        approval_lease: {
          lease_id: "lease-canonical-event",
        },
      },
    }),
  ], { now: "2026-06-07T00:00:00.000Z" });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.approvalId, "approval-canonical-event");
  assert.equal(panel.rows[0]?.threadId, "thread-canonical-event");
  assert.equal(panel.rows[0]?.turnId, "turn-canonical-event");
  assert.equal(panel.rows[0]?.workflowGraphId, "workflow-canonical-event");
  assert.equal(panel.rows[0]?.workflowNodeId, "workflow.policy-lease-canonical");
});

test("policy lease panel ignores retired event identity aliases", () => {
  const panel = buildWorkflowRuntimePolicyLeasePanel([
    event("approval-required-retired-event-approval", 1, {
      approval_id: undefined,
      approvalId: "approval-retired-event",
      payload: {
        approval_lease: {
          lease_id: "lease-retired-event",
        },
      },
    }),
    event("approval-required-retired-event-identity", 2, {
      approval_id: "approval-canonical-event",
      thread_id: undefined,
      turn_id: undefined,
      workflow_graph_id: undefined,
      workflow_node_id: undefined,
      threadId: "thread-retired-event",
      turnId: "turn-retired-event",
      workflowGraphId: "workflow-retired-event",
      workflowNodeId: "workflow.policy-lease-retired",
      payload: {
        approval_lease: {
          lease_id: "lease-canonical-event",
        },
      },
    }),
  ], { now: "2026-06-07T00:00:00.000Z" });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.approvalId, "approval-canonical-event");
  assert.equal(panel.rows[0]?.threadId, null);
  assert.equal(panel.rows[0]?.turnId, null);
  assert.equal(panel.rows[0]?.workflowGraphId, null);
  assert.equal(panel.rows[0]?.workflowNodeId, null);
});

test("policy lease panel ignores retired payload and evidence aliases", () => {
  const panel = buildWorkflowRuntimePolicyLeasePanel([
    event("approval-required-retired", 1, {
      receiptRefs: ["receipt-retired"],
      policyDecisionRefs: ["policy-retired"],
      payload: {
        approvalId: "approval-retired",
        leaseId: "lease-retired",
        policyHash: "policy-hash-retired",
        ttlMs: 120_000,
        expiresAt: "2026-06-07T00:10:00.000Z",
        expectedReceiptRefs: ["receipt-expected-retired"],
        authorityScopeRequirements: ["scope:retired"],
        revokeEndpoint: "/retired/revoke",
        approvalLease: {
          leaseId: "lease-retired-nested",
          policyHash: "policy-hash-retired-nested",
          ttlMs: 180_000,
          expiresAt: "2026-06-07T00:15:00.000Z",
          expectedReceiptRefs: ["receipt-expected-retired-nested"],
          authorityScopeRequirements: ["scope:retired-nested"],
          revokeEndpoint: "/retired/nested/revoke",
        },
      },
    }),
  ], { now: "2026-06-07T00:00:00.000Z" });

  assert.equal(panel.pendingCount, 0);
  assert.equal(panel.rows.length, 0);
});
