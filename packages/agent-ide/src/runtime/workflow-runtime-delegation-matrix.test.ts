import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowRuntimeDelegationMatrix } from "./workflow-runtime-delegation-matrix";

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
    threadId: "thread-test",
    turnId: "turn-test",
    type: "runtime_subagent_manager",
    eventKind: "runtime.subagent.manager",
    sourceEventKind: "Subagent.Manager",
    status: "completed",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    componentKind: "runtime_subagent_manager",
    workflowNodeId: "workflow.delegation",
    workflowGraphId: "workflow.delegation",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

test("delegation matrix reads canonical evidence refs", () => {
  const matrix = buildWorkflowRuntimeDelegationMatrix([
    event("delegation-canonical", 1, {
      receipt_refs: ["receipt-event-canonical"],
      policy_decision_refs: ["policy-event-canonical"],
      payload: {
        object: "ioi.runtime_subagent_manager_event",
        operation: "spawn",
        subagent_id: "subagent-canonical",
        child_thread_id: "thread-child",
        lifecycle_status: "completed",
        receipt_refs: ["receipt-payload-canonical"],
        source_receipt_refs: ["receipt-source-canonical"],
        policy_decision_refs: ["policy-payload-canonical"],
        source_policy_decision_refs: ["policy-source-canonical"],
      },
    }),
  ]);

  assert.equal(matrix.status, "ready");
  assert.deepEqual(matrix.rows[0]?.receiptRefs, [
    "receipt-event-canonical",
    "receipt-payload-canonical",
    "receipt-source-canonical",
  ]);
  assert.deepEqual(matrix.rows[0]?.policyDecisionRefs, [
    "policy-event-canonical",
    "policy-payload-canonical",
    "policy-source-canonical",
  ]);
});

test("delegation matrix ignores retired event evidence aliases", () => {
  const matrix = buildWorkflowRuntimeDelegationMatrix([
    event("delegation-retired", 1, {
      receiptRefs: ["receipt-event-retired"],
      policyDecisionRefs: ["policy-event-retired"],
      payload: {
        object: "ioi.runtime_subagent_manager_event",
        operation: "spawn",
        subagent_id: "subagent-retired",
        child_thread_id: "thread-child",
        lifecycle_status: "completed",
      },
    }),
  ]);

  assert.equal(matrix.status, "ready");
  assert.equal(matrix.rows.length, 1);
  assert.deepEqual(matrix.rows[0]?.receiptRefs, []);
  assert.deepEqual(matrix.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(matrix.receiptRefs, []);
  assert.deepEqual(matrix.policyDecisionRefs, []);
});
