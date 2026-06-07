import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowRuntimeReceiptFirstToolTimeline } from "./workflow-runtime-receipt-first-tool-timeline";

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
    type: "tool_completed",
    eventKind: "tool.completed",
    sourceEventKind: "Tool.Completed",
    status: "completed",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    component_kind: "tool_call",
    componentKind: "tool_call",
    workflow_node_id: "workflow.receipt-first",
    workflowNodeId: "workflow.receipt-first",
    workflow_graph_id: "workflow.receipt-first",
    workflowGraphId: "workflow.receipt-first",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

test("receipt-first tool timeline reads canonical receipt and artifact fields", () => {
  const timeline = buildWorkflowRuntimeReceiptFirstToolTimeline([
    event("tool-canonical", 1, {
      receipt_refs: ["receipt-canonical"],
      artifact_refs: ["artifact-canonical"],
      payload: {
        tool_name: "file.apply_patch",
        tool_call_id: "call-canonical",
        result: {
          receipt_refs: ["receipt-result-canonical"],
          artifact_refs: ["artifact-result-canonical"],
          output_hash: "sha256:canonical",
          output_bytes: 512,
          stdout: "raw output is demoted behind refs",
        },
      },
    }),
  ]);

  assert.equal(timeline.status, "ready");
  assert.equal(timeline.rows.length, 1);
  assert.equal(timeline.rows[0]?.toolName, "file.apply_patch");
  assert.equal(timeline.rows[0]?.toolCallId, "call-canonical");
  assert.equal(timeline.rows[0]?.primaryReceiptRef, "receipt-canonical");
  assert.deepEqual(timeline.rows[0]?.receiptRefs, [
    "receipt-canonical",
    "receipt-result-canonical",
  ]);
  assert.deepEqual(timeline.rows[0]?.artifactRefs, [
    "artifact-canonical",
    "artifact-result-canonical",
  ]);
  assert.equal(timeline.rows[0]?.outputHash, "sha256:canonical");
  assert.equal(timeline.rows[0]?.outputBytes, 512);
  assert.equal(timeline.rows[0]?.rawOutputDemoted, true);
  assert.equal(timeline.rows[0]?.rawOutputIncluded, false);
});

test("receipt-first tool timeline reads canonical event identity fields", () => {
  const timeline = buildWorkflowRuntimeReceiptFirstToolTimeline([
    event("tool-identity", 1, {
      thread_id: "thread-canonical-event",
      turn_id: "turn-canonical-event",
      workflow_graph_id: "workflow-canonical-event",
      workflow_node_id: "workflow.receipt-first-canonical",
      tool_name: "file.apply_patch",
      tool_call_id: "call-canonical-event",
      receipt_refs: ["receipt-canonical-event"],
      payload: {},
    }),
  ]);

  assert.equal(timeline.rows.length, 1);
  assert.equal(timeline.rows[0]?.threadId, "thread-canonical-event");
  assert.equal(timeline.rows[0]?.turnId, "turn-canonical-event");
  assert.equal(timeline.rows[0]?.workflowGraphId, "workflow-canonical-event");
  assert.equal(timeline.rows[0]?.workflowNodeId, "workflow.receipt-first-canonical");
  assert.equal(timeline.rows[0]?.toolName, "file.apply_patch");
  assert.equal(timeline.rows[0]?.toolCallId, "call-canonical-event");
});

test("receipt-first tool timeline ignores retired event identity aliases", () => {
  const timeline = buildWorkflowRuntimeReceiptFirstToolTimeline([
    event("tool-retired-event-tool", 1, {
      toolName: "file.apply_patch",
      toolCallId: "call-retired-event",
      receipt_refs: ["receipt-retired-event"],
      payload: {},
    }),
    event("tool-retired-event-identity", 2, {
      thread_id: undefined,
      turn_id: undefined,
      workflow_graph_id: undefined,
      workflow_node_id: undefined,
      threadId: "thread-retired-event",
      turnId: "turn-retired-event",
      workflowGraphId: "workflow-retired-event",
      workflowNodeId: "workflow.receipt-first-retired",
      tool_name: "file.apply_patch",
      tool_call_id: undefined,
      toolCallId: "call-retired-event-identity",
      receipt_refs: ["receipt-canonical-event"],
      payload: {},
    }),
  ]);

  assert.equal(timeline.rows.length, 1);
  assert.equal(timeline.rows[0]?.eventId, "tool-retired-event-identity");
  assert.equal(timeline.rows[0]?.threadId, null);
  assert.equal(timeline.rows[0]?.turnId, null);
  assert.equal(timeline.rows[0]?.workflowGraphId, null);
  assert.equal(timeline.rows[0]?.workflowNodeId, null);
  assert.equal(timeline.rows[0]?.toolCallId, null);
});

test("receipt-first tool timeline ignores retired payload, result, and evidence aliases", () => {
  const timeline = buildWorkflowRuntimeReceiptFirstToolTimeline([
    event("tool-retired", 1, {
      receiptRefs: ["receipt-retired"],
      artifactRefs: ["artifact-retired"],
      payload: {
        toolName: "file.apply_patch",
        toolCallId: "call-retired",
        receiptRefs: ["payload-receipt-retired"],
        artifactRefs: ["payload-artifact-retired"],
        result: {
          receiptRefs: ["result-receipt-retired"],
          artifactRefs: ["result-artifact-retired"],
          outputHash: "sha256:retired",
          outputBytes: 1024,
          stdout: "retired raw output",
        },
      },
    }),
  ]);

  assert.equal(timeline.status, "empty");
  assert.equal(timeline.rows.length, 0);
  assert.deepEqual(timeline.receiptRefs, []);
  assert.deepEqual(timeline.artifactRefs, []);
  assert.equal(timeline.rawOutputDemotedCount, 0);
});
