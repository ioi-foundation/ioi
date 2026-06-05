import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  workflowRuntimeEventId,
  workflowRuntimeEventKind,
} from "./workflow-runtime-event-identity";

function projectedEvent(
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id: "projected-event-id",
    cursor: "events_thread:1",
    seq: 1,
    threadId: "thread",
    turnId: null,
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "Runtime.Step",
    status: "completed",
    componentKind: "runtime",
    workflowNodeId: null,
    workflowGraphId: null,
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

test("workflow runtime event identity accepts canonical raw runtime event fields", () => {
  assert.equal(
    workflowRuntimeEventId({
      event_id: "canonical-event-id",
      event_kind: "tool.completed",
    }),
    "canonical-event-id",
  );
  assert.equal(
    workflowRuntimeEventKind({
      event_id: "canonical-event-id",
      event_kind: "tool.completed",
    }),
    "tool.completed",
  );
});

test("workflow runtime event identity ignores raw retired aliases", () => {
  assert.equal(
    workflowRuntimeEventId({
      id: "legacy-event-id",
      event: "tool.completed",
    }),
    null,
  );
  assert.equal(
    workflowRuntimeEventKind({
      id: "legacy-event-id",
      event: "tool.completed",
    }),
    null,
  );
});

test("workflow runtime event identity preserves projected IDE event identity", () => {
  assert.equal(workflowRuntimeEventId(projectedEvent()), "projected-event-id");
  assert.equal(workflowRuntimeEventKind(projectedEvent()), "runtime.step");
});

test("workflow runtime event identity lets canonical raw ids override projected ids", () => {
  assert.equal(
    workflowRuntimeEventId(
      projectedEvent({
        id: "projected-event-id",
        event_id: "canonical-event-id",
      } as Partial<WorkflowRuntimeThreadEventLike>),
    ),
    "canonical-event-id",
  );
});
