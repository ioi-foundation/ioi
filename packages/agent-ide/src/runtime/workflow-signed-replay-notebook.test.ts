import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowSignedReplayNotebook } from "./workflow-signed-replay-notebook";

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
    type: "tool_completed",
    eventKind: "tool.completed",
    sourceEventKind: "Tool.Completed",
    status: "completed",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    componentKind: "tool_call",
    workflowNodeId: "workflow.signed-replay",
    workflowGraphId: "workflow.signed-replay",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

test("signed replay notebook reads canonical evidence refs", () => {
  const notebook = buildWorkflowSignedReplayNotebook({
    events: [
      event("snapshot-event", 1, {
        eventKind: "workspace.snapshot.created",
        componentKind: "workspace_snapshot",
        receipt_refs: ["receipt-event-canonical"],
        artifact_refs: ["artifact-event-canonical"],
        rollback_refs: ["snapshot-event-canonical"],
        policy_decision_refs: ["policy-event-canonical"],
        payload: {
          summary: "Snapshot created",
        },
      }),
    ],
    snapshots: [
      {
        snapshot_id: "snapshot-list-canonical",
        receipt_refs: ["receipt-snapshot-canonical"],
        artifact_refs: ["artifact-snapshot-canonical"],
        policy_decision_refs: ["policy-snapshot-canonical"],
      },
    ],
    restoreResults: [
      {
        schema_version: "ioi.workspace-restore-preview.v1",
        snapshot_id: "snapshot-list-canonical",
        preview_status: "ready",
        receipt_refs: ["receipt-result-canonical"],
        artifact_refs: ["artifact-result-canonical"],
        rollback_refs: ["rollback-result-canonical"],
        policy_decision_refs: ["policy-result-canonical"],
      },
    ],
  });

  assert.equal(notebook.status, "blocked");
  assert.equal(notebook.schema_version, "ioi.workflow.signed-replay-notebook.v1");
  assert.equal(Object.prototype.hasOwnProperty.call(notebook, "schemaVersion"), false);
  assert.ok(notebook.evidence_refs.includes("receipt-event-canonical"));
  assert.ok(notebook.evidence_refs.includes("artifact-event-canonical"));
  assert.ok(notebook.evidence_refs.includes("snapshot-event-canonical"));
  assert.ok(notebook.evidence_refs.includes("receipt-snapshot-canonical"));
  assert.ok(notebook.evidence_refs.includes("artifact-snapshot-canonical"));
  assert.ok(notebook.evidence_refs.includes("receipt-result-canonical"));
  assert.ok(notebook.evidence_refs.includes("artifact-result-canonical"));
  assert.ok(notebook.evidence_refs.includes("rollback-result-canonical"));
  for (const cell of notebook.cells) {
    assert.equal(Object.prototype.hasOwnProperty.call(cell, "cellKind"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(cell, "receiptRefs"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(cell, "artifactRefs"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(cell, "rollbackRefs"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(cell, "policyDecisionRefs"), false);
  }
});

test("signed replay notebook ignores retired evidence aliases", () => {
  const notebook = buildWorkflowSignedReplayNotebook({
    events: [
      event("snapshot-retired", 1, {
        eventKind: "workspace.snapshot.created",
        componentKind: "workspace_snapshot",
        receiptRefs: ["receipt-event-retired"],
        artifactRefs: ["artifact-event-retired"],
        rollbackRefs: ["snapshot-event-retired"],
        policyDecisionRefs: ["policy-event-retired"],
        payload: {
          snapshot_id: "snapshot-payload-canonical",
        },
      }),
    ],
    snapshots: [
      {
        snapshot_id: "snapshot-list-retired",
        receiptRefs: ["receipt-snapshot-retired"],
        artifactRefs: ["artifact-snapshot-retired"],
        policyDecisionRefs: ["policy-snapshot-retired"],
      },
    ],
    restoreResults: [
      {
        schema_version: "ioi.workspace-restore-preview.v1",
        snapshot_id: "snapshot-list-retired",
        preview_status: "ready",
        receiptRefs: ["receipt-result-retired"],
        artifactRefs: ["artifact-result-retired"],
        rollbackRefs: ["rollback-result-retired"],
        policyDecisionRefs: ["policy-result-retired"],
      },
    ],
  });

  assert.equal(notebook.status, "blocked");
  assert.equal(notebook.receipt_backed_cell_count, 0);
  assert.deepEqual(notebook.evidence_refs, ["snapshot-list-retired"]);
  assert.equal(notebook.cells.find((cell) => cell.event_id === "snapshot-retired")?.rollback_refs.length, 0);
  assert.equal(notebook.cells.find((cell) => cell.snapshot_id === "snapshot-list-retired")?.receipt_refs.length, 0);
  assert.equal(notebook.cells.find((cell) => cell.cell_kind === "restore_preview")?.artifact_refs.length, 0);
});
