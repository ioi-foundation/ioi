import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowWorkerContributionTrace } from "./workflow-worker-contribution-trace";

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
    workflow_node_id: "workflow.worker-contribution",
    workflowNodeId: "workflow.worker-contribution",
    workflow_graph_id: "workflow.worker-contribution",
    workflowGraphId: "workflow.worker-contribution",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

const subagent = {
  subagent_id: "subagent-canonical",
  child_thread_id: "thread-child",
  parent_thread_id: "thread-parent",
  merge_policy: "manual_review",
  output_contract_status: "satisfied",
};

test("worker contribution trace reads canonical evidence refs", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-canonical", 1, {
        tool_call_id: "tool-call-canonical",
        receipt_refs: ["receipt-event-canonical"],
        artifact_refs: ["artifact-event-canonical"],
        rollback_refs: ["rollback-event-canonical"],
        policy_decision_refs: ["policy-event-canonical"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-canonical",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-canonical",
        receipt_refs: ["receipt-contribution-canonical"],
        policy_decision_refs: ["policy-contribution-canonical"],
      },
    ],
  });

  assert.equal(trace.status, "ready");
  assert.equal(trace.rows[0]?.status, "ready");
  assert.deepEqual(trace.rows[0]?.receiptRefs, [
    "receipt-event-canonical",
    "receipt-contribution-canonical",
  ]);
  assert.deepEqual(trace.rows[0]?.policyDecisionRefs, [
    "policy-event-canonical",
    "policy-contribution-canonical",
  ]);
  assert.deepEqual(trace.rows[0]?.rollbackRefs, ["rollback-event-canonical"]);
  assert.ok(trace.evidenceRefs.includes("artifact-event-canonical"));
});

test("worker contribution trace reads canonical request and worker fields", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-request-canonical", 1, {
        tool_call_id: "tool-call-request-canonical",
        receipt_refs: ["receipt-event-request-canonical"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-request-canonical",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-request-canonical",
        file_path: "canonical-request.txt",
        hunk_index: 2,
        hunk_header: "@@ canonical",
        edit_count: 3,
      },
    ],
  });

  assert.equal(trace.status, "ready");
  assert.equal(trace.rows[0]?.contributionId, "contribution-request-canonical");
  assert.equal(trace.rows[0]?.subagentId, "subagent-canonical");
  assert.equal(trace.rows[0]?.toolCallId, "tool-call-request-canonical");
  assert.equal(trace.rows[0]?.childThreadId, "thread-child");
  assert.equal(trace.rows[0]?.parentThreadId, "thread-parent");
  assert.equal(trace.rows[0]?.mergePolicy, "manual_review");
  assert.equal(trace.rows[0]?.outputContractStatus, "satisfied");
  assert.equal(trace.rows[0]?.filePath, "canonical-request.txt");
  assert.equal(trace.rows[0]?.hunkIndex, 2);
  assert.equal(trace.rows[0]?.hunkHeader, "@@ canonical");
  assert.equal(trace.rows[0]?.editCount, 3);
  assert.ok(trace.evidenceRefs.includes("thread-child"));
});

test("worker contribution trace reads canonical event identity fields", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-identity", 1, {
        tool_call_id: "tool-call-canonical",
        workflow_graph_id: "workflow-canonical-event",
        workflow_node_id: "workflow.worker-contribution-canonical",
        receipt_refs: ["receipt-event-canonical"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-canonical",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-canonical",
      },
    ],
  });

  assert.equal(trace.status, "ready");
  assert.equal(trace.rows[0]?.workflowGraphId, "workflow-canonical-event");
  assert.equal(trace.rows[0]?.workflowNodeId, "workflow.worker-contribution-canonical");
});

test("worker contribution trace ignores retired event identity aliases", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-retired-identity", 1, {
        tool_call_id: undefined,
        toolCallId: "tool-call-retired",
        workflow_graph_id: undefined,
        workflow_node_id: undefined,
        workflowGraphId: "workflow-retired-event",
        workflowNodeId: "workflow.worker-contribution-retired",
        receipt_refs: ["receipt-event-retired"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-retired",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-retired",
      },
    ],
  });

  assert.equal(trace.status, "blocked");
  assert.equal(trace.rows[0]?.status, "needs_event");

  const byEventId = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-retired-workflow", 1, {
        workflow_graph_id: undefined,
        workflow_node_id: undefined,
        workflowGraphId: "workflow-retired-event",
        workflowNodeId: "workflow.worker-contribution-retired",
        receipt_refs: ["receipt-event-retired"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-retired-workflow",
        subagent_id: "subagent-canonical",
        event_id: "tool-retired-workflow",
      },
    ],
  });

  assert.equal(byEventId.rows[0]?.status, "ready");
  assert.equal(byEventId.rows[0]?.workflowGraphId, null);
  assert.equal(byEventId.rows[0]?.workflowNodeId, null);
});

test("worker contribution trace ignores retired evidence aliases", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-retired", 1, {
        tool_call_id: "tool-call-retired",
        receiptRefs: ["receipt-event-retired"],
        artifactRefs: ["artifact-event-retired"],
        rollbackRefs: ["rollback-event-retired"],
        policyDecisionRefs: ["policy-event-retired"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contributionId: "contribution-retired",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-retired",
        receiptRefs: ["receipt-contribution-retired"],
        policyDecisionRefs: ["policy-contribution-retired"],
      },
    ],
  });

  assert.equal(trace.status, "blocked");
  assert.equal(trace.rows[0]?.status, "needs_receipt");
  assert.deepEqual(trace.rows[0]?.receiptRefs, []);
  assert.deepEqual(trace.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(trace.rows[0]?.rollbackRefs, []);
  assert.ok(!trace.evidenceRefs.includes("artifact-event-retired"));
});

test("worker contribution trace ignores retired request aliases", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-retired-request", 1, {
        tool_call_id: "tool-call-retired-request",
        receipt_refs: ["receipt-event-retired-request"],
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contributionId: "contribution-retired-request",
        subagentId: "subagent-canonical",
        toolCallId: "tool-call-retired-request",
        eventId: "tool-retired-request",
        filePath: "retired-file-path.txt",
        hunkFile: "retired-hunk-file.txt",
        hunkIndex: 4,
        hunkHeader: "@@ retired",
        editCount: 6,
      },
    ],
  });

  assert.equal(trace.status, "blocked");
  assert.equal(trace.rows[0]?.status, "needs_worker");
  assert.equal(trace.rows[0]?.contributionId, "contribution-0");
  assert.equal(trace.rows[0]?.subagentId, null);
  assert.equal(trace.rows[0]?.toolCallId, null);
  assert.equal(trace.rows[0]?.eventId, null);
  assert.equal(trace.rows[0]?.filePath, null);
  assert.equal(trace.rows[0]?.hunkIndex, null);
  assert.equal(trace.rows[0]?.hunkHeader, null);
  assert.equal(trace.rows[0]?.editCount, null);
});

test("worker contribution trace ignores retired worker object aliases", () => {
  const trace = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-retired-worker", 1, {
        tool_call_id: "tool-call-retired-worker",
        receipt_refs: ["receipt-event-retired-worker"],
      }),
    ],
    subagents: [
      {
        subagent_id: "subagent-canonical",
        childThreadId: "thread-child-retired",
        parentThreadId: "thread-parent-retired",
        mergePolicy: "manual_review",
        outputContractStatus: "satisfied",
      },
    ],
    contributions: [
      {
        contribution_id: "contribution-retired-worker",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-retired-worker",
      },
    ],
  });

  assert.equal(trace.status, "ready");
  assert.equal(trace.rows[0]?.status, "ready");
  assert.equal(trace.rows[0]?.childThreadId, null);
  assert.equal(trace.rows[0]?.parentThreadId, null);
  assert.equal(trace.rows[0]?.mergePolicy, null);
  assert.equal(trace.rows[0]?.outputContractStatus, null);
  assert.ok(!trace.evidenceRefs.includes("thread-child-retired"));
});

test("worker contribution trace ignores retired result payload aliases", () => {
  const retired = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-retired-result", 1, {
        tool_call_id: "tool-call-retired-result",
        receipt_refs: ["receipt-event-retired-result"],
        payload: {
          result: {
            workspaceSnapshotId: "snapshot-retired-result",
            editCount: 4,
            changedFiles: [{ path: "retired-result.txt" }],
            result: {
              editCount: 5,
              changedFiles: [{ path: "retired-nested-result.txt" }],
            },
          },
        },
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-retired-result",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-retired-result",
      },
    ],
  });

  assert.equal(retired.rows[0]?.status, "ready");
  assert.equal(retired.rows[0]?.snapshotId, null);
  assert.equal(retired.rows[0]?.filePath, null);
  assert.equal(retired.rows[0]?.editCount, null);
  assert.ok(!retired.evidenceRefs.includes("snapshot-retired-result"));

  const canonical = buildWorkflowWorkerContributionTrace({
    events: [
      event("tool-canonical-result", 1, {
        tool_call_id: "tool-call-canonical-result",
        receipt_refs: ["receipt-event-canonical-result"],
        payload: {
          result: {
            workspace_snapshot_id: "snapshot-canonical-result",
            edit_count: 4,
            changed_files: [{ path: "canonical-result.txt" }],
            result: {
              edit_count: 5,
              changed_files: [{ path: "canonical-nested-result.txt" }],
            },
          },
        },
      }),
    ],
    subagents: [subagent],
    contributions: [
      {
        contribution_id: "contribution-canonical-result",
        subagent_id: "subagent-canonical",
        tool_call_id: "tool-call-canonical-result",
      },
    ],
  });

  assert.equal(canonical.rows[0]?.status, "ready");
  assert.equal(canonical.rows[0]?.snapshotId, "snapshot-canonical-result");
  assert.equal(canonical.rows[0]?.filePath, "canonical-nested-result.txt");
  assert.equal(canonical.rows[0]?.editCount, 5);
  assert.ok(canonical.evidenceRefs.includes("snapshot-canonical-result"));
});
