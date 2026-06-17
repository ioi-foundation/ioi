import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowRuntimeGoalVerificationPanel } from "./workflow-runtime-goal-verification-panel";

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
    workflow_node_id: "workflow.goal-verification",
    workflowNodeId: "workflow.goal-verification",
    workflow_graph_id: "workflow.goal-verification",
    workflowGraphId: "workflow.goal-verification",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

test("goal verification panel reads canonical diagnostic and evidence fields", () => {
  const panel = buildWorkflowRuntimeGoalVerificationPanel([
    event("diagnostics", 1, {
      receipt_refs: ["receipt-canonical"],
      policy_decision_refs: ["policy-canonical"],
      rollback_refs: ["rollback-canonical"],
      payload: {
        tool_name: "lsp.diagnostics",
        result: {
          diagnostic_status: "clean",
          diagnostic_count: 0,
        },
      },
    }),
    event("completion", 2, {
      eventKind: "turn.completed",
      sourceEventKind: "Turn.Completed",
      payload: {
        stop_reason: "goal_satisfied",
      },
    }),
  ]);

  assert.equal(panel.status, "passed");
  assert.equal(panel.rows.length, 2);
  assert.equal(panel.latestDiagnosticStatus, "clean");
  assert.equal(panel.rows[0]?.toolName, "lsp.diagnostics");
  assert.equal(panel.rows[0]?.diagnosticStatus, "clean");
  assert.equal(panel.rows[0]?.diagnosticCount, 0);
  assert.deepEqual(panel.rows[0]?.receiptRefs, ["receipt-canonical"]);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, ["policy-canonical"]);
  assert.deepEqual(panel.rows[0]?.rollbackRefs, ["rollback-canonical"]);
  assert.equal(panel.rows[1]?.stopReason, "goal_satisfied");
});

test("goal verification panel reads canonical event identity fields", () => {
  const panel = buildWorkflowRuntimeGoalVerificationPanel([
    event("diagnostics-identity", 1, {
      thread_id: "thread-canonical-event",
      turn_id: "turn-canonical-event",
      workflow_graph_id: "workflow-canonical-event",
      workflow_node_id: "workflow.goal-verification-canonical",
      payload: {
        tool_name: "lsp.diagnostics",
        result: {
          diagnostic_status: "clean",
          diagnostic_count: 0,
        },
      },
    }),
  ]);

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.threadId, "thread-canonical-event");
  assert.equal(panel.rows[0]?.turnId, "turn-canonical-event");
  assert.equal(panel.rows[0]?.workflowGraphId, "workflow-canonical-event");
  assert.equal(panel.rows[0]?.workflowNodeId, "workflow.goal-verification-canonical");
});

test("goal verification panel ignores retired event identity aliases", () => {
  const panel = buildWorkflowRuntimeGoalVerificationPanel([
    event("gate-retired-component-kind", 1, {
      eventKind: "policy.blocked",
      sourceEventKind: "Policy.Blocked",
      component_kind: undefined,
      componentKind: "lsp_diagnostics_gate",
      payload: {
        diagnostic_status: "dirty",
        diagnostic_count: 2,
      },
    }),
    event("diagnostics-retired-tool-name", 2, {
      toolName: "lsp.diagnostics",
      payload: {
        result: {
          diagnostic_status: "clean",
          diagnostic_count: 0,
        },
      },
    }),
    event("diagnostics-retired-identity", 3, {
      thread_id: undefined,
      turn_id: undefined,
      workflow_graph_id: undefined,
      workflow_node_id: undefined,
      threadId: "thread-retired-event",
      turnId: "turn-retired-event",
      workflowGraphId: "workflow-retired-event",
      workflowNodeId: "workflow.goal-verification-retired",
      payload: {
        tool_name: "lsp.diagnostics",
        result: {
          diagnostic_status: "clean",
          diagnostic_count: 0,
        },
      },
    }),
  ]);

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.eventId, "diagnostics-retired-identity");
  assert.equal(panel.rows[0]?.threadId, null);
  assert.equal(panel.rows[0]?.turnId, null);
  assert.equal(panel.rows[0]?.workflowGraphId, null);
  assert.equal(panel.rows[0]?.workflowNodeId, null);
});

test("goal verification panel ignores retired payload and evidence aliases", () => {
  const panel = buildWorkflowRuntimeGoalVerificationPanel([
    event("diagnostics-retired", 1, {
      receiptRefs: ["receipt-retired"],
      policyDecisionRefs: ["policy-retired"],
      rollbackRefs: ["rollback-retired"],
      payload: {
        toolName: "lsp.diagnostics",
        result: {
          diagnosticStatus: "clean",
          diagnosticCount: 0,
        },
        receiptRefs: ["payload-receipt-retired"],
        policyDecisionRefs: ["payload-policy-retired"],
        rollbackRefs: ["payload-rollback-retired"],
      },
    }),
    event("completion-retired", 2, {
      eventKind: "turn.completed",
      sourceEventKind: "Turn.Completed",
      payload: {
        stopReason: "goal_satisfied",
      },
    }),
  ]);

  assert.equal(panel.status, "failed");
  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "completion");
  assert.equal(panel.rows[0]?.stopReason, null);
  assert.deepEqual(panel.rows[0]?.receiptRefs, []);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(panel.rows[0]?.rollbackRefs, []);
});
