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
    threadId: "thread-test",
    turnId: "turn-test",
    type: "tool_completed",
    eventKind: "tool.completed",
    sourceEventKind: "Tool.Completed",
    status: "completed",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    componentKind: "tool_call",
    workflowNodeId: "workflow.goal-verification",
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
