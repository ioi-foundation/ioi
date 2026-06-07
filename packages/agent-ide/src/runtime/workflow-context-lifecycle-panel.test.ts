import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowContextLifecyclePanel } from "./workflow-context-lifecycle-panel";

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
    type: "runtime_context",
    eventKind: "runtime.context",
    sourceEventKind: "Runtime.Context",
    status: "completed",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    componentKind: "compaction_policy",
    workflowNodeId: "workflow.context-lifecycle",
    workflowGraphId: "workflow.context-lifecycle",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  } as WorkflowRuntimeThreadEventLike;
}

test("context lifecycle panel reads canonical usage snapshot identity and evidence", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [],
    usageTelemetry: {
      thread_id: "thread-canonical",
      turn_id: "turn-canonical",
      workflow_graph_id: "workflow-canonical",
      workflow_node_id: "workflow.usage-canonical",
      usage_meter_scope: "thread",
      total_tokens: 2048,
      estimated_cost_usd: 0.42,
      context_pressure: 0.62,
      receipt_refs: ["receipt-canonical"],
      policy_decision_refs: ["policy-canonical"],
    },
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "usage_snapshot");
  assert.equal(panel.rows[0]?.threadId, "thread-canonical");
  assert.equal(panel.rows[0]?.turnId, "turn-canonical");
  assert.equal(panel.rows[0]?.workflowGraphId, "workflow-canonical");
  assert.equal(panel.rows[0]?.workflowNodeId, "workflow.usage-canonical");
  assert.equal(panel.rows[0]?.scope, "thread");
  assert.equal(panel.rows[0]?.totalTokens, 2048);
  assert.equal(panel.rows[0]?.estimatedCostUsd, 0.42);
  assert.equal(panel.rows[0]?.contextPressure, 0.62);
  assert.deepEqual(panel.rows[0]?.receiptRefs, ["receipt-canonical"]);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, ["policy-canonical"]);
  assert.deepEqual(panel.evidenceRefs, ["receipt-canonical"]);
});

test("context lifecycle panel ignores retired usage snapshot aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [],
    usageTelemetry: {
      threadId: "thread-retired",
      turnId: "turn-retired",
      workflowGraphId: "workflow-retired",
      workflowNodeId: "workflow.usage-retired",
      usageMeterScope: "thread-retired",
      total_tokens: 4096,
      estimated_cost_usd: 0.84,
      context_pressure: 0.81,
      receiptRefs: ["receipt-retired"],
      policyDecisionRefs: ["policy-retired"],
    },
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "usage_snapshot");
  assert.equal(panel.rows[0]?.threadId, null);
  assert.equal(panel.rows[0]?.turnId, null);
  assert.equal(panel.rows[0]?.workflowGraphId, null);
  assert.equal(panel.rows[0]?.workflowNodeId, "runtime.usage-meter");
  assert.equal(panel.rows[0]?.scope, null);
  assert.equal(panel.rows[0]?.totalTokens, 4096);
  assert.deepEqual(panel.rows[0]?.receiptRefs, []);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(panel.evidenceRefs, []);
});

test("context lifecycle panel reads canonical compaction policy payload fields", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("policy-canonical", 1, {
        payload: {
          summary: "Compaction approved",
          action: "compact",
          compact_scope: "thread",
          budget_status: "blocked",
          approval_required: true,
          approval_satisfied: true,
          execute_compaction: true,
          compaction_executed: true,
          compaction_event_id: "event-compaction-canonical",
          compact_reason: "pressure",
          context_budget: {
            usage_summary: {
              total_tokens: 8192,
              estimated_cost_usd: 1.25,
              context_pressure: 0.91,
            },
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "compaction_policy");
  assert.equal(panel.rows[0]?.scope, "thread");
  assert.equal(panel.rows[0]?.budgetStatus, "blocked");
  assert.equal(panel.rows[0]?.approvalRequired, true);
  assert.equal(panel.rows[0]?.approvalSatisfied, true);
  assert.equal(panel.rows[0]?.executeCompaction, true);
  assert.equal(panel.rows[0]?.compactionExecuted, true);
  assert.equal(panel.rows[0]?.compactionEventId, "event-compaction-canonical");
  assert.equal(panel.rows[0]?.compactReason, "pressure");
  assert.equal(panel.rows[0]?.totalTokens, 8192);
});

test("context lifecycle panel ignores retired compaction policy payload aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("policy-retired", 1, {
        payload: {
          summary: "Retired compaction payload",
          action: "compact",
          compactScope: "thread-retired",
          budgetStatus: "blocked-retired",
          approvalRequired: true,
          approvalSatisfied: true,
          executeCompaction: true,
          compactionExecuted: true,
          compactionEventId: "event-compaction-retired",
          compactReason: "pressure-retired",
          contextBudget: {
            usageSummary: {
              total_tokens: 16384,
              estimated_cost_usd: 2.5,
              context_pressure: 0.99,
            },
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "compaction_policy");
  assert.equal(panel.rows[0]?.scope, null);
  assert.equal(panel.rows[0]?.budgetStatus, null);
  assert.equal(panel.rows[0]?.approvalRequired, null);
  assert.equal(panel.rows[0]?.approvalSatisfied, null);
  assert.equal(panel.rows[0]?.executeCompaction, null);
  assert.equal(panel.rows[0]?.compactionExecuted, null);
  assert.equal(panel.rows[0]?.compactionEventId, null);
  assert.equal(panel.rows[0]?.compactReason, null);
  assert.equal(panel.rows[0]?.totalTokens, null);
});
