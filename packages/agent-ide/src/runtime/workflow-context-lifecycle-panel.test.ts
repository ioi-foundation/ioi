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
    thread_id: "thread-test",
    threadId: "thread-test",
    turn_id: "turn-test",
    turnId: "turn-test",
    type: "runtime_context",
    eventKind: "runtime.context",
    sourceEventKind: "Runtime.Context",
    status: "completed",
    createdAt: `2026-06-07T00:00:0${seq}.000Z`,
    component_kind: "compaction_policy",
    componentKind: "compaction_policy",
    workflow_node_id: "workflow.context-lifecycle",
    workflowNodeId: "workflow.context-lifecycle",
    workflow_graph_id: "workflow.context-lifecycle",
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

test("context lifecycle panel reads canonical event identity fields", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("identity-canonical", 1, {
        component_kind: "context_budget",
        thread_id: "thread-canonical-event",
        turn_id: "turn-canonical-event",
        workflow_graph_id: "workflow-canonical-event",
        workflow_node_id: "workflow.identity-canonical",
        payload: {
          status: "ready",
          usage_summary: {
            total_tokens: 1024,
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "context_budget");
  assert.equal(panel.rows[0]?.threadId, "thread-canonical-event");
  assert.equal(panel.rows[0]?.turnId, "turn-canonical-event");
  assert.equal(panel.rows[0]?.workflowGraphId, "workflow-canonical-event");
  assert.equal(panel.rows[0]?.workflowNodeId, "workflow.identity-canonical");
});

test("context lifecycle panel ignores retired event identity aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("identity-component-kind-retired", 1, {
        component_kind: undefined,
        componentKind: "context_budget",
        payload: {
          status: "ready",
          usage_summary: {
            total_tokens: 1024,
          },
        },
      }),
      event("identity-retired", 2, {
        component_kind: "context_budget",
        thread_id: undefined,
        turn_id: undefined,
        workflow_graph_id: undefined,
        workflow_node_id: undefined,
        threadId: "thread-retired-identity",
        turnId: "turn-retired-identity",
        workflowGraphId: "workflow-retired-identity",
        workflowNodeId: "workflow.identity-retired",
        payload: {
          status: "ready",
          threadId: "payload-thread-retired-identity",
          turnId: "payload-turn-retired-identity",
          workflowGraphId: "payload-workflow-retired-identity",
          workflowNodeId: "payload.workflow.identity-retired",
          usage_summary: {
            total_tokens: 1024,
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.eventId, "identity-retired");
  assert.equal(panel.rows[0]?.threadId, null);
  assert.equal(panel.rows[0]?.turnId, null);
  assert.equal(panel.rows[0]?.workflowGraphId, null);
  assert.equal(panel.rows[0]?.workflowNodeId, null);
});

test("context lifecycle panel reads canonical context budget usage and threshold fields", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("budget-canonical", 1, {
        component_kind: "context_budget",
        payload: {
          summary: "Budget pressure",
          scope: "thread",
          status: "blocked",
          usage_summary: {
            total_tokens: 6144,
            estimated_cost_usd: 0.73,
            context_pressure: 0.88,
          },
          thresholds: {
            max_total_tokens: 6000,
            max_cost_usd: 0.7,
            max_context_pressure: 0.8,
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "context_budget");
  assert.equal(panel.rows[0]?.scope, "thread");
  assert.equal(panel.rows[0]?.budgetStatus, "blocked");
  assert.equal(panel.rows[0]?.totalTokens, 6144);
  assert.equal(panel.rows[0]?.estimatedCostUsd, 0.73);
  assert.equal(panel.rows[0]?.contextPressure, 0.88);
  assert.equal(panel.rows[0]?.maxTotalTokens, 6000);
  assert.equal(panel.rows[0]?.maxCostUsd, 0.7);
  assert.equal(panel.rows[0]?.maxContextPressure, 0.8);
});

test("context lifecycle panel ignores retired context budget usage and threshold aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("budget-retired", 1, {
        component_kind: "context_budget",
        payload: {
          summary: "Retired budget pressure",
          scope: "thread",
          status: "blocked",
          usageSummary: {
            totalTokens: 6144,
            estimatedCostUsd: 0.73,
            contextPressure: 0.88,
          },
          usageTelemetry: {
            totalTokens: 8192,
            estimatedCostUsd: 0.9,
            contextPressure: 0.95,
          },
          thresholds: {
            maxTotalTokens: 6000,
            maxCostUsd: 0.7,
            maxContextPressure: 0.8,
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "context_budget");
  assert.equal(panel.rows[0]?.totalTokens, null);
  assert.equal(panel.rows[0]?.estimatedCostUsd, null);
  assert.equal(panel.rows[0]?.contextPressure, null);
  assert.equal(panel.rows[0]?.maxTotalTokens, null);
  assert.equal(panel.rows[0]?.maxCostUsd, null);
  assert.equal(panel.rows[0]?.maxContextPressure, null);
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

test("context lifecycle panel reads canonical context compaction payload fields", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("compaction-canonical", 1, {
        component_kind: "context_compaction",
        payload: {
          reason: "pressure",
          scope: "thread",
          compacted_tokens: 4096,
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "context_compaction");
  assert.equal(panel.rows[0]?.summary, "pressure");
  assert.equal(panel.rows[0]?.scope, "thread");
  assert.equal(panel.rows[0]?.totalTokens, 4096);
  assert.equal(panel.rows[0]?.executeCompaction, true);
  assert.equal(panel.rows[0]?.compactionExecuted, true);
});

test("context lifecycle panel ignores retired context compaction payload aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("compaction-retired", 1, {
        component_kind: "context_compaction",
        payload: {
          reason: "pressure",
          scope: "thread",
          compactedTokens: 4096,
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "context_compaction");
  assert.equal(panel.rows[0]?.totalTokens, null);
});

test("context lifecycle panel reads canonical event evidence refs", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("budget-evidence-canonical", 1, {
        component_kind: "context_budget",
        receipt_refs: ["receipt-context-canonical"],
        policy_decision_refs: ["policy-context-canonical"],
        payload: {
          status: "ready",
          usage_summary: {
            total_tokens: 2048,
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.deepEqual(panel.rows[0]?.receiptRefs, ["receipt-context-canonical"]);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, ["policy-context-canonical"]);
  assert.deepEqual(panel.evidenceRefs, ["receipt-context-canonical"]);
  assert.equal(panel.missingReceiptCount, 0);
});

test("context lifecycle panel ignores retired event evidence aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [
      event("budget-evidence-retired", 1, {
        component_kind: "context_budget",
        receiptRefs: ["receipt-context-retired"],
        policyDecisionRefs: ["policy-context-retired"],
        payload: {
          status: "ready",
          usage_summary: {
            total_tokens: 2048,
          },
        },
      }),
    ],
  });

  assert.equal(panel.rows.length, 1);
  assert.deepEqual(panel.rows[0]?.receiptRefs, []);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(panel.evidenceRefs, []);
  assert.equal(panel.missingReceiptCount, 1);
});
