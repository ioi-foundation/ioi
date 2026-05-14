import assert from "node:assert/strict";
import test from "node:test";
import { projectRuntimeTuiControlStateToWorkflowProjection } from "./workflow-runtime-event-projection";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  workflowRuntimeTelemetrySummaryFromProjection,
  workflowRuntimeTelemetrySummaryToUsageTelemetry,
} from "./workflow-runtime-telemetry-summary";

function runtimeThreadEvent(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:${seq}`,
    seq,
    threadId: "thread",
    turnId: "turn-a",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: `2026-05-14T00:00:0${seq}.000Z`,
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId: "workflow",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

test("workflow runtime telemetry summary merges usage, context, TUI, and subagent rows", () => {
  const runtimeEvents = [
    runtimeThreadEvent("usage-1", 1, {
      type: "usage_delta",
      eventKind: "usage.delta",
      sourceEventKind: "RuntimeUsageTelemetry.Delta",
      componentKind: "usage_telemetry",
      workflowNodeId: "runtime.usage-telemetry",
      payloadSchemaVersion: "ioi.runtime.usage-delta.v1",
      payload: {
        total_tokens: 120,
        input_tokens: 70,
        output_tokens: 50,
        estimated_cost_usd: 0.00012,
        context_pressure: 0.45,
        context_pressure_status: "nominal",
      },
    }),
    runtimeThreadEvent("context-2", 2, {
      type: "context_pressure_delta",
      eventKind: "context.pressure_delta",
      sourceEventKind: "RuntimeContextPressure.Delta",
      componentKind: "context_pressure",
      workflowNodeId: "runtime.context-budget",
      payloadSchemaVersion: "ioi.runtime.context-pressure-delta.v1",
      payload: {
        usage_total_tokens: 240,
        usage_cost_estimate_usd: 0.00024,
        usage_context_pressure: 0.72,
        usage_context_pressure_status: "elevated",
      },
    }),
  ];
  const tuiProjection = projectRuntimeTuiControlStateToWorkflowProjection({
    thread_id: "thread",
    workflow_graph_id: "workflow",
    last_cursor: "events_thread:2",
    last_event_id: "context-2",
    usage_status: {
      total_tokens: 320,
      input_tokens: 180,
      output_tokens: 140,
      estimated_cost_usd: 0.00032,
      context_pressure: 0.72,
      context_pressure_status: "elevated",
      source_counts: { runs: 1, subagents: 1 },
      workflow_node_id: "runtime.usage-meter",
    },
    cost_rows: [
      {
        estimated_cost_usd: 0.00032,
        total_tokens: 320,
        workflow_node_id: "runtime.cost-meter",
      },
    ],
    context_rows: [
      {
        row_kind: "context_budget",
        status: "warning",
        usage_total_tokens: 320,
        usage_cost_estimate_usd: 0.00032,
        usage_context_pressure: 0.72,
        usage_context_pressure_status: "elevated",
        workflow_node_id: "runtime.context-budget",
      },
    ],
    subagent_rows: [
      {
        subagent_id: "delegate-a",
        role: "usage-auditor",
        status: "completed",
        subagent_token_estimate: 90,
        subagent_cost_estimate_usd: 0.00009,
        subagent_run_id: "run_child",
        workflow_node_id: "runtime.subagent.spawn.usage-auditor",
      },
    ],
  });

  const summary = workflowRuntimeTelemetrySummaryFromProjection({
    runtimeThreadEvents: runtimeEvents,
    tuiControlStateProjection: tuiProjection,
  });

  assert.equal(
    summary.schemaVersion,
    "ioi.workflow.runtime-telemetry-summary.v1",
  );
  assert.equal(summary.status, "elevated");
  assert.equal(summary.totalTokens, 320);
  assert.equal(summary.inputTokens, 180);
  assert.equal(summary.outputTokens, 140);
  assert.equal(summary.costEstimateUsd, 0.00032);
  assert.equal(summary.contextPressure, 0.72);
  assert.equal(summary.contextPressureStatus, "elevated");
  assert.equal(summary.runCount, 1);
  assert.equal(summary.subagentCount, 1);
  assert.equal(summary.usageEventCount, 1);
  assert.equal(summary.contextPressureEventCount, 1);
  assert.equal(summary.usageRowCount, 1);
  assert.equal(summary.costRowCount, 1);
  assert.equal(summary.contextRowCount, 1);
  assert.equal(summary.subagentRowCount, 1);
  assert.ok(summary.sourceKinds.includes("runtime_usage_events"));
  assert.ok(summary.sourceKinds.includes("tui_subagent_rows"));
  assert.ok(summary.workflowNodeIds.includes("runtime.usage-meter"));
  assert.ok(summary.workflowNodeIds.includes("runtime.context-budget"));
});

test("workflow runtime telemetry summary marks blocked context pressure", () => {
  const summary = workflowRuntimeTelemetrySummaryFromProjection({
    runtimeThreadEvents: [
      runtimeThreadEvent("alert-1", 1, {
        type: "context_pressure_alert",
        eventKind: "context.pressure_alert",
        sourceEventKind: "RuntimeContextPressure.Alert",
        status: "blocked",
        componentKind: "context_pressure_alert",
        workflowNodeId: "runtime.context-pressure-alert",
        payload: {
          usage_total_tokens: 900,
          pressure: 0.93,
          pressure_status: "high",
        },
        receiptRefs: ["receipt_context_pressure_high"],
        policyDecisionRefs: ["policy_context_pressure_compact"],
      }),
    ],
  });

  assert.equal(summary.status, "blocked");
  assert.equal(summary.totalTokens, 900);
  assert.equal(summary.contextPressure, 0.93);
  assert.equal(summary.contextPressureStatus, "high");
  assert.deepEqual(summary.receiptRefs, ["receipt_context_pressure_high"]);
  assert.deepEqual(summary.policyDecisionRefs, ["policy_context_pressure_compact"]);
});

test("workflow runtime telemetry summary converts to daemon budget usage telemetry", () => {
  const summary = workflowRuntimeTelemetrySummaryFromProjection({
    runtimeThreadEvents: [
      runtimeThreadEvent("usage-1", 1, {
        type: "usage_delta",
        eventKind: "usage.delta",
        sourceEventKind: "RuntimeUsageTelemetry.Delta",
        componentKind: "usage_telemetry",
        payload: {
          total_tokens: 500,
          input_tokens: 300,
          output_tokens: 200,
          estimated_cost_usd: 0.0042,
          context_pressure: 0.66,
          context_pressure_status: "elevated",
          usage_run_count: 1,
          usage_subagent_count: 1,
        },
        receiptRefs: ["receipt_usage"],
        policyDecisionRefs: ["policy_usage"],
      }),
    ],
  });

  const usageTelemetry = workflowRuntimeTelemetrySummaryToUsageTelemetry(summary);

  assert.ok(usageTelemetry);
  assert.equal(usageTelemetry.object, "ioi.workflow_runtime_telemetry_summary_usage");
  assert.equal(usageTelemetry.scope, "thread");
  assert.equal(usageTelemetry.thread_id, "thread");
  assert.equal(usageTelemetry.total_tokens, 500);
  assert.equal(usageTelemetry.totalTokens, 500);
  assert.equal(usageTelemetry.input_tokens, 300);
  assert.equal(usageTelemetry.output_tokens, 200);
  assert.equal(usageTelemetry.estimated_cost_usd, 0.0042);
  assert.equal(usageTelemetry.estimatedCostUsd, 0.0042);
  assert.equal(usageTelemetry.costEstimateUsd, 0.0042);
  assert.equal(usageTelemetry.context_pressure, 0.66);
  assert.equal(usageTelemetry.contextPressureStatus, "elevated");
  assert.deepEqual(usageTelemetry.source_counts, { runs: 1, subagents: 1 });
  assert.deepEqual(usageTelemetry.source_refs, ["usage-1"]);
  assert.deepEqual(usageTelemetry.receipt_refs, ["receipt_usage"]);
  assert.deepEqual(usageTelemetry.policy_decision_refs, ["policy_usage"]);
  assert.equal(workflowRuntimeTelemetrySummaryToUsageTelemetry({}), null);
});
