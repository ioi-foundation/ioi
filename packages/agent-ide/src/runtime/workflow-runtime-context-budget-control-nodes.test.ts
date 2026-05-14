import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND,
  RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SOURCE,
  RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND,
  RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION,
  createRuntimeContextBudgetControlRequestFromWorkflowNode,
} from "./workflow-runtime-context-budget-control-nodes";

test("runtime_context_budget workflow node builds a daemon policy request", () => {
  const node = makeWorkflowNode(
    "context-budget",
    "runtime_context_budget",
    "Context budget",
    100,
    120,
  );
  const request = createRuntimeContextBudgetControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-context-budget-1",
      runtimeUsageMeter: {
        total_tokens: 1800,
        estimated_cost_usd: 0.04,
        context_pressure: 0.72,
      },
    },
    { workflowGraphId: "workflow.react-flow.context-budget-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_context_budget");
  assert.equal(request.nodeId, "context-budget");
  assert.equal(request.scope, "thread");
  assert.equal(request.threadId, "thread-context-budget-1");
  assert.equal(request.endpoint, "/v1/threads/thread-context-budget-1/context-budget");
  assert.equal(request.method, "POST");
  assert.equal(request.body.source, RUNTIME_CONTEXT_BUDGET_SOURCE);
  assert.equal(request.body.actor, "operator");
  assert.equal(request.body.eventKind, RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND);
  assert.equal(
    request.body.payloadSchemaVersion,
    RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION,
  );
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.context-budget-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID);
  assert.equal(request.body.mode, "simulate");
  assert.equal(request.body.thresholds.maxTotalTokens, 4096);
  assert.equal(request.body.thresholds.maxCostUsd, 0.25);
  assert.equal(request.body.thresholds.maxContextPressure, 0.85);
  assert.equal(request.body.thresholds.warnAtRatio, 0.8);
  assert.deepEqual(request.body.usageTelemetry, {
    total_tokens: 1800,
    estimated_cost_usd: 0.04,
    context_pressure: 0.72,
  });
});

test("runtime_context_budget helper supports run scope and configurable thresholds", () => {
  const node = makeWorkflowNode(
    "context-budget-run",
    "runtime_context_budget",
    "Context budget",
    100,
    120,
    {
      runtimeContextBudgetEndpoint: "/runtime/runs/{runId}/context-budget",
      runtimeContextBudgetRunIdField: "runtime.runId",
      runtimeContextBudgetScope: "run",
      runtimeContextBudgetMode: "block",
      runtimeContextBudgetMaxTotalTokens: 1200,
      runtimeContextBudgetMaxCostUsd: "0.05",
      runtimeContextBudgetMaxContextPressure: "0.4",
      runtimeContextBudgetWarnAtRatio: 0.7,
      runtimeContextBudgetWorkflowNodeId: "runtime.context-budget.run",
      runtimeContextBudgetActor: "workflow-author",
    },
  );
  const request = createRuntimeContextBudgetControlRequestFromWorkflowNode(node, {
    runtime: { runId: "run with space" },
  });

  assert.equal(request.scope, "run");
  assert.equal(request.runId, "run with space");
  assert.equal(request.threadId, null);
  assert.equal(request.endpoint, "/runtime/runs/run%20with%20space/context-budget");
  assert.equal(request.body.mode, "block");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.thresholds.maxTotalTokens, 1200);
  assert.equal(request.body.thresholds.maxCostUsd, 0.05);
  assert.equal(request.body.thresholds.maxContextPressure, 0.4);
  assert.equal(request.body.thresholds.warnAtRatio, 0.7);
  assert.equal(request.body.workflowNodeId, "runtime.context-budget.run");
});

test("runtime_context_budget helper builds workflow-scope policy requests", () => {
  const node = makeWorkflowNode(
    "context-budget-workflow",
    "runtime_context_budget",
    "Context budget",
    100,
    120,
    {
      runtimeContextBudgetScope: "workflow",
      runtimeContextBudgetMode: "warn",
      runtimeContextBudgetUsageField: "usage",
    },
  );
  const request = createRuntimeContextBudgetControlRequestFromWorkflowNode(
    node,
    { usage: { totalTokens: 4000, contextPressure: 0.8 } },
    { workflowGraphId: "workflow.react-flow.context-budget-proof" },
  );

  assert.equal(request.scope, "workflow");
  assert.equal(request.endpoint, "/v1/context-budget");
  assert.equal(request.body.mode, "warn");
  assert.deepEqual(request.body.usageTelemetry, {
    totalTokens: 4000,
    contextPressure: 0.8,
  });
});

test("runtime_context_budget helper normalizes runtime telemetry summary input", () => {
  const node = makeWorkflowNode(
    "context-budget-summary",
    "runtime_context_budget",
    "Context budget",
    100,
    120,
    {
      runtimeContextBudgetUsageField: "runtimeTelemetrySummary",
      runtimeContextBudgetMode: "block",
      runtimeContextBudgetMaxTotalTokens: 499,
      runtimeContextBudgetMaxCostUsd: 0.004,
      runtimeContextBudgetMaxContextPressure: 0.6,
      runtimeContextBudgetWorkflowNodeId: "runtime.context-budget.summary-gate",
      runtimeContextBudgetActor: "workflow-author",
    },
  );
  const request = createRuntimeContextBudgetControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-summary-budget",
      runtimeTelemetrySummary: {
        schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
        status: "elevated",
        sourceKinds: ["runtime_usage_events", "tui_subagent_rows"],
        threadIds: ["thread-summary-budget"],
        turnIds: ["turn-summary-budget"],
        workflowGraphIds: ["workflow.react-flow.context-budget-proof"],
        workflowNodeIds: ["runtime.usage-telemetry", "runtime.context-budget"],
        eventIds: ["event-usage", "event-context"],
        latestSeq: 2,
        latestCursor: "events_thread:2",
        latestEventId: "event-context",
        runtimeEventCount: 2,
        usageEventCount: 1,
        contextPressureEventCount: 1,
        contextPressureAlertCount: 0,
        tuiRowCount: 2,
        usageRowCount: 1,
        costRowCount: 1,
        contextRowCount: 1,
        subagentRowCount: 1,
        totalTokens: 500,
        inputTokens: 320,
        outputTokens: 180,
        costEstimateUsd: 0.0042,
        contextPressure: 0.66,
        contextPressureStatus: "elevated",
        runCount: 1,
        subagentCount: 1,
        receiptRefs: ["receipt-summary"],
        policyDecisionRefs: ["policy-summary"],
      },
    },
    { workflowGraphId: "workflow.react-flow.context-budget-proof" },
  );

  assert.equal(request.body.mode, "block");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.workflowNodeId, "runtime.context-budget.summary-gate");
  assert.deepEqual(request.body.usageTelemetry, {
    schema_version: "ioi.workflow.runtime-telemetry-summary.v1",
    schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
    object: "ioi.workflow_runtime_telemetry_summary_usage",
    scope: "thread",
    thread_id: "thread-summary-budget",
    threadId: "thread-summary-budget",
    turn_id: "turn-summary-budget",
    turnId: "turn-summary-budget",
    workflow_graph_id: "workflow.react-flow.context-budget-proof",
    workflowGraphId: "workflow.react-flow.context-budget-proof",
    total_tokens: 500,
    totalTokens: 500,
    input_tokens: 320,
    inputTokens: 320,
    output_tokens: 180,
    outputTokens: 180,
    estimated_cost_usd: 0.0042,
    estimatedCostUsd: 0.0042,
    cost_estimate_usd: 0.0042,
    costEstimateUsd: 0.0042,
    context_pressure: 0.66,
    contextPressure: 0.66,
    context_pressure_status: "elevated",
    contextPressureStatus: "elevated",
    source_counts: { runs: 1, subagents: 1 },
    sourceCounts: { runs: 1, subagents: 1 },
    source_refs: ["event-usage", "event-context"],
    sourceRefs: ["event-usage", "event-context"],
    receipt_refs: ["receipt-summary"],
    receiptRefs: ["receipt-summary"],
    policy_decision_refs: ["policy-summary"],
    policyDecisionRefs: ["policy-summary"],
    runtime_telemetry_summary_schema_version:
      "ioi.workflow.runtime-telemetry-summary.v1",
    runtimeTelemetrySummarySchemaVersion:
      "ioi.workflow.runtime-telemetry-summary.v1",
  });
  assert.equal(request.body.usage_telemetry, request.body.usageTelemetry);
});
