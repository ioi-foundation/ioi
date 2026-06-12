import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeUsageEventHelpers } from "./runtime-usage-events.mjs";

function contextBudgetNumber(...values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

function helpers() {
  return createRuntimeUsageEventHelpers({
    contextBudgetNumber,
    eventStreamIdForThread: (threadId) => `stream:${threadId}`,
    normalizeArray,
    optionalString,
    safeId,
  });
}

const retiredUsagePayloadAliasKeys = [
  "schemaVersion",
  "eventKind",
  "workflowNodeId",
  "componentKind",
  "runId",
  "agentId",
  "threadId",
  "turnId",
  "routeId",
  "contextPressureSummary",
  "inputTokens",
  "outputTokens",
  "totalTokens",
  "estimatedCostUsd",
  "contextWindowTokens",
  "contextUsedTokens",
  "contextPressure",
  "contextPressureStatus",
];

const retiredUsageTelemetryInputAliasKeys = [
  "totalTokens",
  "inputTokens",
  "outputTokens",
  "estimatedCostUsd",
  "contextWindowTokens",
  "contextUsedTokens",
  "contextPressure",
  "contextPressureStatus",
  "routeId",
];

const retiredContextPressurePayloadAliasKeys = [
  "schemaVersion",
  "eventKind",
  "workflowNodeId",
  "componentKind",
  "runId",
  "threadId",
  "turnId",
  "usageTotalTokens",
  "usageCostEstimateUsd",
  "usageContextPressure",
  "usageContextPressureStatus",
];

const retiredContextPressureAlertAliasKeys = [
  "schemaVersion",
  "eventKind",
  "workflowNodeId",
  "componentKind",
  "alertId",
  "alertLevel",
  "pressureStatus",
  "recommendedAction",
  "sourceUsageDeltaRef",
  "usageTotalTokens",
  "usageCostEstimateUsd",
  "threadId",
  "turnId",
  "runId",
  "receiptRefs",
  "policyDecisionRefs",
];

const retiredContextPressureAlertActionAliasKeys = [
  "pressureStatus",
  "threadId",
  "turnId",
  "runId",
  "workflowNodeId",
];

function assertMissingKeys(record, keys) {
  for (const key of keys) {
    assert.equal(Object.hasOwn(record, key), false, `retired alias key ${key} must be absent`);
  }
}

test("runtime usage deltas emit canonical telemetry payloads and context pressure rows", () => {
  const runtime = helpers();
  const [prompt, completion] = runtime.runtimeUsageTelemetryDeltaPayloads(
    {
      total_tokens: 1000,
      input_tokens: 250,
      output_tokens: 750,
      estimated_cost_usd: 0.1234567,
      context_window_tokens: 1000,
      context_used_tokens: 900,
      provider: "local",
      model: "qwen",
      route_id: "route.local-first",
    },
    {
      runId: "run-one",
      agentId: "agent-one",
      threadId: "thread-one",
      turnId: "turn-one",
    },
  );

  assert.equal(prompt.stage, "prompt_prepared");
  assert.equal(prompt.context_pressure_status, "nominal");
  assert.equal(completion.stage, "completion_streamed");
  assert.equal(completion.context_pressure_status, "high");
  assert.equal(completion.total_tokens, 1000);
  assert.equal(completion.estimated_cost_usd, 0.123457);
  assertMissingKeys(completion, retiredUsagePayloadAliasKeys);

  const pressure = runtime.contextPressureDeltaPayload(completion);
  assert.equal(pressure.object, "ioi.runtime_context_pressure_delta");
  assert.equal(pressure.status, "blocked");
  assert.equal(pressure.summary, "Context pressure delta 2/2: high at 0.9.");
  assert.equal(pressure.usage_context_pressure_status, "high");
  assertMissingKeys(pressure, retiredContextPressurePayloadAliasKeys);

  const alert = runtime.contextPressureAlertPayload(completion);
  assert.equal(alert.object, "ioi.runtime_context_pressure_alert");
  assert.equal(alert.alert_level, "blocked");
  assert.equal(alert.recommended_action, "compact");
  assert.deepEqual(alert.receipt_refs, []);
  assert.deepEqual(alert.policy_decision_refs, []);
  assert.equal(alert.actions.some((action) => action.action === "stop" && action.executable), true);
  assertMissingKeys(alert, retiredContextPressureAlertAliasKeys);
  for (const action of alert.actions) {
    assertMissingKeys(action, retiredContextPressureAlertActionAliasKeys);
  }
});

test("runtime usage deltas ignore retired telemetry input aliases", () => {
  const runtime = helpers();
  const [prompt, completion] = runtime.runtimeUsageTelemetryDeltaPayloads(
    {
      totalTokens: 1000,
      inputTokens: 250,
      outputTokens: 750,
      estimatedCostUsd: 0.1234567,
      contextWindowTokens: 1000,
      contextUsedTokens: 900,
      contextPressure: 0.9,
      contextPressureStatus: "high",
      provider: "local",
      model: "qwen",
      routeId: "route.legacy",
    },
    {
      runId: "run-one",
      agentId: "agent-one",
      threadId: "thread-one",
      turnId: "turn-one",
    },
  );

  assert.equal(prompt.total_tokens, 1);
  assert.equal(prompt.context_pressure_status, "nominal");
  assert.equal(completion.total_tokens, 0);
  assert.equal(completion.estimated_cost_usd, 0);
  assert.equal(completion.context_window_tokens, 128000);
  assert.equal(completion.context_used_tokens, 0);
  assert.equal(completion.context_pressure, 0);
  assert.equal(completion.context_pressure_status, "nominal");
  assert.equal(completion.route_id, null);
  assertMissingKeys(completion, retiredUsageTelemetryInputAliasKeys);
  assertMissingKeys(completion, retiredUsagePayloadAliasKeys);
});

test("runtime bridge usage events are inserted after turn start and keep public event kinds", () => {
  const runtime = helpers();
  const events = runtime.insertRuntimeBridgeUsageDeltaEvents({
    threadId: "thread-one",
    agent: { id: "agent-one", cwd: "/workspace" },
    projection: {
      runId: "run-one",
      turnId: "turn-one",
      mode: "send",
      prompt: "hello",
      result: "done",
      created_at: "2026-06-03T00:00:00.000Z",
      updated_at: "2026-06-03T00:00:01.000Z",
      usage: {
        total_tokens: 1000,
        input_tokens: 200,
        output_tokens: 800,
        context_window_tokens: 1000,
        context_used_tokens: 900,
      },
      events: [
        { event_kind: "turn.started", item_id: "turn-started" },
        { event_kind: "turn.completed", item_id: "turn-completed" },
      ],
    },
  });

  assert.deepEqual(events.map((event) => event.event_kind), [
    "turn.started",
    "usage.delta",
    "context.pressure_delta",
    "usage.delta",
    "context.pressure_delta",
    "context.pressure_alert",
    "turn.completed",
  ]);
  assert.equal(events[1].payload_schema_version, "ioi.runtime.usage-delta.v1");
  assert.equal(events[1].created_at, "2026-06-03T00:00:01.000Z");
  assert.equal(events[3].payload.stage, "completion_streamed");
  assert.equal(events[5].status, "blocked");
  assert.deepEqual(events[5].receipt_refs, []);
  assert.deepEqual(events[5].policy_decision_refs, []);
});

test("runtime context-pressure alerts do not synthesize JS receipt or policy refs", () => {
  const runtime = helpers();
  const alert = runtime.contextPressureAlertPayload({
    run_id: "run-one",
    thread_id: "thread-one",
    turn_id: "turn-one",
    stage: "completion_streamed",
    delta_index: 2,
    delta_total: 2,
    total_tokens: 1000,
    estimated_cost_usd: 0.12,
    context_pressure: 0.9,
    context_pressure_status: "high",
  });

  assert.equal(alert.alert_id, "context_pressure_turn_run-one_completion_streamed");
  assert.equal(alert.recommended_action, "compact");
  assert.deepEqual(alert.receipt_refs, []);
  assert.deepEqual(alert.policy_decision_refs, []);
  assert.equal(JSON.stringify(alert).includes("receipt_context_pressure"), false);
  assert.equal(JSON.stringify(alert).includes("policy_context_pressure"), false);
});

test("runtime bridge usage events ignore retired projection timestamp aliases", () => {
  const runtime = helpers();
  const events = runtime.insertRuntimeBridgeUsageDeltaEvents({
    threadId: "thread-one",
    agent: { id: "agent-one", cwd: "/workspace" },
    projection: {
      runId: "run-one",
      turnId: "turn-one",
      mode: "send",
      prompt: "hello",
      result: "done",
      created_at: "2026-06-03T00:00:00.000Z",
      updated_at: "2026-06-03T00:00:01.000Z",
      createdAt: "1999-01-01T00:00:00.000Z",
      updatedAt: "1999-01-01T00:00:01.000Z",
      usage: {
        total_tokens: 1000,
        input_tokens: 200,
        output_tokens: 800,
        context_window_tokens: 1000,
        context_used_tokens: 900,
      },
      events: [{ event_kind: "turn.started", item_id: "turn-started" }],
    },
  });

  const usageEvents = events.filter((event) => event.event_kind !== "turn.started");
  assert.equal(usageEvents.length, 5);
  for (const event of usageEvents) {
    assert.equal(event.created_at, "2026-06-03T00:00:01.000Z");
    assert.notEqual(event.created_at, "1999-01-01T00:00:01.000Z");
    assert.equal(Object.hasOwn(event, "createdAt"), false);
  }
});
