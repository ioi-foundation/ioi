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

test("runtime usage deltas preserve telemetry aliases and context pressure rows", () => {
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
  assert.equal(completion.totalTokens, 1000);
  assert.equal(completion.estimated_cost_usd, 0.123457);

  const pressure = runtime.contextPressureDeltaPayload(completion);
  assert.equal(pressure.object, "ioi.runtime_context_pressure_delta");
  assert.equal(pressure.status, "blocked");
  assert.equal(pressure.usage_context_pressure_status, "high");

  const alert = runtime.contextPressureAlertPayload(completion);
  assert.equal(alert.object, "ioi.runtime_context_pressure_alert");
  assert.equal(alert.alert_level, "blocked");
  assert.equal(alert.recommended_action, "compact");
  assert.deepEqual(alert.policy_decision_refs, [
    "policy_context_pressure_turn_run-one_completion_streamed_compact",
  ]);
  assert.equal(alert.actions.some((action) => action.action === "stop" && action.executable), true);
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
      createdAt: "2026-06-03T00:00:00.000Z",
      updatedAt: "2026-06-03T00:00:01.000Z",
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
  assert.equal(events[3].payload.stage, "completion_streamed");
  assert.equal(events[5].status, "blocked");
  assert.equal(events[5].receipt_refs[0], "receipt_context_pressure_turn_run-one_completion_streamed");
});
