import assert from "node:assert/strict";
import test from "node:test";

import {
  runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread,
  runtimeUsageTelemetryList,
  runtimeUsageTelemetrySummary,
} from "./usage-telemetry.mjs";

const retiredUsageTelemetryOutputAliasKeys = [
  "schemaVersion",
  "threadId",
  "turnId",
  "runId",
  "agentId",
  "routeId",
  "modelRouteId",
  "inputTokens",
  "outputTokens",
  "reasoningTokens",
  "cachedInputTokens",
  "toolResultTokens",
  "compactedTokens",
  "totalTokens",
  "estimatedCostMicros",
  "estimatedCostUsd",
  "contextWindowTokens",
  "contextUsedTokens",
  "contextPressure",
  "contextPressureStatus",
  "latencyMs",
  "sourceCounts",
  "sourceRefs",
  "generatedAt",
];

const retiredUsageTelemetrySummaryAliasKeys = [
  "totalTokens",
  "estimatedCostUsd",
  "contextPressure",
  "contextPressureStatus",
  "sourceCounts",
];

const retiredUsageTelemetryListAliasKeys = [
  "schemaVersion",
  "groupBy",
  "generatedAt",
];

const retiredUsageTelemetryInputAliasKeys = [
  "usageTelemetry",
  "runtimeUsage",
  "providerUsage",
  "modelRouteDecision",
  "modelRouteId",
  "routeId",
  "selectedModel",
  "providerId",
  "inputTokens",
  "outputTokens",
  "promptTokens",
  "completionTokens",
  "reasoningTokens",
  "cachedInputTokens",
  "toolResultTokens",
  "compactedTokens",
  "totalTokens",
  "estimatedCostUsd",
  "estimatedCostMicros",
  "costEstimateUsd",
  "contextWindowTokens",
  "modelContextWindowTokens",
  "maxContextTokens",
  "contextUsedTokens",
  "contextPressure",
  "contextPressureStatus",
  "latencyMs",
  "sourceCounts",
  "sourceRefs",
  "parentThreadId",
  "parentTurnId",
  "subagentId",
  "runId",
  "agentId",
  "threadId",
  "turnId",
];

function assertMissingKeys(record, keys) {
  for (const key of keys) {
    assert.equal(Object.hasOwn(record, key), false, `retired alias key ${key} must be absent`);
  }
}

test("runtime run usage telemetry emits canonical fields only", () => {
  const usage = runtimeUsageTelemetryForRun({
    threadId: "thread-one",
    agent: { id: "agent-one" },
    run: {
      id: "run-one",
      agent_id: "agent-one",
      turn_id: "turn-one",
      objective: "hello",
      result: "done",
      usage_telemetry: {
        input_tokens: 30,
        output_tokens: 70,
        total_tokens: 100,
        estimated_cost_usd: 0.0123456,
        context_window_tokens: 200,
        context_used_tokens: 160,
        latency_ms: 42,
        provider: "local",
        model: "qwen",
        route_id: "route.local-first",
      },
    },
  });

  assert.equal(usage.schema_version, "ioi.runtime.usage-telemetry.v1");
  assert.equal(usage.object, "ioi.runtime_usage_telemetry");
  assert.equal(usage.thread_id, "thread-one");
  assert.equal(usage.turn_id, "turn-one");
  assert.equal(usage.run_id, "run-one");
  assert.equal(usage.agent_id, "agent-one");
  assert.equal(usage.route_id, "route.local-first");
  assert.equal(usage.model_route_id, "route.local-first");
  assert.equal(usage.total_tokens, 100);
  assert.equal(usage.estimated_cost_usd, 0.012346);
  assert.equal(usage.context_pressure, 0.8);
  assert.equal(usage.context_pressure_status, "elevated");
  assert.equal(usage.latency_ms, 42);
  assert.deepEqual(usage.source_counts, { runs: 1, subagents: 0 });
  assert.deepEqual(usage.source_refs, ["run-one"]);
  assertMissingKeys(usage, retiredUsageTelemetryOutputAliasKeys);

  const summary = runtimeUsageTelemetrySummary(usage);
  assert.equal(summary.total_tokens, 100);
  assert.equal(summary.estimated_cost_usd, 0.012346);
  assert.equal(summary.context_pressure_status, "elevated");
  assert.deepEqual(summary.source_counts, { runs: 1, subagents: 0 });
  assertMissingKeys(summary, retiredUsageTelemetrySummaryAliasKeys);
});

test("runtime run usage telemetry ignores retired input aliases", () => {
  const usage = runtimeUsageTelemetryForRun({
    run: {
      runId: "legacy-run",
      agentId: "legacy-agent",
      threadId: "legacy-thread",
      turnId: "legacy-turn",
      usageTelemetry: {
        inputTokens: 30,
        outputTokens: 70,
        totalTokens: 100,
        estimatedCostUsd: 0.0123456,
        contextWindowTokens: 200,
        contextUsedTokens: 160,
        latencyMs: 42,
        provider: "legacy-provider",
        model: "legacy-model",
        routeId: "route.legacy",
      },
      providerUsage: {
        totalTokens: 500,
      },
      modelRouteDecision: {
        routeId: "route.legacy-decision",
        selectedModel: "legacy-route-model",
        providerId: "legacy-route-provider",
        contextWindowTokens: 99,
      },
      trace: {
        usageTelemetry: {
          totalTokens: 700,
        },
        runtimeUsage: {
          totalTokens: 800,
        },
        providerUsage: {
          totalTokens: 900,
        },
        modelRouteDecision: {
          routeId: "route.legacy-trace",
        },
      },
    },
  });

  assert.equal(usage.thread_id, null);
  assert.equal(usage.turn_id, null);
  assert.equal(usage.run_id, null);
  assert.equal(usage.agent_id, null);
  assert.equal(usage.provider, "local");
  assert.equal(usage.model, "unknown");
  assert.equal(usage.route_id, null);
  assert.equal(usage.total_tokens, 0);
  assert.equal(usage.estimated_cost_usd, 0);
  assert.equal(usage.context_window_tokens, 128000);
  assert.equal(usage.context_used_tokens, 0);
  assert.equal(usage.context_pressure, 0);
  assert.equal(usage.latency_ms, 0);
  assert.equal(usage.estimated, true);
  assert.deepEqual(usage.source_refs, []);
  assertMissingKeys(usage, retiredUsageTelemetryInputAliasKeys);
  assertMissingKeys(usage, retiredUsageTelemetryOutputAliasKeys);
});

test("runtime thread usage telemetry aggregate emits canonical fields only", () => {
  const usage = runtimeUsageTelemetryForThread({
    threadId: "thread-one",
    agent: { id: "agent-one" },
    runs: [
      {
        id: "run-one",
        agentId: "agent-one",
        usage_telemetry: {
          input_tokens: 10,
          output_tokens: 15,
          total_tokens: 25,
          estimated_cost_usd: 0.000025,
          context_window_tokens: 100,
          context_used_tokens: 25,
        },
      },
    ],
    subagents: [
      {
        subagent_id: "subagent-one",
        run_id: "subagent-run",
        parent_thread_id: "thread-one",
        usage_telemetry: {
          total_tokens: 40,
          input_tokens: 12,
          output_tokens: 28,
          cumulative_cost_estimate_usd: 0.00004,
        },
      },
    ],
  });

  assert.equal(usage.scope, "thread");
  assert.equal(usage.thread_id, "thread-one");
  assert.equal(usage.agent_id, "agent-one");
  assert.equal(usage.total_tokens, 65);
  assert.equal(usage.input_tokens, 22);
  assert.equal(usage.output_tokens, 43);
  assert.equal(usage.estimated_cost_usd, 0.000065);
  assert.deepEqual(usage.source_counts, { runs: 1, subagents: 1 });
  assert.deepEqual(usage.source_refs, ["run-one", "subagent-one", "subagent-run"]);
  assertMissingKeys(usage, retiredUsageTelemetryOutputAliasKeys);
});

test("runtime thread usage telemetry ignores retired aggregate and subagent aliases", () => {
  const usage = runtimeUsageTelemetryForThread({
    thread: { threadId: "legacy-thread", agentId: "legacy-agent" },
    runs: [
      {
        runId: "legacy-run",
        agentId: "legacy-agent",
        threadId: "legacy-thread",
        usageTelemetry: {
          totalTokens: 25,
          estimatedCostUsd: 0.000025,
          contextWindowTokens: 100,
          contextUsedTokens: 25,
        },
      },
    ],
    subagents: [
      {
        subagentId: "legacy-subagent",
        runId: "legacy-subagent-run",
        parentThreadId: "legacy-thread",
        usageTelemetry: {
          cumulativeTotalTokens: 40,
          cumulativeCostEstimateUsd: 0.00004,
        },
      },
    ],
  });

  assert.equal(usage.thread_id, null);
  assert.equal(usage.agent_id, null);
  assert.equal(usage.total_tokens, 0);
  assert.equal(usage.estimated_cost_usd, 0);
  assert.deepEqual(usage.source_counts, { runs: 1, subagents: 0 });
  assert.deepEqual(usage.source_refs, []);
  assertMissingKeys(usage, retiredUsageTelemetryInputAliasKeys);
  assertMissingKeys(usage, retiredUsageTelemetryOutputAliasKeys);

  const summary = runtimeUsageTelemetrySummary({
    totalTokens: 100,
    estimatedCostUsd: 0.5,
    contextPressure: 0.9,
    contextPressureStatus: "high",
    sourceCounts: { runs: 1, subagents: 1 },
  });

  assert.equal(summary.total_tokens, 0);
  assert.equal(summary.estimated_cost_usd, 0);
  assert.equal(summary.context_pressure, 0);
  assert.equal(summary.context_pressure_status, "nominal");
  assert.equal(summary.source_counts, null);
  assertMissingKeys(summary, retiredUsageTelemetrySummaryAliasKeys);
});

test("runtime usage telemetry list envelope emits canonical fields only", () => {
  const list = runtimeUsageTelemetryList({
    groupBy: "run",
    runs: [
      {
        id: "run-one",
        usage_telemetry: {
          total_tokens: 9,
          input_tokens: 4,
          output_tokens: 5,
        },
      },
    ],
  });

  assert.equal(list.schema_version, "ioi.runtime.usage-telemetry.v1");
  assert.equal(list.object, "ioi.runtime_usage_list");
  assert.equal(list.group_by, "run");
  assert.equal(list.count, 1);
  assert.equal(list.usage[0]?.total_tokens, 9);
  assertMissingKeys(list, retiredUsageTelemetryListAliasKeys);
  assertMissingKeys(list.usage[0], retiredUsageTelemetryOutputAliasKeys);
});
