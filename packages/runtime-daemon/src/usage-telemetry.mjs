export const RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION = "ioi.runtime.usage-telemetry.v1";

const DEFAULT_CONTEXT_WINDOW_TOKENS = 128000;
const FALLBACK_COST_USD_PER_TOKEN = 0.000001;

export function runtimeUsageTelemetryForRun({ run = {}, agent = null, threadId = null } = {}) {
  const generatedAt = new Date().toISOString();
  const explicit = firstObject(
    run.usage_telemetry,
    run.usage,
    run.trace?.usage_telemetry,
    run.trace?.usage,
  );
  const providerUsage = normalizeProviderUsage(explicit);
  const route = firstObject(
    run.model_route_decision,
    run.trace?.model_route_decision,
    agent?.model_route_decision,
    explicit?.model_route_decision,
  );
  const promptText = run.objective ?? firstConversationContent(run.conversation, "user") ?? "";
  const resultText = run.result ?? firstConversationContent(run.conversation, "assistant") ?? "";
  const inputTokens =
    positiveInteger(
      providerUsage.input_tokens ??
        providerUsage.prompt_tokens,
    ) ?? estimatedTokenCount(promptText);
  const outputTokens =
    positiveInteger(
      providerUsage.output_tokens ??
        providerUsage.completion_tokens,
    ) ?? estimatedTokenCount(resultText);
  const reasoningTokens = positiveInteger(providerUsage.reasoning_tokens) ?? 0;
  const cachedInputTokens =
    positiveInteger(providerUsage.cached_input_tokens) ?? 0;
  const toolResultTokens =
    positiveInteger(providerUsage.tool_result_tokens) ?? 0;
  const compactedTokens =
    positiveInteger(providerUsage.compacted_tokens) ?? 0;
  const explicitTotal =
    positiveInteger(providerUsage.total_tokens) ??
    positiveInteger(explicit?.total_tokens);
  const totalTokens =
    explicitTotal ?? inputTokens + outputTokens + reasoningTokens + toolResultTokens;
  const estimatedCostUsd = costEstimateUsd({
    explicit,
    providerUsage,
    route,
    totalTokens,
  });
  const estimatedCostMicros =
    positiveInteger(providerUsage.estimated_cost_micros) ??
    Math.round(estimatedCostUsd * 1_000_000);
  const contextWindowTokens =
    positiveInteger(
      explicit?.context_window_tokens ??
        providerUsage.context_window_tokens ??
        route?.context_window_tokens ??
        route?.model_context_window_tokens ??
        route?.max_context_tokens,
    ) ?? DEFAULT_CONTEXT_WINDOW_TOKENS;
  const contextUsedTokens =
    positiveInteger(explicit?.context_used_tokens) ??
    Math.max(0, totalTokens - cachedInputTokens);
  const contextPressure = contextWindowTokens > 0
    ? roundRatio(contextUsedTokens / contextWindowTokens)
    : 0;
  const status = contextPressureStatus(contextPressure);
  const model =
    stringValue(
      providerUsage.model ??
        explicit?.model ??
        route?.selected_model ??
        agent?.model_id ??
        agent?.requested_model_id,
    ) ?? "unknown";
  const provider =
    stringValue(providerUsage.provider ?? explicit?.provider ?? route?.provider_id) ??
    "local";
  const routeId =
    stringValue(
      explicit?.route_id ??
        route?.route_id ??
        agent?.model_route_id,
    ) ?? null;
  const record = {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_telemetry",
    scope: "run",
    thread_id: threadId ?? run.thread_id ?? (run.agent_id ? `thread_${run.agent_id}` : null),
    turn_id: run.turn_id ?? (run.id ? `turn_${run.id}` : null),
    run_id: run.id ?? run.run_id ?? null,
    agent_id: run.agent_id ?? agent?.id ?? null,
    provider,
    model,
    route_id: routeId,
    model_route_id: routeId,
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    reasoning_tokens: reasoningTokens,
    cached_input_tokens: cachedInputTokens,
    tool_result_tokens: toolResultTokens,
    compacted_tokens: compactedTokens,
    total_tokens: totalTokens,
    estimated_cost_micros: estimatedCostMicros,
    estimated_cost_usd: roundUsd(estimatedCostUsd),
    currency: stringValue(explicit?.currency ?? providerUsage.currency) ?? "USD",
    context_window_tokens: contextWindowTokens,
    context_used_tokens: contextUsedTokens,
    context_pressure: contextPressure,
    context_pressure_status: status,
    latency_ms: positiveInteger(providerUsage.latency_ms) ?? 0,
    estimated: !explicit || Object.keys(providerUsage).length === 0,
    source_counts: { runs: 1, subagents: 0 },
    source_refs: [run.id ?? run.run_id].filter(Boolean),
    generated_at: generatedAt,
  };
  return record;
}

export function runtimeUsageTelemetryForThread({
  thread = null,
  threadId = null,
  agent = null,
  runs = [],
  subagents = [],
} = {}) {
  const resolvedThreadId = threadId ?? thread?.thread_id ?? null;
  const runRecords = normalizeArray(runs).map((run) =>
    runtimeUsageTelemetryForRun({ run, agent, threadId: resolvedThreadId }),
  );
  const subagentRecords = normalizeArray(subagents)
    .map((record) => usageTelemetryFromSubagent(record))
    .filter(Boolean);
  const records = [...runRecords, ...subagentRecords];
  return aggregateUsageRecords({
    records,
    scope: "thread",
    threadId: resolvedThreadId,
    agentId: agent?.id ?? thread?.agent_id ?? null,
    source_counts: { runs: runRecords.length, subagents: subagentRecords.length },
  });
}

export function runtimeUsageTelemetryList({ runs = [], subagents = [], groupBy = "run" } = {}) {
  const grouping = stringValue(groupBy) ?? "run";
  if (grouping === "thread") {
    const groups = new Map();
    for (const run of normalizeArray(runs)) {
      const threadId = run.thread_id ?? (run.agent_id ? `thread_${run.agent_id}` : "thread_unknown");
      const entry = groups.get(threadId) ?? { threadId, runs: [], subagents: [] };
      entry.runs.push(run);
      groups.set(threadId, entry);
    }
    for (const subagent of normalizeArray(subagents)) {
      const threadId = subagent.parent_thread_id ?? subagent.thread_id ?? "thread_unknown";
      const entry = groups.get(threadId) ?? { threadId, runs: [], subagents: [] };
      entry.subagents.push(subagent);
      groups.set(threadId, entry);
    }
    return usageListEnvelope({
      group_by: "thread",
      usage: [...groups.values()].map((group) =>
        runtimeUsageTelemetryForThread({
          threadId: group.threadId,
          runs: group.runs,
          subagents: group.subagents,
        }),
      ),
    });
  }
  return usageListEnvelope({
    group_by: "run",
    usage: normalizeArray(runs).map((run) => runtimeUsageTelemetryForRun({ run })),
  });
}

export function runtimeUsageTelemetrySummary(record = {}) {
  const totalTokens = positiveInteger(record.total_tokens) ?? 0;
  const costUsd =
    numberValue(
      record.estimated_cost_usd ??
        record.cost_estimate_usd,
    ) ?? 0;
  const contextPressure = numberValue(record.context_pressure) ?? 0;
  const status =
    stringValue(record.context_pressure_status) ??
    contextPressureStatus(contextPressure);
  return {
    total_tokens: totalTokens,
    estimated_cost_usd: roundUsd(costUsd),
    context_pressure: roundRatio(contextPressure),
    context_pressure_status: status,
    source_counts: record.source_counts ?? null,
  };
}

function aggregateUsageRecords({
  records = [],
  scope,
  threadId = null,
  agentId = null,
  source_counts = null,
} = {}) {
  const generatedAt = new Date().toISOString();
  const totals = normalizeArray(records).reduce(
    (accumulator, record) => {
      accumulator.inputTokens += positiveInteger(record.input_tokens) ?? 0;
      accumulator.outputTokens += positiveInteger(record.output_tokens) ?? 0;
      accumulator.reasoningTokens += positiveInteger(record.reasoning_tokens) ?? 0;
      accumulator.cachedInputTokens += positiveInteger(record.cached_input_tokens) ?? 0;
      accumulator.toolResultTokens += positiveInteger(record.tool_result_tokens) ?? 0;
      accumulator.compactedTokens += positiveInteger(record.compacted_tokens) ?? 0;
      accumulator.totalTokens += positiveInteger(record.total_tokens) ?? 0;
      accumulator.estimatedCostUsd += numberValue(record.estimated_cost_usd) ?? 0;
      accumulator.estimatedCostMicros += positiveInteger(record.estimated_cost_micros) ?? 0;
      accumulator.contextWindowTokens = Math.max(
        accumulator.contextWindowTokens,
        positiveInteger(record.context_window_tokens) ?? 0,
      );
      accumulator.contextUsedTokens += positiveInteger(record.context_used_tokens) ?? 0;
      accumulator.latencyMs += positiveInteger(record.latency_ms) ?? 0;
      accumulator.refs.push(...normalizeArray(record.source_refs), record.run_id);
      return accumulator;
    },
    {
      inputTokens: 0,
      outputTokens: 0,
      reasoningTokens: 0,
      cachedInputTokens: 0,
      toolResultTokens: 0,
      compactedTokens: 0,
      totalTokens: 0,
      estimatedCostUsd: 0,
      estimatedCostMicros: 0,
      contextWindowTokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
      contextUsedTokens: 0,
      latencyMs: 0,
      refs: [],
    },
  );
  const contextPressure = totals.contextWindowTokens > 0
    ? roundRatio(totals.contextUsedTokens / totals.contextWindowTokens)
    : 0;
  const counts = source_counts ?? { runs: records.length, subagents: 0 };
  return {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_telemetry",
    scope,
    thread_id: threadId,
    agent_id: agentId,
    provider: "aggregate",
    model: "aggregate",
    route_id: null,
    model_route_id: null,
    input_tokens: totals.inputTokens,
    output_tokens: totals.outputTokens,
    reasoning_tokens: totals.reasoningTokens,
    cached_input_tokens: totals.cachedInputTokens,
    tool_result_tokens: totals.toolResultTokens,
    compacted_tokens: totals.compactedTokens,
    total_tokens: totals.totalTokens,
    estimated_cost_micros: totals.estimatedCostMicros || Math.round(totals.estimatedCostUsd * 1_000_000),
    estimated_cost_usd: roundUsd(totals.estimatedCostUsd),
    currency: "USD",
    context_window_tokens: totals.contextWindowTokens,
    context_used_tokens: totals.contextUsedTokens,
    context_pressure: contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    latency_ms: totals.latencyMs,
    estimated: true,
    source_counts: counts,
    source_refs: uniqueStrings(totals.refs),
    generated_at: generatedAt,
  };
}

function usageTelemetryFromSubagent(record = {}) {
  const usage = firstObject(record.usage_telemetry, record.budget_status?.usage);
  if (!usage) return null;
  const totalTokens =
    positiveInteger(
      usage.cumulative_total_tokens ??
        usage.total_tokens,
    ) ?? 0;
  const inputTokens =
    positiveInteger(
      usage.cumulative_input_tokens ??
        usage.input_tokens,
    ) ?? 0;
  const outputTokens =
    positiveInteger(
      usage.cumulative_output_tokens ??
        usage.output_tokens,
    ) ?? 0;
  const costUsd =
    numberValue(
      usage.cumulative_cost_estimate_usd ??
        usage.cost_estimate_usd,
    ) ?? totalTokens * FALLBACK_COST_USD_PER_TOKEN;
  const costMicros = Math.round(costUsd * 1_000_000);
  const contextPressure = roundRatio(totalTokens / DEFAULT_CONTEXT_WINDOW_TOKENS);
  return {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_telemetry",
    scope: "subagent",
    thread_id: record.parent_thread_id ?? null,
    turn_id: record.parent_turn_id ?? null,
    run_id: record.run_id ?? usage.run_id ?? null,
    agent_id: record.agent_id ?? null,
    provider: "subagent",
    model: "subagent",
    route_id: record.model_route_id ?? usage.model_route_id ?? null,
    model_route_id: record.model_route_id ?? usage.model_route_id ?? null,
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    reasoning_tokens: 0,
    cached_input_tokens: 0,
    tool_result_tokens: 0,
    compacted_tokens: 0,
    total_tokens: totalTokens,
    estimated_cost_micros: costMicros,
    estimated_cost_usd: roundUsd(costUsd),
    currency: "USD",
    context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
    context_used_tokens: totalTokens,
    context_pressure: contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    latency_ms: 0,
    estimated: true,
    source_counts: { runs: 0, subagents: 1 },
    source_refs: [record.subagent_id, record.run_id].filter(Boolean),
    generated_at: new Date().toISOString(),
  };
}

function usageListEnvelope({ group_by, usage }) {
  return {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_list",
    group_by,
    count: usage.length,
    usage,
    generated_at: new Date().toISOString(),
  };
}

function normalizeProviderUsage(value) {
  const usage = firstObject(value);
  if (!usage) return {};
  const nested = firstObject(usage.usage, usage.provider_usage);
  return nested ?? usage;
}

function costEstimateUsd({ explicit = null, providerUsage = {}, route = null, totalTokens = 0 } = {}) {
  const explicitUsd = numberValue(
    explicit?.estimated_cost_usd ??
      explicit?.cost_estimate_usd ??
      providerUsage.estimated_cost_usd ??
      providerUsage.cost_estimate_usd,
  );
  if (explicitUsd !== null && explicitUsd > 0) return explicitUsd;
  const explicitMicros = positiveInteger(
    explicit?.estimated_cost_micros ??
      providerUsage.estimated_cost_micros,
  );
  if (explicitMicros !== null && explicitMicros > 0) return explicitMicros / 1_000_000;
  const routeEstimate = numberValue(route?.cost_estimate_usd);
  if (routeEstimate !== null && routeEstimate > 0) return routeEstimate;
  return totalTokens * FALLBACK_COST_USD_PER_TOKEN;
}

function firstConversationContent(conversation, role) {
  return normalizeArray(conversation).find((message) => message?.role === role)?.content ?? null;
}

function firstObject(...values) {
  return values.find((value) => value && typeof value === "object" && !Array.isArray(value)) ?? null;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => stringValue(value)).filter(Boolean))];
}

function stringValue(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function positiveInteger(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}

function numberValue(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function estimatedTokenCount(value) {
  const text = String(value ?? "");
  if (!text) return 0;
  return Math.max(1, Math.ceil(text.length / 4));
}

function contextPressureStatus(pressure) {
  if (pressure >= 0.85) return "high";
  if (pressure >= 0.6) return "elevated";
  return "nominal";
}

function roundUsd(value) {
  return Math.round((Number(value) || 0) * 1_000_000) / 1_000_000;
}

function roundRatio(value) {
  return Math.round((Number(value) || 0) * 10000) / 10000;
}
