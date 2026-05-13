export const RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION = "ioi.runtime.usage-telemetry.v1";

const DEFAULT_CONTEXT_WINDOW_TOKENS = 128000;
const FALLBACK_COST_USD_PER_TOKEN = 0.000001;

export function runtimeUsageTelemetryForRun({ run = {}, agent = null, threadId = null } = {}) {
  const generatedAt = new Date().toISOString();
  const explicit = firstObject(
    run.usage_telemetry,
    run.usageTelemetry,
    run.runtimeUsage,
    run.usage,
    run.trace?.usage_telemetry,
    run.trace?.usageTelemetry,
    run.trace?.runtimeUsage,
    run.trace?.usage,
    run.providerUsage,
    run.trace?.providerUsage,
  );
  const providerUsage = normalizeProviderUsage(explicit);
  const route = firstObject(
    run.modelRouteDecision,
    run.trace?.modelRouteDecision,
    agent?.modelRouteDecision,
    explicit?.model_route_decision,
    explicit?.modelRouteDecision,
  );
  const promptText = run.objective ?? firstConversationContent(run.conversation, "user") ?? "";
  const resultText = run.result ?? firstConversationContent(run.conversation, "assistant") ?? "";
  const inputTokens =
    positiveInteger(
      providerUsage.input_tokens ??
        providerUsage.inputTokens ??
        providerUsage.prompt_tokens ??
        providerUsage.promptTokens,
    ) ?? estimatedTokenCount(promptText);
  const outputTokens =
    positiveInteger(
      providerUsage.output_tokens ??
        providerUsage.outputTokens ??
        providerUsage.completion_tokens ??
        providerUsage.completionTokens,
    ) ?? estimatedTokenCount(resultText);
  const reasoningTokens = positiveInteger(providerUsage.reasoning_tokens ?? providerUsage.reasoningTokens) ?? 0;
  const cachedInputTokens =
    positiveInteger(providerUsage.cached_input_tokens ?? providerUsage.cachedInputTokens) ?? 0;
  const toolResultTokens =
    positiveInteger(providerUsage.tool_result_tokens ?? providerUsage.toolResultTokens) ?? 0;
  const compactedTokens =
    positiveInteger(providerUsage.compacted_tokens ?? providerUsage.compactedTokens) ?? 0;
  const explicitTotal =
    positiveInteger(providerUsage.total_tokens ?? providerUsage.totalTokens) ??
    positiveInteger(explicit?.total_tokens ?? explicit?.totalTokens);
  const totalTokens =
    explicitTotal ?? inputTokens + outputTokens + reasoningTokens + toolResultTokens;
  const estimatedCostUsd = costEstimateUsd({
    explicit,
    providerUsage,
    route,
    totalTokens,
  });
  const estimatedCostMicros =
    positiveInteger(providerUsage.estimated_cost_micros ?? providerUsage.estimatedCostMicros) ??
    Math.round(estimatedCostUsd * 1_000_000);
  const contextWindowTokens =
    positiveInteger(
      explicit?.context_window_tokens ??
        explicit?.contextWindowTokens ??
        providerUsage.context_window_tokens ??
        providerUsage.contextWindowTokens ??
        route?.contextWindowTokens ??
        route?.context_window_tokens ??
        route?.modelContextWindowTokens ??
        route?.maxContextTokens,
    ) ?? DEFAULT_CONTEXT_WINDOW_TOKENS;
  const contextUsedTokens =
    positiveInteger(explicit?.context_used_tokens ?? explicit?.contextUsedTokens) ??
    Math.max(0, totalTokens - cachedInputTokens);
  const contextPressure = contextWindowTokens > 0
    ? roundRatio(contextUsedTokens / contextWindowTokens)
    : 0;
  const status = contextPressureStatus(contextPressure);
  const model =
    stringValue(
      providerUsage.model ??
        explicit?.model ??
        route?.selectedModel ??
        route?.selected_model ??
        agent?.modelId ??
        agent?.requestedModelId,
    ) ?? "unknown";
  const provider =
    stringValue(providerUsage.provider ?? explicit?.provider ?? route?.providerId ?? route?.provider_id) ??
    "local";
  const routeId =
    stringValue(
      explicit?.route_id ??
        explicit?.routeId ??
        route?.routeId ??
        route?.route_id ??
        agent?.modelRouteId,
    ) ?? null;
  const record = {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    schemaVersion: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_telemetry",
    scope: "run",
    thread_id: threadId ?? run.threadId ?? run.thread_id ?? (run.agentId ? `thread_${run.agentId}` : null),
    threadId: threadId ?? run.threadId ?? run.thread_id ?? (run.agentId ? `thread_${run.agentId}` : null),
    turn_id: run.turnId ?? run.turn_id ?? (run.id ? `turn_${run.id}` : null),
    turnId: run.turnId ?? run.turn_id ?? (run.id ? `turn_${run.id}` : null),
    run_id: run.id ?? run.run_id ?? run.runId ?? null,
    runId: run.id ?? run.runId ?? run.run_id ?? null,
    agent_id: run.agentId ?? run.agent_id ?? agent?.id ?? null,
    agentId: run.agentId ?? run.agent_id ?? agent?.id ?? null,
    provider,
    model,
    route_id: routeId,
    routeId,
    model_route_id: routeId,
    modelRouteId: routeId,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    reasoning_tokens: reasoningTokens,
    reasoningTokens,
    cached_input_tokens: cachedInputTokens,
    cachedInputTokens,
    tool_result_tokens: toolResultTokens,
    toolResultTokens,
    compacted_tokens: compactedTokens,
    compactedTokens,
    total_tokens: totalTokens,
    totalTokens,
    estimated_cost_micros: estimatedCostMicros,
    estimatedCostMicros,
    estimated_cost_usd: roundUsd(estimatedCostUsd),
    estimatedCostUsd: roundUsd(estimatedCostUsd),
    currency: stringValue(explicit?.currency ?? providerUsage.currency) ?? "USD",
    context_window_tokens: contextWindowTokens,
    contextWindowTokens,
    context_used_tokens: contextUsedTokens,
    contextUsedTokens,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: status,
    contextPressureStatus: status,
    latency_ms: positiveInteger(providerUsage.latency_ms ?? providerUsage.latencyMs) ?? 0,
    latencyMs: positiveInteger(providerUsage.latency_ms ?? providerUsage.latencyMs) ?? 0,
    estimated: !explicit || Object.keys(providerUsage).length === 0,
    source_counts: { runs: 1, subagents: 0 },
    sourceCounts: { runs: 1, subagents: 0 },
    source_refs: [run.id ?? run.run_id ?? run.runId].filter(Boolean),
    sourceRefs: [run.id ?? run.run_id ?? run.runId].filter(Boolean),
    generated_at: generatedAt,
    generatedAt,
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
  const resolvedThreadId = threadId ?? thread?.thread_id ?? thread?.threadId ?? null;
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
    agentId: agent?.id ?? thread?.agent_id ?? thread?.agentId ?? null,
    sourceCounts: { runs: runRecords.length, subagents: subagentRecords.length },
  });
}

export function runtimeUsageTelemetryList({ runs = [], subagents = [], groupBy = "run" } = {}) {
  const grouping = stringValue(groupBy) ?? "run";
  if (grouping === "thread") {
    const groups = new Map();
    for (const run of normalizeArray(runs)) {
      const threadId = run.threadId ?? run.thread_id ?? (run.agentId ? `thread_${run.agentId}` : "thread_unknown");
      const entry = groups.get(threadId) ?? { threadId, runs: [], subagents: [] };
      entry.runs.push(run);
      groups.set(threadId, entry);
    }
    for (const subagent of normalizeArray(subagents)) {
      const threadId = subagent.parent_thread_id ?? subagent.parentThreadId ?? subagent.thread_id ?? subagent.threadId ?? "thread_unknown";
      const entry = groups.get(threadId) ?? { threadId, runs: [], subagents: [] };
      entry.subagents.push(subagent);
      groups.set(threadId, entry);
    }
    return usageListEnvelope({
      groupBy: "thread",
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
    groupBy: "run",
    usage: normalizeArray(runs).map((run) => runtimeUsageTelemetryForRun({ run })),
  });
}

export function runtimeUsageTelemetrySummary(record = {}) {
  const totalTokens = positiveInteger(record.total_tokens ?? record.totalTokens) ?? 0;
  const costUsd = numberValue(record.estimated_cost_usd ?? record.estimatedCostUsd) ?? 0;
  const contextPressure = numberValue(record.context_pressure ?? record.contextPressure) ?? 0;
  const status =
    stringValue(record.context_pressure_status ?? record.contextPressureStatus) ??
    contextPressureStatus(contextPressure);
  return {
    total_tokens: totalTokens,
    totalTokens,
    estimated_cost_usd: roundUsd(costUsd),
    estimatedCostUsd: roundUsd(costUsd),
    context_pressure: roundRatio(contextPressure),
    contextPressure: roundRatio(contextPressure),
    context_pressure_status: status,
    contextPressureStatus: status,
    source_counts: record.source_counts ?? record.sourceCounts ?? null,
    sourceCounts: record.sourceCounts ?? record.source_counts ?? null,
  };
}

function aggregateUsageRecords({
  records = [],
  scope,
  threadId = null,
  agentId = null,
  sourceCounts = null,
} = {}) {
  const generatedAt = new Date().toISOString();
  const totals = normalizeArray(records).reduce(
    (accumulator, record) => {
      accumulator.inputTokens += positiveInteger(record.input_tokens ?? record.inputTokens) ?? 0;
      accumulator.outputTokens += positiveInteger(record.output_tokens ?? record.outputTokens) ?? 0;
      accumulator.reasoningTokens += positiveInteger(record.reasoning_tokens ?? record.reasoningTokens) ?? 0;
      accumulator.cachedInputTokens += positiveInteger(record.cached_input_tokens ?? record.cachedInputTokens) ?? 0;
      accumulator.toolResultTokens += positiveInteger(record.tool_result_tokens ?? record.toolResultTokens) ?? 0;
      accumulator.compactedTokens += positiveInteger(record.compacted_tokens ?? record.compactedTokens) ?? 0;
      accumulator.totalTokens += positiveInteger(record.total_tokens ?? record.totalTokens) ?? 0;
      accumulator.estimatedCostUsd += numberValue(record.estimated_cost_usd ?? record.estimatedCostUsd) ?? 0;
      accumulator.estimatedCostMicros += positiveInteger(record.estimated_cost_micros ?? record.estimatedCostMicros) ?? 0;
      accumulator.contextWindowTokens = Math.max(
        accumulator.contextWindowTokens,
        positiveInteger(record.context_window_tokens ?? record.contextWindowTokens) ?? 0,
      );
      accumulator.contextUsedTokens += positiveInteger(record.context_used_tokens ?? record.contextUsedTokens) ?? 0;
      accumulator.latencyMs += positiveInteger(record.latency_ms ?? record.latencyMs) ?? 0;
      accumulator.refs.push(...normalizeArray(record.source_refs ?? record.sourceRefs), record.run_id ?? record.runId);
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
  const counts = sourceCounts ?? { runs: records.length, subagents: 0 };
  return {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    schemaVersion: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_telemetry",
    scope,
    thread_id: threadId,
    threadId,
    agent_id: agentId,
    agentId,
    provider: "aggregate",
    model: "aggregate",
    route_id: null,
    routeId: null,
    model_route_id: null,
    modelRouteId: null,
    input_tokens: totals.inputTokens,
    inputTokens: totals.inputTokens,
    output_tokens: totals.outputTokens,
    outputTokens: totals.outputTokens,
    reasoning_tokens: totals.reasoningTokens,
    reasoningTokens: totals.reasoningTokens,
    cached_input_tokens: totals.cachedInputTokens,
    cachedInputTokens: totals.cachedInputTokens,
    tool_result_tokens: totals.toolResultTokens,
    toolResultTokens: totals.toolResultTokens,
    compacted_tokens: totals.compactedTokens,
    compactedTokens: totals.compactedTokens,
    total_tokens: totals.totalTokens,
    totalTokens: totals.totalTokens,
    estimated_cost_micros: totals.estimatedCostMicros || Math.round(totals.estimatedCostUsd * 1_000_000),
    estimatedCostMicros: totals.estimatedCostMicros || Math.round(totals.estimatedCostUsd * 1_000_000),
    estimated_cost_usd: roundUsd(totals.estimatedCostUsd),
    estimatedCostUsd: roundUsd(totals.estimatedCostUsd),
    currency: "USD",
    context_window_tokens: totals.contextWindowTokens,
    contextWindowTokens: totals.contextWindowTokens,
    context_used_tokens: totals.contextUsedTokens,
    contextUsedTokens: totals.contextUsedTokens,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    contextPressureStatus: contextPressureStatus(contextPressure),
    latency_ms: totals.latencyMs,
    latencyMs: totals.latencyMs,
    estimated: true,
    source_counts: counts,
    sourceCounts: counts,
    source_refs: uniqueStrings(totals.refs),
    sourceRefs: uniqueStrings(totals.refs),
    generated_at: generatedAt,
    generatedAt,
  };
}

function usageTelemetryFromSubagent(record = {}) {
  const usage = firstObject(record.usage_telemetry, record.usageTelemetry, record.budgetStatus?.usage);
  if (!usage) return null;
  const totalTokens =
    positiveInteger(
      usage.cumulative_total_tokens ??
        usage.cumulativeTotalTokens ??
        usage.total_tokens ??
        usage.totalTokens,
    ) ?? 0;
  const inputTokens =
    positiveInteger(
      usage.cumulative_input_tokens ??
        usage.cumulativeInputTokens ??
        usage.input_tokens ??
        usage.inputTokens,
    ) ?? 0;
  const outputTokens =
    positiveInteger(
      usage.cumulative_output_tokens ??
        usage.cumulativeOutputTokens ??
        usage.output_tokens ??
        usage.outputTokens,
    ) ?? 0;
  const costUsd =
    numberValue(
      usage.cumulative_cost_estimate_usd ??
        usage.cumulativeCostEstimateUsd ??
        usage.cost_estimate_usd ??
        usage.costEstimateUsd,
    ) ?? totalTokens * FALLBACK_COST_USD_PER_TOKEN;
  const costMicros = Math.round(costUsd * 1_000_000);
  const contextPressure = roundRatio(totalTokens / DEFAULT_CONTEXT_WINDOW_TOKENS);
  return {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    schemaVersion: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_telemetry",
    scope: "subagent",
    thread_id: record.parent_thread_id ?? record.parentThreadId ?? null,
    threadId: record.parentThreadId ?? record.parent_thread_id ?? null,
    turn_id: record.parent_turn_id ?? record.parentTurnId ?? null,
    turnId: record.parentTurnId ?? record.parent_turn_id ?? null,
    run_id: record.run_id ?? record.runId ?? usage.run_id ?? usage.runId ?? null,
    runId: record.runId ?? record.run_id ?? usage.runId ?? usage.run_id ?? null,
    agent_id: record.agent_id ?? record.agentId ?? null,
    agentId: record.agentId ?? record.agent_id ?? null,
    provider: "subagent",
    model: "subagent",
    route_id: record.model_route_id ?? record.modelRouteId ?? usage.model_route_id ?? usage.modelRouteId ?? null,
    routeId: record.modelRouteId ?? record.model_route_id ?? usage.modelRouteId ?? usage.model_route_id ?? null,
    model_route_id: record.model_route_id ?? record.modelRouteId ?? usage.model_route_id ?? usage.modelRouteId ?? null,
    modelRouteId: record.modelRouteId ?? record.model_route_id ?? usage.modelRouteId ?? usage.model_route_id ?? null,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    reasoning_tokens: 0,
    reasoningTokens: 0,
    cached_input_tokens: 0,
    cachedInputTokens: 0,
    tool_result_tokens: 0,
    toolResultTokens: 0,
    compacted_tokens: 0,
    compactedTokens: 0,
    total_tokens: totalTokens,
    totalTokens,
    estimated_cost_micros: costMicros,
    estimatedCostMicros: costMicros,
    estimated_cost_usd: roundUsd(costUsd),
    estimatedCostUsd: roundUsd(costUsd),
    currency: "USD",
    context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
    contextWindowTokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
    context_used_tokens: totalTokens,
    contextUsedTokens: totalTokens,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: contextPressureStatus(contextPressure),
    contextPressureStatus: contextPressureStatus(contextPressure),
    latency_ms: 0,
    latencyMs: 0,
    estimated: true,
    source_counts: { runs: 0, subagents: 1 },
    sourceCounts: { runs: 0, subagents: 1 },
    source_refs: [record.subagent_id ?? record.subagentId, record.run_id ?? record.runId].filter(Boolean),
    sourceRefs: [record.subagentId ?? record.subagent_id, record.runId ?? record.run_id].filter(Boolean),
    generated_at: new Date().toISOString(),
    generatedAt: new Date().toISOString(),
  };
}

function usageListEnvelope({ groupBy, usage }) {
  return {
    schema_version: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    schemaVersion: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    object: "ioi.runtime_usage_list",
    group_by: groupBy,
    groupBy,
    count: usage.length,
    usage,
    generated_at: new Date().toISOString(),
    generatedAt: new Date().toISOString(),
  };
}

function normalizeProviderUsage(value) {
  const usage = firstObject(value);
  if (!usage) return {};
  const nested = firstObject(usage.usage, usage.provider_usage, usage.providerUsage);
  return nested ?? usage;
}

function costEstimateUsd({ explicit = null, providerUsage = {}, route = null, totalTokens = 0 } = {}) {
  const explicitUsd = numberValue(
    explicit?.estimated_cost_usd ??
      explicit?.estimatedCostUsd ??
      explicit?.cost_estimate_usd ??
      explicit?.costEstimateUsd ??
      providerUsage.estimated_cost_usd ??
      providerUsage.estimatedCostUsd ??
      providerUsage.cost_estimate_usd ??
      providerUsage.costEstimateUsd,
  );
  if (explicitUsd !== null && explicitUsd > 0) return explicitUsd;
  const explicitMicros = positiveInteger(
    explicit?.estimated_cost_micros ??
      explicit?.estimatedCostMicros ??
      providerUsage.estimated_cost_micros ??
      providerUsage.estimatedCostMicros,
  );
  if (explicitMicros !== null && explicitMicros > 0) return explicitMicros / 1_000_000;
  const routeEstimate = numberValue(route?.costEstimateUsd ?? route?.cost_estimate_usd);
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
