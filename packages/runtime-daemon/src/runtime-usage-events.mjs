import {
  RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
  RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import { runtimeUsageTelemetryForRun } from "./usage-telemetry.mjs";

export function createRuntimeUsageEventHelpers({
  contextBudgetNumber,
  eventStreamIdForThread,
  normalizeArray,
  optionalString,
  safeId,
} = {}) {
  function insertRuntimeBridgeUsageDeltaEvents({ projection, agent, threadId }) {
    const usageTelemetry = runtimeUsageTelemetryForRun({
      run: {
        id: projection.runId,
        agentId: agent.id,
        mode: projection.mode,
        objective: projection.prompt,
        result: projection.result,
        createdAt: projection.createdAt,
        updatedAt: projection.updatedAt,
        modelRouteDecision: agent.modelRouteDecision ?? null,
        usage: projection.usage,
      },
      agent,
      threadId,
    });
    const deltas = runtimeUsageTelemetryDeltaPayloads(usageTelemetry, {
      runId: projection.runId,
      agentId: agent.id,
      threadId,
      turnId: projection.turnId,
    });
    if (!deltas.length) return normalizeArray(projection.events);

    const deltaEvents = deltas.flatMap((delta) => {
      const alert = contextPressureAlertPayload(delta);
      return [
        {
          event_stream_id: eventStreamIdForThread(threadId),
          thread_id: threadId,
          turn_id: projection.turnId,
          item_id: `${projection.turnId}:item:usage-delta:${safeId(delta.stage)}`,
          idempotency_key: `turn:${projection.turnId}:usage-delta:${safeId(delta.stage)}`,
          source: "runtime_auto",
          source_event_kind: "RuntimeUsageTelemetry.Delta",
          event_kind: "usage.delta",
          status: "running",
          actor: "runtime",
          created_at: projection.updated_at ?? projection.created_at,
          workspace_root: agent.cwd,
          workflow_node_id: "runtime.usage-telemetry",
          component_kind: "usage_telemetry",
          payload_schema_version: RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
          payload: delta,
          receipt_refs: [],
          artifact_refs: [],
          policy_decision_refs: [],
          rollback_refs: [],
        },
        {
          event_stream_id: eventStreamIdForThread(threadId),
          thread_id: threadId,
          turn_id: projection.turnId,
          item_id: `${projection.turnId}:item:context-pressure:${safeId(delta.stage)}`,
          idempotency_key: `turn:${projection.turnId}:context-pressure:${safeId(delta.stage)}`,
          source: "runtime_auto",
          source_event_kind: "RuntimeContextPressure.Delta",
          event_kind: "context.pressure_delta",
          status: delta.context_pressure_status === "high" ? "blocked" : "running",
          actor: "runtime",
          created_at: projection.updated_at ?? projection.created_at,
          workspace_root: agent.cwd,
          workflow_node_id: "runtime.context-budget",
          component_kind: "context_pressure",
          payload_schema_version: RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
          payload: contextPressureDeltaPayload(delta),
          receipt_refs: [],
          artifact_refs: [],
          policy_decision_refs: [],
          rollback_refs: [],
        },
        ...(alert
          ? [
              {
                event_stream_id: eventStreamIdForThread(threadId),
                thread_id: threadId,
                turn_id: projection.turnId,
                item_id: `${projection.turnId}:item:context-pressure-alert:${safeId(delta.stage)}`,
                idempotency_key: `turn:${projection.turnId}:context-pressure-alert:${safeId(delta.stage)}`,
                source: "runtime_auto",
                source_event_kind: "RuntimeContextPressure.Alert",
                event_kind: "context.pressure_alert",
                status: alert.alert_level === "blocked" ? "blocked" : "warning",
                actor: "runtime",
                created_at: projection.updated_at ?? projection.created_at,
                workspace_root: agent.cwd,
                workflow_node_id: "runtime.context-pressure-alert",
                component_kind: "context_pressure_alert",
                payload_schema_version: RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
                payload: alert,
                receipt_refs: alert.receipt_refs,
                artifact_refs: [],
                policy_decision_refs: alert.policy_decision_refs,
                rollback_refs: [],
              },
            ]
          : []),
      ];
    });
    const events = [...normalizeArray(projection.events)];
    const turnStartedIndex = events.findIndex((candidate) => candidate?.event_kind === "turn.started");
    if (turnStartedIndex >= 0) {
      events.splice(turnStartedIndex + 1, 0, ...deltaEvents);
      return events;
    }
    return [...deltaEvents, ...events];
  }

  function runtimeUsageTelemetryDeltaPayloads(usageTelemetry = {}, {
    runId,
    agentId,
    threadId,
    turnId,
  } = {}) {
    const totalTokens = contextBudgetNumber(
      usageTelemetry.total_tokens,
    ) ?? 0;
    const inputTokens = contextBudgetNumber(
      usageTelemetry.input_tokens,
    ) ?? 0;
    const outputTokens = contextBudgetNumber(
      usageTelemetry.output_tokens,
    ) ?? Math.max(0, totalTokens - inputTokens);
    const costUsd = contextBudgetNumber(
      usageTelemetry.estimated_cost_usd,
    ) ?? 0;
    const contextUsedTokens = contextBudgetNumber(
      usageTelemetry.context_used_tokens,
    ) ?? totalTokens;
    const contextWindowTokens = contextBudgetNumber(
      usageTelemetry.context_window_tokens,
    ) ?? 128000;
    const contextPressure = contextBudgetNumber(
      usageTelemetry.context_pressure,
    ) ?? (contextWindowTokens > 0 ? roundRuntimeRatio(contextUsedTokens / contextWindowTokens) : 0);
    const contextPressureStatus =
      optionalString(
        usageTelemetry.context_pressure_status,
      ) ?? runtimeContextPressureStatus(contextPressure);
    const provider = optionalString(usageTelemetry.provider) ?? "local";
    const model = optionalString(usageTelemetry.model) ?? "unknown";
    const routeId =
      optionalString(usageTelemetry.route_id) ?? null;
    const promptTotal = Math.max(1, inputTokens);
    const promptCost = totalTokens > 0 ? costUsd * (promptTotal / totalTokens) : 0;
    const promptPressure = contextWindowTokens > 0
      ? roundRuntimeRatio(promptTotal / contextWindowTokens)
      : 0;
    const stages = [
      {
        stage: "prompt_prepared",
        delta_index: 1,
        delta_total: 2,
        input_tokens_delta: promptTotal,
        output_tokens_delta: 0,
        total_tokens_delta: promptTotal,
        cumulative_input_tokens: inputTokens,
        cumulative_output_tokens: 0,
        cumulative_total_tokens: promptTotal,
        cumulative_cost_estimate_usd: roundRuntimeUsd(promptCost),
        context_used_tokens: promptTotal,
        context_pressure: promptPressure,
        context_pressure_status: runtimeContextPressureStatus(promptPressure),
      },
      {
        stage: "completion_streamed",
        delta_index: 2,
        delta_total: 2,
        input_tokens_delta: 0,
        output_tokens_delta: outputTokens,
        total_tokens_delta: Math.max(0, totalTokens - promptTotal),
        cumulative_input_tokens: inputTokens,
        cumulative_output_tokens: outputTokens,
        cumulative_total_tokens: totalTokens,
        cumulative_cost_estimate_usd: roundRuntimeUsd(costUsd),
        context_used_tokens: contextUsedTokens,
        context_pressure: contextPressure,
        context_pressure_status: contextPressureStatus,
      },
    ];
    return stages.map((stage) => {
      const summary =
        `Usage delta ${stage.delta_index}/${stage.delta_total}: ` +
        `${stage.cumulative_total_tokens} tokens, context ${stage.context_pressure}.`;
      return {
        schema_version: RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
        object: "ioi.runtime_usage_delta",
        run_id: runId,
        agent_id: agentId,
        thread_id: threadId,
        turn_id: turnId,
        provider,
        model,
        route_id: routeId,
        status: "running",
        summary,
        ...stage,
        input_tokens: stage.cumulative_input_tokens,
        output_tokens: stage.cumulative_output_tokens,
        total_tokens: stage.cumulative_total_tokens,
        estimated_cost_usd: stage.cumulative_cost_estimate_usd,
        context_window_tokens: contextWindowTokens,
        context_used_tokens: stage.context_used_tokens,
        generated_at: new Date().toISOString(),
      };
    });
  }

  function contextPressureDeltaPayload(usageDelta = {}) {
    const pressureStatus = usageDelta.context_pressure_status ?? "nominal";
    const pressure = usageDelta.context_pressure ?? 0;
    const deltaIndex = usageDelta.delta_index ?? null;
    const deltaTotal = usageDelta.delta_total ?? null;
    const summary = deltaIndex !== null && deltaTotal !== null
      ? `Context pressure delta ${deltaIndex}/${deltaTotal}: ${pressureStatus} at ${pressure}.`
      : usageDelta.summary ?? null;
    return {
      schema_version: RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
      object: "ioi.runtime_context_pressure_delta",
      run_id: usageDelta.run_id ?? null,
      thread_id: usageDelta.thread_id ?? null,
      turn_id: usageDelta.turn_id ?? null,
      status: pressureStatus === "high" ? "blocked" : "running",
      summary,
      stage: usageDelta.stage ?? null,
      delta_index: deltaIndex,
      delta_total: deltaTotal,
      usage_delta_ref: `${usageDelta.run_id ?? "run"}:${usageDelta.stage ?? "delta"}`,
      usage_total_tokens: usageDelta.total_tokens ?? 0,
      usage_cost_estimate_usd: usageDelta.estimated_cost_usd ?? 0,
      usage_context_pressure: pressure,
      usage_context_pressure_status: pressureStatus,
      generated_at: new Date().toISOString(),
    };
  }

  function contextPressureAlertPayload(usageDelta = {}) {
    const pressureStatus = usageDelta.context_pressure_status ?? "nominal";
    if (pressureStatus !== "elevated" && pressureStatus !== "high") return null;
    const pressure = usageDelta.context_pressure ?? 0;
    const threadId = usageDelta.thread_id ?? null;
    const turnId = usageDelta.turn_id ?? null;
    const runId = usageDelta.run_id ?? null;
    const scope =
      Number(usageDelta.usage_subagent_count ?? 0) > 0
        ? "subagent_aggregate"
        : "turn";
    const alertLevel = pressureStatus === "high" ? "blocked" : "warn";
    const alertId = `context_pressure_${safeId(scope)}_${safeId(runId ?? turnId ?? threadId ?? "detached")}_${safeId(usageDelta.stage ?? "delta")}`;
    const primaryAction = pressureStatus === "high" ? "compact" : "delegate_summary";
    const stopExecutable = Boolean(turnId);
    const actionBase = {
      pressure,
      pressure_status: pressureStatus,
      scope,
      thread_id: threadId,
      turn_id: turnId,
      run_id: runId,
    };
    const actions = [
      {
        ...actionBase,
        action: "compact",
        label: "Compact context",
        status: "available",
        executable: true,
        workflow_node_id: "runtime.context-compact",
        summary: `Compact ${scope.replace(/_/g, " ")} context at pressure ${pressure}.`,
      },
      {
        ...actionBase,
        action: "delegate_summary",
        label: "Delegate summary",
        status: pressureStatus === "high" ? "recommended" : "available",
        executable: true,
        workflow_node_id: "runtime.subagent.delegate-summary",
        summary: "Create a summarization delegate before continuing the long-running turn.",
      },
    ];
    if (pressureStatus === "high") {
      actions.push(
        {
          ...actionBase,
          action: "request_approval",
          label: "Request approval",
          status: "available",
          executable: true,
          workflow_node_id: "runtime.approval.context-pressure",
          summary: "Ask the operator to approve continuing despite high context pressure.",
        },
        {
          ...actionBase,
          action: "stop",
          label: "Stop turn",
          status: stopExecutable ? "available" : "missing_turn",
          executable: stopExecutable,
          workflow_node_id: "runtime.operator-interrupt",
          summary: "Stop the turn through the runtime operator interrupt control.",
        },
      );
    }
    const summary =
      pressureStatus === "high"
        ? `Context pressure blocked ${scope.replace(/_/g, " ")} at ${pressure}; compact or stop before continuing.`
        : `Context pressure warning for ${scope.replace(/_/g, " ")} at ${pressure}; compact or delegate a summary.`;
    return {
      schema_version: RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
      object: "ioi.runtime_context_pressure_alert",
      alert_id: alertId,
      alert_level: alertLevel,
      status: alertLevel === "blocked" ? "blocked" : "warning",
      scope,
      pressure,
      pressure_status: pressureStatus,
      recommended_action: primaryAction,
      actions,
      source_usage_delta_ref: `${runId ?? "run"}:${usageDelta.stage ?? "delta"}`,
      stage: usageDelta.stage ?? null,
      delta_index: usageDelta.delta_index ?? null,
      delta_total: usageDelta.delta_total ?? null,
      usage_total_tokens: usageDelta.total_tokens ?? 0,
      usage_cost_estimate_usd: usageDelta.estimated_cost_usd ?? 0,
      thread_id: threadId,
      turn_id: turnId,
      run_id: runId,
      summary,
      receipt_refs: [],
      policy_decision_refs: [],
      generated_at: new Date().toISOString(),
    };
  }

  function roundRuntimeRatio(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return 0;
    return Math.round(number * 10000) / 10000;
  }

  function roundRuntimeUsd(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return 0;
    return Math.round(number * 1_000_000) / 1_000_000;
  }

  function runtimeContextPressureStatus(pressure) {
    if (pressure >= 0.85) return "high";
    if (pressure >= 0.6) return "elevated";
    return "nominal";
  }

  return {
    contextPressureAlertPayload,
    contextPressureDeltaPayload,
    insertRuntimeBridgeUsageDeltaEvents,
    roundRuntimeRatio,
    roundRuntimeUsd,
    runtimeContextPressureStatus,
    runtimeUsageTelemetryDeltaPayloads,
  };
}
