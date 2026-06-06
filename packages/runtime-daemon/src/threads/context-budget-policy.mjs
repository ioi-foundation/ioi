import {
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  createContextPolicyRunnerFromEnv,
} from "../runtime-context-policy-runner.mjs";

export function contextBudgetUsageTelemetryFromRequest(request = {}) {
  return contextBudgetFirstObject(
    request.usage_telemetry,
    request.usage,
  );
}

export function codingToolBudgetPolicyForRequest({
  request = {},
  threadId = null,
  toolId = null,
  toolCallId = null,
  workflowGraphId = null,
  workflowNodeId = null,
  budgetRunner = createContextPolicyRunnerFromEnv(),
} = {}) {
  const codingPack = codingToolBudgetConfigForRequest(request);
  const usageTelemetry = contextBudgetFirstObject(
    request.budget_usage_telemetry,
    request.usage_telemetry,
    codingPack.budget_usage_telemetry,
  );
  if (!usageTelemetry) return null;

  const requestThresholds = contextBudgetThresholds(request);
  const codingPackThresholds = contextBudgetThresholds(codingPack);
  const thresholds = {
    max_total_tokens: contextBudgetNumber(
      requestThresholds.max_total_tokens,
      codingPackThresholds.max_total_tokens,
    ),
    maxTotalTokens: contextBudgetNumber(
      requestThresholds.maxTotalTokens,
      codingPackThresholds.maxTotalTokens,
    ),
    max_cost_usd: contextBudgetNumber(
      requestThresholds.max_cost_usd,
      codingPackThresholds.max_cost_usd,
    ),
    maxCostUsd: contextBudgetNumber(
      requestThresholds.maxCostUsd,
      codingPackThresholds.maxCostUsd,
    ),
    max_context_pressure: contextBudgetNumber(
      requestThresholds.max_context_pressure,
      codingPackThresholds.max_context_pressure,
    ),
    maxContextPressure: contextBudgetNumber(
      requestThresholds.maxContextPressure,
      codingPackThresholds.maxContextPressure,
    ),
    warn_at_ratio:
      contextBudgetNumber(requestThresholds.warn_at_ratio, codingPackThresholds.warn_at_ratio) ??
      0.8,
    warnAtRatio:
      contextBudgetNumber(requestThresholds.warnAtRatio, codingPackThresholds.warnAtRatio) ??
      0.8,
  };
  const hasBudgetLimit = [
    thresholds.max_total_tokens,
    thresholds.max_cost_usd,
    thresholds.max_context_pressure,
  ].some((value) => contextBudgetNumber(value) !== null);
  if (!hasBudgetLimit) return null;

  const mode = contextBudgetMode(
    optionalString(
      request.budget_mode ??
        request.budgetMode ??
        request.mode ??
        codingPack.budget_mode ??
        codingPack.budgetMode,
    ) ?? "simulate",
  );
  return budgetRunner.evaluateCodingToolBudgetPolicy({
    schema_version: CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
    usage_telemetry: usageTelemetry,
    thresholds: {
      max_total_tokens: thresholds.max_total_tokens,
      max_cost_usd: thresholds.max_cost_usd,
      max_context_pressure: thresholds.max_context_pressure,
      warn_at_ratio: thresholds.warn_at_ratio,
    },
    mode,
    scope: "thread",
    thread_id: threadId,
    tool_id: toolId,
    tool_call_id: toolCallId,
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
    source: operatorControlSource(request.source),
  });
}

export function codingToolBudgetConfigForRequest(request = {}) {
  const toolPack =
    contextBudgetFirstObject(
      request.toolPack,
      request.tool_pack,
      request.options?.toolPack,
      request.options?.tool_pack,
    ) ?? {};
  const codingPack =
    contextBudgetFirstObject(
      toolPack.coding,
      toolPack.CODING,
      request.coding,
      request.coding_tool,
      request.codingTool,
    ) ?? {};
  return {
    ...toolPack,
    ...codingPack,
  };
}

export function evaluateContextBudgetPolicy({
  usageTelemetry,
  request = {},
  budgetRunner = createContextPolicyRunnerFromEnv(),
} = {}) {
  const canonicalUsageTelemetry = contextBudgetFirstObject(usageTelemetry) ?? {};
  const thresholds = contextBudgetThresholds(request);
  const mode = contextBudgetMode(request.mode);
  const scope = optionalString(request.scope) ?? canonicalUsageTelemetry.scope ?? "thread";
  const workflowNodeId =
    optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
    "runtime.context-budget";
  const workflowGraphId =
    optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
  const threadId =
    optionalString(request.thread_id ?? request.threadId) ??
    optionalString(canonicalUsageTelemetry.thread_id) ??
    null;
  const runId =
    optionalString(request.run_id ?? request.runId) ??
    optionalString(canonicalUsageTelemetry.run_id) ??
    null;
  return budgetRunner.evaluateContextBudgetPolicy({
    schema_version: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
    usage_telemetry: canonicalUsageTelemetry,
    thresholds: {
      max_total_tokens: thresholds.max_total_tokens,
      max_cost_usd: thresholds.max_cost_usd,
      max_context_pressure: thresholds.max_context_pressure,
      warn_at_ratio: thresholds.warn_at_ratio,
    },
    mode,
    scope,
    thread_id: threadId,
    run_id: runId,
    source: operatorControlSource(request.source),
    actor: optionalString(request.actor) ?? "operator",
    event_kind:
      optionalString(request.event_kind ?? request.eventKind) ??
      "RuntimeContextBudget.Evaluate",
    component_kind: "context_budget",
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
  });
}

export function contextBudgetThresholds(request = {}) {
  const thresholds = contextBudgetFirstObject(request.thresholds, request.contextBudget, request.context_budget) ?? {};
  return {
    max_total_tokens: contextBudgetNumber(
      thresholds.max_total_tokens,
      thresholds.maxTotalTokens,
      request.max_total_tokens,
      request.maxTotalTokens,
    ),
    maxTotalTokens: contextBudgetNumber(
      thresholds.maxTotalTokens,
      thresholds.max_total_tokens,
      request.maxTotalTokens,
      request.max_total_tokens,
    ),
    max_cost_usd: contextBudgetNumber(
      thresholds.max_cost_usd,
      thresholds.maxCostUsd,
      request.max_cost_usd,
      request.maxCostUsd,
    ),
    maxCostUsd: contextBudgetNumber(
      thresholds.maxCostUsd,
      thresholds.max_cost_usd,
      request.maxCostUsd,
      request.max_cost_usd,
    ),
    max_context_pressure: contextBudgetNumber(
      thresholds.max_context_pressure,
      thresholds.maxContextPressure,
      request.max_context_pressure,
      request.maxContextPressure,
    ),
    maxContextPressure: contextBudgetNumber(
      thresholds.maxContextPressure,
      thresholds.max_context_pressure,
      request.maxContextPressure,
      request.max_context_pressure,
    ),
    warn_at_ratio: contextBudgetNumber(
      thresholds.warn_at_ratio,
      thresholds.warnAtRatio,
      request.warn_at_ratio,
      request.warnAtRatio,
    ) ?? 0.8,
    warnAtRatio: contextBudgetNumber(
      thresholds.warnAtRatio,
      thresholds.warn_at_ratio,
      request.warnAtRatio,
      request.warn_at_ratio,
    ) ?? 0.8,
  };
}

export function contextBudgetNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const number = Number(value);
    if (Number.isFinite(number) && number >= 0) return number;
  }
  return null;
}

export function contextBudgetMode(value) {
  const mode = optionalString(value)?.toLowerCase();
  if (mode === "warn" || mode === "block") return mode;
  return "simulate";
}

export function contextBudgetFirstObject(...values) {
  return values.find(
    (value) => value && typeof value === "object" && !Array.isArray(value),
  ) ?? null;
}

export function evaluateCompactionPolicyDecision({
  threadId,
  turnId = "",
  request = {},
  policyRunner = createContextPolicyRunnerFromEnv(),
} = {}) {
  const policy = contextBudgetFirstObject(request.policy, request.compaction_policy) ?? {};
  const contextBudget = contextBudgetFirstObject(
    request.context_budget,
    request.runtime_context_budget,
  ) ?? {};
  return policyRunner.evaluateCompactionPolicy({
    schema_version: COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
    thread_id: threadId,
    turn_id: turnId || null,
    context_budget: contextBudget,
    context_budget_status: optionalString(request.context_budget_status) ?? null,
    actions: {
      ok_action: optionalString(policy.ok_action ?? request.ok_action) ?? undefined,
      warn_action: optionalString(policy.warn_action ?? request.warn_action) ?? undefined,
      blocked_action:
        optionalString(policy.blocked_action ?? request.blocked_action) ?? undefined,
    },
    approval: {
      approval_required: compactionPolicyBoolean(
        policy.approval_required,
        request.approval_required,
      ),
      approval_granted: compactionPolicyBoolean(
        policy.approval_granted,
        request.approval_granted,
        request.approved,
      ),
    },
    compact: {
      execute_compaction: compactionPolicyBoolean(
        policy.execute_compaction,
        request.execute_compaction,
      ),
      compact_workflow_node_id:
        optionalString(policy.compact_workflow_node_id ?? request.compact_workflow_node_id) ??
        undefined,
      compact_reason:
        optionalString(policy.compact_reason ?? request.compact_reason ?? request.reason) ??
        undefined,
      compact_scope:
        optionalString(policy.compact_scope ?? request.compact_scope) ?? undefined,
    },
    source: optionalString(request.source) ?? "react_flow",
    actor: optionalString(request.actor) ?? "operator",
    event_kind:
      optionalString(request.event_kind) ??
      "RuntimeCompactionPolicy.Evaluate",
    workflow_graph_id: optionalString(request.workflow_graph_id) ?? null,
    workflow_node_id:
      optionalString(request.workflow_node_id) ?? "runtime.compaction-policy",
  });
}

export function compactionPolicyBoolean(...values) {
  for (const value of values) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const clean = value.trim().toLowerCase();
      if (clean === "true" || clean === "1" || clean === "yes") return true;
      if (clean === "false" || clean === "0" || clean === "no") return false;
    }
  }
  return false;
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function operatorControlSource(value) {
  const source = optionalString(value);
  return ["cli_tui", "react_flow", "sdk_client", "runtime_auto", "mcp_serve"].includes(source) ? source : "sdk_client";
}
