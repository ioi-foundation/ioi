import {
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
} from "../runtime-context-policy-core.mjs";

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
  budgetRunner = null,
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
    max_cost_usd: contextBudgetNumber(
      requestThresholds.max_cost_usd,
      codingPackThresholds.max_cost_usd,
    ),
    max_context_pressure: contextBudgetNumber(
      requestThresholds.max_context_pressure,
      codingPackThresholds.max_context_pressure,
    ),
    warn_at_ratio:
      contextBudgetNumber(requestThresholds.warn_at_ratio, codingPackThresholds.warn_at_ratio) ??
      0.8,
  };
  const hasBudgetLimit = [
    thresholds.max_total_tokens,
    thresholds.max_cost_usd,
    thresholds.max_context_pressure,
  ].some((value) => contextBudgetNumber(value) !== null);
  if (!hasBudgetLimit) return null;

  const runner = requiredContextBudgetPolicyRunner(
    budgetRunner,
    "evaluateCodingToolBudgetPolicy",
    "coding_tool_budget_policy",
  );
  const mode = contextBudgetMode(
    optionalString(
      request.budget_mode ??
        request.mode ??
        codingPack.budget_mode,
    ) ?? "simulate",
  );
  return runner.evaluateCodingToolBudgetPolicy({
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
      request.tool_pack,
      request.options?.tool_pack,
    ) ?? {};
  const codingPack =
    contextBudgetFirstObject(
      toolPack.coding,
      toolPack.CODING,
      request.coding,
      request.coding_tool,
    ) ?? {};
  return {
    ...toolPack,
    ...codingPack,
  };
}

export function evaluateContextBudgetPolicy({
  usageTelemetry,
  request = {},
  budgetRunner = null,
} = {}) {
  const runner = requiredContextBudgetPolicyRunner(
    budgetRunner,
    "evaluateContextBudgetPolicy",
    "context_budget_policy",
  );
  const canonicalUsageTelemetry = contextBudgetFirstObject(usageTelemetry) ?? {};
  const thresholds = contextBudgetThresholds(request);
  const mode = contextBudgetMode(request.mode);
  const scope = optionalString(request.scope) ?? canonicalUsageTelemetry.scope ?? "thread";
  const workflowNodeId =
    optionalString(request.workflow_node_id) ??
    "runtime.context-budget";
  const workflowGraphId =
    optionalString(request.workflow_graph_id) ?? null;
  const threadId =
    optionalString(request.thread_id) ??
    optionalString(canonicalUsageTelemetry.thread_id) ??
    null;
  const runId =
    optionalString(request.run_id) ??
    optionalString(canonicalUsageTelemetry.run_id) ??
    null;
  const turnId = optionalString(request.turn_id) ?? null;
  return runner.evaluateContextBudgetPolicy({
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
    turn_id: turnId,
    run_id: runId,
    source: operatorControlSource(request.source),
    actor: optionalString(request.actor) ?? "operator",
    event_kind:
      optionalString(request.event_kind) ??
      "RuntimeContextBudget.Evaluate",
    component_kind: "context_budget",
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
  });
}

export function contextBudgetThresholds(request = {}) {
  const thresholds = contextBudgetFirstObject(request.thresholds, request.context_budget) ?? {};
  return {
    max_total_tokens: contextBudgetNumber(
      thresholds.max_total_tokens,
      request.max_total_tokens,
    ),
    max_cost_usd: contextBudgetNumber(
      thresholds.max_cost_usd,
      request.max_cost_usd,
    ),
    max_context_pressure: contextBudgetNumber(
      thresholds.max_context_pressure,
      request.max_context_pressure,
    ),
    warn_at_ratio: contextBudgetNumber(
      thresholds.warn_at_ratio,
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
  policyRunner = null,
} = {}) {
  const runner = requiredContextBudgetPolicyRunner(
    policyRunner,
    "evaluateCompactionPolicy",
    "compaction_policy",
  );
  const policy = contextBudgetFirstObject(request.policy, request.compaction_policy) ?? {};
  const contextBudget = contextBudgetFirstObject(
    request.context_budget,
    request.runtime_context_budget,
  ) ?? {};
  return runner.evaluateCompactionPolicy({
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

function requiredContextBudgetPolicyRunner(runner, method, operation) {
  if (typeof runner?.[method] === "function") return runner;
  const error = new Error(
    "Runtime context-budget policy evaluation requires the daemon-mounted Rust context policy core.",
  );
  error.status = 501;
  error.code = "runtime_context_budget_policy_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.context_budget_policy",
    operation,
    required_mount: "contextPolicyCore",
    required_method: method,
    evidence_refs: [
      "context_budget_policy_self_core_fallback_retired",
      "rust_daemon_core_context_budget_policy_required",
      "agentgres_context_policy_truth_required",
    ],
  };
  throw error;
}
