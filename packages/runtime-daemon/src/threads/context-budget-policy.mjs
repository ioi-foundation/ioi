import crypto from "node:crypto";

import {
  RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
} from "../runtime-contract-constants.mjs";
import {
  runtimeUsageTelemetrySummary,
} from "../usage-telemetry.mjs";

export function contextBudgetUsageTelemetryFromRequest(request = {}) {
  return contextBudgetFirstObject(
    request.usageTelemetry,
    request.usage_telemetry,
    request.runtimeUsageMeter,
    request.runtime_usage_meter,
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
} = {}) {
  const codingPack = codingToolBudgetConfigForRequest(request);
  const usageTelemetry = contextBudgetFirstObject(
    request.budget_usage_telemetry,
    request.budgetUsageTelemetry,
    request.usage_telemetry,
    request.usageTelemetry,
    request.runtime_telemetry_summary,
    request.runtimeTelemetrySummary,
    codingPack.budget_usage_telemetry,
    codingPack.budgetUsageTelemetry,
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
  return evaluateContextBudgetPolicy({
    usageTelemetry,
    request: {
      ...request,
      mode,
      thresholds,
      scope: "thread",
      threadId,
      thread_id: threadId,
      toolId,
      tool_id: toolId,
      toolCallId,
      tool_call_id: toolCallId,
      workflowGraphId,
      workflow_graph_id: workflowGraphId,
      workflowNodeId,
      workflow_node_id: workflowNodeId,
      source: operatorControlSource(request.source),
      eventKind: "RuntimeCodingToolBudget.Evaluate",
      event_kind: "RuntimeCodingToolBudget.Evaluate",
      componentKind: "coding_tool",
      component_kind: "coding_tool",
    },
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

export function evaluateContextBudgetPolicy({ usageTelemetry, request = {} } = {}) {
  const usageSummary = contextBudgetUsageSummary(usageTelemetry);
  const thresholds = contextBudgetThresholds(request);
  const mode = contextBudgetMode(request.mode);
  const warnAtRatio = contextBudgetNumber(
    thresholds.warnAtRatio,
    thresholds.warn_at_ratio,
  ) ?? 0.8;
  const checks = [
    contextBudgetCheck({
      id: "total_tokens",
      label: "total tokens",
      actual: usageSummary.total_tokens,
      limit: thresholds.max_total_tokens,
      warnAtRatio,
    }),
    contextBudgetCheck({
      id: "estimated_cost_usd",
      label: "estimated cost USD",
      actual: usageSummary.estimated_cost_usd,
      limit: thresholds.max_cost_usd,
      warnAtRatio,
    }),
    contextBudgetCheck({
      id: "context_pressure",
      label: "context pressure",
      actual: usageSummary.context_pressure,
      limit: thresholds.max_context_pressure,
      warnAtRatio,
    }),
  ].filter(Boolean);
  const violations = checks.filter((check) => check.severity === "violation");
  const warnings = checks.filter((check) => check.severity === "warning");
  const wouldBlock = violations.length > 0;
  const status =
    wouldBlock && mode === "block"
      ? "blocked"
      : wouldBlock || warnings.length > 0
        ? "warn"
        : "ok";
  const scope = optionalString(request.scope) ?? usageSummary.scope ?? "thread";
  const workflowNodeId =
    optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
    "runtime.context-budget";
  const workflowGraphId =
    optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
  const threadId =
    optionalString(request.thread_id ?? request.threadId) ??
    usageSummary.thread_id ??
    null;
  const runId =
    optionalString(request.run_id ?? request.runId) ?? usageSummary.run_id ?? null;
  const decisionHash = doctorHash(
    JSON.stringify({
      scope,
      threadId,
      runId,
      workflowGraphId,
      workflowNodeId,
      status,
      mode,
      checks,
    }),
  ).slice(0, 16);
  const policyDecisionId = `policy_context_budget_${safeId(scope)}_${decisionHash}_${status}`;
  const receiptId = `receipt_context_budget_${safeId(scope)}_${decisionHash}`;
  const summary =
    status === "blocked"
      ? `Context budget blocked: ${violations.map((check) => check.label).join(", ")} exceeded.`
      : status === "warn"
        ? `Context budget warning: ${[...violations, ...warnings].map((check) => check.label).join(", ")} near or over limit.`
        : "Context budget is within policy.";
  const generatedAt = new Date().toISOString();
  const policyDecision = {
    policy_decision_id: policyDecisionId,
    policyDecisionId,
    status,
    mode,
    would_block: wouldBlock,
    wouldBlock,
    summary,
    checks,
    violations,
    warnings,
  };
  return {
    schema_version: RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
    schemaVersion: RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
    object: "ioi.runtime_context_budget_policy",
    status,
    mode,
    scope,
    thread_id: threadId,
    threadId,
    run_id: runId,
    runId,
    source: optionalString(request.source) ?? "react_flow",
    actor: optionalString(request.actor) ?? "operator",
    event_kind:
      optionalString(request.event_kind ?? request.eventKind) ??
      "RuntimeContextBudget.Evaluate",
    eventKind:
      optionalString(request.eventKind ?? request.event_kind) ??
      "RuntimeContextBudget.Evaluate",
    component_kind: "context_budget",
    componentKind: "context_budget",
    payload_schema_version: RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
    payloadSchemaVersion: RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
    workflow_graph_id: workflowGraphId,
    workflowGraphId,
    workflow_node_id: workflowNodeId,
    workflowNodeId,
    thresholds,
    usage_telemetry: usageTelemetry,
    usageTelemetry,
    usage_summary: usageSummary,
    usageSummary,
    policy_decision_id: policyDecisionId,
    policyDecisionId,
    policy_decision: policyDecision,
    policyDecision,
    receipt_refs: [receiptId],
    receiptRefs: [receiptId],
    policy_decision_refs: [policyDecisionId],
    policyDecisionRefs: [policyDecisionId],
    warnings,
    violations,
    would_block: wouldBlock,
    wouldBlock,
    simulation_mode: request.simulation_mode ?? request.simulationMode ?? mode === "simulate",
    simulationMode: request.simulationMode ?? request.simulation_mode ?? mode === "simulate",
    summary,
    generated_at: generatedAt,
    generatedAt,
  };
}

export function contextBudgetUsageSummary(usageTelemetry = {}) {
  if (Array.isArray(usageTelemetry?.usage)) {
    const usage = usageTelemetry.usage;
    const totalTokens = usage.reduce(
      (total, entry) => total + (contextBudgetNumber(entry.total_tokens, entry.totalTokens) ?? 0),
      0,
    );
    const costUsd = usage.reduce(
      (total, entry) =>
        total + (contextBudgetNumber(entry.estimated_cost_usd, entry.estimatedCostUsd) ?? 0),
      0,
    );
    const pressure = usage.reduce(
      (max, entry) =>
        Math.max(max, contextBudgetNumber(entry.context_pressure, entry.contextPressure) ?? 0),
      0,
    );
    return {
      ...runtimeUsageTelemetrySummary({
        total_tokens: totalTokens,
        estimated_cost_usd: costUsd,
        context_pressure: pressure,
        source_counts: { runs: usage.length, subagents: 0 },
      }),
      scope: usageTelemetry.scope ?? "workflow",
      thread_id: usageTelemetry.thread_id ?? usageTelemetry.threadId ?? null,
      run_id: usageTelemetry.run_id ?? usageTelemetry.runId ?? null,
    };
  }
  const summary = runtimeUsageTelemetrySummary(usageTelemetry ?? {});
  return {
    ...summary,
    scope: usageTelemetry?.scope ?? "thread",
    thread_id: usageTelemetry?.thread_id ?? usageTelemetry?.threadId ?? null,
    run_id: usageTelemetry?.run_id ?? usageTelemetry?.runId ?? null,
  };
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

export function contextBudgetCheck({ id, label, actual, limit, warnAtRatio }) {
  const resolvedActual = contextBudgetNumber(actual);
  const resolvedLimit = contextBudgetNumber(limit);
  if (resolvedActual === null || resolvedLimit === null || resolvedLimit <= 0) {
    return null;
  }
  const ratio = Math.round((resolvedActual / resolvedLimit) * 10000) / 10000;
  if (resolvedActual > resolvedLimit) {
    return { id, label, actual: resolvedActual, limit: resolvedLimit, ratio, severity: "violation" };
  }
  if (resolvedActual >= resolvedLimit * warnAtRatio) {
    return { id, label, actual: resolvedActual, limit: resolvedLimit, ratio, severity: "warning" };
  }
  return { id, label, actual: resolvedActual, limit: resolvedLimit, ratio, severity: "ok" };
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

export function evaluateCompactionPolicyDecision({ threadId, turnId = "", request = {} } = {}) {
  const policy = contextBudgetFirstObject(request.policy, request.compactionPolicy, request.compaction_policy) ?? {};
  const contextBudget = contextBudgetFirstObject(
    request.contextBudget,
    request.context_budget,
    request.runtimeContextBudget,
    request.runtime_context_budget,
  ) ?? {};
  const budgetStatus = compactionPolicyBudgetStatus(
    request.contextBudgetStatus,
    request.context_budget_status,
    contextBudget.status,
    contextBudget.policyDecision?.status,
    contextBudget.policy_decision?.status,
  );
  const okAction = compactionPolicyAction(policy.okAction ?? policy.ok_action ?? request.okAction ?? request.ok_action, "noop");
  const warnAction = compactionPolicyAction(policy.warnAction ?? policy.warn_action ?? request.warnAction ?? request.warn_action, "warn");
  const blockedAction = compactionPolicyAction(
    policy.blockedAction ?? policy.blocked_action ?? request.blockedAction ?? request.blocked_action,
    "compact",
  );
  const selectedAction =
    budgetStatus === "blocked" ? blockedAction : budgetStatus === "warn" ? warnAction : okAction;
  const approvalRequired =
    compactionPolicyBoolean(
      policy.approvalRequired,
      policy.approval_required,
      request.approvalRequired,
      request.approval_required,
    ) || selectedAction === "approval_required";
  const approvalGranted = compactionPolicyBoolean(
    policy.approvalGranted,
    policy.approval_granted,
    request.approvalGranted,
    request.approval_granted,
    request.approved,
    request.confirm,
  );
  const executeCompaction = compactionPolicyBoolean(
    policy.executeCompaction,
    policy.execute_compaction,
    request.executeCompaction,
    request.execute_compaction,
  );
  const action =
    selectedAction === "approval_required" && approvalGranted
      ? "compact"
      : selectedAction === "compact" && approvalRequired && !approvalGranted
        ? "approval_required"
        : selectedAction;
  const approvalSatisfied = !approvalRequired || approvalGranted;
  const continuationAllowed = action !== "stop";
  const workflowGraphId =
    optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
  const workflowNodeId =
    optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
    "runtime.compaction-policy";
  const compactWorkflowNodeId =
    optionalString(
      policy.compactWorkflowNodeId ??
        policy.compact_workflow_node_id ??
        request.compactWorkflowNodeId ??
        request.compact_workflow_node_id,
    ) ?? "runtime.context-compact";
  const contextBudgetSummary =
    optionalString(contextBudget.summary ?? contextBudget.policyDecision?.summary) ??
    `context budget status ${budgetStatus}`;
  const compactReason =
    optionalString(
      policy.compactReason ??
        policy.compact_reason ??
        request.compactReason ??
        request.compact_reason ??
        request.reason,
    ) ?? `Compaction policy ${budgetStatus}: ${contextBudgetSummary}`;
  const compactScope =
    optionalString(policy.compactScope ?? policy.compact_scope ?? request.compactScope ?? request.compact_scope) ??
    "thread";
  const decisionHash = doctorHash(
    JSON.stringify({
      threadId,
      turnId,
      workflowGraphId,
      workflowNodeId,
      budgetStatus,
      selectedAction,
      action,
      approvalRequired,
      approvalGranted,
      executeCompaction,
    }),
  ).slice(0, 16);
  const policyDecisionId = `policy_compaction_${safeId(threadId)}_${decisionHash}_${action}`;
  const receiptId = `receipt_compaction_policy_${safeId(threadId)}_${decisionHash}`;
  const approvalId =
    action === "approval_required"
      ? `approval_compaction_${safeId(threadId)}_${decisionHash}`
      : null;
  const status =
    action === "stop"
      ? "blocked"
      : action === "approval_required"
        ? "waiting"
        : action === "compact"
          ? executeCompaction && approvalSatisfied
            ? "compacted"
            : "compact_pending"
          : action === "warn"
            ? "warn"
            : "ok";
  const summary =
    action === "stop"
      ? "Compaction policy blocked continuation."
      : action === "approval_required"
        ? "Compaction policy requires operator approval before compacting."
        : action === "compact"
          ? executeCompaction
            ? "Compaction policy executed context compaction."
            : "Compaction policy selected context compaction."
          : action === "warn"
            ? "Compaction policy emitted a warning."
            : "Compaction policy allowed continuation.";
  const generatedAt = new Date().toISOString();
  return {
    schema_version: RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
    schemaVersion: RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
    object: "ioi.runtime_compaction_policy",
    status,
    action,
    selected_action: selectedAction,
    selectedAction,
    budget_status: budgetStatus,
    budgetStatus,
    thread_id: threadId,
    threadId,
    turn_id: turnId || null,
    turnId: turnId || null,
    source: optionalString(request.source) ?? "react_flow",
    actor: optionalString(request.actor) ?? "operator",
    event_kind:
      optionalString(request.event_kind ?? request.eventKind) ??
      "RuntimeCompactionPolicy.Evaluate",
    eventKind:
      optionalString(request.eventKind ?? request.event_kind) ??
      "RuntimeCompactionPolicy.Evaluate",
    component_kind: "compaction_policy",
    componentKind: "compaction_policy",
    payload_schema_version: RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
    payloadSchemaVersion: RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
    workflow_graph_id: workflowGraphId,
    workflowGraphId,
    workflow_node_id: workflowNodeId,
    workflowNodeId,
    compact_workflow_node_id: compactWorkflowNodeId,
    compactWorkflowNodeId,
    context_budget: contextBudget,
    contextBudget,
    approval_required: approvalRequired,
    approvalRequired,
    approval_granted: approvalGranted,
    approvalGranted,
    approval_satisfied: approvalSatisfied,
    approvalSatisfied,
    approval_id: approvalId,
    approvalId,
    execute_compaction: executeCompaction,
    executeCompaction,
    compaction_requested: action === "compact",
    compactionRequested: action === "compact",
    compaction_executed: false,
    compactionExecuted: false,
    compaction_event_id: null,
    compactionEventId: null,
    compaction_seq: null,
    compactionSeq: null,
    compact_reason: compactReason,
    compactReason,
    compact_scope: compactScope,
    compactScope,
    continuation_allowed: continuationAllowed,
    continuationAllowed,
    receipt_refs: [receiptId],
    receiptRefs: [receiptId],
    policy_decision_refs: [policyDecisionId],
    policyDecisionRefs: [policyDecisionId],
    policy_decision_id: policyDecisionId,
    policyDecisionId,
    summary,
    generated_at: generatedAt,
    generatedAt,
  };
}

export function compactionPolicyBudgetStatus(...values) {
  const status = values
    .map((value) => optionalString(value)?.toLowerCase())
    .find(Boolean);
  if (status === "blocked" || status === "block") return "blocked";
  if (status === "warn" || status === "warning") return "warn";
  return "ok";
}

export function compactionPolicyAction(value, fallback) {
  const action = optionalString(value)?.toLowerCase();
  if (
    action === "noop" ||
    action === "warn" ||
    action === "compact" ||
    action === "stop" ||
    action === "approval_required"
  ) {
    return action;
  }
  return fallback;
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

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
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

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
