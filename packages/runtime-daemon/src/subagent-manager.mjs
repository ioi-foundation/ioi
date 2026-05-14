export const RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION =
  "ioi.runtime.subagent-manager.v1";
export const RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION =
  "ioi.runtime.subagent-result.v1";
export const RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION =
  "ioi.runtime.subagent-budget-status.v1";
export const RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT = [
  "SUMMARY",
  "CHANGES",
  "EVIDENCE",
  "RISKS",
  "BLOCKERS",
  "RECEIPTS",
];

export function normalizeSubagentRole(value) {
  const role = optionalString(value)?.toLowerCase();
  return role ?? "general";
}

export function optionalPositiveInteger(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : null;
}

export function optionalPositiveNumber(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

export function subagentIsActive(record = {}) {
  return ["queued", "running", "waiting_for_input", "interrupted"].includes(
    record.lifecycle_status ?? record.lifecycleStatus ?? record.status,
  );
}

export function subagentBudgetForRequest(request = {}) {
  const budget = request.budget ?? request.subagentBudget ?? request.options?.budget ?? null;
  return budget && typeof budget === "object" && !Array.isArray(budget) ? budget : null;
}

export function subagentBudgetUsageTelemetryForRequest(request = {}) {
  return normalizeSubagentBudgetUsageTelemetry(
    request.budget_usage_telemetry ??
      request.budgetUsageTelemetry ??
      request.runtime_telemetry_summary ??
      request.runtimeTelemetrySummary ??
      request.options?.budget_usage_telemetry ??
      request.options?.budgetUsageTelemetry ??
      null,
  );
}

export function normalizeSubagentBudgetUsageTelemetry(usage = null) {
  if (!usage || typeof usage !== "object" || Array.isArray(usage)) return null;
  const inputTokens =
    optionalPositiveInteger(
      usage.cumulative_input_tokens ??
        usage.cumulativeInputTokens ??
        usage.input_tokens ??
        usage.inputTokens,
    ) ?? 0;
  const outputTokens =
    optionalPositiveInteger(
      usage.cumulative_output_tokens ??
        usage.cumulativeOutputTokens ??
        usage.output_tokens ??
        usage.outputTokens,
    ) ?? 0;
  const totalTokens =
    optionalPositiveInteger(
      usage.cumulative_total_tokens ??
        usage.cumulativeTotalTokens ??
        usage.total_tokens ??
        usage.totalTokens,
    ) ??
    inputTokens + outputTokens;
  const costEstimateUsd =
    optionalPositiveNumber(
      usage.cumulative_cost_estimate_usd ??
        usage.cumulativeCostEstimateUsd ??
        usage.cost_estimate_usd ??
        usage.costEstimateUsd ??
        usage.estimated_cost_usd ??
        usage.estimatedCostUsd,
    ) ?? 0;
  return {
    schema_version: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_previous_usage_telemetry",
    cumulative_input_tokens: inputTokens,
    cumulativeInputTokens: inputTokens,
    cumulative_output_tokens: outputTokens,
    cumulativeOutputTokens: outputTokens,
    cumulative_total_tokens: totalTokens,
    cumulativeTotalTokens: totalTokens,
    cumulative_cost_estimate_usd: roundUsd(costEstimateUsd),
    cumulativeCostEstimateUsd: roundUsd(costEstimateUsd),
    source_counts: usage.source_counts ?? usage.sourceCounts ?? null,
    sourceCounts: usage.sourceCounts ?? usage.source_counts ?? null,
    source_refs: normalizeArray(usage.source_refs ?? usage.sourceRefs),
    sourceRefs: normalizeArray(usage.sourceRefs ?? usage.source_refs),
    receipt_refs: normalizeArray(usage.receipt_refs ?? usage.receiptRefs),
    receiptRefs: normalizeArray(usage.receiptRefs ?? usage.receipt_refs),
    policy_decision_refs: normalizeArray(
      usage.policy_decision_refs ?? usage.policyDecisionRefs,
    ),
    policyDecisionRefs: normalizeArray(
      usage.policyDecisionRefs ?? usage.policy_decision_refs,
    ),
    runtime_telemetry_summary_schema_version:
      usage.runtime_telemetry_summary_schema_version ??
      usage.runtimeTelemetrySummarySchemaVersion ??
      null,
    runtimeTelemetrySummarySchemaVersion:
      usage.runtimeTelemetrySummarySchemaVersion ??
      usage.runtime_telemetry_summary_schema_version ??
      null,
  };
}

export function normalizeSubagentBudget(budget = null) {
  if (!budget || typeof budget !== "object" || Array.isArray(budget)) return null;
  const maxTokens = optionalPositiveInteger(
    budget.maxTokens ??
      budget.max_tokens ??
      budget.maxTotalTokens ??
      budget.max_total_tokens ??
      budget.tokenLimit ??
      budget.token_limit,
  );
  const maxInputTokens = optionalPositiveInteger(
    budget.maxInputTokens ?? budget.max_input_tokens,
  );
  const maxOutputTokens = optionalPositiveInteger(
    budget.maxOutputTokens ?? budget.max_output_tokens,
  );
  const maxCostUsd = optionalPositiveNumber(
    budget.maxCostUsd ?? budget.max_cost_usd ?? budget.costLimitUsd ?? budget.cost_limit_usd,
  );
  const hasCap = Boolean(maxTokens || maxInputTokens || maxOutputTokens || maxCostUsd);
  return {
    schema_version: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_budget",
    configured: hasCap,
    max_tokens: maxTokens,
    maxTokens,
    max_input_tokens: maxInputTokens,
    maxInputTokens,
    max_output_tokens: maxOutputTokens,
    maxOutputTokens,
    max_cost_usd: maxCostUsd,
    maxCostUsd,
    currency: optionalString(budget.currency) ?? "USD",
    raw_keys: Object.keys(budget).sort(),
    rawKeys: Object.keys(budget).sort(),
  };
}

export function subagentUsageTelemetryForRun(run = {}, prompt = "", previousUsage = {}) {
  const inputTokens = estimatedTokenCount(prompt);
  const outputTokens = estimatedTokenCount(run.result ?? "");
  const totalTokens = inputTokens + outputTokens;
  const previousInputTokens = optionalPositiveInteger(
    previousUsage.cumulative_input_tokens ??
      previousUsage.cumulativeInputTokens ??
      previousUsage.input_tokens ??
      previousUsage.inputTokens,
  ) ?? 0;
  const previousOutputTokens = optionalPositiveInteger(
    previousUsage.cumulative_output_tokens ??
      previousUsage.cumulativeOutputTokens ??
      previousUsage.output_tokens ??
      previousUsage.outputTokens,
  ) ?? 0;
  const previousTotalTokens = optionalPositiveInteger(
    previousUsage.cumulative_total_tokens ??
      previousUsage.cumulativeTotalTokens ??
      previousUsage.total_tokens ??
      previousUsage.totalTokens,
  ) ?? 0;
  const costEstimateUsd = costEstimateUsdForRun(run, totalTokens);
  const previousCostEstimateUsd = optionalPositiveNumber(
    previousUsage.cumulative_cost_estimate_usd ??
      previousUsage.cumulativeCostEstimateUsd ??
      previousUsage.cost_estimate_usd ??
      previousUsage.costEstimateUsd ??
      previousUsage.estimated_cost_usd ??
      previousUsage.estimatedCostUsd,
  ) ?? 0;
  return {
    schema_version: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_usage_telemetry",
    run_id: run.id ?? null,
    runId: run.id ?? null,
    estimated: true,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    total_tokens: totalTokens,
    totalTokens,
    cumulative_input_tokens: previousInputTokens + inputTokens,
    cumulativeInputTokens: previousInputTokens + inputTokens,
    cumulative_output_tokens: previousOutputTokens + outputTokens,
    cumulativeOutputTokens: previousOutputTokens + outputTokens,
    cumulative_total_tokens: previousTotalTokens + totalTokens,
    cumulativeTotalTokens: previousTotalTokens + totalTokens,
    cost_estimate_usd: costEstimateUsd,
    costEstimateUsd,
    cumulative_cost_estimate_usd: roundUsd(previousCostEstimateUsd + costEstimateUsd),
    cumulativeCostEstimateUsd: roundUsd(previousCostEstimateUsd + costEstimateUsd),
    model_route_id: run.modelRouteDecision?.routeId ?? run.modelRouteDecision?.route_id ?? null,
    modelRouteId: run.modelRouteDecision?.routeId ?? run.modelRouteDecision?.route_id ?? null,
  };
}

export function subagentBudgetStatusForRun({
  budget = null,
  run = {},
  prompt = "",
  previousUsage = {},
} = {}) {
  const normalizedBudget = normalizeSubagentBudget(budget);
  const usage = subagentUsageTelemetryForRun(run, prompt, previousUsage);
  const violations = [];
  if (normalizedBudget?.max_tokens && usage.cumulative_total_tokens > normalizedBudget.max_tokens) {
    violations.push(budgetViolation("max_tokens", normalizedBudget.max_tokens, usage.cumulative_total_tokens));
  }
  if (
    normalizedBudget?.max_input_tokens &&
    usage.cumulative_input_tokens > normalizedBudget.max_input_tokens
  ) {
    violations.push(budgetViolation("max_input_tokens", normalizedBudget.max_input_tokens, usage.cumulative_input_tokens));
  }
  if (
    normalizedBudget?.max_output_tokens &&
    usage.cumulative_output_tokens > normalizedBudget.max_output_tokens
  ) {
    violations.push(budgetViolation("max_output_tokens", normalizedBudget.max_output_tokens, usage.cumulative_output_tokens));
  }
  if (
    normalizedBudget?.max_cost_usd &&
    usage.cumulative_cost_estimate_usd > normalizedBudget.max_cost_usd
  ) {
    violations.push(
      budgetViolation(
        "max_cost_usd",
        normalizedBudget.max_cost_usd,
        usage.cumulative_cost_estimate_usd,
      ),
    );
  }
  const status = !normalizedBudget?.configured
    ? "not_configured"
    : violations.length
      ? "exceeded"
      : "within_budget";
  const checkedAt = new Date().toISOString();
  const policyDecision = {
    schema_version: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    id: `policy_subagent_budget_${safePolicyId(run.id ?? "runless")}_${status}`,
    status: status === "exceeded" ? "blocked" : "allow",
    reason: status === "exceeded" ? "subagent_budget_exceeded" : "subagent_budget_within_limit",
    violated_caps: violations.map((violation) => violation.cap),
    violatedCaps: violations.map((violation) => violation.cap),
  };
  return {
    schema_version: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_BUDGET_STATUS_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_budget_status",
    status,
    budget: normalizedBudget,
    usage,
    violations,
    policy_decision: policyDecision,
    policyDecision,
    checked_at: checkedAt,
    checkedAt,
  };
}

export function subagentCancellationPropagates(record = {}) {
  return normalizeSubagentCancellationInheritance(
    record.cancellation_inheritance ?? record.cancellationInheritance,
  ) === "propagate";
}

export function normalizeSubagentCancellationInheritance(value) {
  const mode = optionalString(value)?.toLowerCase();
  return mode ?? "propagate";
}

export function normalizeSubagentOutputContract(value) {
  const raw = value?.sections ?? value?.requiredSections ?? value ?? RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT;
  const sections = normalizeArray(raw)
    .map((section) => optionalString(section))
    .filter(Boolean);
  return sections.length ? sections : [...RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT];
}

export function subagentContractOutputForRun(
  run = {},
  outputContract = RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT,
) {
  const evidenceRefs = uniqueStrings([
    ...normalizeArray(run.trace?.taskState?.evidenceRefs),
    ...normalizeArray(run.trace?.qualityLedger?.failureOntologyLabels),
    ...normalizeArray(run.receipts).map((receipt) => receipt.id),
  ]);
  const sections = {
    SUMMARY: run.result ?? "",
    CHANGES: normalizeArray(run.trace?.taskState?.changedObjects),
    EVIDENCE: evidenceRefs,
    RISKS: normalizeArray(run.trace?.taskState?.uncertainFacts),
    BLOCKERS: normalizeArray(run.trace?.taskState?.blockers),
    RECEIPTS: normalizeArray(run.receipts).map((receipt) => receipt.id),
  };
  const requiredSections = normalizeSubagentOutputContract(outputContract);
  return {
    schema_version: RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_output_contract",
    required_sections: requiredSections,
    requiredSections,
    sections,
    text: run.result ?? "",
  };
}

export function validateSubagentOutputContract(
  output = {},
  outputContract = RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT,
) {
  const requiredSections = normalizeSubagentOutputContract(outputContract);
  const sectionMap = output.sections && typeof output.sections === "object" ? output.sections : {};
  const presentSections = requiredSections.filter((section) => Object.hasOwn(sectionMap, section));
  const missingSections = requiredSections.filter((section) => !Object.hasOwn(sectionMap, section));
  return {
    schema_version: "ioi.runtime.subagent-output-contract-status.v1",
    schemaVersion: "ioi.runtime.subagent-output-contract-status.v1",
    status: missingSections.length ? "failed" : "passed",
    required_sections: requiredSections,
    requiredSections,
    present_sections: presentSections,
    presentSections,
    missing_sections: missingSections,
    missingSections,
    validated_at: new Date().toISOString(),
    validatedAt: new Date().toISOString(),
  };
}

export function subagentResultForRun({ record, run = {}, output, outputContractStatus } = {}) {
  const subagentId = record?.subagent_id ?? record?.subagentId ?? record?.agent_id ?? record?.agentId ?? null;
  const lifecycleStatus = lifecycleStatusForRun(
    record?.lifecycle_status ?? record?.lifecycleStatus ?? record?.status ?? run.status,
  );
  return {
    schema_version: RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_result",
    subagent_id: subagentId,
    subagentId,
    agent_id: record?.agent_id ?? record?.agentId ?? run.agentId ?? null,
    agentId: record?.agentId ?? record?.agent_id ?? run.agentId ?? null,
    run_id: run.id ?? record?.run_id ?? record?.runId ?? null,
    runId: run.id ?? record?.runId ?? record?.run_id ?? null,
    status: lifecycleStatus,
    lifecycle_status: lifecycleStatus,
    lifecycleStatus,
    result: run.result ?? "",
    output,
    output_contract_status: outputContractStatus?.status ?? null,
    outputContractStatus: outputContractStatus ?? null,
    budget_status: record?.budget_status ?? record?.budgetStatus?.status ?? null,
    budgetStatus: record?.budgetStatus ?? record?.budget_status ?? null,
    usage_telemetry: record?.usage_telemetry ?? record?.usageTelemetry ?? null,
    usageTelemetry: record?.usageTelemetry ?? record?.usage_telemetry ?? null,
    receipt_refs: uniqueStrings([
      ...normalizeArray(record?.receipt_refs ?? record?.receiptRefs),
      ...normalizeArray(run.receipts).map((receipt) => receipt.id),
    ]),
    receiptRefs: uniqueStrings([
      ...normalizeArray(record?.receiptRefs ?? record?.receipt_refs),
      ...normalizeArray(run.receipts).map((receipt) => receipt.id),
    ]),
  };
}

export function subagentManagerEventPayload({ record = {}, operation, status }) {
  return {
    schema_version: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
    schemaVersion: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
    object: "ioi.runtime_subagent_manager_event",
    event_kind: subagentOperatorControlKind(operation),
    eventKind: subagentOperatorControlKind(operation),
    operation,
    thread_id: record.parent_thread_id ?? record.parentThreadId ?? null,
    threadId: record.parentThreadId ?? record.parent_thread_id ?? null,
    parent_thread_id: record.parent_thread_id ?? record.parentThreadId ?? null,
    parentThreadId: record.parentThreadId ?? record.parent_thread_id ?? null,
    parent_turn_id: record.parent_turn_id ?? record.parentTurnId ?? null,
    parentTurnId: record.parentTurnId ?? record.parent_turn_id ?? null,
    subagent_id: record.subagent_id ?? record.subagentId ?? null,
    subagentId: record.subagentId ?? record.subagent_id ?? null,
    agent_id: record.agent_id ?? record.agentId ?? null,
    agentId: record.agentId ?? record.agent_id ?? null,
    run_id: record.run_id ?? record.runId ?? null,
    runId: record.runId ?? record.run_id ?? null,
    role: record.role ?? "general",
    tool_pack: record.tool_pack ?? record.toolPack ?? null,
    toolPack: record.toolPack ?? record.tool_pack ?? null,
    model_route_id: record.model_route_id ?? record.modelRouteId ?? null,
    modelRouteId: record.modelRouteId ?? record.model_route_id ?? null,
    lifecycle_status: status ?? record.lifecycle_status ?? record.lifecycleStatus ?? record.status,
    lifecycleStatus: status ?? record.lifecycleStatus ?? record.lifecycle_status ?? record.status,
    output_contract_status:
      record.output_contract_status ??
      record.outputContractStatus?.status ??
      record.output_contract_validation?.status ??
      null,
    outputContractStatus:
      record.outputContractStatus ??
      record.output_contract_validation ??
      record.output_contract_status ??
      null,
    max_concurrency: record.max_concurrency ?? record.maxConcurrency ?? null,
    maxConcurrency: record.maxConcurrency ?? record.max_concurrency ?? null,
    budget_status: record.budget_status ?? record.budgetStatus?.status ?? null,
    budgetStatus: record.budgetStatus ?? record.budget_status ?? null,
    usage_telemetry: record.usage_telemetry ?? record.usageTelemetry ?? null,
    usageTelemetry: record.usageTelemetry ?? record.usage_telemetry ?? null,
    cost_estimate_usd:
      record.usage_telemetry?.cumulative_cost_estimate_usd ??
      record.usageTelemetry?.cumulativeCostEstimateUsd ??
      null,
    costEstimateUsd:
      record.usageTelemetry?.cumulativeCostEstimateUsd ??
      record.usage_telemetry?.cumulative_cost_estimate_usd ??
      null,
    token_estimate:
      record.usage_telemetry?.cumulative_total_tokens ??
      record.usageTelemetry?.cumulativeTotalTokens ??
      null,
    tokenEstimate:
      record.usageTelemetry?.cumulativeTotalTokens ??
      record.usage_telemetry?.cumulative_total_tokens ??
      null,
    merge_policy: record.merge_policy ?? record.mergePolicy ?? null,
    mergePolicy: record.mergePolicy ?? record.merge_policy ?? null,
    cancellation_inheritance: record.cancellation_inheritance ?? record.cancellationInheritance ?? null,
    cancellationInheritance: record.cancellationInheritance ?? record.cancellation_inheritance ?? null,
    context_pressure_action:
      record.context_pressure_action ?? record.contextPressureAction ?? null,
    contextPressureAction:
      record.contextPressureAction ?? record.context_pressure_action ?? null,
    context_pressure:
      record.context_pressure ?? record.contextPressure ?? record.pressure ?? null,
    contextPressure:
      record.contextPressure ?? record.context_pressure ?? record.pressure ?? null,
    pressure: record.pressure ?? record.context_pressure ?? record.contextPressure ?? null,
    pressure_status: record.pressure_status ?? record.pressureStatus ?? null,
    pressureStatus: record.pressureStatus ?? record.pressure_status ?? null,
    alert_id: record.alert_id ?? record.alertId ?? null,
    alertId: record.alertId ?? record.alert_id ?? null,
    source_event_id: record.source_event_id ?? record.sourceEventId ?? null,
    sourceEventId: record.sourceEventId ?? record.source_event_id ?? null,
    source_receipt_refs: uniqueStrings(
      record.source_receipt_refs ?? record.sourceReceiptRefs,
    ),
    sourceReceiptRefs: uniqueStrings(
      record.sourceReceiptRefs ?? record.source_receipt_refs,
    ),
    source_policy_decision_refs:
      uniqueStrings(
        record.source_policy_decision_refs ?? record.sourcePolicyDecisionRefs,
      ),
    sourcePolicyDecisionRefs:
      uniqueStrings(
        record.sourcePolicyDecisionRefs ?? record.source_policy_decision_refs,
      ),
    input_id: record.input_id ?? record.inputId ?? null,
    inputId: record.inputId ?? record.input_id ?? null,
    input_count: record.input_count ?? record.inputCount ?? null,
    inputCount: record.inputCount ?? record.input_count ?? null,
    cancellation_reason: record.cancellation_reason ?? record.cancellationReason ?? record.cancellation?.reason ?? null,
    cancellationReason: record.cancellationReason ?? record.cancellation_reason ?? record.cancellation?.reason ?? null,
    cancellation_inherited:
      record.cancellation_inherited ?? record.cancellationInherited ?? record.cancellation?.inherited ?? null,
    cancellationInherited:
      record.cancellationInherited ?? record.cancellation_inherited ?? record.cancellation?.inherited ?? null,
    propagated_from_thread_id:
      record.propagated_from_thread_id ?? record.propagatedFromThreadId ?? record.cancellation?.propagated_from_thread_id ?? null,
    propagatedFromThreadId:
      record.propagatedFromThreadId ?? record.propagated_from_thread_id ?? record.cancellation?.propagatedFromThreadId ?? null,
    restart_status: record.restart_status ?? record.restartStatus ?? null,
    restartStatus: record.restartStatus ?? record.restart_status ?? null,
    restart_count: record.restart_count ?? record.restartCount ?? null,
    restartCount: record.restartCount ?? record.restart_count ?? null,
    resume_id: record.resume_id ?? record.resumeId ?? null,
    resumeId: record.resumeId ?? record.resume_id ?? null,
    assignment_id: record.assignment_id ?? record.assignmentId ?? null,
    assignmentId: record.assignmentId ?? record.assignment_id ?? null,
    assignment_count: record.assignment_count ?? record.assignmentCount ?? null,
    assignmentCount: record.assignmentCount ?? record.assignment_count ?? null,
    target_agent_id: record.target_agent_id ?? record.targetAgentId ?? null,
    targetAgentId: record.targetAgentId ?? record.target_agent_id ?? null,
  };
}

export function subagentOperatorControlKind(operation) {
  switch (operation) {
    case "spawn":
      return "OperatorControl.SubagentSpawn";
    case "wait":
      return "OperatorControl.SubagentWait";
    case "result":
      return "OperatorControl.SubagentResult";
    case "send_input":
      return "OperatorControl.SubagentSendInput";
    case "cancel":
      return "OperatorControl.SubagentCancel";
    case "resume":
      return "OperatorControl.SubagentResume";
    case "assign":
      return "OperatorControl.SubagentAssign";
    default:
      return "OperatorControl.SubagentList";
  }
}

export function subagentRuntimeEventKind(operation) {
  switch (operation) {
    case "spawn":
      return "subagent.spawned";
    case "wait":
      return "subagent.wait_completed";
    case "result":
      return "subagent.result_read";
    case "send_input":
      return "subagent.input_sent";
    case "cancel":
      return "subagent.canceled";
    case "resume":
      return "subagent.resumed";
    case "assign":
      return "subagent.assigned";
    default:
      return "subagent.listed";
  }
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function estimatedTokenCount(value) {
  const text = String(value ?? "").trim();
  return text ? Math.max(1, Math.ceil(text.length / 4)) : 0;
}

function costEstimateUsdForRun(run = {}, totalTokens = 0) {
  const decisionCost = optionalPositiveNumber(
    run.modelRouteDecision?.costEstimateUsd ?? run.modelRouteDecision?.cost_estimate_usd,
  );
  if (decisionCost !== null) return roundUsd(decisionCost);
  return roundUsd(totalTokens * 0.000001);
}

function roundUsd(value) {
  return Math.round((Number(value) || 0) * 1_000_000) / 1_000_000;
}

function budgetViolation(cap, limit, observed) {
  return {
    cap,
    limit,
    observed,
    amount_over: roundUsd(observed - limit),
    amountOver: roundUsd(observed - limit),
  };
}

function safePolicyId(value) {
  return String(value ?? "subagent")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "") || "subagent";
}

function lifecycleStatusForRun(status) {
  switch (status) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "canceled":
      return "canceled";
    case "failed":
    case "error":
      return "failed";
    case "blocked":
      return "blocked";
    case "completed":
    default:
      return "completed";
  }
}
