export const RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION =
  "ioi.runtime.subagent-manager.v1";
export const RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION =
  "ioi.runtime.subagent-result.v1";
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

export function subagentIsActive(record = {}) {
  return ["queued", "running", "waiting_for_input", "interrupted"].includes(
    record.lifecycle_status ?? record.lifecycleStatus ?? record.status,
  );
}

export function subagentBudgetForRequest(request = {}) {
  const budget = request.budget ?? request.subagentBudget ?? request.options?.budget ?? null;
  return budget && typeof budget === "object" && !Array.isArray(budget) ? budget : null;
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
    status: lifecycleStatusForRun(run.status ?? record?.status),
    lifecycle_status: lifecycleStatusForRun(run.status ?? record?.status),
    lifecycleStatus: lifecycleStatusForRun(run.status ?? record?.status),
    result: run.result ?? "",
    output,
    output_contract_status: outputContractStatus?.status ?? null,
    outputContractStatus: outputContractStatus ?? null,
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
    merge_policy: record.merge_policy ?? record.mergePolicy ?? null,
    mergePolicy: record.mergePolicy ?? record.merge_policy ?? null,
    cancellation_inheritance: record.cancellation_inheritance ?? record.cancellationInheritance ?? null,
    cancellationInheritance: record.cancellationInheritance ?? record.cancellation_inheritance ?? null,
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
      return "waiting_for_input";
    case "completed":
    default:
      return "completed";
  }
}
