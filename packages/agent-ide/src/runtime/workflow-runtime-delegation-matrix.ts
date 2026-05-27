import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_DELEGATION_MATRIX_SCHEMA_VERSION =
  "ioi.workflow.delegation-matrix.v1" as const;

export type WorkflowRuntimeDelegationMatrixRowKind =
  | "subagent_lane"
  | "memory_scope";

export interface WorkflowRuntimeDelegationMatrixOptions {
  threadId?: string | null;
  workflowGraphId?: string | null;
}

export interface WorkflowRuntimeDelegationMatrixRow {
  rowKind: WorkflowRuntimeDelegationMatrixRowKind;
  status: string;
  eventId: string | null;
  eventSeq: number | null;
  eventKind: string;
  operation: string | null;
  threadId: string | null;
  parentThreadId: string | null;
  parentTurnId: string | null;
  childThreadId: string | null;
  childRunId: string | null;
  subagentId: string | null;
  role: string | null;
  lifecycleStatus: string | null;
  outputContractStatus: string | null;
  mergePolicy: string | null;
  cancellationInheritance: string | null;
  cancellationReason: string | null;
  memoryMode: string | null;
  inheritedMemoryCount: number | null;
  writeBlockReason: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimeDelegationMatrix {
  schemaVersion: typeof WORKFLOW_RUNTIME_DELEGATION_MATRIX_SCHEMA_VERSION;
  status: "empty" | "ready" | "blocked";
  rows: WorkflowRuntimeDelegationMatrixRow[];
  subagentLaneCount: number;
  memoryScopeCount: number;
  childThreadCount: number;
  manualReviewCount: number;
  cancellationIsolatedCount: number;
  cancellationPropagatedCount: number;
  writeBlockedCount: number;
  writeAllowedCount: number;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  eventIds: string[];
}

type RuntimeEventInput = WorkflowRuntimeThreadEventLike | Record<string, unknown>;

export function buildWorkflowRuntimeDelegationMatrix(
  events: readonly RuntimeEventInput[],
  options: WorkflowRuntimeDelegationMatrixOptions = {},
): WorkflowRuntimeDelegationMatrix {
  const threadFilter = cleanString(options.threadId);
  const graphFilter = cleanString(options.workflowGraphId);
  const rows = [...events]
    .filter((event) => {
      const threadId = eventThreadId(event);
      const graphId = eventWorkflowGraphId(event);
      return (
        (!threadFilter || !threadId || threadId === threadFilter) &&
        (!graphFilter || !graphId || graphId === graphFilter)
      );
    })
    .sort((left, right) => eventSeq(left) - eventSeq(right))
    .map((event) => delegationMatrixRowForEvent(event))
    .filter((row): row is WorkflowRuntimeDelegationMatrixRow => Boolean(row));

  const subagentRows = rows.filter((row) => row.rowKind === "subagent_lane");
  const memoryRows = rows.filter((row) => row.rowKind === "memory_scope");
  const writeBlockedCount = memoryRows.filter((row) => Boolean(row.writeBlockReason)).length;
  const writeAllowedCount = memoryRows.filter((row) => row.writeBlockReason === null && row.memoryMode === "full").length;
  return {
    schemaVersion: WORKFLOW_RUNTIME_DELEGATION_MATRIX_SCHEMA_VERSION,
    status: rows.length === 0 ? "empty" : subagentRows.some((row) => row.status === "blocked") ? "blocked" : "ready",
    rows,
    subagentLaneCount: uniqueStrings(subagentRows.map((row) => row.subagentId)).length,
    memoryScopeCount: memoryRows.length,
    childThreadCount: uniqueStrings(subagentRows.map((row) => row.childThreadId)).length,
    manualReviewCount: subagentRows.filter((row) => row.mergePolicy === "manual_review").length,
    cancellationIsolatedCount: subagentRows.filter((row) => row.cancellationInheritance === "isolate").length,
    cancellationPropagatedCount: subagentRows.filter((row) => row.cancellationInheritance === "propagate").length,
    writeBlockedCount,
    writeAllowedCount,
    receiptRefs: uniqueStrings(rows.flatMap((row) => row.receiptRefs)),
    policyDecisionRefs: uniqueStrings(rows.flatMap((row) => row.policyDecisionRefs)),
    eventIds: uniqueStrings(rows.map((row) => row.eventId)),
  };
}

function delegationMatrixRowForEvent(
  event: RuntimeEventInput,
): WorkflowRuntimeDelegationMatrixRow | null {
  const payload = eventPayload(event);
  const payloadObject = stringField(payload, "object");
  const payloadEventKind = stringField(payload, "eventKind", "event_kind");
  if (payloadObject === "ioi.runtime_subagent_manager_event") {
    return baseRow(event, payload, {
      rowKind: "subagent_lane",
      status: stringField(payload, "lifecycleStatus", "lifecycle_status") ?? eventStatus(event) ?? "unknown",
      operation: stringField(payload, "operation"),
      parentThreadId: stringField(payload, "parentThreadId", "parent_thread_id"),
      parentTurnId: stringField(payload, "parentTurnId", "parent_turn_id"),
      childThreadId: stringField(payload, "childThreadId", "child_thread_id"),
      childRunId: stringField(payload, "runId", "run_id"),
      subagentId: stringField(payload, "subagentId", "subagent_id"),
      role: stringField(payload, "role"),
      lifecycleStatus: stringField(payload, "lifecycleStatus", "lifecycle_status"),
      outputContractStatus: outputContractStatus(payload),
      mergePolicy: stringField(payload, "mergePolicy", "merge_policy"),
      cancellationInheritance: stringField(payload, "cancellationInheritance", "cancellation_inheritance"),
      cancellationReason: stringField(payload, "cancellationReason", "cancellation_reason"),
    });
  }
  if (payloadEventKind === "SubagentMemoryInheritance") {
    const effectivePolicy = objectField(payload, "effectivePolicy", "effective_policy");
    return baseRow(event, payload, {
      rowKind: "memory_scope",
      status: memoryWriteBlockReason(payload) ? "blocked" : "ready",
      operation: "subagent_inheritance",
      parentThreadId: stringField(payload, "threadId", "thread_id"),
      role: stringField(payload, "subagentName", "subagent_name"),
      memoryMode: stringField(payload, "mode", "subagentInheritance", "subagent_inheritance_mode"),
      inheritedMemoryCount:
        numberField(payload, "inheritedMemoryCount", "inherited_memory_count") ??
        arrayField(payload, "inheritedRecordIds", "inherited_record_ids").length,
      writeBlockReason: memoryWriteBlockReason(payload),
      cancellationInheritance: stringField(effectivePolicy, "subagentInheritance", "subagent_inheritance"),
    });
  }
  return null;
}

function baseRow(
  event: RuntimeEventInput,
  payload: Record<string, unknown>,
  overrides: Partial<WorkflowRuntimeDelegationMatrixRow>,
): WorkflowRuntimeDelegationMatrixRow {
  return {
    rowKind: overrides.rowKind ?? "subagent_lane",
    status: overrides.status ?? eventStatus(event) ?? "unknown",
    eventId: eventIdForRuntimeEvent(event),
    eventSeq: eventSeq(event),
    eventKind: eventKind(event),
    operation: overrides.operation ?? null,
    threadId: eventThreadId(event),
    parentThreadId: overrides.parentThreadId ?? null,
    parentTurnId: overrides.parentTurnId ?? null,
    childThreadId: overrides.childThreadId ?? null,
    childRunId: overrides.childRunId ?? null,
    subagentId: overrides.subagentId ?? null,
    role: overrides.role ?? null,
    lifecycleStatus: overrides.lifecycleStatus ?? null,
    outputContractStatus: overrides.outputContractStatus ?? null,
    mergePolicy: overrides.mergePolicy ?? null,
    cancellationInheritance: overrides.cancellationInheritance ?? null,
    cancellationReason: overrides.cancellationReason ?? null,
    memoryMode: overrides.memoryMode ?? null,
    inheritedMemoryCount: overrides.inheritedMemoryCount ?? null,
    writeBlockReason: overrides.writeBlockReason ?? null,
    workflowGraphId: eventWorkflowGraphId(event),
    workflowNodeId: eventWorkflowNodeId(event),
    receiptRefs: uniqueStrings([
      ...arrayField(event, "receiptRefs", "receipt_refs"),
      ...arrayField(payload, "receiptRefs", "receipt_refs"),
      ...arrayField(payload, "sourceReceiptRefs", "source_receipt_refs"),
    ]),
    policyDecisionRefs: uniqueStrings([
      ...arrayField(event, "policyDecisionRefs", "policy_decision_refs"),
      ...arrayField(payload, "policyDecisionRefs", "policy_decision_refs"),
      ...arrayField(payload, "sourcePolicyDecisionRefs", "source_policy_decision_refs"),
    ]),
  };
}

function memoryWriteBlockReason(payload: Record<string, unknown>): string | null {
  return stringField(
    payload,
    "writeBlockReason",
    "write_block_reason",
    "writeBlockedReason",
    "write_blocked_reason",
  );
}

function outputContractStatus(payload: Record<string, unknown>): string | null {
  const objectStatus = objectField(payload, "outputContractStatus", "output_contract_status");
  return stringField(objectStatus, "status") ?? stringField(payload, "outputContractStatus", "output_contract_status");
}

function eventPayload(event: RuntimeEventInput): Record<string, unknown> {
  const record = event as Record<string, unknown>;
  return objectValue(record.payload_summary) ?? objectValue(record.payload) ?? {};
}

function objectField(record: Record<string, unknown>, ...keys: string[]): Record<string, unknown> {
  for (const key of keys) {
    const object = objectValue(record[key]);
    if (object) return object;
  }
  return {};
}

function objectValue(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function stringField(record: unknown, ...keys: string[]): string | null {
  const object = objectValue(record);
  if (!object) return null;
  for (const key of keys) {
    const value = object[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    if (typeof value === "boolean") return String(value);
  }
  return null;
}

function numberField(record: unknown, ...keys: string[]): number | null {
  const object = objectValue(record);
  if (!object) return null;
  for (const key of keys) {
    const value = object[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim()) {
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
  }
  return null;
}

function arrayField(record: unknown, ...keys: string[]): string[] {
  const object = objectValue(record);
  if (!object) return [];
  for (const key of keys) {
    const value = object[key];
    if (Array.isArray(value)) {
      return value
        .map((item) => cleanString(item))
        .filter((item): item is string => Boolean(item));
    }
  }
  return [];
}

function eventIdForRuntimeEvent(event: RuntimeEventInput): string | null {
  return stringField(event, "event_id", "eventId", "id");
}

function eventKind(event: RuntimeEventInput): string {
  return stringField(event, "eventKind", "event_kind", "event") ?? "";
}

function eventStatus(event: RuntimeEventInput): string | null {
  return stringField(event, "status");
}

function eventSeq(event: RuntimeEventInput): number {
  return numberField(event, "seq") ?? 0;
}

function eventThreadId(event: RuntimeEventInput): string | null {
  return stringField(event, "threadId", "thread_id");
}

function eventWorkflowGraphId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflowGraphId", "workflow_graph_id");
}

function eventWorkflowNodeId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflowNodeId", "workflow_node_id");
}

function cleanString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(values.map((value) => cleanString(value)).filter((value): value is string => Boolean(value))),
  );
}
