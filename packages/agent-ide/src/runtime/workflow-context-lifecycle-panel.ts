import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export const WORKFLOW_CONTEXT_LIFECYCLE_PANEL_SCHEMA_VERSION =
  "ioi.workflow.context-lifecycle-panel.v1" as const;

export interface WorkflowContextLifecyclePanelInput {
  events: readonly WorkflowRuntimeThreadEventLike[];
  usageTelemetry?: unknown;
}

export type WorkflowContextLifecycleRowKind =
  | "usage_snapshot"
  | "context_budget"
  | "compaction_policy"
  | "context_compaction";

export interface WorkflowContextLifecycleRow {
  id: string;
  rowKind: WorkflowContextLifecycleRowKind;
  status: string;
  eventId: string | null;
  eventSeq: number | null;
  threadId: string | null;
  turnId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  summary: string | null;
  scope: string | null;
  totalTokens: number | null;
  estimatedCostUsd: number | null;
  contextPressure: number | null;
  maxTotalTokens: number | null;
  maxCostUsd: number | null;
  maxContextPressure: number | null;
  violationIds: string[];
  warningIds: string[];
  action: string | null;
  budgetStatus: string | null;
  approvalRequired: boolean | null;
  approvalSatisfied: boolean | null;
  executeCompaction: boolean | null;
  compactionExecuted: boolean | null;
  compactionEventId: string | null;
  compactReason: string | null;
  compactScope: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowContextLifecyclePanel {
  schemaVersion: typeof WORKFLOW_CONTEXT_LIFECYCLE_PANEL_SCHEMA_VERSION;
  status: "ready" | "needs_evidence" | "blocked";
  totalTokens: number | null;
  contextPressure: number | null;
  budgetStatus: string | null;
  compactionAction: string | null;
  compactionExecuted: boolean;
  blockedBudgetCount: number;
  compactedCount: number;
  missingReceiptCount: number;
  rows: WorkflowContextLifecycleRow[];
  evidenceRefs: string[];
}

export function buildWorkflowContextLifecyclePanel(
  input: WorkflowContextLifecyclePanelInput,
): WorkflowContextLifecyclePanel {
  const events = normalizeArray(input.events).sort((a, b) => eventSeq(a) - eventSeq(b));
  const usageRow = usageSnapshotRow(input.usageTelemetry);
  const rows = [
    ...(usageRow ? [usageRow] : []),
    ...events
      .map(rowForEvent)
      .filter((row): row is WorkflowContextLifecycleRow => Boolean(row)),
  ];
  const budgetRows = rows.filter((row) => row.rowKind === "context_budget");
  const policyRows = rows.filter((row) => row.rowKind === "compaction_policy");
  const compactRows = rows.filter((row) => row.rowKind === "context_compaction");
  const latestBudget = budgetRows.at(-1) ?? null;
  const latestPolicy = policyRows.at(-1) ?? null;
  const latestUsage = [...rows].reverse().find((row) => row.totalTokens !== null) ?? null;
  const blockedBudgetCount = budgetRows.filter((row) => row.status === "blocked").length;
  const compactedCount = compactRows.length;
  const compactionExecuted =
    compactRows.length > 0 ||
    Boolean(latestPolicy?.compactionExecuted);
  const missingReceiptCount = rows.filter(
    (row) => row.rowKind !== "usage_snapshot" && row.receiptRefs.length === 0,
  ).length;
  return {
    schemaVersion: WORKFLOW_CONTEXT_LIFECYCLE_PANEL_SCHEMA_VERSION,
    status:
      missingReceiptCount > 0 || !latestBudget || !latestPolicy
        ? "needs_evidence"
        : blockedBudgetCount > 0 && !compactionExecuted
          ? "blocked"
          : "ready",
    totalTokens: latestUsage?.totalTokens ?? null,
    contextPressure: latestUsage?.contextPressure ?? null,
    budgetStatus: latestBudget?.status ?? null,
    compactionAction: latestPolicy?.action ?? null,
    compactionExecuted,
    blockedBudgetCount,
    compactedCount,
    missingReceiptCount,
    rows,
    evidenceRefs: uniqueStrings(rows.flatMap((row) => row.receiptRefs)),
  };
}

function usageSnapshotRow(value: unknown): WorkflowContextLifecycleRow | null {
  const usage = objectValue(value);
  if (!usage) return null;
  const summary = usageSummary(usage);
  return {
    id: "context-lifecycle-usage-snapshot",
    rowKind: "usage_snapshot",
    status: "completed",
    eventId: null,
    eventSeq: null,
    threadId: stringField(usage, "threadId", "thread_id"),
    turnId: stringField(usage, "turnId", "turn_id"),
    workflowGraphId: stringField(usage, "workflowGraphId", "workflow_graph_id"),
    workflowNodeId: stringField(usage, "workflowNodeId", "workflow_node_id") ?? "runtime.usage-meter",
    summary: "Usage telemetry snapshot",
    scope: stringField(usage, "scope", "usageMeterScope", "usage_meter_scope"),
    totalTokens: summary.totalTokens,
    estimatedCostUsd: summary.estimatedCostUsd,
    contextPressure: summary.contextPressure,
    maxTotalTokens: null,
    maxCostUsd: null,
    maxContextPressure: null,
    violationIds: [],
    warningIds: [],
    action: null,
    budgetStatus: null,
    approvalRequired: null,
    approvalSatisfied: null,
    executeCompaction: null,
    compactionExecuted: null,
    compactionEventId: null,
    compactReason: null,
    compactScope: null,
    receiptRefs: uniqueStrings(arrayField(usage, "receiptRefs", "receipt_refs")),
    policyDecisionRefs: uniqueStrings(arrayField(usage, "policyDecisionRefs", "policy_decision_refs")),
  };
}

function rowForEvent(event: WorkflowRuntimeThreadEventLike): WorkflowContextLifecycleRow | null {
  const componentKind = stringField(event, "componentKind", "component_kind");
  const payload = payloadForEvent(event);
  if (componentKind === "context_budget") return contextBudgetRow(event, payload);
  if (componentKind === "compaction_policy") return compactionPolicyRow(event, payload);
  if (componentKind === "context_compaction") return contextCompactionRow(event, payload);
  return null;
}

function contextBudgetRow(
  event: WorkflowRuntimeThreadEventLike,
  payload: Record<string, unknown>,
): WorkflowContextLifecycleRow {
  const summary = usageSummary(
    objectField(payload, "usageSummary", "usage_summary") ||
      objectField(payload, "usageTelemetry", "usage_telemetry"),
  );
  const thresholds = objectField(payload, "thresholds");
  return baseRow(event, payload, {
    rowKind: "context_budget",
    summary: stringField(payload, "summary"),
    scope: stringField(payload, "scope"),
    totalTokens: summary.totalTokens,
    estimatedCostUsd: summary.estimatedCostUsd,
    contextPressure: summary.contextPressure,
    maxTotalTokens: numberField(thresholds, "maxTotalTokens", "max_total_tokens"),
    maxCostUsd: numberField(thresholds, "maxCostUsd", "max_cost_usd"),
    maxContextPressure: numberField(thresholds, "maxContextPressure", "max_context_pressure"),
    violationIds: arrayField(payload, "violations").map(checkId).filter(Boolean),
    warningIds: arrayField(payload, "warnings").map(checkId).filter(Boolean),
    action: null,
    budgetStatus: stringField(payload, "status"),
    approvalRequired: null,
    approvalSatisfied: null,
    executeCompaction: null,
    compactionExecuted: null,
    compactionEventId: null,
    compactReason: null,
    compactScope: null,
  });
}

function compactionPolicyRow(
  event: WorkflowRuntimeThreadEventLike,
  payload: Record<string, unknown>,
): WorkflowContextLifecycleRow {
  const contextBudget = objectField(payload, "contextBudget", "context_budget");
  const budgetSummary = usageSummary(
    objectField(contextBudget, "usageSummary", "usage_summary") ||
      objectField(contextBudget, "usageTelemetry", "usage_telemetry"),
  );
  return baseRow(event, payload, {
    rowKind: "compaction_policy",
    summary: stringField(payload, "summary"),
    scope: stringField(payload, "compactScope", "compact_scope"),
    totalTokens: budgetSummary.totalTokens,
    estimatedCostUsd: budgetSummary.estimatedCostUsd,
    contextPressure: budgetSummary.contextPressure,
    maxTotalTokens: null,
    maxCostUsd: null,
    maxContextPressure: null,
    violationIds: [],
    warningIds: [],
    action: stringField(payload, "action"),
    budgetStatus: stringField(payload, "budgetStatus", "budget_status"),
    approvalRequired: booleanField(payload, "approvalRequired", "approval_required"),
    approvalSatisfied: booleanField(payload, "approvalSatisfied", "approval_satisfied"),
    executeCompaction: booleanField(payload, "executeCompaction", "execute_compaction"),
    compactionExecuted: booleanField(payload, "compactionExecuted", "compaction_executed"),
    compactionEventId: stringField(payload, "compactionEventId", "compaction_event_id"),
    compactReason: stringField(payload, "compactReason", "compact_reason"),
    compactScope: stringField(payload, "compactScope", "compact_scope"),
  });
}

function contextCompactionRow(
  event: WorkflowRuntimeThreadEventLike,
  payload: Record<string, unknown>,
): WorkflowContextLifecycleRow {
  return baseRow(event, payload, {
    rowKind: "context_compaction",
    summary: stringField(payload, "reason") ?? "Context compacted",
    scope: stringField(payload, "scope"),
    totalTokens: numberField(payload, "compactedTokens", "compacted_tokens"),
    estimatedCostUsd: null,
    contextPressure: null,
    maxTotalTokens: null,
    maxCostUsd: null,
    maxContextPressure: null,
    violationIds: [],
    warningIds: [],
    action: "compact",
    budgetStatus: null,
    approvalRequired: null,
    approvalSatisfied: null,
    executeCompaction: true,
    compactionExecuted: true,
    compactionEventId: eventId(event),
    compactReason: stringField(payload, "reason"),
    compactScope: stringField(payload, "scope"),
  });
}

function baseRow(
  event: WorkflowRuntimeThreadEventLike,
  payload: Record<string, unknown>,
  fields: Omit<
    WorkflowContextLifecycleRow,
    | "id"
    | "status"
    | "eventId"
    | "eventSeq"
    | "threadId"
    | "turnId"
    | "workflowGraphId"
    | "workflowNodeId"
    | "receiptRefs"
    | "policyDecisionRefs"
  >,
): WorkflowContextLifecycleRow {
  const rowKind = fields.rowKind;
  const eventIdValue = eventId(event);
  return {
    id: `context-lifecycle-${rowKind}-${safeId(eventIdValue ?? String(eventSeq(event)))}`,
    status: stringField(event, "status") ?? stringField(payload, "status") ?? "unknown",
    eventId: eventIdValue,
    eventSeq: eventSeq(event),
    threadId: stringField(event, "threadId", "thread_id") ?? stringField(payload, "threadId", "thread_id"),
    turnId: stringField(event, "turnId", "turn_id") ?? stringField(payload, "turnId", "turn_id"),
    workflowGraphId:
      stringField(event, "workflowGraphId", "workflow_graph_id") ??
      stringField(payload, "workflowGraphId", "workflow_graph_id"),
    workflowNodeId:
      stringField(event, "workflowNodeId", "workflow_node_id") ??
      stringField(payload, "workflowNodeId", "workflow_node_id"),
    receiptRefs: uniqueStrings(arrayField(event, "receiptRefs", "receipt_refs")),
    policyDecisionRefs: uniqueStrings(arrayField(event, "policyDecisionRefs", "policy_decision_refs")),
    ...fields,
  };
}

function usageSummary(value: unknown): {
  totalTokens: number | null;
  estimatedCostUsd: number | null;
  contextPressure: number | null;
} {
  const record = objectValue(value);
  return {
    totalTokens: numberField(record, "totalTokens", "total_tokens"),
    estimatedCostUsd: numberField(record, "estimatedCostUsd", "estimated_cost_usd"),
    contextPressure: numberField(record, "contextPressure", "context_pressure"),
  };
}

function checkId(value: unknown): string {
  return stringField(value, "id", "label") ?? "";
}

function payloadForEvent(event: WorkflowRuntimeThreadEventLike | null): Record<string, unknown> {
  return objectField(event, "payload_summary", "payload");
}

function eventId(event: WorkflowRuntimeThreadEventLike | null): string | null {
  return stringField(event, "event_id", "id");
}

function eventSeq(event: WorkflowRuntimeThreadEventLike | null): number {
  return numberField(event, "seq") ?? 0;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function objectField(record: unknown, ...keys: string[]): Record<string, unknown> {
  const object = objectValue(record);
  for (const key of keys) {
    const value = objectValue(object?.[key]);
    if (value) return value;
  }
  return {};
}

function stringField(record: unknown, ...keys: string[]): string | null {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return null;
}

function numberField(record: unknown, ...keys: string[]): number | null {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) {
      return Number(value);
    }
  }
  return null;
}

function booleanField(record: unknown, ...keys: string[]): boolean | null {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const clean = value.trim().toLowerCase();
      if (clean === "true" || clean === "1") return true;
      if (clean === "false" || clean === "0") return false;
    }
  }
  return null;
}

function arrayField(record: unknown, ...keys: string[]): unknown[] {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function normalizeArray(
  value: readonly WorkflowRuntimeThreadEventLike[] | undefined,
): WorkflowRuntimeThreadEventLike[] {
  return Array.isArray(value) ? [...value] : [];
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (value === undefined || value === null ? null : String(value).trim()))
        .filter((value): value is string => Boolean(value)),
    ),
  );
}

function safeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._:-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
}
