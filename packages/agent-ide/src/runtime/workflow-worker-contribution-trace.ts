import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { workflowRuntimeEventId } from "./workflow-runtime-event-identity";

export const WORKFLOW_WORKER_CONTRIBUTION_TRACE_SCHEMA_VERSION =
  "ioi.workflow.worker-contribution-trace.v1" as const;

export interface WorkflowWorkerContributionTraceInput {
  events: readonly WorkflowRuntimeThreadEventLike[];
  subagents: readonly unknown[];
  contributions: readonly unknown[];
}

export interface WorkflowWorkerContributionTraceRow {
  id: string;
  status: "ready" | "needs_event" | "needs_worker" | "needs_receipt";
  contributionId: string;
  subagentId: string | null;
  role: string | null;
  childThreadId: string | null;
  parentThreadId: string | null;
  mergePolicy: string | null;
  outputContractStatus: string | null;
  toolCallId: string | null;
  eventId: string | null;
  eventSeq: number | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  filePath: string | null;
  hunkIndex: number | null;
  hunkHeader: string | null;
  editCount: number | null;
  snapshotId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
  evidenceRefs: string[];
}

export interface WorkflowWorkerContributionTrace {
  schemaVersion: typeof WORKFLOW_WORKER_CONTRIBUTION_TRACE_SCHEMA_VERSION;
  status: "ready" | "needs_evidence" | "blocked";
  contributionCount: number;
  readyCount: number;
  manualReviewCount: number;
  missingWorkerCount: number;
  missingEventCount: number;
  missingReceiptCount: number;
  workerIds: string[];
  childThreadIds: string[];
  touchedFiles: string[];
  rows: WorkflowWorkerContributionTraceRow[];
  evidenceRefs: string[];
}

export function buildWorkflowWorkerContributionTrace(
  input: WorkflowWorkerContributionTraceInput,
): WorkflowWorkerContributionTrace {
  const events = normalizeEvents(input.events);
  const subagents = normalizeUnknownArray(input.subagents).map(objectValue).filter(Boolean) as Record<string, unknown>[];
  const rows = normalizeUnknownArray(input.contributions).map((contribution, index) =>
    rowForContribution({
      contribution: objectValue(contribution) ?? {},
      index,
      events,
      subagents,
    }),
  );
  const readyCount = rows.filter((row) => row.status === "ready").length;
  const missingWorkerCount = rows.filter((row) => row.status === "needs_worker").length;
  const missingEventCount = rows.filter((row) => row.status === "needs_event").length;
  const missingReceiptCount = rows.filter((row) => row.status === "needs_receipt").length;
  return {
    schemaVersion: WORKFLOW_WORKER_CONTRIBUTION_TRACE_SCHEMA_VERSION,
    status:
      rows.length === 0
        ? "needs_evidence"
        : missingWorkerCount || missingEventCount || missingReceiptCount
          ? "blocked"
          : "ready",
    contributionCount: rows.length,
    readyCount,
    manualReviewCount: rows.filter((row) => row.mergePolicy === "manual_review").length,
    missingWorkerCount,
    missingEventCount,
    missingReceiptCount,
    workerIds: uniqueStrings(rows.map((row) => row.subagentId)),
    childThreadIds: uniqueStrings(rows.map((row) => row.childThreadId)),
    touchedFiles: uniqueStrings(rows.map((row) => row.filePath)),
    rows,
    evidenceRefs: uniqueStrings(rows.flatMap((row) => row.evidenceRefs)),
  };
}

function rowForContribution({
  contribution,
  index,
  events,
  subagents,
}: {
  contribution: Record<string, unknown>;
  index: number;
  events: WorkflowRuntimeThreadEventLike[];
  subagents: Record<string, unknown>[];
}): WorkflowWorkerContributionTraceRow {
  const subagentId = stringField(contribution, "subagent_id");
  const toolCallId = stringField(contribution, "tool_call_id");
  const requestedEventId = stringField(contribution, "event_id");
  const worker = subagents.find((candidate) =>
    stringField(candidate, "subagent_id") === subagentId,
  );
  const event = events.find((candidate) =>
    (requestedEventId && eventId(candidate) === requestedEventId) ||
    (toolCallId && stringField(candidate, "tool_call_id") === toolCallId),
  );
  const payload = payloadForEvent(event);
  const result = objectField(payload, "result");
  const snapshotId =
    stringField(result, "workspace_snapshot_id") ??
    firstString(arrayField(event, "rollback_refs"));
  const receiptRefs = uniqueStrings([
    ...arrayField(event, "receipt_refs"),
    ...arrayField(contribution, "receipt_refs"),
  ]);
  const status =
    !worker ? "needs_worker" : !event ? "needs_event" : receiptRefs.length === 0 ? "needs_receipt" : "ready";
  const filePath =
    stringField(contribution, "file_path", "hunk_file") ??
    firstString(arrayField(objectField(result, "result"), "changed_files").map((file) => stringField(file, "path"))) ??
    firstString(arrayField(result, "changed_files").map((file) => stringField(file, "path")));
  return {
    id: `worker-contribution-${safeId(stringField(contribution, "contribution_id") ?? String(index))}`,
    status,
    contributionId: stringField(contribution, "contribution_id") ?? `contribution-${index}`,
    subagentId,
    role: stringField(worker, "role"),
    childThreadId: stringField(worker, "child_thread_id"),
    parentThreadId: stringField(worker, "parent_thread_id"),
    mergePolicy: stringField(worker, "merge_policy"),
    outputContractStatus: stringField(worker, "output_contract_status"),
    toolCallId,
    eventId: eventId(event),
    eventSeq: eventSeq(event),
    workflowGraphId: stringField(event, "workflow_graph_id"),
    workflowNodeId: stringField(event, "workflow_node_id"),
    filePath,
    hunkIndex: numberField(contribution, "hunk_index"),
    hunkHeader: stringField(contribution, "hunk_header"),
    editCount:
      numberField(contribution, "edit_count") ??
      numberField(objectField(result, "result"), "edit_count") ??
      numberField(result, "edit_count"),
    snapshotId,
    receiptRefs,
    policyDecisionRefs: uniqueStrings([
      ...arrayField(event, "policy_decision_refs"),
      ...arrayField(contribution, "policy_decision_refs"),
    ]),
    rollbackRefs: uniqueStrings(arrayField(event, "rollback_refs")),
    evidenceRefs: uniqueStrings([
      subagentId,
      stringField(worker, "child_thread_id"),
      eventId(event),
      snapshotId,
      ...receiptRefs,
      ...arrayField(event, "artifact_refs"),
    ]),
  };
}

function payloadForEvent(event: WorkflowRuntimeThreadEventLike | null | undefined): Record<string, unknown> {
  return objectField(event, "payload_summary", "payload");
}

function eventId(event: WorkflowRuntimeThreadEventLike | null | undefined): string | null {
  return workflowRuntimeEventId(event);
}

function eventSeq(event: WorkflowRuntimeThreadEventLike | null | undefined): number | null {
  return numberField(event, "seq");
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

function arrayField(record: unknown, ...keys: string[]): unknown[] {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function firstString(values: unknown[]): string | null {
  return values.map((value) => String(value ?? "").trim()).find(Boolean) ?? null;
}

function normalizeEvents(value: readonly WorkflowRuntimeThreadEventLike[] | undefined): WorkflowRuntimeThreadEventLike[] {
  return Array.isArray(value) ? [...value] : [];
}

function normalizeUnknownArray(value: readonly unknown[] | undefined): unknown[] {
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
