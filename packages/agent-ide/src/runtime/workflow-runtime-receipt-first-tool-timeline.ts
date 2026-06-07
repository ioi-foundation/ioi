import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  workflowRuntimeEventId,
  workflowRuntimeEventKind,
} from "./workflow-runtime-event-identity";

export const WORKFLOW_RUNTIME_RECEIPT_FIRST_TOOL_TIMELINE_SCHEMA_VERSION =
  "ioi.workflow.receipt-first-tool-timeline.v1" as const;

export interface WorkflowRuntimeReceiptFirstToolTimelineOptions {
  threadId?: string | null;
  workflowGraphId?: string | null;
}

export interface WorkflowRuntimeReceiptFirstToolTimelineRow {
  rowKind: "tool";
  status: string;
  displayMode: "receipt_first";
  primaryReceiptRef: string | null;
  receiptRefs: string[];
  artifactRefs: string[];
  eventId: string | null;
  eventSeq: number | null;
  eventKind: string;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  threadId: string | null;
  turnId: string | null;
  toolName: string | null;
  toolCallId: string | null;
  summary: string | null;
  outputHash: string | null;
  outputBytes: number | null;
  rawOutputDemoted: boolean;
  rawOutputIncluded: false;
  childArtifactCount: number;
}

export interface WorkflowRuntimeReceiptFirstToolTimeline {
  schemaVersion: typeof WORKFLOW_RUNTIME_RECEIPT_FIRST_TOOL_TIMELINE_SCHEMA_VERSION;
  status: "empty" | "ready" | "missing_receipts";
  rows: WorkflowRuntimeReceiptFirstToolTimelineRow[];
  receiptRefs: string[];
  artifactRefs: string[];
  missingReceiptCount: number;
  rawOutputDemotedCount: number;
  eventIds: string[];
  threadIds: string[];
  workflowGraphIds: string[];
  workflowNodeIds: string[];
}

type RuntimeEventInput = WorkflowRuntimeThreadEventLike | Record<string, unknown>;

export function buildWorkflowRuntimeReceiptFirstToolTimeline(
  events: readonly RuntimeEventInput[],
  options: WorkflowRuntimeReceiptFirstToolTimelineOptions = {},
): WorkflowRuntimeReceiptFirstToolTimeline {
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
    .map((event) => receiptFirstToolRowForEvent(event))
    .filter((row): row is WorkflowRuntimeReceiptFirstToolTimelineRow => Boolean(row));

  const missingReceiptCount = rows.filter((row) => !row.primaryReceiptRef).length;
  return {
    schemaVersion: WORKFLOW_RUNTIME_RECEIPT_FIRST_TOOL_TIMELINE_SCHEMA_VERSION,
    status: rows.length === 0 ? "empty" : missingReceiptCount > 0 ? "missing_receipts" : "ready",
    rows,
    receiptRefs: uniqueStrings(rows.flatMap((row) => row.receiptRefs)),
    artifactRefs: uniqueStrings(rows.flatMap((row) => row.artifactRefs)),
    missingReceiptCount,
    rawOutputDemotedCount: rows.filter((row) => row.rawOutputDemoted).length,
    eventIds: uniqueStrings(rows.map((row) => row.eventId)),
    threadIds: uniqueStrings(rows.map((row) => row.threadId)),
    workflowGraphIds: uniqueStrings(rows.map((row) => row.workflowGraphId)),
    workflowNodeIds: uniqueStrings(rows.map((row) => row.workflowNodeId)),
  };
}

function receiptFirstToolRowForEvent(
  event: RuntimeEventInput,
): WorkflowRuntimeReceiptFirstToolTimelineRow | null {
  const kind = eventKind(event);
  if (kind !== "tool.completed" && kind !== "tool.failed" && kind !== "policy.blocked") {
    return null;
  }
  const payload = eventPayload(event);
  const result = objectField(payload, "result");
  const toolName = stringField(payload, "tool_name") ?? eventToolName(event);
  if (!toolName) return null;
  const receiptRefs = uniqueStrings([
    ...arrayField(event, "receipt_refs"),
    ...arrayField(payload, "receipt_refs"),
    ...arrayField(result, "receipt_refs"),
  ]);
  const artifactRefs = uniqueStrings([
    ...arrayField(event, "artifact_refs"),
    ...arrayField(payload, "artifact_refs"),
    ...arrayField(result, "artifact_refs"),
  ]);
  const outputHash = stringField(result, "output_hash") ??
    stringField(payload, "output_hash");
  const outputBytes = numberField(result, "output_bytes") ??
    numberField(payload, "output_bytes");
  const hasRawOutput = Boolean(
    stringField(result, "stdout") ||
      stringField(result, "stderr") ||
      stringField(payload, "stdout") ||
      stringField(payload, "stderr"),
  );
  return {
    rowKind: "tool",
    status: stringField(payload, "status") ?? eventStatus(event) ?? "completed",
    displayMode: "receipt_first",
    primaryReceiptRef: receiptRefs[0] ?? null,
    receiptRefs,
    artifactRefs,
    eventId: eventIdForRuntimeEvent(event),
    eventSeq: eventSeq(event),
    eventKind: kind,
    workflowGraphId: eventWorkflowGraphId(event),
    workflowNodeId: eventWorkflowNodeId(event),
    threadId: eventThreadId(event),
    turnId: eventTurnId(event),
    toolName,
    toolCallId:
      stringField(payload, "tool_call_id") ??
      eventToolCallId(event),
    summary: stringField(payload, "summary") ?? stringField(result, "summary"),
    outputHash,
    outputBytes,
    rawOutputDemoted: hasRawOutput && (artifactRefs.length > 0 || Boolean(outputHash)),
    rawOutputIncluded: false,
    childArtifactCount: artifactRefs.length,
  };
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
  return workflowRuntimeEventId(event);
}

function eventKind(event: RuntimeEventInput): string {
  return workflowRuntimeEventKind(event) ?? "";
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

function eventTurnId(event: RuntimeEventInput): string | null {
  return stringField(event, "turnId", "turn_id");
}

function eventWorkflowGraphId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflowGraphId", "workflow_graph_id");
}

function eventWorkflowNodeId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflowNodeId", "workflow_node_id");
}

function eventToolName(event: RuntimeEventInput): string | null {
  return stringField(event, "toolName", "tool_name");
}

function eventToolCallId(event: RuntimeEventInput): string | null {
  return stringField(event, "toolCallId", "tool_call_id");
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
