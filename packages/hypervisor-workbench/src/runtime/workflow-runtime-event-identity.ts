import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export type WorkflowRuntimeEventIdentityInput =
  | WorkflowRuntimeThreadEventLike
  | Record<string, unknown>
  | null
  | undefined;

export function workflowRuntimeEventId(
  event: WorkflowRuntimeEventIdentityInput,
): string | null {
  const record = objectRecord(event);
  if (!record) return null;
  return cleanString(record.event_id) ?? projectedEventId(record);
}

export function workflowRuntimeEventKind(
  event: WorkflowRuntimeEventIdentityInput,
): string | null {
  const record = objectRecord(event);
  if (!record) return null;
  return cleanString(record.event_kind) ?? projectedEventKind(record);
}

function projectedEventId(record: Record<string, unknown>): string | null {
  return isProjectedRuntimeThreadEvent(record) ? cleanString(record.id) : null;
}

function projectedEventKind(record: Record<string, unknown>): string | null {
  return isProjectedRuntimeThreadEvent(record) ? cleanString(record.eventKind) : null;
}

function isProjectedRuntimeThreadEvent(record: Record<string, unknown>): boolean {
  return Boolean(
    cleanString(record.id) &&
      cleanString(record.cursor) &&
      cleanString(record.threadId) &&
      cleanString(record.eventKind) &&
      cleanString(record.sourceEventKind) &&
      cleanString(record.status) &&
      cleanString(record.payloadSchemaVersion),
  );
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
