export const WORKFLOW_TERMINAL_STREAM_CARD_SCHEMA_VERSION =
  "ioi.workflow.terminal-stream-card.v1" as const;

export interface WorkflowTerminalStreamCardInput {
  events: unknown[];
}

export interface WorkflowTerminalStreamCardRow {
  id: string;
  streamId: string;
  status: "streaming" | "completed";
  toolCallId: string | null;
  toolName: string | null;
  command: string | null;
  channels: string[];
  chunkCount: number;
  finalSeen: boolean;
  truncated: boolean;
  preview: string | null;
  receiptRefs: string[];
  artifactRefs: string[];
}

export interface WorkflowTerminalStreamCard {
  schemaVersion: typeof WORKFLOW_TERMINAL_STREAM_CARD_SCHEMA_VERSION;
  status: "ready" | "streaming" | "empty";
  streamCount: number;
  completedCount: number;
  artifactBackedCount: number;
  rows: WorkflowTerminalStreamCardRow[];
}

const STREAM_PREVIEW_MAX_LINES = 12;
const STREAM_PREVIEW_MAX_CHARS = 1600;

export function buildWorkflowTerminalStreamCard(
  input: WorkflowTerminalStreamCardInput,
): WorkflowTerminalStreamCard {
  const streamEvents = normalizeArray(input.events)
    .map(objectValue)
    .filter((event): event is Record<string, unknown> => {
      const kind =
        stringField(event, "event_kind", "type") ??
        stringField(objectField(event, "payload_summary", "payload"), "event_kind");
      return kind === "COMMAND_STREAM";
    });
  const groups = new Map<string, Record<string, unknown>[]>();
  for (const event of streamEvents) {
    const payload = objectField(event, "payload_summary", "payload");
    const streamId =
      stringField(payload, "stream_id") ??
      `${stringField(event, "event_stream_id") ?? "events"}:${stringField(event, "tool_call_id") ?? "command"}`;
    const group = groups.get(streamId) ?? [];
    group.push(event);
    groups.set(streamId, group);
  }
  const rows = [...groups.entries()]
    .map(([streamId, events]) => streamRow(streamId, events))
    .sort((left, right) => left.streamId.localeCompare(right.streamId));
  const completedCount = rows.filter((row) => row.finalSeen).length;
  const artifactBackedCount = rows.filter((row) => row.artifactRefs.length > 0).length;
  return {
    schemaVersion: WORKFLOW_TERMINAL_STREAM_CARD_SCHEMA_VERSION,
    status: rows.length === 0 ? "empty" : completedCount === rows.length ? "ready" : "streaming",
    streamCount: rows.length,
    completedCount,
    artifactBackedCount,
    rows,
  };
}

function streamRow(streamId: string, events: Record<string, unknown>[]): WorkflowTerminalStreamCardRow {
  const ordered = [...events].sort((left, right) => {
    const leftPayload = objectField(left, "payload_summary", "payload");
    const rightPayload = objectField(right, "payload_summary", "payload");
    const leftSeq = numberField(leftPayload, "stream_seq") ?? numberField(left, "seq") ?? 0;
    const rightSeq = numberField(rightPayload, "stream_seq") ?? numberField(right, "seq") ?? 0;
    if (leftSeq !== rightSeq) return leftSeq - rightSeq;
    return (stringField(left, "created_at") ?? "").localeCompare(stringField(right, "created_at") ?? "");
  });
  const payloads = ordered.map((event) => objectField(event, "payload_summary", "payload"));
  const latestPayload = payloads[payloads.length - 1] ?? {};
  const mergedOutput = payloads
    .map((payload) => stringField(payload, "output_text") ?? "")
    .join("");
  const finalSeen = payloads.some((payload) => booleanField(payload, "is_final"));
  const receiptRefs = uniqueStrings([
    ...ordered.flatMap((event) => arrayField(event, "receipt_refs")),
    ...payloads.flatMap((payload) => arrayField(payload, "receipt_refs")),
  ]);
  const artifactRefs = uniqueStrings([
    ...ordered.flatMap((event) => arrayField(event, "artifact_refs")),
    ...payloads.flatMap((payload) => arrayField(payload, "artifact_refs")),
  ]);
  return {
    id: `terminal-stream-${safeId(streamId)}`,
    streamId,
    status: finalSeen ? "completed" : "streaming",
    toolCallId:
      stringField(latestPayload, "tool_call_id") ??
      stringField(ordered[ordered.length - 1], "tool_call_id"),
    toolName:
      stringField(latestPayload, "tool_name") ??
      stringField(ordered[ordered.length - 1], "tool_name"),
    command: stringField(latestPayload, "command"),
    channels: uniqueStrings(payloads.map((payload) => stringField(payload, "channel"))),
    chunkCount: payloads.filter((payload) => stringField(payload, "output_text")).length,
    finalSeen,
    truncated: payloads.some((payload) => booleanField(payload, "truncated")),
    preview: streamPreview(mergedOutput),
    receiptRefs,
    artifactRefs,
  };
}

function streamPreview(value: string): string | null {
  const lines = value
    .split(/\r?\n/g)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);
  let preview = lines.length > 0 ? lines.slice(-STREAM_PREVIEW_MAX_LINES).join("\n") : value.trim();
  if (preview.length > STREAM_PREVIEW_MAX_CHARS) {
    preview = preview.slice(preview.length - STREAM_PREVIEW_MAX_CHARS);
  }
  return preview || null;
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
  }
  return null;
}

function booleanField(record: unknown, ...keys: string[]): boolean {
  const object = objectValue(record);
  return keys.some((key) => object?.[key] === true);
}

function arrayField(record: unknown, ...keys: string[]): unknown[] {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function normalizeArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
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
