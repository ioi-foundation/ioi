import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { workflowRuntimeEventId } from "./workflow-runtime-event-identity";

export const WORKFLOW_SIGNED_REPLAY_NOTEBOOK_SCHEMA_VERSION =
  "ioi.workflow.signed-replay-notebook.v1" as const;

export interface WorkflowSignedReplayNotebookInput {
  events: readonly WorkflowRuntimeThreadEventLike[];
  snapshots?: readonly unknown[];
  restoreResults?: readonly unknown[];
}

export type WorkflowSignedReplayNotebookCellKind =
  | "tool"
  | "snapshot"
  | "restore_preview"
  | "restore_apply";

export interface WorkflowSignedReplayNotebookCell {
  id: string;
  cell_kind: WorkflowSignedReplayNotebookCellKind;
  status: string;
  read_only_replay: boolean;
  event_id: string | null;
  event_seq: number | null;
  thread_id: string | null;
  workflow_graph_id: string | null;
  workflow_node_id: string | null;
  title: string;
  summary: string | null;
  tool_name: string | null;
  tool_call_id: string | null;
  snapshot_id: string | null;
  file_paths: string[];
  operation_count: number;
  approval_required: boolean | null;
  approval_satisfied: boolean | null;
  restore_preview_endpoint: string | null;
  restore_apply_endpoint: string | null;
  receipt_refs: string[];
  artifact_refs: string[];
  rollback_refs: string[];
  policy_decision_refs: string[];
}

export interface WorkflowSignedReplayNotebook {
  schema_version: typeof WORKFLOW_SIGNED_REPLAY_NOTEBOOK_SCHEMA_VERSION;
  status: "ready" | "needs_evidence" | "blocked";
  read_only_replay_mode: boolean;
  cell_count: number;
  receipt_backed_cell_count: number;
  snapshot_count: number;
  restore_preview_count: number;
  restore_apply_blocked_count: number;
  restore_apply_applied_count: number;
  rollback_ref_count: number;
  cells: WorkflowSignedReplayNotebookCell[];
  evidence_refs: string[];
}

export function buildWorkflowSignedReplayNotebook(
  input: WorkflowSignedReplayNotebookInput,
): WorkflowSignedReplayNotebook {
  const events = normalizeEvents(input.events).sort((a, b) => eventSeq(a) - eventSeq(b));
  const eventCells = events
    .map((event) => cellForEvent(event))
    .filter((cell): cell is WorkflowSignedReplayNotebookCell => Boolean(cell));
  const resultCells = normalizeUnknownArray(input.restoreResults)
    .map((result) => cellForRestoreResult(result))
    .filter((cell): cell is WorkflowSignedReplayNotebookCell => Boolean(cell));
  const snapshotCells = normalizeUnknownArray(input.snapshots)
    .map((snapshot) => cellForSnapshotListItem(snapshot))
    .filter((cell): cell is WorkflowSignedReplayNotebookCell => Boolean(cell));
  const cells = mergeCells([...eventCells, ...snapshotCells, ...resultCells]);
  const receiptBackedCellCount = cells.filter((cell) => cell.receipt_refs.length > 0).length;
  const snapshotCount = cells.filter((cell) => cell.cell_kind === "snapshot").length;
  const restorePreviewCount = cells.filter((cell) => cell.cell_kind === "restore_preview").length;
  const restoreApplyBlockedCount = cells.filter(
    (cell) => cell.cell_kind === "restore_apply" && cell.status === "blocked",
  ).length;
  const restoreApplyAppliedCount = cells.filter(
    (cell) => cell.cell_kind === "restore_apply" && cell.status === "applied",
  ).length;
  const rollbackRefs = uniqueStrings(cells.flatMap((cell) => cell.rollback_refs));
  const readOnlyReplayMode = restorePreviewCount > 0 && restoreApplyBlockedCount > 0;
  return {
    schema_version: WORKFLOW_SIGNED_REPLAY_NOTEBOOK_SCHEMA_VERSION,
    status:
      snapshotCount === 0 || restorePreviewCount === 0
        ? "needs_evidence"
        : readOnlyReplayMode || restoreApplyAppliedCount > 0
          ? "ready"
          : "blocked",
    read_only_replay_mode: readOnlyReplayMode,
    cell_count: cells.length,
    receipt_backed_cell_count: receiptBackedCellCount,
    snapshot_count: snapshotCount,
    restore_preview_count: restorePreviewCount,
    restore_apply_blocked_count: restoreApplyBlockedCount,
    restore_apply_applied_count: restoreApplyAppliedCount,
    rollback_ref_count: rollbackRefs.length,
    cells,
    evidence_refs: uniqueStrings(cells.flatMap((cell) => [...cell.receipt_refs, ...cell.artifact_refs, ...cell.rollback_refs])),
  };
}

function cellForEvent(event: WorkflowRuntimeThreadEventLike): WorkflowSignedReplayNotebookCell | null {
  const eventKind = stringField(event, "eventKind", "event_kind");
  const componentKind = stringField(event, "componentKind", "component_kind");
  const payload = payloadForEvent(event);
  if (eventKind === "tool.completed" || eventKind === "tool.failed") {
    return baseCell(event, {
      cell_kind: "tool",
      title: stringField(event, "toolName", "tool_name") ?? "Runtime tool",
      summary: stringField(payload, "summary") ?? stringField(payload, "error", "message"),
      tool_name: stringField(event, "toolName", "tool_name"),
      tool_call_id: stringField(event, "toolCallId", "tool_call_id"),
      snapshot_id: null,
      file_paths: filePathsFromPayload(payload),
      operation_count: filePathsFromPayload(payload).length,
      approval_required: null,
      approval_satisfied: null,
      restore_preview_endpoint: null,
      restore_apply_endpoint: null,
      read_only_replay: false,
    });
  }
  if (eventKind === "workspace.snapshot.created" || componentKind === "workspace_snapshot") {
    const snapshotId = stringField(payload, "snapshotId", "snapshot_id") ?? firstString(arrayField(event, "rollback_refs"));
    return baseCell(event, {
      cell_kind: "snapshot",
      title: "Workspace snapshot",
      summary: stringField(payload, "summary"),
      tool_name: null,
      tool_call_id: stringField(payload, "toolCallId", "tool_call_id"),
      snapshot_id: snapshotId,
      file_paths: filePathsFromPayload(payload),
      operation_count: numberField(payload, "fileCount", "file_count") ?? filePathsFromPayload(payload).length,
      approval_required: null,
      approval_satisfied: null,
      restore_preview_endpoint: endpointForSnapshot(event, snapshotId, "restore-preview"),
      restore_apply_endpoint: endpointForSnapshot(event, snapshotId, "restore-apply"),
      read_only_replay: false,
    });
  }
  if (eventKind === "workspace.restore.previewed") {
    const snapshotId = stringField(payload, "snapshotId", "snapshot_id") ?? firstString(arrayField(event, "rollback_refs"));
    return baseCell(event, {
      cell_kind: "restore_preview",
      title: "Read-only restore preview",
      summary: stringField(payload, "summary"),
      tool_name: null,
      tool_call_id: null,
      snapshot_id: snapshotId,
      file_paths: filePathsFromOperations(payload),
      operation_count: arrayField(payload, "operations").length,
      approval_required: null,
      approval_satisfied: null,
      restore_preview_endpoint: endpointForSnapshot(event, snapshotId, "restore-preview"),
      restore_apply_endpoint: endpointForSnapshot(event, snapshotId, "restore-apply"),
      read_only_replay: true,
    });
  }
  if (eventKind === "workspace.restore.applied") {
    const snapshotId = stringField(payload, "snapshotId", "snapshot_id") ?? firstString(arrayField(event, "rollback_refs"));
    return baseCell(event, {
      cell_kind: "restore_apply",
      title: "Restore apply",
      summary: stringField(payload, "summary"),
      tool_name: null,
      tool_call_id: null,
      snapshot_id: snapshotId,
      file_paths: filePathsFromOperations(payload),
      operation_count: arrayField(payload, "operations").length,
      approval_required: booleanField(payload, "approvalRequired", "approval_required"),
      approval_satisfied: booleanField(payload, "approvalSatisfied", "approval_satisfied"),
      restore_preview_endpoint: endpointForSnapshot(event, snapshotId, "restore-preview"),
      restore_apply_endpoint: endpointForSnapshot(event, snapshotId, "restore-apply"),
      read_only_replay: false,
    });
  }
  return null;
}

function cellForRestoreResult(value: unknown): WorkflowSignedReplayNotebookCell | null {
  const result = objectValue(value);
  if (!result) return null;
  const schema = stringField(result, "schema_version") ?? "";
  const snapshotId = stringField(result, "snapshot_id");
  const preview = schema.includes("workspace-restore-preview");
  const apply = schema.includes("workspace-restore-apply");
  if (!preview && !apply) return null;
  return {
    id: `signed-replay-${preview ? "preview" : "apply"}-${safeId(snapshotId ?? "snapshot")}-${safeId(stringField(result, "apply_status", "preview_status") ?? "status")}`,
    cell_kind: preview ? "restore_preview" : "restore_apply",
    status: preview
      ? stringField(result, "preview_status") ?? "ready"
      : stringField(result, "apply_status") ?? "unknown",
    read_only_replay: preview || stringField(result, "apply_status") === "blocked",
    event_id: stringField(objectField(result, "event"), "event_id"),
    event_seq: numberField(objectField(result, "event"), "seq"),
    thread_id: stringField(result, "thread_id") ?? stringField(objectField(result, "event"), "thread_id"),
    workflow_graph_id: stringField(objectField(result, "event"), "workflow_graph_id"),
    workflow_node_id: stringField(objectField(result, "event"), "workflow_node_id"),
    title: preview ? "Read-only restore preview" : "Restore apply",
    summary: stringField(result, "summary"),
    tool_name: null,
    tool_call_id: null,
    snapshot_id: snapshotId,
    file_paths: filePathsFromOperations(result),
    operation_count: arrayField(result, "operations").length,
    approval_required: booleanField(result, "approval_required"),
    approval_satisfied: booleanField(result, "approval_satisfied"),
    restore_preview_endpoint: endpointForThreadSnapshot(result, snapshotId, "restore-preview"),
    restore_apply_endpoint: endpointForThreadSnapshot(result, snapshotId, "restore-apply"),
    receipt_refs: uniqueStrings(arrayField(result, "receipt_refs")),
    artifact_refs: uniqueStrings(arrayField(result, "artifact_refs")),
    rollback_refs: uniqueStrings(arrayField(result, "rollback_refs")),
    policy_decision_refs: uniqueStrings(arrayField(result, "policy_decision_refs")),
  };
}

function cellForSnapshotListItem(value: unknown): WorkflowSignedReplayNotebookCell | null {
  const snapshot = objectValue(value);
  const snapshotId = stringField(snapshot, "snapshot_id");
  if (!snapshot || !snapshotId) return null;
  return {
    id: `signed-replay-snapshot-list-${safeId(snapshotId)}`,
    cell_kind: "snapshot",
    status: stringField(snapshot, "status") ?? "completed",
    read_only_replay: false,
    event_id: stringField(snapshot, "event_id"),
    event_seq: null,
    thread_id: stringField(snapshot, "thread_id"),
    workflow_graph_id: stringField(snapshot, "workflow_graph_id"),
    workflow_node_id: "runtime.workspace-snapshot",
    title: "Workspace snapshot",
    summary: stringField(snapshot, "summary"),
    tool_name: null,
    tool_call_id: stringField(snapshot, "tool_call_id"),
    snapshot_id: snapshotId,
    file_paths: filePathsFromPayload(snapshot),
    operation_count: numberField(snapshot, "file_count") ?? filePathsFromPayload(snapshot).length,
    approval_required: null,
    approval_satisfied: null,
    restore_preview_endpoint: endpointForThreadSnapshot(snapshot, snapshotId, "restore-preview"),
    restore_apply_endpoint: endpointForThreadSnapshot(snapshot, snapshotId, "restore-apply"),
    receipt_refs: uniqueStrings(arrayField(snapshot, "receipt_refs")),
    artifact_refs: uniqueStrings(arrayField(snapshot, "artifact_refs")),
    rollback_refs: uniqueStrings([snapshotId]),
    policy_decision_refs: uniqueStrings(arrayField(snapshot, "policy_decision_refs")),
  };
}

function baseCell(
  event: WorkflowRuntimeThreadEventLike,
  fields: Omit<
    WorkflowSignedReplayNotebookCell,
    | "id"
    | "status"
    | "event_id"
    | "event_seq"
    | "thread_id"
    | "workflow_graph_id"
    | "workflow_node_id"
    | "receipt_refs"
    | "artifact_refs"
    | "rollback_refs"
    | "policy_decision_refs"
  >,
): WorkflowSignedReplayNotebookCell {
  const eventIdValue = eventId(event);
  return {
    id: `signed-replay-${fields.cell_kind}-${safeId(eventIdValue ?? String(eventSeq(event)))}`,
    status: stringField(event, "status") ?? "unknown",
    event_id: eventIdValue,
    event_seq: eventSeq(event),
    thread_id: stringField(event, "threadId", "thread_id"),
    workflow_graph_id: stringField(event, "workflowGraphId", "workflow_graph_id"),
    workflow_node_id: stringField(event, "workflowNodeId", "workflow_node_id"),
    receipt_refs: uniqueStrings(arrayField(event, "receipt_refs")),
    artifact_refs: uniqueStrings(arrayField(event, "artifact_refs")),
    rollback_refs: uniqueStrings(arrayField(event, "rollback_refs")),
    policy_decision_refs: uniqueStrings(arrayField(event, "policy_decision_refs")),
    ...fields,
  };
}

function mergeCells(cells: WorkflowSignedReplayNotebookCell[]): WorkflowSignedReplayNotebookCell[] {
  const byId = new Map<string, WorkflowSignedReplayNotebookCell>();
  for (const cell of cells) {
    const key =
      cell.cell_kind === "snapshot" && cell.snapshot_id
        ? `snapshot:${cell.snapshot_id}`
        : cell.event_id ?? `${cell.cell_kind}:${cell.snapshot_id}:${cell.status}:${cell.workflow_node_id}`;
    const existing = byId.get(key);
    if (!existing) {
      byId.set(key, cell);
      continue;
    }
    byId.set(key, {
      ...existing,
      ...cell,
      receipt_refs: uniqueStrings([...existing.receipt_refs, ...cell.receipt_refs]),
      artifact_refs: uniqueStrings([...existing.artifact_refs, ...cell.artifact_refs]),
      rollback_refs: uniqueStrings([...existing.rollback_refs, ...cell.rollback_refs]),
      policy_decision_refs: uniqueStrings([...existing.policy_decision_refs, ...cell.policy_decision_refs]),
      file_paths: uniqueStrings([...existing.file_paths, ...cell.file_paths]),
    });
  }
  return [...byId.values()].sort((a, b) => (a.event_seq ?? 999999) - (b.event_seq ?? 999999));
}

function endpointForSnapshot(
  event: WorkflowRuntimeThreadEventLike,
  snapshotId: string | null,
  action: "restore-preview" | "restore-apply",
): string | null {
  return endpointForThreadSnapshot(
    { thread_id: stringField(event, "threadId", "thread_id") },
    snapshotId,
    action,
  );
}

function endpointForThreadSnapshot(
  value: unknown,
  snapshotId: string | null,
  action: "restore-preview" | "restore-apply",
): string | null {
  const threadId = stringField(value, "thread_id");
  return threadId && snapshotId
    ? `/v1/threads/${encodeURIComponent(threadId)}/snapshots/${encodeURIComponent(snapshotId)}/${action}`
    : null;
}

function filePathsFromPayload(payload: Record<string, unknown>): string[] {
  return uniqueStrings([
    ...arrayField(payload, "files").map((file) => stringField(file, "path")),
    ...arrayField(payload, "changedFiles", "changed_files").map((file) => stringField(file, "path")),
  ]);
}

function filePathsFromOperations(payload: Record<string, unknown>): string[] {
  return uniqueStrings(arrayField(payload, "operations").map((operation) => stringField(operation, "path")));
}

function payloadForEvent(event: WorkflowRuntimeThreadEventLike | null): Record<string, unknown> {
  return objectField(event, "payload_summary", "payload");
}

function eventId(event: WorkflowRuntimeThreadEventLike | null): string | null {
  return workflowRuntimeEventId(event);
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

function firstString(values: unknown[]): string | null {
  return values.map((value) => String(value ?? "").trim()).find(Boolean) ?? null;
}

function normalizeEvents(
  value: readonly WorkflowRuntimeThreadEventLike[] | undefined,
): WorkflowRuntimeThreadEventLike[] {
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
