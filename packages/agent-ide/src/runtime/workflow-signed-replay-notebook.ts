import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

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
  cellKind: WorkflowSignedReplayNotebookCellKind;
  status: string;
  readOnlyReplay: boolean;
  eventId: string | null;
  eventSeq: number | null;
  threadId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  title: string;
  summary: string | null;
  toolName: string | null;
  toolCallId: string | null;
  snapshotId: string | null;
  filePaths: string[];
  operationCount: number;
  approvalRequired: boolean | null;
  approvalSatisfied: boolean | null;
  restorePreviewEndpoint: string | null;
  restoreApplyEndpoint: string | null;
  receiptRefs: string[];
  artifactRefs: string[];
  rollbackRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowSignedReplayNotebook {
  schemaVersion: typeof WORKFLOW_SIGNED_REPLAY_NOTEBOOK_SCHEMA_VERSION;
  status: "ready" | "needs_evidence" | "blocked";
  readOnlyReplayMode: boolean;
  cellCount: number;
  receiptBackedCellCount: number;
  snapshotCount: number;
  restorePreviewCount: number;
  restoreApplyBlockedCount: number;
  restoreApplyAppliedCount: number;
  rollbackRefCount: number;
  cells: WorkflowSignedReplayNotebookCell[];
  evidenceRefs: string[];
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
  const receiptBackedCellCount = cells.filter((cell) => cell.receiptRefs.length > 0).length;
  const snapshotCount = cells.filter((cell) => cell.cellKind === "snapshot").length;
  const restorePreviewCount = cells.filter((cell) => cell.cellKind === "restore_preview").length;
  const restoreApplyBlockedCount = cells.filter(
    (cell) => cell.cellKind === "restore_apply" && cell.status === "blocked",
  ).length;
  const restoreApplyAppliedCount = cells.filter(
    (cell) => cell.cellKind === "restore_apply" && cell.status === "applied",
  ).length;
  const rollbackRefs = uniqueStrings(cells.flatMap((cell) => cell.rollbackRefs));
  const readOnlyReplayMode = restorePreviewCount > 0 && restoreApplyBlockedCount > 0;
  return {
    schemaVersion: WORKFLOW_SIGNED_REPLAY_NOTEBOOK_SCHEMA_VERSION,
    status:
      snapshotCount === 0 || restorePreviewCount === 0
        ? "needs_evidence"
        : readOnlyReplayMode || restoreApplyAppliedCount > 0
          ? "ready"
          : "blocked",
    readOnlyReplayMode,
    cellCount: cells.length,
    receiptBackedCellCount,
    snapshotCount,
    restorePreviewCount,
    restoreApplyBlockedCount,
    restoreApplyAppliedCount,
    rollbackRefCount: rollbackRefs.length,
    cells,
    evidenceRefs: uniqueStrings(cells.flatMap((cell) => [...cell.receiptRefs, ...cell.artifactRefs, ...cell.rollbackRefs])),
  };
}

function cellForEvent(event: WorkflowRuntimeThreadEventLike): WorkflowSignedReplayNotebookCell | null {
  const eventKind = stringField(event, "eventKind", "event_kind");
  const componentKind = stringField(event, "componentKind", "component_kind");
  const payload = payloadForEvent(event);
  if (eventKind === "tool.completed" || eventKind === "tool.failed") {
    return baseCell(event, {
      cellKind: "tool",
      title: stringField(event, "toolName", "tool_name") ?? "Runtime tool",
      summary: stringField(payload, "summary") ?? stringField(payload, "error", "message"),
      toolName: stringField(event, "toolName", "tool_name"),
      toolCallId: stringField(event, "toolCallId", "tool_call_id"),
      snapshotId: null,
      filePaths: filePathsFromPayload(payload),
      operationCount: filePathsFromPayload(payload).length,
      approvalRequired: null,
      approvalSatisfied: null,
      restorePreviewEndpoint: null,
      restoreApplyEndpoint: null,
      readOnlyReplay: false,
    });
  }
  if (eventKind === "workspace.snapshot.created" || componentKind === "workspace_snapshot") {
    const snapshotId = stringField(payload, "snapshotId", "snapshot_id") ?? firstString(arrayField(event, "rollbackRefs", "rollback_refs"));
    return baseCell(event, {
      cellKind: "snapshot",
      title: "Workspace snapshot",
      summary: stringField(payload, "summary"),
      toolName: null,
      toolCallId: stringField(payload, "toolCallId", "tool_call_id"),
      snapshotId,
      filePaths: filePathsFromPayload(payload),
      operationCount: numberField(payload, "fileCount", "file_count") ?? filePathsFromPayload(payload).length,
      approvalRequired: null,
      approvalSatisfied: null,
      restorePreviewEndpoint: endpointForSnapshot(event, snapshotId, "restore-preview"),
      restoreApplyEndpoint: endpointForSnapshot(event, snapshotId, "restore-apply"),
      readOnlyReplay: false,
    });
  }
  if (eventKind === "workspace.restore.previewed") {
    const snapshotId = stringField(payload, "snapshotId", "snapshot_id") ?? firstString(arrayField(event, "rollbackRefs", "rollback_refs"));
    return baseCell(event, {
      cellKind: "restore_preview",
      title: "Read-only restore preview",
      summary: stringField(payload, "summary"),
      toolName: null,
      toolCallId: null,
      snapshotId,
      filePaths: filePathsFromOperations(payload),
      operationCount: arrayField(payload, "operations").length,
      approvalRequired: null,
      approvalSatisfied: null,
      restorePreviewEndpoint: endpointForSnapshot(event, snapshotId, "restore-preview"),
      restoreApplyEndpoint: endpointForSnapshot(event, snapshotId, "restore-apply"),
      readOnlyReplay: true,
    });
  }
  if (eventKind === "workspace.restore.applied") {
    const snapshotId = stringField(payload, "snapshotId", "snapshot_id") ?? firstString(arrayField(event, "rollbackRefs", "rollback_refs"));
    return baseCell(event, {
      cellKind: "restore_apply",
      title: "Restore apply",
      summary: stringField(payload, "summary"),
      toolName: null,
      toolCallId: null,
      snapshotId,
      filePaths: filePathsFromOperations(payload),
      operationCount: arrayField(payload, "operations").length,
      approvalRequired: booleanField(payload, "approvalRequired", "approval_required"),
      approvalSatisfied: booleanField(payload, "approvalSatisfied", "approval_satisfied"),
      restorePreviewEndpoint: endpointForSnapshot(event, snapshotId, "restore-preview"),
      restoreApplyEndpoint: endpointForSnapshot(event, snapshotId, "restore-apply"),
      readOnlyReplay: false,
    });
  }
  return null;
}

function cellForRestoreResult(value: unknown): WorkflowSignedReplayNotebookCell | null {
  const result = objectValue(value);
  if (!result) return null;
  const schema = stringField(result, "schemaVersion", "schema_version") ?? "";
  const snapshotId = stringField(result, "snapshotId", "snapshot_id");
  const preview = schema.includes("workspace-restore-preview");
  const apply = schema.includes("workspace-restore-apply");
  if (!preview && !apply) return null;
  return {
    id: `signed-replay-${preview ? "preview" : "apply"}-${safeId(snapshotId ?? "snapshot")}-${safeId(stringField(result, "applyStatus", "apply_status", "previewStatus", "preview_status") ?? "status")}`,
    cellKind: preview ? "restore_preview" : "restore_apply",
    status: preview
      ? stringField(result, "previewStatus", "preview_status") ?? "ready"
      : stringField(result, "applyStatus", "apply_status") ?? "unknown",
    readOnlyReplay: preview || stringField(result, "applyStatus", "apply_status") === "blocked",
    eventId: stringField(objectField(result, "event"), "eventId", "event_id"),
    eventSeq: numberField(objectField(result, "event"), "seq"),
    threadId: stringField(result, "threadId", "thread_id") ?? stringField(objectField(result, "event"), "threadId", "thread_id"),
    workflowGraphId: stringField(objectField(result, "event"), "workflowGraphId", "workflow_graph_id"),
    workflowNodeId: stringField(objectField(result, "event"), "workflowNodeId", "workflow_node_id"),
    title: preview ? "Read-only restore preview" : "Restore apply",
    summary: stringField(result, "summary"),
    toolName: null,
    toolCallId: null,
    snapshotId,
    filePaths: filePathsFromOperations(result),
    operationCount: arrayField(result, "operations").length,
    approvalRequired: booleanField(result, "approvalRequired", "approval_required"),
    approvalSatisfied: booleanField(result, "approvalSatisfied", "approval_satisfied"),
    restorePreviewEndpoint: endpointForThreadSnapshot(result, snapshotId, "restore-preview"),
    restoreApplyEndpoint: endpointForThreadSnapshot(result, snapshotId, "restore-apply"),
    receiptRefs: uniqueStrings(arrayField(result, "receiptRefs", "receipt_refs")),
    artifactRefs: uniqueStrings(arrayField(result, "artifactRefs", "artifact_refs")),
    rollbackRefs: uniqueStrings(arrayField(result, "rollbackRefs", "rollback_refs")),
    policyDecisionRefs: uniqueStrings(arrayField(result, "policyDecisionRefs", "policy_decision_refs")),
  };
}

function cellForSnapshotListItem(value: unknown): WorkflowSignedReplayNotebookCell | null {
  const snapshot = objectValue(value);
  const snapshotId = stringField(snapshot, "snapshotId", "snapshot_id");
  if (!snapshotId) return null;
  return {
    id: `signed-replay-snapshot-list-${safeId(snapshotId)}`,
    cellKind: "snapshot",
    status: stringField(snapshot, "status") ?? "completed",
    readOnlyReplay: false,
    eventId: stringField(snapshot, "eventId", "event_id"),
    eventSeq: null,
    threadId: stringField(snapshot, "threadId", "thread_id"),
    workflowGraphId: stringField(snapshot, "workflowGraphId", "workflow_graph_id"),
    workflowNodeId: "runtime.workspace-snapshot",
    title: "Workspace snapshot",
    summary: stringField(snapshot, "summary"),
    toolName: null,
    toolCallId: stringField(snapshot, "toolCallId", "tool_call_id"),
    snapshotId,
    filePaths: filePathsFromPayload(snapshot),
    operationCount: numberField(snapshot, "fileCount", "file_count") ?? filePathsFromPayload(snapshot).length,
    approvalRequired: null,
    approvalSatisfied: null,
    restorePreviewEndpoint: endpointForThreadSnapshot(snapshot, snapshotId, "restore-preview"),
    restoreApplyEndpoint: endpointForThreadSnapshot(snapshot, snapshotId, "restore-apply"),
    receiptRefs: uniqueStrings(arrayField(snapshot, "receiptRefs", "receipt_refs")),
    artifactRefs: uniqueStrings(arrayField(snapshot, "artifactRefs", "artifact_refs")),
    rollbackRefs: uniqueStrings([snapshotId]),
    policyDecisionRefs: uniqueStrings(arrayField(snapshot, "policyDecisionRefs", "policy_decision_refs")),
  };
}

function baseCell(
  event: WorkflowRuntimeThreadEventLike,
  fields: Omit<
    WorkflowSignedReplayNotebookCell,
    | "id"
    | "status"
    | "eventId"
    | "eventSeq"
    | "threadId"
    | "workflowGraphId"
    | "workflowNodeId"
    | "receiptRefs"
    | "artifactRefs"
    | "rollbackRefs"
    | "policyDecisionRefs"
  >,
): WorkflowSignedReplayNotebookCell {
  const eventIdValue = eventId(event);
  return {
    id: `signed-replay-${fields.cellKind}-${safeId(eventIdValue ?? String(eventSeq(event)))}`,
    status: stringField(event, "status") ?? "unknown",
    eventId: eventIdValue,
    eventSeq: eventSeq(event),
    threadId: stringField(event, "threadId", "thread_id"),
    workflowGraphId: stringField(event, "workflowGraphId", "workflow_graph_id"),
    workflowNodeId: stringField(event, "workflowNodeId", "workflow_node_id"),
    receiptRefs: uniqueStrings(arrayField(event, "receiptRefs", "receipt_refs")),
    artifactRefs: uniqueStrings(arrayField(event, "artifactRefs", "artifact_refs")),
    rollbackRefs: uniqueStrings(arrayField(event, "rollbackRefs", "rollback_refs")),
    policyDecisionRefs: uniqueStrings(arrayField(event, "policyDecisionRefs", "policy_decision_refs")),
    ...fields,
  };
}

function mergeCells(cells: WorkflowSignedReplayNotebookCell[]): WorkflowSignedReplayNotebookCell[] {
  const byId = new Map<string, WorkflowSignedReplayNotebookCell>();
  for (const cell of cells) {
    const key =
      cell.cellKind === "snapshot" && cell.snapshotId
        ? `snapshot:${cell.snapshotId}`
        : cell.eventId ?? `${cell.cellKind}:${cell.snapshotId}:${cell.status}:${cell.workflowNodeId}`;
    const existing = byId.get(key);
    if (!existing) {
      byId.set(key, cell);
      continue;
    }
    byId.set(key, {
      ...existing,
      ...cell,
      receiptRefs: uniqueStrings([...existing.receiptRefs, ...cell.receiptRefs]),
      artifactRefs: uniqueStrings([...existing.artifactRefs, ...cell.artifactRefs]),
      rollbackRefs: uniqueStrings([...existing.rollbackRefs, ...cell.rollbackRefs]),
      policyDecisionRefs: uniqueStrings([...existing.policyDecisionRefs, ...cell.policyDecisionRefs]),
      filePaths: uniqueStrings([...existing.filePaths, ...cell.filePaths]),
    });
  }
  return [...byId.values()].sort((a, b) => (a.eventSeq ?? 999999) - (b.eventSeq ?? 999999));
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
  const threadId = stringField(value, "threadId", "thread_id");
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
