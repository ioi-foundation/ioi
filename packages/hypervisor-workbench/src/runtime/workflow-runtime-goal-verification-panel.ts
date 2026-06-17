import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  workflowRuntimeEventId,
  workflowRuntimeEventKind,
} from "./workflow-runtime-event-identity";

export const WORKFLOW_RUNTIME_GOAL_VERIFICATION_PANEL_SCHEMA_VERSION =
  "ioi.workflow.goal-verification-panel.v1" as const;

export type WorkflowRuntimeGoalVerificationStatus =
  | "empty"
  | "passed"
  | "failed"
  | "blocked"
  | "waiting";

export type WorkflowRuntimeGoalVerificationRowKind =
  | "diagnostics_run"
  | "diagnostics_gate"
  | "repair_action"
  | "completion";

export interface WorkflowRuntimeGoalVerificationPanelOptions {
  threadId?: string | null;
  workflowGraphId?: string | null;
}

export interface WorkflowRuntimeGoalVerificationRow {
  rowKind: WorkflowRuntimeGoalVerificationRowKind;
  status: Exclude<WorkflowRuntimeGoalVerificationStatus, "empty">;
  label: string;
  eventId: string | null;
  eventKind: string;
  eventSeq: number | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  threadId: string | null;
  turnId: string | null;
  toolName: string | null;
  diagnosticStatus: string | null;
  diagnosticCount: number | null;
  stopReason: string | null;
  summary: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
}

export interface WorkflowRuntimeGoalVerificationPanel {
  schemaVersion: typeof WORKFLOW_RUNTIME_GOAL_VERIFICATION_PANEL_SCHEMA_VERSION;
  status: WorkflowRuntimeGoalVerificationStatus;
  rows: WorkflowRuntimeGoalVerificationRow[];
  passedCount: number;
  failedCount: number;
  blockedCount: number;
  latestDiagnosticStatus: string | null;
  latestBlockingGateEventId: string | null;
  latestCleanDiagnosticEventId: string | null;
  latestCompletionEventId: string | null;
  eventIds: string[];
  threadIds: string[];
  workflowGraphIds: string[];
  workflowNodeIds: string[];
}

type RuntimeEventInput = WorkflowRuntimeThreadEventLike | Record<string, unknown>;

export function buildWorkflowRuntimeGoalVerificationPanel(
  events: readonly RuntimeEventInput[],
  options: WorkflowRuntimeGoalVerificationPanelOptions = {},
): WorkflowRuntimeGoalVerificationPanel {
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
    .flatMap((event) => rowsForGoalVerificationEvent(event));

  const passedCount = rows.filter((row) => row.status === "passed").length;
  const failedCount = rows.filter((row) => row.status === "failed").length;
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const latestDiagnostics = latestRow(rows, "diagnostics_run");
  const latestBlockingGate = latestRow(rows, "diagnostics_gate");
  const latestCleanDiagnostics = latestMatchingRow(
    rows,
    (row) => row.rowKind === "diagnostics_run" && row.diagnosticStatus === "clean",
  );
  const latestCompletion = latestRow(rows, "completion");
  const status = panelStatus({
    rows,
    latestDiagnostics,
    latestBlockingGate,
    latestCleanDiagnostics,
    latestCompletion,
  });

  return {
    schemaVersion: WORKFLOW_RUNTIME_GOAL_VERIFICATION_PANEL_SCHEMA_VERSION,
    status,
    rows,
    passedCount,
    failedCount,
    blockedCount,
    latestDiagnosticStatus: latestDiagnostics?.diagnosticStatus ?? null,
    latestBlockingGateEventId: latestBlockingGate?.eventId ?? null,
    latestCleanDiagnosticEventId: latestCleanDiagnostics?.eventId ?? null,
    latestCompletionEventId: latestCompletion?.eventId ?? null,
    eventIds: uniqueStrings(rows.map((row) => row.eventId)),
    threadIds: uniqueStrings(rows.map((row) => row.threadId)),
    workflowGraphIds: uniqueStrings(rows.map((row) => row.workflowGraphId)),
    workflowNodeIds: uniqueStrings(rows.map((row) => row.workflowNodeId)),
  };
}

function rowsForGoalVerificationEvent(event: RuntimeEventInput): WorkflowRuntimeGoalVerificationRow[] {
  const kind = eventKind(event);
  const payload = eventPayload(event);
  const componentKind = eventComponentKind(event);
  const toolName = stringField(payload, "tool_name") ?? eventToolName(event);
  if (kind === "tool.completed" && toolName === "lsp.diagnostics") {
    const result = objectField(payload, "result");
    const diagnosticStatus = stringField(result, "diagnostic_status") ??
      stringField(payload, "diagnostic_status");
    const diagnosticCount =
      numberField(result, "diagnostic_count") ??
      numberField(payload, "diagnostic_count");
    return [
      baseRow(event, payload, {
        rowKind: "diagnostics_run",
        status: diagnosticStatus === "clean" ? "passed" : "failed",
        label: diagnosticStatus === "clean" ? "Diagnostics clean" : "Diagnostics found issues",
        toolName,
        diagnosticStatus: diagnosticStatus ?? null,
        diagnosticCount: diagnosticCount ?? null,
      }),
    ];
  }
  if (kind === "policy.blocked" && componentKind === "lsp_diagnostics_gate") {
    return [
      baseRow(event, payload, {
        rowKind: "diagnostics_gate",
        status: "blocked",
        label: "Completion blocked by diagnostics",
        diagnosticStatus: stringField(payload, "diagnostic_status"),
        diagnosticCount: numberField(payload, "diagnostic_count"),
      }),
    ];
  }
  if (kind === "tool.completed" && toolName === "file.apply_patch") {
    const nodeId = eventWorkflowNodeId(event) ?? "";
    const summary = stringField(payload, "summary");
    if (!/repair|fix|green|diagnostic/i.test(`${nodeId} ${summary ?? ""}`)) return [];
    return [
      baseRow(event, payload, {
        rowKind: "repair_action",
        status: "passed",
        label: "Repair patch applied",
        toolName,
      }),
    ];
  }
  if (kind === "turn.completed") {
    return [
      baseRow(event, payload, {
        rowKind: "completion",
        status: "passed",
        label: "Completion allowed",
        stopReason: stringField(payload, "stop_reason"),
      }),
    ];
  }
  return [];
}

function panelStatus({
  rows,
  latestDiagnostics,
  latestBlockingGate,
  latestCleanDiagnostics,
  latestCompletion,
}: {
  rows: WorkflowRuntimeGoalVerificationRow[];
  latestDiagnostics?: WorkflowRuntimeGoalVerificationRow;
  latestBlockingGate?: WorkflowRuntimeGoalVerificationRow;
  latestCleanDiagnostics?: WorkflowRuntimeGoalVerificationRow;
  latestCompletion?: WorkflowRuntimeGoalVerificationRow;
}): WorkflowRuntimeGoalVerificationStatus {
  if (!rows.length) return "empty";
  const latestCleanSeq = latestCleanDiagnostics?.eventSeq ?? 0;
  const latestGateSeq = latestBlockingGate?.eventSeq ?? 0;
  const latestCompletionSeq = latestCompletion?.eventSeq ?? 0;
  if (latestCleanSeq > latestGateSeq && latestCompletionSeq > latestCleanSeq) return "passed";
  if (latestGateSeq > latestCleanSeq) return "blocked";
  if (latestDiagnostics?.status === "failed") return "failed";
  return latestCleanDiagnostics ? "waiting" : "failed";
}

function baseRow(
  event: RuntimeEventInput,
  payload: Record<string, unknown>,
  overrides: Partial<WorkflowRuntimeGoalVerificationRow>,
): WorkflowRuntimeGoalVerificationRow {
  return {
    rowKind: overrides.rowKind ?? "completion",
    status: overrides.status ?? "waiting",
    label: overrides.label ?? "Verification",
    eventId: eventIdForRuntimeEvent(event),
    eventKind: eventKind(event),
    eventSeq: eventSeq(event),
    workflowGraphId: eventWorkflowGraphId(event),
    workflowNodeId: eventWorkflowNodeId(event),
    threadId: eventThreadId(event),
    turnId: eventTurnId(event),
    toolName: overrides.toolName ?? stringField(payload, "tool_name") ?? eventToolName(event),
    diagnosticStatus: overrides.diagnosticStatus ?? null,
    diagnosticCount: overrides.diagnosticCount ?? null,
    stopReason: overrides.stopReason ?? stringField(payload, "stop_reason"),
    summary: overrides.summary ?? stringField(payload, "summary", "message"),
    receiptRefs: uniqueStrings([
      ...arrayField(event, "receipt_refs"),
      ...arrayField(payload, "receipt_refs"),
    ]),
    policyDecisionRefs: uniqueStrings([
      ...arrayField(event, "policy_decision_refs"),
      ...arrayField(payload, "policy_decision_refs"),
    ]),
    rollbackRefs: uniqueStrings([
      ...arrayField(event, "rollback_refs"),
      ...arrayField(payload, "rollback_refs"),
    ]),
  };
}

function latestRow(
  rows: readonly WorkflowRuntimeGoalVerificationRow[],
  rowKind: WorkflowRuntimeGoalVerificationRowKind,
): WorkflowRuntimeGoalVerificationRow | undefined {
  return latestMatchingRow(rows, (row) => row.rowKind === rowKind);
}

function latestMatchingRow(
  rows: readonly WorkflowRuntimeGoalVerificationRow[],
  predicate: (row: WorkflowRuntimeGoalVerificationRow) => boolean,
): WorkflowRuntimeGoalVerificationRow | undefined {
  const matches = rows
    .filter(predicate)
    .sort((left, right) => (left.eventSeq ?? 0) - (right.eventSeq ?? 0));
  return matches[matches.length - 1];
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

function eventSeq(event: RuntimeEventInput): number {
  return numberField(event, "seq") ?? 0;
}

function eventThreadId(event: RuntimeEventInput): string | null {
  return stringField(event, "thread_id");
}

function eventTurnId(event: RuntimeEventInput): string | null {
  return stringField(event, "turn_id");
}

function eventWorkflowGraphId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflow_graph_id");
}

function eventWorkflowNodeId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflow_node_id");
}

function eventComponentKind(event: RuntimeEventInput): string | null {
  return stringField(event, "component_kind");
}

function eventToolName(event: RuntimeEventInput): string | null {
  return stringField(event, "tool_name");
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
