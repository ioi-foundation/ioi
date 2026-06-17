export const WORKFLOW_AUTH_STREAM_FAILURE_PANEL_SCHEMA_VERSION =
  "ioi.workflow.auth-stream-failure-panel.v1" as const;

export interface WorkflowAuthFailureInput {
  surface: string;
  status: number;
  code?: string | null;
  message?: string | null;
  tokenValueIncluded?: boolean | null;
}

export interface WorkflowStreamFailurePanelInput {
  authFailures?: readonly WorkflowAuthFailureInput[] | null;
  receipts?: readonly Record<string, unknown>[] | null;
}

export interface WorkflowAuthStreamFailureRow {
  rowKind: "auth_failure" | "stream_canceled" | "stream_completed";
  status: "blocked" | "canceled" | "completed";
  surface: string | null;
  statusCode: number | null;
  code: string | null;
  message: string | null;
  receiptId: string | null;
  invocationReceiptId: string | null;
  streamKind: string | null;
  routeId: string | null;
  selectedModel: string | null;
  framesWritten: number | null;
  tokenValueIncluded: boolean;
}

export interface WorkflowAuthStreamFailurePanel {
  schemaVersion: typeof WORKFLOW_AUTH_STREAM_FAILURE_PANEL_SCHEMA_VERSION;
  status: "empty" | "ready" | "blocked";
  authFailureCount: number;
  streamCanceledCount: number;
  streamCompletedCount: number;
  cleanErrorCount: number;
  tokenLeakDetected: boolean;
  receiptIds: string[];
  invocationReceiptIds: string[];
  rows: WorkflowAuthStreamFailureRow[];
}

export function buildWorkflowAuthStreamFailurePanel(
  input: WorkflowStreamFailurePanelInput,
): WorkflowAuthStreamFailurePanel {
  const authRows = (input.authFailures ?? []).map(authFailureRow);
  const streamRows = (input.receipts ?? [])
    .map(streamReceiptRow)
    .filter((row): row is WorkflowAuthStreamFailureRow => Boolean(row));
  const rows = [...authRows, ...streamRows];
  const authFailureCount = authRows.length;
  const streamCanceledCount = rows.filter((row) => row.rowKind === "stream_canceled").length;
  const streamCompletedCount = rows.filter((row) => row.rowKind === "stream_completed").length;
  const cleanErrorCount = authRows.filter((row) => row.statusCode === 401 || row.statusCode === 403).length;
  const tokenLeakDetected = rows.some((row) => row.tokenValueIncluded);
  const status =
    rows.length === 0
      ? "empty"
      : tokenLeakDetected || authFailureCount === 0 || streamCanceledCount === 0
        ? "blocked"
        : "ready";
  return {
    schemaVersion: WORKFLOW_AUTH_STREAM_FAILURE_PANEL_SCHEMA_VERSION,
    status,
    authFailureCount,
    streamCanceledCount,
    streamCompletedCount,
    cleanErrorCount,
    tokenLeakDetected,
    receiptIds: uniqueStrings(rows.map((row) => row.receiptId)),
    invocationReceiptIds: uniqueStrings(rows.map((row) => row.invocationReceiptId)),
    rows,
  };
}

function authFailureRow(input: WorkflowAuthFailureInput): WorkflowAuthStreamFailureRow {
  return {
    rowKind: "auth_failure",
    status: "blocked",
    surface: input.surface,
    statusCode: Number.isFinite(input.status) ? input.status : null,
    code: cleanString(input.code),
    message: cleanString(input.message),
    receiptId: null,
    invocationReceiptId: null,
    streamKind: null,
    routeId: null,
    selectedModel: null,
    framesWritten: null,
    tokenValueIncluded: Boolean(input.tokenValueIncluded),
  };
}

function streamReceiptRow(receipt: Record<string, unknown>): WorkflowAuthStreamFailureRow | null {
  const kind = cleanString(receipt.kind);
  if (kind !== "model_invocation_stream_canceled" && kind !== "model_invocation_stream_completed") {
    return null;
  }
  const details = objectField(receipt, "details") ?? {};
  const canceled = kind === "model_invocation_stream_canceled";
  return {
    rowKind: canceled ? "stream_canceled" : "stream_completed",
    status: canceled ? "canceled" : "completed",
    surface: null,
    statusCode: null,
    code: cleanString(details.reason) ?? (canceled ? "client_disconnect" : null),
    message: cleanString(receipt.summary),
    receiptId: cleanString(receipt.id),
    invocationReceiptId: cleanString(details.invocation_receipt_id),
    streamKind: cleanString(details.stream_kind),
    routeId: cleanString(details.route_id),
    selectedModel: cleanString(details.selected_model),
    framesWritten: numberField(details, "frames_written", "chunks_forwarded"),
    tokenValueIncluded: JSON.stringify(receipt).includes("sk-") || JSON.stringify(receipt).includes("Bearer "),
  };
}

function objectField(record: unknown, key: string): Record<string, unknown> | null {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  const value = (record as Record<string, unknown>)[key];
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function numberField(record: unknown, ...keys: string[]): number | null {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  for (const key of keys) {
    const value = (record as Record<string, unknown>)[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
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
