export const WORKFLOW_RECEIPT_GATE_PANEL_SCHEMA_VERSION =
  "ioi.workflow.receipt-gate-panel.v1" as const;

export interface WorkflowReceiptGatePanelInput {
  gates: unknown[];
}

export interface WorkflowReceiptGatePanelRow {
  id: string;
  rowKind: "gate_passed" | "gate_blocked";
  status: "passed" | "blocked";
  receiptId: string | null;
  gateReceiptId: string | null;
  routeId: string | null;
  selectedModel: string | null;
  endpointId: string | null;
  backendId: string | null;
  requiredToolReceiptIds: string[];
  failures: string[];
  evidenceRefs: string[];
}

export interface WorkflowReceiptGatePanel {
  schemaVersion: typeof WORKFLOW_RECEIPT_GATE_PANEL_SCHEMA_VERSION;
  status: "ready" | "needs_evidence" | "blocked";
  passedCount: number;
  blockedCount: number;
  missingReceiptCount: number;
  rows: WorkflowReceiptGatePanelRow[];
  evidenceRefs: string[];
}

export function buildWorkflowReceiptGatePanel(
  input: WorkflowReceiptGatePanelInput,
): WorkflowReceiptGatePanel {
  const rows = normalizeArray(input.gates)
    .map(gateRow)
    .filter((row): row is WorkflowReceiptGatePanelRow => Boolean(row));
  const passedCount = rows.filter((row) => row.status === "passed").length;
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const missingReceiptCount = rows.filter((row) => !row.receiptId || !row.gateReceiptId).length;
  return {
    schemaVersion: WORKFLOW_RECEIPT_GATE_PANEL_SCHEMA_VERSION,
    status:
      missingReceiptCount > 0
        ? "needs_evidence"
        : passedCount > 0 && blockedCount > 0
          ? "ready"
          : "blocked",
    passedCount,
    blockedCount,
    missingReceiptCount,
    rows,
    evidenceRefs: uniqueStrings(rows.flatMap((row) => row.evidenceRefs)),
  };
}

function gateRow(value: unknown): WorkflowReceiptGatePanelRow | null {
  const gate = objectValue(value);
  if (!gate) return null;
  const gateReceipt = objectField(gate, "gate_receipt");
  const blocked = objectField(gate, "blocked");
  const blockedDetails = objectField(blocked, "details");
  const sourceReceipt = objectField(gate, "receipt");
  const receiptDetails = objectField(sourceReceipt, "details");
  const blockedReceipt = objectField(gate, "blocked_receipt");
  const blockedReceiptDetails = objectField(blockedReceipt, "details");
  const passed = stringField(gate, "status") === "passed" || Boolean(gateReceipt.id);
  const receiptId =
    stringField(gate, "receipt_id") ??
    stringField(receiptDetails, "receipt_id") ??
    stringField(blockedDetails, "receipt_id") ??
    stringField(blockedReceiptDetails, "receipt_id") ??
    stringField(sourceReceipt, "id");
  const gateReceiptId =
    stringField(gateReceipt, "id") ??
    stringField(blockedDetails, "gate_receipt_id") ??
    stringField(blockedReceipt, "id");
  const failures = uniqueStrings([
    ...arrayField(blockedDetails, "failures"),
    ...arrayField(blockedReceiptDetails, "failures"),
  ]);
  const rowKind = passed ? "gate_passed" : "gate_blocked";
  const details = passed ? objectField(gateReceipt, "details") : blockedReceiptDetails;
  return {
    id: `receipt-gate-${passed ? "passed" : "blocked"}-${safeId(gateReceiptId ?? receiptId ?? "gate")}`,
    rowKind,
    status: passed ? "passed" : "blocked",
    receiptId,
    gateReceiptId,
    routeId:
      stringField(details, "route_id") ??
      stringField(receiptDetails, "route_id") ??
      routeFailureValue(failures),
    selectedModel:
      stringField(details, "selected_model") ??
      stringField(receiptDetails, "selected_model"),
    endpointId:
      stringField(details, "endpoint_id") ??
      stringField(receiptDetails, "endpoint_id"),
    backendId:
      stringField(details, "backend_id", "selected_backend") ??
      stringField(receiptDetails, "backend_id", "selected_backend"),
    requiredToolReceiptIds: uniqueStrings([
      ...arrayField(details, "required_tool_receipt_ids"),
      ...arrayField(receiptDetails, "tool_receipt_ids"),
    ]),
    failures,
    evidenceRefs: uniqueStrings([
      receiptId,
      gateReceiptId,
      ...arrayField(gateReceipt, "evidence_refs"),
      ...arrayField(blockedReceipt, "evidence_refs"),
    ]),
  };
}

function routeFailureValue(failures: string[]): string | null {
  const routeFailure = failures.find((failure) => failure.startsWith("route:"));
  return routeFailure ? routeFailure.slice("route:".length) : null;
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
