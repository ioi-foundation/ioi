export const WORKFLOW_TRAJECTORY_IMPORT_AUDIT_SCHEMA_VERSION =
  "ioi.workflow.trajectory-import-audit.v1" as const;

export type WorkflowTrajectoryImportAuditRowKind =
  | "message"
  | "tool_call"
  | "executor_metadata"
  | "trajectory_metadata"
  | "workspace_uri"
  | "unknown";

export type WorkflowTrajectoryImportAuditRowStatus = "ready" | "manual_review" | "blocked";

export interface WorkflowTrajectoryImportAuditRecord {
  sourceTable: string;
  fieldPath?: string | null;
  sequence?: number | null;
  stepId?: string | null;
  decodedType?: string | null;
  payload?: unknown;
  workspaceUri?: string | null;
  receiptRefs?: readonly string[] | null;
  ioiReceiptRefs?: readonly string[] | null;
}

export interface WorkflowTrajectoryImportAuditInput {
  currentWorkspaceRoot?: string | null;
  records: readonly WorkflowTrajectoryImportAuditRecord[];
}

export interface WorkflowTrajectoryImportAuditRow {
  id: string;
  sourceTable: string;
  fieldPath: string;
  seq: number;
  stepId: string | null;
  kind: WorkflowTrajectoryImportAuditRowKind;
  status: WorkflowTrajectoryImportAuditRowStatus;
  summary: string;
  redactedPreview: string;
  receiptRefs: string[];
  workspaceUris: string[];
  policyRefs: string[];
}

export interface WorkflowTrajectoryImportAuditPanel {
  schemaVersion: typeof WORKFLOW_TRAJECTORY_IMPORT_AUDIT_SCHEMA_VERSION;
  status: "empty" | "ready" | "needs_review" | "blocked";
  applyMode: "plan_only";
  sourceFormat: "decoded_sqlite_rows";
  rowCount: number;
  messageCount: number;
  toolCallCount: number;
  workspaceUriCount: number;
  secretFindingCount: number;
  missingReceiptCount: number;
  blockedCount: number;
  manualReviewCount: number;
  rows: WorkflowTrajectoryImportAuditRow[];
}

const BASE_POLICY_REFS = ["policy:trajectory_import.plan_only"] as const;

export function buildWorkflowTrajectoryImportAudit(
  input: WorkflowTrajectoryImportAuditInput,
): WorkflowTrajectoryImportAuditPanel {
  const root = normalizeFsPath(input.currentWorkspaceRoot ?? "");
  const rows = normalizeRecords(input.records).map((record, index) => auditRecord(record, index, root));
  rows.sort((left, right) => left.seq - right.seq || left.id.localeCompare(right.id));

  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const manualReviewCount = rows.filter((row) => row.status === "manual_review").length;
  const workspaceUris = new Set(rows.flatMap((row) => row.workspaceUris));

  return {
    schemaVersion: WORKFLOW_TRAJECTORY_IMPORT_AUDIT_SCHEMA_VERSION,
    status: rows.length === 0 ? "empty" : blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    applyMode: "plan_only",
    sourceFormat: "decoded_sqlite_rows",
    rowCount: rows.length,
    messageCount: rows.filter((row) => row.kind === "message").length,
    toolCallCount: rows.filter((row) => row.kind === "tool_call").length,
    workspaceUriCount: workspaceUris.size,
    secretFindingCount: rows.filter((row) =>
      row.policyRefs.includes("policy:trajectory_import.block.secret_material")
    ).length,
    missingReceiptCount: rows.filter((row) =>
      row.policyRefs.includes("policy:trajectory_import.review.missing_ioi_receipt")
    ).length,
    blockedCount,
    manualReviewCount,
    rows,
  };
}

function auditRecord(
  record: WorkflowTrajectoryImportAuditRecord,
  index: number,
  currentWorkspaceRoot: string,
): WorkflowTrajectoryImportAuditRow {
  const sourceTable = stringField(record.sourceTable) ?? "unknown_table";
  const fieldPath = stringField(record.fieldPath) ?? defaultFieldPath(sourceTable);
  const seq = typeof record.sequence === "number" && Number.isFinite(record.sequence)
    ? record.sequence
    : index + 1;
  const stepId = stringField(record.stepId);
  const payload = record.payload ?? {};
  const kind = inferKind(record);
  const receiptRefs = uniqueStrings([
    ...(record.receiptRefs ?? []),
    ...(record.ioiReceiptRefs ?? []),
    ...receiptRefsFromPayload(payload),
  ]);
  const workspaceUris = uniqueStrings([
    ...workspaceUrisFromPayload(payload),
    ...(stringField(record.workspaceUri) ? [stringField(record.workspaceUri) as string] : []),
  ]);
  const preview = redactedPreview(payload);
  const policyRefs: string[] = [...BASE_POLICY_REFS];

  if (receiptRefs.length === 0 && kind !== "trajectory_metadata" && kind !== "workspace_uri") {
    policyRefs.push("policy:trajectory_import.review.external_unsigned");
    policyRefs.push("policy:trajectory_import.review.missing_ioi_receipt");
  }
  if (preview.secretCount > 0) {
    policyRefs.push("policy:trajectory_import.block.secret_material");
  }
  if (hasWorkspaceEscape(workspaceUris, currentWorkspaceRoot)) {
    policyRefs.push("policy:trajectory_import.block.workspace_escape");
  }
  if (kind === "unknown") {
    policyRefs.push("policy:trajectory_import.review.unknown_record");
  }

  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "manual_review"
      : "ready";

  return {
    id: `trajectory:${seq}:${safeId(sourceTable)}:${safeId(fieldPath)}:${safeId(stepId ?? String(index + 1))}`,
    sourceTable,
    fieldPath,
    seq,
    stepId,
    kind,
    status,
    summary: summarizeRecord(record, kind),
    redactedPreview: preview.text,
    receiptRefs,
    workspaceUris,
    policyRefs,
  };
}

function inferKind(record: WorkflowTrajectoryImportAuditRecord): WorkflowTrajectoryImportAuditRowKind {
  const table = stringField(record.sourceTable)?.toLowerCase() ?? "";
  const decodedType = stringField(record.decodedType)?.toLowerCase() ?? "";
  const payload = recordValue(record.payload);

  if (table === "executor_metadata" || decodedType.includes("executor")) {
    return "executor_metadata";
  }
  if (decodedType.includes("tool") || payloadHasAny(payload, ["toolName", "tool_name", "toolCall", "tool_call"])) {
    return "tool_call";
  }
  if (decodedType.includes("message") || payloadHasAny(payload, ["role", "content", "message", "text"])) {
    return "message";
  }
  if (table === "trajectory_metadata_blob" || decodedType.includes("trajectory")) {
    return "trajectory_metadata";
  }
  if (workspaceUrisFromPayload(record.payload).length > 0 || stringField(record.workspaceUri)) {
    return "workspace_uri";
  }
  return "unknown";
}

function summarizeRecord(
  record: WorkflowTrajectoryImportAuditRecord,
  kind: WorkflowTrajectoryImportAuditRowKind,
): string {
  const payload = recordValue(record.payload);
  if (kind === "message") {
    const role = stringField(payload?.role) ?? "message";
    const content = stringField(payload?.content) ?? stringField(payload?.text) ?? stringField(payload?.message);
    return `${role}: ${truncate(content ?? "decoded message", 96)}`;
  }
  if (kind === "tool_call") {
    const tool = stringField(payload?.toolName) ?? stringField(payload?.tool_name) ?? stringField(payload?.name);
    const command = stringField(payload?.command) ?? stringField(payload?.input);
    return `tool call: ${tool ?? "unknown"}${command ? ` (${truncate(command, 72)})` : ""}`;
  }
  if (kind === "executor_metadata") {
    const command = stringField(payload?.command) ?? stringField(payload?.argv);
    const status = stringField(payload?.status) ?? stringField(payload?.exitCode);
    return `executor metadata${command ? `: ${truncate(command, 72)}` : ""}${status ? ` [${status}]` : ""}`;
  }
  if (kind === "trajectory_metadata" || kind === "workspace_uri") {
    const uri = stringField(record.workspaceUri) ?? workspaceUrisFromPayload(record.payload)[0];
    return `trajectory metadata${uri ? `: ${uri}` : ""}`;
  }
  return "decoded trajectory record requires manual classification";
}

function redactedPreview(value: unknown): { text: string; secretCount: number } {
  const redacted = redactUnknown(value, undefined, new WeakSet<object>());
  return {
    text: truncate(JSON.stringify(redacted.value, null, 2) ?? "null", 1_200),
    secretCount: redacted.secretCount,
  };
}

function redactUnknown(
  value: unknown,
  keyHint: string | undefined,
  seen: WeakSet<object>,
): { value: unknown; secretCount: number } {
  if (isSecretKey(keyHint) || isSecretString(value)) {
    return { value: "[REDACTED]", secretCount: 1 };
  }
  if (!value || typeof value !== "object") {
    return { value, secretCount: 0 };
  }
  if (seen.has(value)) {
    return { value: "[Circular]", secretCount: 0 };
  }
  seen.add(value);

  if (Array.isArray(value)) {
    let secretCount = 0;
    const next = value.map((entry) => {
      const redacted = redactUnknown(entry, keyHint, seen);
      secretCount += redacted.secretCount;
      return redacted.value;
    });
    return { value: next, secretCount };
  }

  let secretCount = 0;
  const next: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const redacted = redactUnknown(entry, key, seen);
    secretCount += redacted.secretCount;
    next[key] = redacted.value;
  }
  return { value: next, secretCount };
}

function workspaceUrisFromPayload(value: unknown): string[] {
  const uris: string[] = [];
  collectWorkspaceUris(value, uris, new WeakSet<object>());
  return uniqueStrings(uris);
}

function collectWorkspaceUris(value: unknown, uris: string[], seen: WeakSet<object>): void {
  if (typeof value === "string") {
    if (value.startsWith("file://") || value.startsWith("vscode-remote://")) {
      uris.push(value);
    }
    return;
  }
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const entry of value) collectWorkspaceUris(entry, uris, seen);
    return;
  }
  for (const entry of Object.values(value as Record<string, unknown>)) {
    collectWorkspaceUris(entry, uris, seen);
  }
}

function receiptRefsFromPayload(value: unknown): string[] {
  const payload = recordValue(value);
  if (!payload) return [];
  return uniqueStrings([
    ...arrayOfStrings(payload.receiptRefs),
    ...arrayOfStrings(payload.receipts),
    ...arrayOfStrings(payload.ioiReceiptRefs),
  ]);
}

function hasWorkspaceEscape(workspaceUris: readonly string[], currentWorkspaceRoot: string): boolean {
  if (!currentWorkspaceRoot) return false;
  return workspaceUris.some((uri) => {
    const uriPath = fileUriPath(uri);
    if (!uriPath) return false;
    const fsPath = normalizeFsPath(uriPath);
    return fsPath ? fsPath !== currentWorkspaceRoot && !fsPath.startsWith(`${currentWorkspaceRoot}/`) : false;
  });
}

function fileUriPath(uri: string): string | null {
  if (!uri.startsWith("file://")) return null;
  try {
    return decodeURIComponent(new URL(uri).pathname);
  } catch {
    return uri.replace(/^file:\/\//, "");
  }
}

function normalizeFsPath(value: string): string {
  return value.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/, "");
}

function defaultFieldPath(sourceTable: string): string {
  if (sourceTable === "steps") return "steps.step_payload";
  if (sourceTable === "executor_metadata") return "executor_metadata.data";
  if (sourceTable === "trajectory_metadata_blob") return "trajectory_metadata_blob.data";
  return `${sourceTable}.data`;
}

function normalizeRecords(
  records: readonly WorkflowTrajectoryImportAuditRecord[] | undefined,
): WorkflowTrajectoryImportAuditRecord[] {
  return Array.isArray(records) ? records.filter(Boolean) : [];
}

function payloadHasAny(payload: Record<string, unknown> | null, keys: readonly string[]): boolean {
  return !!payload && keys.some((key) => Object.prototype.hasOwnProperty.call(payload, key));
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringField(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    : [];
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function isSecretKey(value: string | undefined): boolean {
  return !!value && /(?:token|secret|password|api[_-]?key|credential)/i.test(value);
}

function isSecretString(value: unknown): boolean {
  return typeof value === "string" && /\b(?:sk-[a-z0-9_-]{8,}|ghp_[a-z0-9_]{8,})\b/i.test(value);
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}...` : value;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "record"
  );
}
