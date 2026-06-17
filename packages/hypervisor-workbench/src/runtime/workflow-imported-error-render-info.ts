export const WORKFLOW_IMPORTED_ERROR_RENDER_INFO_SCHEMA_VERSION =
  "ioi.workflow.imported-error-render-info.v1" as const;

export type WorkflowImportedErrorRenderColumn =
  | "error_details"
  | "render_info"
  | "task_details";

export type WorkflowImportedErrorRenderStatus = "ready" | "needs_review" | "blocked";

export interface WorkflowImportedErrorRenderInfoInputRow {
  sourceRowId?: string | number | null;
  stepIndex?: number | null;
  column: WorkflowImportedErrorRenderColumn;
  code?: string | null;
  severity?: "info" | "warning" | "error" | string | null;
  message?: string | null;
  stack?: string | null;
  diagnosticPath?: string | null;
  renderKind?: "screenshot" | "markdown" | "diff" | "trace" | string | null;
  artifactRef?: string | null;
  targetUri?: string | null;
  receiptRefs?: readonly string[] | null;
}

export interface WorkflowImportedErrorRenderInfoInput {
  sourceTable?: string | null;
  trajectoryId: string;
  workspaceRoot?: string | null;
  rows: readonly WorkflowImportedErrorRenderInfoInputRow[];
}

export interface WorkflowImportedErrorRenderInfoRow {
  id: string;
  sourceRowId: string | null;
  stepIndex: number | null;
  column: WorkflowImportedErrorRenderColumn;
  status: WorkflowImportedErrorRenderStatus;
  retention: "summary_only" | "artifact_ref_only" | "blocked";
  code: string | null;
  severity: "info" | "warning" | "error";
  redactedMessage: string;
  stackHash: string | null;
  diagnosticPath: string | null;
  renderKind: string | null;
  artifactRef: string | null;
  targetUri: string | null;
  receiptRefs: string[];
  policyRefs: string[];
}

export interface WorkflowImportedErrorRenderInfoPanel {
  schemaVersion: typeof WORKFLOW_IMPORTED_ERROR_RENDER_INFO_SCHEMA_VERSION;
  status: WorkflowImportedErrorRenderStatus;
  sourceTable: string;
  trajectoryId: string;
  workspaceRoot: string | null;
  importedAuthority: "historical_only";
  applyMode: "audit_only";
  rawStackRetention: "never";
  externalRenderRetention: "never";
  rowCount: number;
  readyCount: number;
  needsReviewCount: number;
  blockedCount: number;
  rows: WorkflowImportedErrorRenderInfoRow[];
}

export function buildWorkflowImportedErrorRenderInfoPanel(
  input: WorkflowImportedErrorRenderInfoInput,
): WorkflowImportedErrorRenderInfoPanel {
  const workspaceRoot = cleanString(input.workspaceRoot);
  const rows = input.rows.map((row, index) => buildRow(row, index, workspaceRoot));
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const needsReviewCount = rows.filter((row) => row.status === "needs_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;
  return {
    schemaVersion: WORKFLOW_IMPORTED_ERROR_RENDER_INFO_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : needsReviewCount > 0 ? "needs_review" : "ready",
    sourceTable: cleanString(input.sourceTable) ?? "steps",
    trajectoryId: input.trajectoryId,
    workspaceRoot,
    importedAuthority: "historical_only",
    applyMode: "audit_only",
    rawStackRetention: "never",
    externalRenderRetention: "never",
    rowCount: rows.length,
    readyCount,
    needsReviewCount,
    blockedCount,
    rows,
  };
}

function buildRow(
  row: WorkflowImportedErrorRenderInfoInputRow,
  index: number,
  workspaceRoot: string | null,
): WorkflowImportedErrorRenderInfoRow {
  const sourceRowId = stringField(row.sourceRowId);
  const receiptRefs = uniqueStrings(row.receiptRefs ?? []);
  const policyRefs = [
    "policy:error_render.import.historical_only",
    "policy:error_render.raw_stack_retention.never",
  ];
  if (receiptRefs.length === 0) {
    policyRefs.push("policy:error_render.review.missing_receipt");
  }
  const diagnosticPath = normalizeWorkspacePath(row.diagnosticPath ?? null, workspaceRoot);
  if (row.diagnosticPath && !diagnosticPath) {
    policyRefs.push("policy:error_render.block.workspace_path_escape");
  }
  const artifactRef = cleanString(row.artifactRef);
  if (row.column === "render_info") {
    policyRefs.push("policy:error_render.artifact_ref_only");
    if (!artifactRef) policyRefs.push("policy:error_render.review.missing_artifact_ref");
  }
  const targetUri = cleanString(row.targetUri);
  if (targetUri && isExternalUri(targetUri)) {
    policyRefs.push("policy:error_render.block.external_render_uri");
  }

  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "needs_review"
      : "ready";

  return {
    id: `step:${positiveNumber(row.stepIndex) ?? index}:${safeId(row.column)}:${sourceRowId ?? index}`,
    sourceRowId,
    stepIndex: positiveNumber(row.stepIndex),
    column: row.column,
    status,
    retention: status === "blocked"
      ? "blocked"
      : row.column === "render_info"
        ? "artifact_ref_only"
        : "summary_only",
    code: safeMetadataString(row.code),
    severity: severity(row.severity),
    redactedMessage: redactText(row.message ?? ""),
    stackHash: row.stack ? stableContentHash({ stack: row.stack }) : null,
    diagnosticPath,
    renderKind: safeMetadataString(row.renderKind),
    artifactRef,
    targetUri,
    receiptRefs,
    policyRefs,
  };
}

function normalizeWorkspacePath(value: string | null, workspaceRoot: string | null): string | null {
  const text = cleanString(value);
  if (!text) return null;
  if (/^[a-z]+:\/\//i.test(text)) return null;
  if (text.startsWith("/")) {
    if (!workspaceRoot) return null;
    const root = workspaceRoot.endsWith("/") ? workspaceRoot : `${workspaceRoot}/`;
    if (!text.startsWith(root)) return null;
    return text.slice(root.length);
  }
  if (text.split("/").some((part) => part === "..")) return null;
  return text.replace(/^\.\/+/, "");
}

function isExternalUri(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function severity(value: unknown): WorkflowImportedErrorRenderInfoRow["severity"] {
  return value === "info" || value === "warning" || value === "error" ? value : "error";
}

function safeMetadataString(value: unknown): string | null {
  const text = cleanString(value);
  return text ? redactText(text) : null;
}

function redactText(value: unknown): string {
  return String(value ?? "")
    .replace(/\b(?:bearer\s+)?ya29\.[a-z0-9._-]+/gi, "[REDACTED]")
    .replace(/\bsk-[a-z0-9_-]{8,}\b/gi, "[REDACTED]")
    .replace(/\b(?:csrf|oauth|token|secret|password|credential)[=:][^\s,;]+/gi, "[REDACTED]");
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function stringField(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return cleanString(value);
}

function positiveNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "row"
  );
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}

function stableContentHash(value: unknown): string {
  const input = stableStringify(value);
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `stable-fnv1a32:${hash.toString(16).padStart(8, "0")}`;
}
