export const WORKFLOW_IMPORTED_GENERATION_METADATA_SCHEMA_VERSION =
  "ioi.workflow.imported-generation-metadata.v1" as const;

export type WorkflowImportedGenerationMetadataKind =
  | "prompt_context"
  | "model_route"
  | "thinking_trace"
  | "gateway_request"
  | "assistant_output"
  | "token_usage";

export type WorkflowImportedGenerationMetadataStatus =
  | "ready"
  | "needs_review"
  | "blocked";

export interface WorkflowImportedGenerationMetadataInputRow {
  sourceRowId?: string | number | null;
  kind: WorkflowImportedGenerationMetadataKind;
  text?: string | null;
  modelId?: string | null;
  routeId?: string | null;
  provider?: string | null;
  tokenCounts?: {
    input?: number | null;
    output?: number | null;
    reasoning?: number | null;
  } | null;
  gatewayUrl?: string | null;
  headers?: Record<string, unknown> | null;
  receiptRefs?: readonly string[] | null;
}

export interface WorkflowImportedGenerationMetadataInput {
  sourceTable?: string | null;
  trajectoryId: string;
  rows: readonly WorkflowImportedGenerationMetadataInputRow[];
}

export interface WorkflowImportedGenerationMetadataRow {
  id: string;
  sourceRowId: string | null;
  kind: WorkflowImportedGenerationMetadataKind;
  status: WorkflowImportedGenerationMetadataStatus;
  retention:
    | "metadata_only"
    | "summary_only"
    | "reasoning_summary_only"
    | "redacted_headers"
    | "blocked";
  label: string;
  contentHash: string | null;
  redactedPreview: string;
  modelId: string | null;
  routeId: string | null;
  provider: string | null;
  tokenCounts: {
    input: number | null;
    output: number | null;
    reasoning: number | null;
  };
  endpointHost: string | null;
  endpointPath: string | null;
  redactedHeaders: Record<string, unknown>;
  receiptRefs: string[];
  policyRefs: string[];
}

export interface WorkflowImportedGenerationMetadataPanel {
  schemaVersion: typeof WORKFLOW_IMPORTED_GENERATION_METADATA_SCHEMA_VERSION;
  status: WorkflowImportedGenerationMetadataStatus;
  sourceTable: string;
  trajectoryId: string;
  importedAuthority: "historical_only";
  applyMode: "audit_only";
  rowCount: number;
  readyCount: number;
  needsReviewCount: number;
  blockedCount: number;
  rawPromptRetention: "never";
  rawReasoningRetention: "never";
  rows: WorkflowImportedGenerationMetadataRow[];
}

export function buildWorkflowImportedGenerationMetadataPanel(
  input: WorkflowImportedGenerationMetadataInput,
): WorkflowImportedGenerationMetadataPanel {
  const rows = input.rows.map((row, index) => buildRow(row, index));
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const needsReviewCount = rows.filter((row) => row.status === "needs_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;
  return {
    schemaVersion: WORKFLOW_IMPORTED_GENERATION_METADATA_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : needsReviewCount > 0 ? "needs_review" : "ready",
    sourceTable: cleanString(input.sourceTable) ?? "gen_metadata",
    trajectoryId: input.trajectoryId,
    importedAuthority: "historical_only",
    applyMode: "audit_only",
    rowCount: rows.length,
    readyCount,
    needsReviewCount,
    blockedCount,
    rawPromptRetention: "never",
    rawReasoningRetention: "never",
    rows,
  };
}

function buildRow(
  row: WorkflowImportedGenerationMetadataInputRow,
  index: number,
): WorkflowImportedGenerationMetadataRow {
  const sourceRowId = stringField(row.sourceRowId);
  const receiptRefs = uniqueStrings(row.receiptRefs ?? []);
  const parsedGatewayUrl = parseUrl(row.gatewayUrl ?? "");
  const text = cleanString(row.text);
  const contentHash = text ? stableContentHash({ kind: row.kind, text }) : null;
  const basePolicyRefs = [
    "policy:gen_metadata.import.historical_only",
    "policy:gen_metadata.raw_prompt_retention.never",
  ];
  if (row.kind === "thinking_trace") {
    basePolicyRefs.push("policy:gen_metadata.raw_reasoning_retention.never");
  }
  if (receiptRefs.length === 0) {
    basePolicyRefs.push("policy:gen_metadata.review.missing_receipt");
  }
  const redactedHeaders = redactObject(row.headers ?? {});
  const gatewayBlocked =
    row.kind === "gateway_request" &&
    (!!row.gatewayUrl && (!parsedGatewayUrl || parsedGatewayUrl.protocol !== "https:"));
  if (gatewayBlocked) {
    basePolicyRefs.push("policy:gen_metadata.block.non_https_gateway_trace");
  }
  if (row.kind === "gateway_request") {
    basePolicyRefs.push("policy:gen_metadata.gateway_headers.redacted");
  }

  const status = basePolicyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : basePolicyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "needs_review"
      : "ready";

  return {
    id: `gen:${safeId(row.kind)}:${sourceRowId ?? index}`,
    sourceRowId,
    kind: row.kind,
    status,
    retention: retentionForKind(row.kind, status),
    label: labelForKind(row.kind),
    contentHash,
    redactedPreview: previewForKind(row.kind, text),
    modelId: safeMetadataString(row.modelId),
    routeId: safeMetadataString(row.routeId),
    provider: safeMetadataString(row.provider),
    tokenCounts: normalizeTokenCounts(row.tokenCounts ?? null),
    endpointHost: parsedGatewayUrl?.host ?? null,
    endpointPath: parsedGatewayUrl?.pathname ?? null,
    redactedHeaders,
    receiptRefs,
    policyRefs: basePolicyRefs,
  };
}

function retentionForKind(
  kind: WorkflowImportedGenerationMetadataKind,
  status: WorkflowImportedGenerationMetadataStatus,
): WorkflowImportedGenerationMetadataRow["retention"] {
  if (status === "blocked") return "blocked";
  if (kind === "gateway_request") return "redacted_headers";
  if (kind === "thinking_trace") return "reasoning_summary_only";
  if (kind === "prompt_context" || kind === "assistant_output") return "summary_only";
  return "metadata_only";
}

function previewForKind(
  kind: WorkflowImportedGenerationMetadataKind,
  text: string | null,
): string {
  if (!text) return "";
  if (kind === "prompt_context") return "[PROMPT SUMMARY REDACTED]";
  if (kind === "thinking_trace") return "[REASONING SUMMARY REDACTED]";
  if (kind === "assistant_output") return "[ASSISTANT OUTPUT SUMMARY REDACTED]";
  return redactTokenValue(text).slice(0, 120);
}

function labelForKind(kind: WorkflowImportedGenerationMetadataKind): string {
  return kind
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function normalizeTokenCounts(
  tokenCounts: WorkflowImportedGenerationMetadataInputRow["tokenCounts"],
): WorkflowImportedGenerationMetadataRow["tokenCounts"] {
  return {
    input: positiveNumber(tokenCounts?.input),
    output: positiveNumber(tokenCounts?.output),
    reasoning: positiveNumber(tokenCounts?.reasoning),
  };
}

function safeMetadataString(value: unknown): string | null {
  const text = cleanString(value);
  if (!text) return null;
  return redactTokenValue(text);
}

function redactObject(value: Record<string, unknown>): Record<string, unknown> {
  const next: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    next[key] = isTokenKey(key) || isTokenValue(entry) ? "[REDACTED]" : entry;
  }
  return next;
}

function redactTokenValue(value: string): string {
  return value
    .replace(/\b(?:bearer\s+)?ya29\.[a-z0-9._-]+/gi, "[REDACTED]")
    .replace(/\bsk-[a-z0-9_-]{8,}\b/gi, "[REDACTED]")
    .replace(/\b(?:csrf|oauth|token|secret|password|credential)[=:][^\s,;]+/gi, "[REDACTED]");
}

function isTokenKey(value: string): boolean {
  return /(?:authorization|csrf|oauth|token|secret|password|credential)/i.test(value);
}

function isTokenValue(value: unknown): boolean {
  return typeof value === "string" && redactTokenValue(value) !== value;
}

function parseUrl(value: string): URL | null {
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
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
