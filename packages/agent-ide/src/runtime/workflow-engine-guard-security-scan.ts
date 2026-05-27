import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export const WORKFLOW_ENGINE_GUARD_SECURITY_SCAN_SCHEMA_VERSION =
  "ioi.workflow.engine-guard-security-scan.v1" as const;

export interface WorkflowEngineGuardSecurityFileInput {
  path?: string | null;
  content?: string | null;
  scope?: string | null;
  sourceEventId?: string | null;
  receiptRefs?: readonly unknown[] | null;
  policyDecisionRefs?: readonly unknown[] | null;
  rollbackRefs?: readonly unknown[] | null;
}

export interface WorkflowEngineGuardSecurityScanInput {
  files?: readonly WorkflowEngineGuardSecurityFileInput[] | null;
  events?: readonly WorkflowRuntimeThreadEventLike[] | null;
}

export interface WorkflowEngineGuardSecurityFinding {
  id: string;
  status: "introduced" | "existing";
  severity: "critical" | "high" | "medium";
  kind: "plaintext_secret" | "credential_header";
  filePath: string | null;
  line: number;
  column: number;
  redactedPreview: string;
  fingerprint: string;
  sourceEventId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
}

export interface WorkflowEngineGuardSecurityScanPanel {
  schemaVersion: typeof WORKFLOW_ENGINE_GUARD_SECURITY_SCAN_SCHEMA_VERSION;
  status: "passed" | "blocked" | "empty";
  scanScopeCount: number;
  findingCount: number;
  introducedFindingCount: number;
  criticalCount: number;
  mergeActionDisabled: boolean;
  mergeBlockReason: string | null;
  secretValuesIncluded: boolean;
  scannedFiles: string[];
  sourceEventIds: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
  findings: WorkflowEngineGuardSecurityFinding[];
}

export function buildWorkflowEngineGuardSecurityScanPanel(
  input: WorkflowEngineGuardSecurityScanInput,
): WorkflowEngineGuardSecurityScanPanel {
  const eventReceiptRefs = receiptRefsFromEvents(input.events ?? []);
  const findings = (input.files ?? []).flatMap((file, fileIndex) => scanFile(file, fileIndex, eventReceiptRefs));
  const introducedFindingCount = findings.filter((finding) => finding.status === "introduced").length;
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const mergeActionDisabled = introducedFindingCount > 0 && criticalCount > 0;
  const serializedFindings = JSON.stringify(findings);
  return {
    schemaVersion: WORKFLOW_ENGINE_GUARD_SECURITY_SCAN_SCHEMA_VERSION,
    status:
      (input.files ?? []).length === 0
        ? "empty"
        : mergeActionDisabled
          ? "blocked"
          : "passed",
    scanScopeCount: (input.files ?? []).length,
    findingCount: findings.length,
    introducedFindingCount,
    criticalCount,
    mergeActionDisabled,
    mergeBlockReason: mergeActionDisabled ? "introduced_plaintext_secret" : null,
    secretValuesIncluded: /sk-[A-Za-z0-9_-]{6,}|ghp_[A-Za-z0-9_]{6,}|Bearer\s+[A-Za-z0-9._-]{8,}/.test(serializedFindings),
    scannedFiles: uniqueStrings((input.files ?? []).map((file) => file.path)),
    sourceEventIds: uniqueStrings(findings.map((finding) => finding.sourceEventId)),
    receiptRefs: uniqueStrings(findings.flatMap((finding) => finding.receiptRefs)),
    policyDecisionRefs: uniqueStrings(findings.flatMap((finding) => finding.policyDecisionRefs)),
    rollbackRefs: uniqueStrings(findings.flatMap((finding) => finding.rollbackRefs)),
    findings,
  };
}

function scanFile(
  file: WorkflowEngineGuardSecurityFileInput,
  fileIndex: number,
  eventReceiptRefs: Map<string, string[]>,
): WorkflowEngineGuardSecurityFinding[] {
  const content = cleanString(file.content) ?? "";
  const filePath = cleanString(file.path);
  const explicitReceiptRefs = normalizeStringArray(file.receiptRefs);
  const sourceEventId = cleanString(file.sourceEventId);
  const eventRefs = sourceEventId ? eventReceiptRefs.get(sourceEventId) ?? [] : [];
  const receiptRefs = uniqueStrings([...explicitReceiptRefs, ...eventRefs]);
  const policyDecisionRefs = uniqueStrings([
    ...normalizeStringArray(file.policyDecisionRefs),
    "policy_engine_guard_block_plaintext_secret",
  ]);
  const rollbackRefs = normalizeStringArray(file.rollbackRefs);
  const findings: WorkflowEngineGuardSecurityFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const assignment = line.match(
      /\b(api[_-]?key|token|secret|password|authorization)\b\s*[:=]\s*["']([^"']{6,})["']/i,
    );
    const bearer = line.match(/\bAuthorization\b\s*[:=]\s*["']Bearer\s+([^"']{8,})["']/i);
    const skToken = line.match(/\b(sk-[A-Za-z0-9_-]{6,})\b/);
    const matchedSecret = assignment?.[2] ?? bearer?.[1] ?? skToken?.[1] ?? null;
    if (!matchedSecret) continue;
    const column = Math.max(1, line.indexOf(matchedSecret) + 1);
    const kind = bearer ? "credential_header" : "plaintext_secret";
    findings.push({
      id: `engine-guard-${fileIndex + 1}-${index + 1}`,
      status: "introduced",
      severity: kind === "credential_header" ? "high" : "critical",
      kind,
      filePath,
      line: index + 1,
      column,
      redactedPreview: redactLine(line),
      fingerprint: hashFingerprint(`${filePath ?? "unknown"}:${index + 1}:${kind}:${matchedSecret}`),
      sourceEventId,
      receiptRefs,
      policyDecisionRefs,
      rollbackRefs,
    });
  }
  return findings;
}

function receiptRefsFromEvents(events: readonly WorkflowRuntimeThreadEventLike[]): Map<string, string[]> {
  const refs = new Map<string, string[]>();
  for (const event of events ?? []) {
    const record = event as unknown as Record<string, unknown>;
    const eventId = cleanString(record.event_id ?? record.id);
    if (!eventId) continue;
    const payload = objectValue(record.payload_summary) ?? objectValue(record.payload) ?? objectValue(record.data) ?? {};
    refs.set(
      eventId,
      uniqueStrings([
        ...normalizeStringArray(record.receipt_refs),
        ...normalizeStringArray(record.receiptRefs),
        ...normalizeStringArray(payload.receipt_refs),
        ...normalizeStringArray(payload.receiptRefs),
      ]),
    );
  }
  return refs;
}

function redactLine(line: string): string {
  return line
    .replace(/(["'])(sk-[A-Za-z0-9_-]{6,})(["'])/g, "$1[REDACTED]$3")
    .replace(/(["'])(Bearer\s+)[^"']{8,}(["'])/gi, "$1$2[REDACTED]$3")
    .replace(/(["'])((?:ghp_)[A-Za-z0-9_]{6,})(["'])/g, "$1[REDACTED]$3");
}

function hashFingerprint(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `finding_${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function normalizeStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((item) => cleanString(item)).filter((item): item is string => Boolean(item))
    : [];
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
