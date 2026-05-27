export const WORKFLOW_IMPORTED_STOP_HOOK_GATES_SCHEMA_VERSION =
  "ioi.workflow.imported-stop-hook-gates.v1" as const;

export type WorkflowImportedStopHookStatus = "passed" | "blocked" | "manual_review";

export interface WorkflowImportedStopHookRecord {
  id: string;
  sourceTable?: string | null;
  sourceRowId?: string | number | null;
  trajectoryId: string;
  stepId: string;
  stepType?: number | string | null;
  importedStatus: "completed" | "rejected" | "failed" | "cancelled" | "unknown";
  gateKind: "diagnostics" | "tests" | "lint" | "unknown";
  summary?: string | null;
  diagnosticCount?: number | null;
  failingTestCount?: number | null;
  receiptRefs?: readonly string[] | null;
}

export interface WorkflowImportedStopHookGateRow {
  id: string;
  sourceTable: string;
  sourceRowId: string | null;
  trajectoryId: string;
  stepId: string;
  stepType: string;
  importedStatus: string;
  gateKind: WorkflowImportedStopHookRecord["gateKind"];
  status: WorkflowImportedStopHookStatus;
  historicalOnly: true;
  liveVerificationRequired: true;
  summary: string;
  diagnosticCount: number;
  failingTestCount: number;
  receiptRefs: string[];
  policyRefs: string[];
}

export interface WorkflowImportedStopHookGatePanel {
  schemaVersion: typeof WORKFLOW_IMPORTED_STOP_HOOK_GATES_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  rowCount: number;
  passedCount: number;
  blockedCount: number;
  manualReviewCount: number;
  liveVerificationRequiredCount: number;
  missingReceiptCount: number;
  rows: WorkflowImportedStopHookGateRow[];
}

export function buildWorkflowImportedStopHookGatePanel(input: {
  records: readonly WorkflowImportedStopHookRecord[];
}): WorkflowImportedStopHookGatePanel {
  const rows = normalizeRecords(input.records).map(stopHookRow);
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const manualReviewCount = rows.filter((row) => row.status === "manual_review").length;
  const passedCount = rows.filter((row) => row.status === "passed").length;
  return {
    schemaVersion: WORKFLOW_IMPORTED_STOP_HOOK_GATES_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    rowCount: rows.length,
    passedCount,
    blockedCount,
    manualReviewCount,
    liveVerificationRequiredCount: rows.filter((row) => row.liveVerificationRequired).length,
    missingReceiptCount: rows.filter((row) =>
      row.policyRefs.includes("policy:imported_stop_hook.review.missing_receipt")
    ).length,
    rows,
  };
}

function stopHookRow(record: WorkflowImportedStopHookRecord): WorkflowImportedStopHookGateRow {
  const receiptRefs = uniqueStrings(record.receiptRefs ?? []);
  const diagnosticCount = Math.max(0, Number(record.diagnosticCount ?? 0));
  const failingTestCount = Math.max(0, Number(record.failingTestCount ?? 0));
  const policyRefs = [
    "policy:imported_stop_hook.historical_only",
    "policy:imported_stop_hook.live_verification_required",
  ];
  if (receiptRefs.length === 0) {
    policyRefs.push("policy:imported_stop_hook.review.missing_receipt");
  }
  if (record.importedStatus === "rejected" || record.importedStatus === "failed" || diagnosticCount > 0 || failingTestCount > 0) {
    policyRefs.push("policy:imported_stop_hook.block.imported_gate_failed");
  }
  if (record.gateKind === "unknown" || record.importedStatus === "unknown") {
    policyRefs.push("policy:imported_stop_hook.review.unknown_gate");
  }

  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "manual_review"
      : "passed";

  return {
    id: safeId(record.id),
    sourceTable: stringField(record.sourceTable) ?? "steps",
    sourceRowId: stringField(record.sourceRowId),
    trajectoryId: record.trajectoryId,
    stepId: record.stepId,
    stepType: stringField(record.stepType) ?? "STEP_TYPE_STOP_HOOK",
    importedStatus: record.importedStatus,
    gateKind: record.gateKind,
    status,
    historicalOnly: true,
    liveVerificationRequired: true,
    summary: stringField(record.summary) ?? defaultSummary(record, status),
    diagnosticCount,
    failingTestCount,
    receiptRefs,
    policyRefs,
  };
}

function defaultSummary(
  record: WorkflowImportedStopHookRecord,
  status: WorkflowImportedStopHookStatus,
): string {
  if (status === "blocked") {
    return `Imported ${record.gateKind} stop hook blocked the historical run.`;
  }
  if (status === "manual_review") {
    return `Imported ${record.gateKind} stop hook requires review before replay.`;
  }
  return `Imported ${record.gateKind} stop hook passed historically; live verification is still required.`;
}

function normalizeRecords(
  records: readonly WorkflowImportedStopHookRecord[] | undefined,
): WorkflowImportedStopHookRecord[] {
  return Array.isArray(records) ? records.filter(Boolean) : [];
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function stringField(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "stop-hook"
  );
}
