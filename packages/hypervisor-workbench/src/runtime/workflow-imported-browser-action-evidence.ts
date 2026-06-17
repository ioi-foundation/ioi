export const WORKFLOW_IMPORTED_BROWSER_ACTION_EVIDENCE_SCHEMA_VERSION =
  "ioi.workflow.imported-browser-action-evidence.v1" as const;

export type WorkflowImportedBrowserActionStatus = "ready" | "manual_review" | "blocked";

export interface WorkflowImportedBrowserActionRecord {
  id: string;
  sourceTable?: string | null;
  sourceRowId?: string | number | null;
  trajectoryId: string;
  stepId: string;
  action: "click" | "type" | "navigate" | "unknown";
  url?: string | null;
  target?: { x: number; y: number; width?: number | null; height?: number | null } | null;
  viewport?: { width: number; height: number } | null;
  screenshotRef?: string | null;
  domSnapshotRef?: string | null;
  accessibilityRef?: string | null;
  postconditionRef?: string | null;
  cleanupRef?: string | null;
  receiptRefs?: readonly string[] | null;
}

export interface WorkflowImportedBrowserActionEvidenceRow {
  id: string;
  sourceTable: string;
  sourceRowId: string | null;
  trajectoryId: string;
  stepId: string;
  action: WorkflowImportedBrowserActionRecord["action"];
  status: WorkflowImportedBrowserActionStatus;
  url: string | null;
  target: WorkflowImportedBrowserActionRecord["target"];
  viewport: WorkflowImportedBrowserActionRecord["viewport"];
  evidenceRefs: {
    screenshotRef: string | null;
    domSnapshotRef: string | null;
    accessibilityRef: string | null;
    postconditionRef: string | null;
    cleanupRef: string | null;
  };
  receiptRefs: string[];
  policyRefs: string[];
  summary: string;
}

export interface WorkflowImportedBrowserActionEvidencePanel {
  schemaVersion: typeof WORKFLOW_IMPORTED_BROWSER_ACTION_EVIDENCE_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  rowCount: number;
  readyCount: number;
  manualReviewCount: number;
  blockedCount: number;
  missingObservationCount: number;
  missingPostconditionCount: number;
  missingCleanupCount: number;
  rows: WorkflowImportedBrowserActionEvidenceRow[];
}

export function buildWorkflowImportedBrowserActionEvidencePanel(input: {
  records: readonly WorkflowImportedBrowserActionRecord[];
}): WorkflowImportedBrowserActionEvidencePanel {
  const rows = normalizeRecords(input.records).map(browserActionRow);
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const manualReviewCount = rows.filter((row) => row.status === "manual_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;
  return {
    schemaVersion: WORKFLOW_IMPORTED_BROWSER_ACTION_EVIDENCE_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    rowCount: rows.length,
    readyCount,
    manualReviewCount,
    blockedCount,
    missingObservationCount: rows.filter((row) =>
      row.policyRefs.includes("policy:imported_browser.review.missing_observation")
    ).length,
    missingPostconditionCount: rows.filter((row) =>
      row.policyRefs.includes("policy:imported_browser.review.missing_postcondition")
    ).length,
    missingCleanupCount: rows.filter((row) =>
      row.policyRefs.includes("policy:imported_browser.review.missing_cleanup")
    ).length,
    rows,
  };
}

function browserActionRow(
  record: WorkflowImportedBrowserActionRecord,
): WorkflowImportedBrowserActionEvidenceRow {
  const receiptRefs = uniqueStrings(record.receiptRefs ?? []);
  const policyRefs = [
    "policy:imported_browser.historical_only",
    "policy:imported_browser.replay_requires_fresh_observation",
  ];
  if (!record.screenshotRef || !record.domSnapshotRef) {
    policyRefs.push("policy:imported_browser.review.missing_observation");
  }
  if (!record.postconditionRef) {
    policyRefs.push("policy:imported_browser.review.missing_postcondition");
  }
  if (!record.cleanupRef) {
    policyRefs.push("policy:imported_browser.review.missing_cleanup");
  }
  if (receiptRefs.length === 0) {
    policyRefs.push("policy:imported_browser.review.missing_receipt");
  }
  if (targetOutOfViewport(record.target, record.viewport)) {
    policyRefs.push("policy:imported_browser.block.target_out_of_viewport");
  }
  if (record.action === "unknown") {
    policyRefs.push("policy:imported_browser.review.unknown_action");
  }

  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "manual_review"
      : "ready";

  return {
    id: safeId(record.id),
    sourceTable: stringField(record.sourceTable) ?? "steps",
    sourceRowId: stringField(record.sourceRowId),
    trajectoryId: record.trajectoryId,
    stepId: record.stepId,
    action: record.action,
    status,
    url: stringField(record.url),
    target: record.target ?? null,
    viewport: record.viewport ?? null,
    evidenceRefs: {
      screenshotRef: stringField(record.screenshotRef),
      domSnapshotRef: stringField(record.domSnapshotRef),
      accessibilityRef: stringField(record.accessibilityRef),
      postconditionRef: stringField(record.postconditionRef),
      cleanupRef: stringField(record.cleanupRef),
    },
    receiptRefs,
    policyRefs,
    summary: summaryForRecord(record, status),
  };
}

function targetOutOfViewport(
  target: WorkflowImportedBrowserActionRecord["target"],
  viewport: WorkflowImportedBrowserActionRecord["viewport"],
): boolean {
  if (!target || !viewport) return false;
  return target.x < 0 || target.y < 0 || target.x > viewport.width || target.y > viewport.height;
}

function summaryForRecord(
  record: WorkflowImportedBrowserActionRecord,
  status: WorkflowImportedBrowserActionStatus,
): string {
  if (status === "blocked") return `Imported browser ${record.action} target cannot be replayed safely.`;
  if (status === "manual_review") return `Imported browser ${record.action} needs observation/postcondition review.`;
  return `Imported browser ${record.action} has observation, verification, cleanup, and receipt evidence.`;
}

function normalizeRecords(
  records: readonly WorkflowImportedBrowserActionRecord[] | undefined,
): WorkflowImportedBrowserActionRecord[] {
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
      .replace(/^-+|-+$/g, "") || "browser-action"
  );
}
