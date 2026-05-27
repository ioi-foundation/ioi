export const WORKFLOW_BATTLE_MODE_PERMISSION_IMPORT_SCHEMA_VERSION =
  "ioi.workflow.battle-mode-permission-import.v1" as const;

export type WorkflowBattleModeDecision =
  | "allow_once"
  | "allow_always"
  | "deny"
  | "rollback"
  | "unknown";

export type WorkflowBattleModeImportStatus = "ready" | "manual_review" | "blocked";

export interface WorkflowBattleModePermissionRecord {
  id: string;
  sourceTable?: string | null;
  sourceRowId?: string | number | null;
  trajectoryId: string;
  stepId?: string | null;
  action: string;
  decision: WorkflowBattleModeDecision;
  decidedAt?: string | null;
  receiptRefs?: readonly string[] | null;
}

export interface WorkflowBattleModePermissionImportRow {
  id: string;
  sourceTable: string;
  sourceRowId: string | null;
  trajectoryId: string;
  stepId: string | null;
  action: string;
  decision: WorkflowBattleModeDecision;
  decidedAt: string | null;
  status: WorkflowBattleModeImportStatus;
  importedAuthority: "historical_only";
  canReplayWithoutFreshApproval: false;
  receiptRefs: string[];
  policyRefs: string[];
  summary: string;
}

export interface WorkflowBattleModePermissionImportPanel {
  schemaVersion: typeof WORKFLOW_BATTLE_MODE_PERMISSION_IMPORT_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  rowCount: number;
  readyCount: number;
  manualReviewCount: number;
  blockedCount: number;
  importedPersistentGrantCount: number;
  missingReceiptCount: number;
  rows: WorkflowBattleModePermissionImportRow[];
}

export function buildWorkflowBattleModePermissionImportPanel(input: {
  records: readonly WorkflowBattleModePermissionRecord[];
}): WorkflowBattleModePermissionImportPanel {
  const rows = normalizeRecords(input.records).map(permissionRow);
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const manualReviewCount = rows.filter((row) => row.status === "manual_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;
  return {
    schemaVersion: WORKFLOW_BATTLE_MODE_PERMISSION_IMPORT_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    rowCount: rows.length,
    readyCount,
    manualReviewCount,
    blockedCount,
    importedPersistentGrantCount: rows.filter((row) =>
      row.policyRefs.includes("policy:battle_mode.block.imported_persistent_grant")
    ).length,
    missingReceiptCount: rows.filter((row) =>
      row.policyRefs.includes("policy:battle_mode.review.missing_receipt")
    ).length,
    rows,
  };
}

function permissionRow(record: WorkflowBattleModePermissionRecord): WorkflowBattleModePermissionImportRow {
  const receiptRefs = uniqueStrings(record.receiptRefs ?? []);
  const policyRefs = [
    "policy:battle_mode.import.plan_only",
    "policy:battle_mode.import.historical_only",
    "policy:battle_mode.fresh_lease_required",
  ];
  if (receiptRefs.length === 0) {
    policyRefs.push("policy:battle_mode.review.missing_receipt");
  }
  if (record.decision === "allow_always") {
    policyRefs.push("policy:battle_mode.block.imported_persistent_grant");
  }
  if (record.decision === "unknown") {
    policyRefs.push("policy:battle_mode.review.unknown_decision");
  }

  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "manual_review"
      : "ready";

  return {
    id: safeId(record.id),
    sourceTable: stringField(record.sourceTable) ?? "battle_mode_infos",
    sourceRowId: stringField(record.sourceRowId),
    trajectoryId: record.trajectoryId,
    stepId: stringField(record.stepId),
    action: record.action,
    decision: record.decision,
    decidedAt: stringField(record.decidedAt),
    status,
    importedAuthority: "historical_only",
    canReplayWithoutFreshApproval: false,
    receiptRefs,
    policyRefs,
    summary: summaryForDecision(record),
  };
}

function summaryForDecision(record: WorkflowBattleModePermissionRecord): string {
  if (record.decision === "allow_once") {
    return `Historical allow-once for ${record.action}; fresh IOI approval is still required.`;
  }
  if (record.decision === "allow_always") {
    return `Historical persistent grant for ${record.action} is blocked on import.`;
  }
  if (record.decision === "deny") {
    return `Historical denial for ${record.action} is preserved for audit.`;
  }
  if (record.decision === "rollback") {
    return `Historical rollback decision for ${record.action} is preserved for audit.`;
  }
  return `Unknown battle-mode decision for ${record.action} requires review.`;
}

function normalizeRecords(
  records: readonly WorkflowBattleModePermissionRecord[] | undefined,
): WorkflowBattleModePermissionRecord[] {
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
      .replace(/^-+|-+$/g, "") || "permission"
  );
}
