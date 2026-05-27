export const WORKFLOW_PARENT_TRAJECTORY_LINKAGE_SCHEMA_VERSION =
  "ioi.workflow.parent-trajectory-linkage.v1" as const;

export type WorkflowParentTrajectoryLinkStatus = "ready" | "manual_review" | "blocked";
export type WorkflowParentTrajectoryMergePolicy = "manual_review" | "read_only" | "auto_merge";

export interface WorkflowParentTrajectoryLinkInput {
  currentTrajectoryId: string;
  links: readonly {
    id: string;
    parentTrajectoryId: string;
    childTrajectoryId: string;
    sourceTable?: string | null;
    sourceRowId?: string | number | null;
    childDbPath?: string | null;
    childExists?: boolean | null;
    childStatus?: string | null;
    mergePolicy?: WorkflowParentTrajectoryMergePolicy | null;
    receiptRefs?: readonly string[] | null;
  }[];
}

export interface WorkflowParentTrajectoryLinkRow {
  id: string;
  parentTrajectoryId: string;
  childTrajectoryId: string;
  sourceTable: string;
  sourceRowId: string | null;
  childDbPath: string | null;
  childExists: boolean;
  childStatus: string | null;
  mergePolicy: WorkflowParentTrajectoryMergePolicy;
  status: WorkflowParentTrajectoryLinkStatus;
  summary: string;
  receiptRefs: string[];
  policyRefs: string[];
}

export interface WorkflowParentTrajectoryLinkagePanel {
  schemaVersion: typeof WORKFLOW_PARENT_TRAJECTORY_LINKAGE_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  currentTrajectoryId: string;
  linkCount: number;
  readyCount: number;
  manualReviewCount: number;
  blockedCount: number;
  missingChildCount: number;
  missingReceiptCount: number;
  rows: WorkflowParentTrajectoryLinkRow[];
}

export function buildWorkflowParentTrajectoryLinkagePanel(
  input: WorkflowParentTrajectoryLinkInput,
): WorkflowParentTrajectoryLinkagePanel {
  const rows = normalizeLinks(input.links).map((link) => linkRow(input.currentTrajectoryId, link));
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const manualReviewCount = rows.filter((row) => row.status === "manual_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;
  return {
    schemaVersion: WORKFLOW_PARENT_TRAJECTORY_LINKAGE_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    currentTrajectoryId: input.currentTrajectoryId,
    linkCount: rows.length,
    readyCount,
    manualReviewCount,
    blockedCount,
    missingChildCount: rows.filter((row) => !row.childExists).length,
    missingReceiptCount: rows.filter((row) => row.policyRefs.includes("policy:parent_trajectory.review.missing_receipt")).length,
    rows,
  };
}

function linkRow(
  currentTrajectoryId: string,
  link: WorkflowParentTrajectoryLinkInput["links"][number],
): WorkflowParentTrajectoryLinkRow {
  const receiptRefs = uniqueStrings(link.receiptRefs ?? []);
  const mergePolicy = link.mergePolicy ?? "manual_review";
  const sourceTable = stringField(link.sourceTable) ?? "parent_references";
  const sourceRowId = stringField(link.sourceRowId);
  const childExists = link.childExists === true;
  const policyRefs = [
    "policy:parent_trajectory.import.plan_only",
    "policy:parent_trajectory.manual_writeback_gate",
  ];
  if (link.parentTrajectoryId !== currentTrajectoryId) {
    policyRefs.push("policy:parent_trajectory.block.parent_mismatch");
  }
  if (link.childTrajectoryId === currentTrajectoryId) {
    policyRefs.push("policy:parent_trajectory.block.cycle");
  }
  if (!childExists) {
    policyRefs.push("policy:parent_trajectory.review.missing_child_db");
  }
  if (receiptRefs.length === 0) {
    policyRefs.push("policy:parent_trajectory.review.missing_receipt");
  }
  if (mergePolicy === "auto_merge") {
    policyRefs.push("policy:parent_trajectory.block.auto_merge");
  }

  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "manual_review"
      : "ready";

  return {
    id: safeId(link.id),
    parentTrajectoryId: link.parentTrajectoryId,
    childTrajectoryId: link.childTrajectoryId,
    sourceTable,
    sourceRowId,
    childDbPath: stringField(link.childDbPath),
    childExists,
    childStatus: stringField(link.childStatus),
    mergePolicy,
    status,
    summary: summaryForLink(link, status),
    receiptRefs,
    policyRefs,
  };
}

function summaryForLink(
  link: WorkflowParentTrajectoryLinkInput["links"][number],
  status: WorkflowParentTrajectoryLinkStatus,
): string {
  if (status === "blocked") {
    return `Child trajectory ${link.childTrajectoryId} cannot be imported without policy repair.`;
  }
  if (status === "manual_review") {
    return `Child trajectory ${link.childTrajectoryId} requires manual import review.`;
  }
  return `Child trajectory ${link.childTrajectoryId} is linked for read-only audit.`;
}

function normalizeLinks(
  links: readonly WorkflowParentTrajectoryLinkInput["links"][number][] | undefined,
): WorkflowParentTrajectoryLinkInput["links"][number][] {
  return Array.isArray(links) ? links.filter(Boolean) : [];
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
      .replace(/^-+|-+$/g, "") || "link"
  );
}
