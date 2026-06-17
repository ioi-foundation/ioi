import type {
  WorkflowImportedExecutorConfigPanel,
  WorkflowImportedExecutorConfigRow,
} from "./workflow-imported-executor-config";

export const WORKFLOW_IMPORTED_POLICY_DRAFT_SCHEMA_VERSION =
  "ioi.workflow.imported-policy-draft.v1" as const;

export type WorkflowImportedPolicyDraftStatus = "ready" | "needs_review" | "blocked";
export type WorkflowImportedPolicyDraftItemStatus =
  | "proposed"
  | "needs_review"
  | "blocked"
  | "preserved";

export interface WorkflowImportedPolicyDraftInput {
  sourcePanel: WorkflowImportedExecutorConfigPanel;
  policyId?: string | null;
  name?: string | null;
  leaseTtlMs?: number | null;
}

export interface WorkflowImportedPolicyAuthorityRuleDraft {
  id: string;
  target: string;
  tools: string[];
  effectClasses: string[];
  requiresApproval: boolean;
  approvalMode: string;
  trustProfile: string;
  nodeApprovalOverride: string;
  authorityScopes: string[];
  leaseTtlMs: number;
  expectedReceiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowImportedStructuredPolicyDraftInput {
  id: string;
  name: string;
  authorityRules: WorkflowImportedPolicyAuthorityRuleDraft[];
  advisoryGuidelines: string[];
}

export interface WorkflowImportedStructuredPolicyDraft {
  schemaVersion: "ioi.workflow.structured-policy-composer.v1";
  status: "ready" | "blocked";
  policyId: string;
  name: string;
  policyHash: string;
  enforceableRuleCount: number;
  advisoryGuidelineCount: number;
  promptSoupGuard: "passed" | "blocked";
  diagnostics: Array<{
    code: string;
    severity: "info" | "warning" | "error";
    message: string;
  }>;
  authorityRules: WorkflowImportedPolicyAuthorityRuleDraft[];
  advisoryGuidelines: string[];
}

export interface WorkflowImportedPolicyDraftItem {
  id: string;
  section:
    | "allowed_command"
    | "blocked_command"
    | "ide_check"
    | "resource_limit"
    | "network_default";
  label: string;
  status: WorkflowImportedPolicyDraftItemStatus;
  selected: boolean;
  detail: string;
  sourceRowId: string;
  policyRefs: string[];
}

export interface WorkflowImportedPolicyDraft {
  schemaVersion: typeof WORKFLOW_IMPORTED_POLICY_DRAFT_SCHEMA_VERSION;
  status: WorkflowImportedPolicyDraftStatus;
  applyMode: "draft_only";
  importedAuthority: "advisory_only";
  sourceSchemaVersion: string;
  sourceTrajectoryId: string;
  receiptRefs: string[];
  policyInput: WorkflowImportedStructuredPolicyDraftInput;
  structuredPolicyDraft: WorkflowImportedStructuredPolicyDraft;
  proposedCommandScopes: string[];
  forcedNetworkDefault: "deny";
  memoryLimitMb: number | null;
  draftItemCount: number;
  proposedCount: number;
  reviewCount: number;
  blockedCount: number;
  preservedCount: number;
  items: WorkflowImportedPolicyDraftItem[];
}

export function buildWorkflowImportedPolicyDraft(
  input: WorkflowImportedPolicyDraftInput,
): WorkflowImportedPolicyDraft {
  const sourcePanel = input.sourcePanel;
  const commandRows = sourcePanel.rows.filter((row) => row.kind === "allowed_command");
  const safeCommands = commandRows
    .filter((row) => row.status === "ready")
    .map((row) => row.label);
  const items = sourcePanel.rows.map((row) => draftItemFromSourceRow(row));
  const proposedCommandScopes = safeCommands.map((command) => `command:${command}`);
  const receiptRefs = uniqueStrings(sourcePanel.receiptRefs);
  const leaseTtlMs = positiveNumber(input.leaseTtlMs) ?? 600_000;
  const memoryLimitMb = memoryLimitFromRows(sourcePanel.rows);
  const policyInput: WorkflowImportedStructuredPolicyDraftInput = {
    id: cleanString(input.policyId) ?? `policy.imported.${safeId(sourcePanel.trajectoryId)}`,
    name:
      cleanString(input.name) ??
      `Imported executor draft for ${sourcePanel.trajectoryId}`,
    authorityRules:
      proposedCommandScopes.length > 0
        ? [
            {
              id: "imported-safe-base-command-review",
              target: "runtime_coding_tool",
              tools: ["terminal.run"],
              effectClasses: ["local_process"],
              requiresApproval: true,
              approvalMode: "operator_review_required",
              trustProfile: "imported_advisory_only",
              nodeApprovalOverride: "require_approval",
              authorityScopes: [
                "scope:workspace.read",
                "scope:network.deny_default",
                ...proposedCommandScopes,
              ],
              leaseTtlMs,
              expectedReceiptRefs: receiptRefs,
              policyDecisionRefs: [
                "policy:imported_policy_draft.operator_review_required",
                "policy:executor_config.import.advisory_only",
              ],
            },
          ]
        : [],
    advisoryGuidelines: buildAdvisoryGuidelines(sourcePanel, safeCommands, memoryLimitMb),
  };
  const structuredPolicyDraft = compileImportedStructuredPolicyDraft(policyInput);
  const blockedCount = items.filter((item) => item.status === "blocked").length;
  const reviewCount = items.filter((item) => item.status === "needs_review").length;
  const proposedCount = items.filter((item) => item.status === "proposed").length;
  const preservedCount = items.filter((item) => item.status === "preserved").length;
  const status: WorkflowImportedPolicyDraftStatus =
    structuredPolicyDraft.status !== "ready"
      ? "blocked"
      : blockedCount > 0 || reviewCount > 0
        ? "needs_review"
        : "ready";

  return {
    schemaVersion: WORKFLOW_IMPORTED_POLICY_DRAFT_SCHEMA_VERSION,
    status,
    applyMode: "draft_only",
    importedAuthority: "advisory_only",
    sourceSchemaVersion: sourcePanel.schemaVersion,
    sourceTrajectoryId: sourcePanel.trajectoryId,
    receiptRefs,
    policyInput,
    structuredPolicyDraft,
    proposedCommandScopes,
    forcedNetworkDefault: "deny",
    memoryLimitMb,
    draftItemCount: items.length,
    proposedCount,
    reviewCount,
    blockedCount,
    preservedCount,
    items,
  };
}

function compileImportedStructuredPolicyDraft(
  input: WorkflowImportedStructuredPolicyDraftInput,
): WorkflowImportedStructuredPolicyDraft {
  const enforceableRuleCount = input.authorityRules.length;
  const diagnostics: WorkflowImportedStructuredPolicyDraft["diagnostics"] = [];
  if (enforceableRuleCount === 0) {
    diagnostics.push({
      code: "prompt_soup_no_enforceable_rules",
      severity: "error",
      message:
        "Imported executor policy draft needs at least one structured authority rule before advisory text can be reviewed.",
    });
  }
  if (input.advisoryGuidelines.length > 0) {
    diagnostics.push({
      code: "advisory_guidelines_not_authority",
      severity: enforceableRuleCount > 0 ? "info" : "warning",
      message:
        "Imported advisory guidelines are retained for review but do not grant daemon authority.",
    });
  }
  const normalized = {
    policyId: input.id,
    name: input.name,
    authorityRules: input.authorityRules,
    advisoryGuidelines: input.advisoryGuidelines,
  };
  const status: WorkflowImportedStructuredPolicyDraft["status"] =
    diagnostics.some((diagnostic) => diagnostic.severity === "error")
      ? "blocked"
      : "ready";
  return {
    schemaVersion: "ioi.workflow.structured-policy-composer.v1",
    status,
    policyId: input.id,
    name: input.name,
    policyHash: stableContentHash(normalized),
    enforceableRuleCount,
    advisoryGuidelineCount: input.advisoryGuidelines.length,
    promptSoupGuard: status === "ready" ? "passed" : "blocked",
    diagnostics,
    authorityRules: input.authorityRules,
    advisoryGuidelines: input.advisoryGuidelines,
  };
}

function draftItemFromSourceRow(
  row: WorkflowImportedExecutorConfigRow,
): WorkflowImportedPolicyDraftItem {
  if (row.kind === "allowed_command") {
    if (row.status === "ready") {
      return {
        id: `draft:${row.id}`,
        section: row.kind,
        label: row.label,
        status: "proposed",
        selected: true,
        detail:
          "Safe-base imported command is proposed as an approval-required policy scope.",
        sourceRowId: row.id,
        policyRefs: [
          ...row.policyRefs,
          "policy:imported_policy_draft.operator_review_required",
        ],
      };
    }
    return {
      id: `draft:${row.id}`,
      section: row.kind,
      label: row.label,
      status: row.status === "blocked" ? "blocked" : "needs_review",
      selected: false,
      detail:
        row.status === "blocked"
          ? "Imported command is excluded from the draft because it would add unsafe authority."
          : "Imported command is held for operator review before policy inclusion.",
      sourceRowId: row.id,
      policyRefs: row.policyRefs,
    };
  }
  if (row.kind === "blocked_command") {
    return {
      id: `draft:${row.id}`,
      section: row.kind,
      label: row.label,
      status: "preserved",
      selected: true,
      detail: "Imported deny hint is preserved for operator review; it does not grant authority.",
      sourceRowId: row.id,
      policyRefs: row.policyRefs,
    };
  }
  if (row.kind === "network_default") {
    return {
      id: `draft:${row.id}`,
      section: row.kind,
      label: "network_default",
      status: row.status === "ready" ? "proposed" : row.status === "blocked" ? "blocked" : "needs_review",
      selected: true,
      detail:
        row.status === "ready"
          ? "Network default deny is retained."
          : "Imported network posture is not inherited; draft forces IOI network default deny.",
      sourceRowId: row.id,
      policyRefs: [
        ...row.policyRefs,
        "policy:imported_policy_draft.force_network_default_deny",
      ],
    };
  }
  return {
    id: `draft:${row.id}`,
    section: row.kind,
    label: row.label,
    status: row.status === "ready" ? "proposed" : "needs_review",
    selected: row.status === "ready",
    detail:
      row.status === "ready"
        ? "Imported row is proposed as policy-draft context."
        : "Imported row is held for operator review before policy inclusion.",
    sourceRowId: row.id,
    policyRefs: row.policyRefs,
  };
}

function buildAdvisoryGuidelines(
  sourcePanel: WorkflowImportedExecutorConfigPanel,
  safeCommands: string[],
  memoryLimitMb: number | null,
): string[] {
  const enabledChecks = sourcePanel.rows
    .filter((row) => row.kind === "ide_check" && row.status === "ready")
    .map((row) => row.label);
  const deniedCommands = sourcePanel.rows
    .filter((row) => row.kind === "blocked_command")
    .map((row) => row.label);
  return [
    "Imported executor metadata is advisory-only and cannot grant runtime authority.",
    safeCommands.length > 0
      ? `Proposed safe-base commands require operator approval: ${safeCommands.join(", ")}.`
      : "No imported command is eligible for automatic policy inclusion.",
    enabledChecks.length > 0
      ? `Require live IOI verification for imported checks: ${enabledChecks.join(", ")}.`
      : "No imported IDE checks were enabled.",
    deniedCommands.length > 0
      ? `Preserve imported deny hints for review: ${deniedCommands.join(", ")}.`
      : "No imported deny hints were present.",
    memoryLimitMb !== null
      ? `Imported memory limit visible for review: ${memoryLimitMb} MB.`
      : "Imported memory limit missing; keep default IOI resource caps.",
    "Force network default deny regardless of imported executor metadata.",
  ];
}

function memoryLimitFromRows(rows: readonly WorkflowImportedExecutorConfigRow[]): number | null {
  const memoryRow = rows.find((row) => row.id === "resource:memory");
  if (!memoryRow) return null;
  const match = memoryRow.detail.match(/Imported memory limit (\d+) MB/);
  return match ? Number(match[1]) : null;
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function positiveNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "trajectory"
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
