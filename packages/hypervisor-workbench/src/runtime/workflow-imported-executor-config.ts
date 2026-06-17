export const WORKFLOW_IMPORTED_EXECUTOR_CONFIG_SCHEMA_VERSION =
  "ioi.workflow.imported-executor-config.v1" as const;

export type WorkflowImportedExecutorConfigStatus = "ready" | "manual_review" | "blocked";

export interface WorkflowImportedExecutorConfigInput {
  sourceTable?: string | null;
  sourceRowId?: string | number | null;
  trajectoryId: string;
  allowedCommands?: readonly string[] | null;
  blockedCommands?: readonly string[] | null;
  ideChecks?: {
    diagnostics?: boolean | null;
    tests?: boolean | null;
    lint?: boolean | null;
  } | null;
  memoryLimitMb?: number | null;
  networkDefault?: "deny" | "allow" | "unknown" | null;
  receiptRefs?: readonly string[] | null;
}

export interface WorkflowImportedExecutorConfigRow {
  id: string;
  kind: "allowed_command" | "blocked_command" | "ide_check" | "resource_limit" | "network_default";
  label: string;
  status: WorkflowImportedExecutorConfigStatus;
  detail: string;
  policyRefs: string[];
}

export interface WorkflowImportedExecutorConfigPanel {
  schemaVersion: typeof WORKFLOW_IMPORTED_EXECUTOR_CONFIG_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  sourceTable: string;
  sourceRowId: string | null;
  trajectoryId: string;
  importedAuthority: "advisory_only";
  receiptRefs: string[];
  rowCount: number;
  readyCount: number;
  manualReviewCount: number;
  blockedCount: number;
  rows: WorkflowImportedExecutorConfigRow[];
}

const SAFE_BASE_COMMANDS = new Set(["cat", "cp", "date", "echo", "head", "ls", "mv", "tail"]);

export function buildWorkflowImportedExecutorConfigPanel(
  input: WorkflowImportedExecutorConfigInput,
): WorkflowImportedExecutorConfigPanel {
  const receiptRefs = uniqueStrings(input.receiptRefs ?? []);
  const rows = [
    ...allowedCommandRows(input.allowedCommands ?? []),
    ...blockedCommandRows(input.blockedCommands ?? []),
    ...ideCheckRows(input.ideChecks ?? {}),
    resourceLimitRow(input.memoryLimitMb ?? null),
    networkDefaultRow(input.networkDefault ?? "unknown"),
  ];
  if (receiptRefs.length === 0) {
    rows.push({
      id: "missing-receipt",
      kind: "resource_limit",
      label: "Missing executor config receipt",
      status: "manual_review",
      detail: "Imported executor config has no IOI receipt reference.",
      policyRefs: ["policy:executor_config.review.missing_receipt"],
    });
  }
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const manualReviewCount = rows.filter((row) => row.status === "manual_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;

  return {
    schemaVersion: WORKFLOW_IMPORTED_EXECUTOR_CONFIG_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    sourceTable: stringField(input.sourceTable) ?? "executor_metadata",
    sourceRowId: stringField(input.sourceRowId),
    trajectoryId: input.trajectoryId,
    importedAuthority: "advisory_only",
    receiptRefs,
    rowCount: rows.length,
    readyCount,
    manualReviewCount,
    blockedCount,
    rows,
  };
}

function allowedCommandRows(commands: readonly string[]): WorkflowImportedExecutorConfigRow[] {
  return uniqueStrings(commands).map((command) => {
    const network = networkShapedCommand(command);
    const safeBase = SAFE_BASE_COMMANDS.has(command);
    return {
      id: `allow:${safeId(command)}`,
      kind: "allowed_command",
      label: command,
      status: network ? "blocked" : safeBase ? "ready" : "manual_review",
      detail: network
        ? "Imported allowlist includes network-capable command; IOI blocks this on import."
        : safeBase
          ? "Imported safe-base command can seed an advisory allowlist."
          : "Imported command needs IOI policy review before use.",
      policyRefs: [
        "policy:executor_config.import.advisory_only",
        network
          ? "policy:executor_config.block.imported_network_allow"
          : safeBase
            ? "policy:executor_config.safe_base_command"
            : "policy:executor_config.review.imported_command",
      ],
    };
  });
}

function blockedCommandRows(commands: readonly string[]): WorkflowImportedExecutorConfigRow[] {
  return uniqueStrings(commands).map((command) => ({
    id: `block:${safeId(command)}`,
    kind: "blocked_command",
    label: command,
    status: "ready",
    detail: "Imported blocked command is preserved as an advisory deny hint.",
    policyRefs: ["policy:executor_config.import.advisory_only", "policy:executor_config.imported_deny_hint"],
  }));
}

function ideCheckRows(checks: NonNullable<WorkflowImportedExecutorConfigInput["ideChecks"]>): WorkflowImportedExecutorConfigRow[] {
  return (["diagnostics", "tests", "lint"] as const).map((key) => {
    const enabled = checks[key] === true;
    return {
      id: `ide-check:${key}`,
      kind: "ide_check",
      label: key,
      status: enabled ? "ready" : "manual_review",
      detail: enabled
        ? `Imported ${key} check is enabled and can seed goal verification requirements.`
        : `Imported ${key} check is absent or disabled and must be reviewed.`,
      policyRefs: [
        "policy:executor_config.import.advisory_only",
        enabled ? "policy:executor_config.ide_check.enabled" : "policy:executor_config.review.ide_check_disabled",
      ],
    };
  });
}

function resourceLimitRow(memoryLimitMb: number | null): WorkflowImportedExecutorConfigRow {
  const valid = typeof memoryLimitMb === "number" && Number.isFinite(memoryLimitMb) && memoryLimitMb > 0;
  return {
    id: "resource:memory",
    kind: "resource_limit",
    label: "memory_limit",
    status: valid ? "ready" : "manual_review",
    detail: valid
      ? `Imported memory limit ${memoryLimitMb} MB is visible for IOI resource policy review.`
      : "Imported memory limit is missing and must be reviewed.",
    policyRefs: [
      "policy:executor_config.import.advisory_only",
      valid ? "policy:executor_config.resource.memory_visible" : "policy:executor_config.review.memory_missing",
    ],
  };
}

function networkDefaultRow(networkDefault: "deny" | "allow" | "unknown"): WorkflowImportedExecutorConfigRow {
  return {
    id: "network:default",
    kind: "network_default",
    label: "network_default",
    status: networkDefault === "deny" ? "ready" : networkDefault === "allow" ? "blocked" : "manual_review",
    detail:
      networkDefault === "deny"
        ? "Imported network default deny aligns with IOI sandbox posture."
        : networkDefault === "allow"
          ? "Imported network default allow is blocked; IOI defaults to deny."
          : "Imported network default is unknown and must be reviewed.",
    policyRefs: [
      "policy:executor_config.import.advisory_only",
      networkDefault === "deny"
        ? "policy:executor_config.network.default_deny"
        : networkDefault === "allow"
          ? "policy:executor_config.block.network_default_allow"
          : "policy:executor_config.review.network_unknown",
    ],
  };
}

function networkShapedCommand(command: string): boolean {
  return /^(curl|wget|ssh|scp|nc|ncat|telnet)$/i.test(command);
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
      .replace(/^-+|-+$/g, "") || "item"
  );
}
