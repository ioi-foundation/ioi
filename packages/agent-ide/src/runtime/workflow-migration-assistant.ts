export const WORKFLOW_MIGRATION_ASSISTANT_SCHEMA_VERSION =
  "ioi.workflow.migration-assistant.v1" as const;

export type WorkflowMigrationSourceEditor = "vscode" | "cursor" | "windsurf" | "cider";
export type WorkflowMigrationItemKind =
  | "settings"
  | "keybindings"
  | "extensions"
  | "exclusions"
  | "policy";
export type WorkflowMigrationItemStatus = "ready" | "manual_review" | "blocked";

export interface WorkflowMigrationAssistantInput {
  sourceEditor: WorkflowMigrationSourceEditor;
  settings?: Record<string, unknown>;
  keybindings?: readonly unknown[];
  extensions?: readonly string[];
}

export interface WorkflowMigrationAssistantItem {
  id: string;
  kind: WorkflowMigrationItemKind;
  status: WorkflowMigrationItemStatus;
  label: string;
  detail: string;
  sourceKey: string | null;
  redactedPreview: string | null;
  policyRef: string | null;
}

export interface WorkflowMigrationAssistantPlan {
  schemaVersion: typeof WORKFLOW_MIGRATION_ASSISTANT_SCHEMA_VERSION;
  sourceEditor: WorkflowMigrationSourceEditor;
  status: "ready" | "needs_review" | "blocked";
  applyMode: "plan_only";
  itemCount: number;
  readyCount: number;
  manualReviewCount: number;
  blockedCount: number;
  items: WorkflowMigrationAssistantItem[];
  commandIds: string[];
}

const MIGRATION_COMMANDS = [
  "ioi.migration.openAssistant",
  "ioi.migration.importVSCodeSettings",
  "ioi.migration.importCursorSettings",
  "ioi.migration.importWindsurfSettings",
  "ioi.migration.importVSCodeExtensions",
  "ioi.migration.importCursorExtensions",
  "ioi.migration.importWindsurfExtensions",
] as const;

export function buildWorkflowMigrationAssistantPlan(
  input: WorkflowMigrationAssistantInput,
): WorkflowMigrationAssistantPlan {
  const items: WorkflowMigrationAssistantItem[] = [
    ...settingsItems(input.settings ?? {}),
    ...keybindingItems(input.keybindings ?? []),
    ...extensionItems(input.extensions ?? []),
  ];
  const readyCount = items.filter((item) => item.status === "ready").length;
  const manualReviewCount = items.filter((item) => item.status === "manual_review").length;
  const blockedCount = items.filter((item) => item.status === "blocked").length;
  return {
    schemaVersion: WORKFLOW_MIGRATION_ASSISTANT_SCHEMA_VERSION,
    sourceEditor: input.sourceEditor,
    status: blockedCount > 0 ? "blocked" : manualReviewCount > 0 ? "needs_review" : "ready",
    applyMode: "plan_only",
    itemCount: items.length,
    readyCount,
    manualReviewCount,
    blockedCount,
    items,
    commandIds: [...MIGRATION_COMMANDS],
  };
}

function settingsItems(settings: Record<string, unknown>): WorkflowMigrationAssistantItem[] {
  return Object.entries(settings).map(([key, value]) => {
    const risk = settingRisk(key, value);
    return {
      id: `setting:${safeId(key)}`,
      kind:
        key === "files.exclude" || key === "search.exclude"
          ? "exclusions"
          : risk.policyRef
            ? "policy"
            : "settings",
      status: risk.status,
      label: key,
      detail: risk.detail,
      sourceKey: key,
      redactedPreview: redactedPreview(value),
      policyRef: risk.policyRef,
    };
  });
}

function keybindingItems(keybindings: readonly unknown[]): WorkflowMigrationAssistantItem[] {
  return keybindings.map((entry, index) => ({
    id: `keybinding:${index + 1}`,
    kind: "keybindings",
    status: "ready",
    label: stringField(recordValue(entry)?.key) ?? `Keybinding ${index + 1}`,
    detail: "Keybindings import is staged as user-controlled editor preference.",
    sourceKey: stringField(recordValue(entry)?.command),
    redactedPreview: redactedPreview(entry),
    policyRef: null,
  }));
}

function extensionItems(extensions: readonly string[]): WorkflowMigrationAssistantItem[] {
  return extensions.map((extensionId) => {
    const normalized = String(extensionId || "").trim();
    const status = /remote|ssh|docker|kubernetes|credential|secret/i.test(normalized)
      ? "manual_review"
      : "ready";
    return {
      id: `extension:${safeId(normalized || "extension")}`,
      kind: "extensions",
      status,
      label: normalized || "Extension",
      detail:
        status === "manual_review"
          ? "Extension can alter runtime or credential posture and must be reviewed before import."
          : "Extension is staged for opt-in import.",
      sourceKey: normalized || null,
      redactedPreview: normalized || null,
      policyRef: status === "manual_review" ? "policy:migration.extension.review" : null,
    };
  });
}

function settingRisk(
  key: string,
  value: unknown,
): { status: WorkflowMigrationItemStatus; detail: string; policyRef: string | null } {
  if (key === "http.proxyStrictSSL" && value === false) {
    return {
      status: "blocked",
      detail: "Disabling proxy TLS verification cannot be imported automatically.",
      policyRef: "policy:migration.block.proxy_tls_disabled",
    };
  }
  if (key === "security.workspace.trust.enabled" && value === false) {
    return {
      status: "blocked",
      detail: "Disabling workspace trust would weaken IOI authority boundaries.",
      policyRef: "policy:migration.block.workspace_trust_disabled",
    };
  }
  if (/terminal\.integrated\.env\./.test(key)) {
    return {
      status: "manual_review",
      detail: "Terminal environment variables are redacted and require manual review.",
      policyRef: "policy:migration.review.terminal_env",
    };
  }
  if (key === "files.exclude" || key === "search.exclude") {
    return {
      status: "manual_review",
      detail: "Workspace exclusions are staged for review so hidden files do not bypass sandbox scans.",
      policyRef: "policy:migration.review.exclusions",
    };
  }
  return {
    status: "ready",
    detail: "Setting can be staged for opt-in import.",
    policyRef: null,
  };
}

function redactedPreview(value: unknown): string {
  return String(JSON.stringify(value, null, 2) ?? "").replace(
    /("[^"]*(?:token|secret|password|api[_-]?key)[^"]*"\s*:\s*)"[^"]*"/gi,
    "$1\"[REDACTED]\"",
  );
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringField(value: unknown): string | null {
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
