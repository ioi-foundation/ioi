import type { WorkflowHarnessComponentKind, WorkflowNodeKind } from "../types/graph";

export const WORKFLOW_RUNTIME_UI_STRING_CATALOG_SCHEMA_VERSION =
  "ioi.workflow.runtime-ui-string-catalog.v1";

export const WORKFLOW_RUNTIME_UI_STRING_CATALOG_ID =
  "ioi.workflow.runtime-ui.chrome.v1";

export const WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  canceled: "Canceled",
  blocked: "Blocked",
  warning: "Warning",
  passed: "Passed",
  ready: "Ready",
  unavailable: "Unavailable",
  unbound: "Unbound",
  projection_only: "Projection only",
  unknown: "Unknown",
} as const;

const WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT_ES = {
  queued: "En cola",
  running: "En curso",
  completed: "Completado",
  failed: "Error",
  canceled: "Cancelado",
  blocked: "Bloqueado",
  warning: "Advertencia",
  passed: "Aprobado",
  ready: "Listo",
  unavailable: "No disponible",
  unbound: "Sin vincular",
  projection_only: "Solo proyeccion",
  unknown: "Desconocido",
} as const;

const RUNTIME_CHROME_NODE_LABELS = {
  runtime_doctor: "Runtime doctor",
  runtime_task: "Runtime task",
  runtime_job: "Runtime job",
  runtime_checklist: "Runtime checklist",
  repository_context: "Repository context",
  branch_policy: "Branch policy",
  github_context: "GitHub context",
  issue_context: "Issue context",
  pr_attempt: "PR attempt",
  review_gate: "Review gate",
  github_pr_create: "GitHub PR create",
} as const;

const RUNTIME_CHROME_NODE_LABELS_ES = {
  runtime_doctor: "Diagnostico del runtime",
  runtime_task: "Tarea del runtime",
  runtime_job: "Trabajo del runtime",
  runtime_checklist: "Lista de verificacion del runtime",
  repository_context: "Contexto del repositorio",
  branch_policy: "Politica de rama",
  github_context: "Contexto de GitHub",
  issue_context: "Contexto de issue",
  pr_attempt: "Intento de PR",
  review_gate: "Puerta de revision",
  github_pr_create: "Crear PR en GitHub",
} as const;

export type WorkflowRuntimeChromeNodeKind = keyof typeof RUNTIME_CHROME_NODE_LABELS;

export const WORKFLOW_RUNTIME_UI_REQUIRED_STRING_KEYS = [
  "runtime.node.runtime_doctor.label",
  "runtime.node.runtime_task.label",
  "runtime.node.runtime_job.aria",
  "runtime.node.runtime_checklist.status",
  "runtime.node.repository_context.label",
  "runtime.node.branch_policy.status",
  "runtime.node.github_pr_create.aria",
  "runtime.status.blocked",
] as const;

type RuntimeChromeComponentKind = Extract<
  WorkflowHarnessComponentKind,
  WorkflowRuntimeChromeNodeKind
>;

type RuntimeChromeNodeKind = Extract<WorkflowNodeKind, WorkflowRuntimeChromeNodeKind>;

function chromeStringEntry(
  defaultMessage: string,
  description: string,
  translations: Record<string, string> = {},
) {
  return {
    defaultMessage,
    description,
    translations: {
      "en-US": defaultMessage,
      ...translations,
    },
  };
}

function runtimeChromeStrings() {
  return Object.fromEntries(
    Object.entries(RUNTIME_CHROME_NODE_LABELS).flatMap(([kind, label]) => [
      [
        `runtime.node.${kind}.label`,
        chromeStringEntry(label, `Visible workflow node label for ${label}.`, {
          "es-ES": RUNTIME_CHROME_NODE_LABELS_ES[kind as WorkflowRuntimeChromeNodeKind],
        }),
      ],
      [
        `runtime.node.${kind}.aria`,
        chromeStringEntry(`${label} node`, `Accessible name for ${label}.`, {
          "es-ES": `Nodo ${RUNTIME_CHROME_NODE_LABELS_ES[kind as WorkflowRuntimeChromeNodeKind]}`,
        }),
      ],
      [
        `runtime.node.${kind}.status`,
        chromeStringEntry(`${label} status: {status}`, `Status announcement for ${label}.`, {
          "es-ES": `${RUNTIME_CHROME_NODE_LABELS_ES[kind as WorkflowRuntimeChromeNodeKind]} estado: {status}`,
        }),
      ],
    ]),
  );
}

export const WORKFLOW_RUNTIME_UI_STRING_CATALOG = {
  schemaVersion: WORKFLOW_RUNTIME_UI_STRING_CATALOG_SCHEMA_VERSION,
  catalogId: WORKFLOW_RUNTIME_UI_STRING_CATALOG_ID,
  scope: "workflow_chrome",
  defaultLocale: "en-US",
  supportedLocales: ["en-US", "es-ES"],
  modelOutputLocalized: false,
  modelOutputBoundary: "model output language stays controlled by user prompt and runtime locale config",
  strings: {
    ...runtimeChromeStrings(),
    ...Object.fromEntries(
      Object.entries(WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT).map(([status, label]) => [
        `runtime.status.${status}`,
        chromeStringEntry(label, `Color-independent text equivalent for ${status} status.`, {
          "es-ES": WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT_ES[
            status as keyof typeof WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT_ES
          ],
        }),
      ]),
    ),
  },
} as const;

export function runtimeNodeChromeLogic(
  kind: WorkflowRuntimeChromeNodeKind,
  accessibleStatusField: string,
) {
  return {
    runtimeUiStringCatalogRef: WORKFLOW_RUNTIME_UI_STRING_CATALOG.catalogId,
    localeKey: `runtime.node.${kind}.label`,
    ariaLabelKey: `runtime.node.${kind}.aria`,
    statusAnnouncementKey: `runtime.node.${kind}.status`,
    accessibleStatusField,
    accessibleStatusText: WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT,
    colorIndependentStatus: true,
  };
}

export function runtimeNodeLocalization(kind: WorkflowRuntimeChromeNodeKind) {
  return {
    catalogId: WORKFLOW_RUNTIME_UI_STRING_CATALOG.catalogId,
    localeKey: `runtime.node.${kind}.label`,
    labelKey: `runtime.node.${kind}.label`,
    ariaLabelKey: `runtime.node.${kind}.aria`,
    statusAnnouncementKey: `runtime.node.${kind}.status`,
    modelOutputLocalized: false,
  };
}

export function runtimeNodeAccessibility(
  kind: WorkflowRuntimeChromeNodeKind,
  accessibleStatusField: string,
) {
  return {
    ariaLabelKey: `runtime.node.${kind}.aria`,
    statusAnnouncementKey: `runtime.node.${kind}.status`,
    accessibleStatusField,
    statusTextByValue: WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT,
    colorIndependentStatus: true,
  };
}

export function isRuntimeChromeNodeKind(
  kind: WorkflowNodeKind | WorkflowHarnessComponentKind | string,
): kind is RuntimeChromeNodeKind | RuntimeChromeComponentKind {
  return Object.prototype.hasOwnProperty.call(RUNTIME_CHROME_NODE_LABELS, kind);
}
