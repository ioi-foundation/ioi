import type {
  NodeLogic,
  WorkflowHarnessComponentKind,
  WorkflowNodeKind,
  WorkflowRuntimeUiStringCatalog,
} from "../types/graph";

export const WORKFLOW_RUNTIME_UI_STRING_CATALOG_SCHEMA_VERSION =
  "ioi.workflow.runtime-ui-string-catalog.v1";

export const WORKFLOW_RUNTIME_UI_STRING_CATALOG_ID =
  "ioi.workflow.runtime-ui.chrome.v1";

export const WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT = {
  idle: "Idle",
  queued: "Queued",
  running: "Running",
  success: "Success",
  completed: "Completed",
  error: "Error",
  failed: "Failed",
  canceled: "Canceled",
  blocked: "Blocked",
  warning: "Warning",
  passed: "Passed",
  ready: "Ready",
  needs_attention: "Needs attention",
  sandboxed: "Sandboxed",
  approval: "Approval path",
  not_run: "Not run",
  unavailable: "Unavailable",
  unbound: "Unbound",
  projection_only: "Projection only",
  unknown: "Unknown",
} as const;

const WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT_ES = {
  idle: "Inactivo",
  queued: "En cola",
  running: "En curso",
  success: "Exito",
  completed: "Completado",
  error: "Error",
  failed: "Error",
  canceled: "Cancelado",
  blocked: "Bloqueado",
  warning: "Advertencia",
  passed: "Aprobado",
  ready: "Listo",
  needs_attention: "Necesita atencion",
  sandboxed: "En sandbox",
  approval: "Ruta de aprobacion",
  not_run: "Sin ejecutar",
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
  runtime_thread_fork: "Runtime thread fork",
  workflow_package_export: "Workflow package export",
  workflow_package_import: "Workflow package import",
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
  runtime_thread_fork: "Bifurcacion de hilo del runtime",
  workflow_package_export: "Exportar paquete de workflow",
  workflow_package_import: "Importar paquete de workflow",
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
  "runtime.node.runtime_thread_fork.label",
  "runtime.node.workflow_package_export.label",
  "runtime.node.workflow_package_import.status",
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
type WorkflowRuntimeUiStringValues = Record<
  string,
  string | number | boolean | null | undefined
>;

export interface WorkflowRuntimeNodeChromeSource {
  id?: string;
  type?: string;
  name?: string;
  label?: string;
  status?: string | null;
  config?: {
    logic?: NodeLogic | null;
  } | null;
}

export interface WorkflowRuntimeNodeChromeResult {
  label: string;
  ariaLabel: string;
  statusText: string;
  statusAnnouncement: string;
  locale: string;
  isRuntimeChrome: boolean;
  modelOutputLocalized: boolean;
  accessibleStatusValue: string;
  colorIndependentStatus: boolean;
}

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

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isNodeChromeSource(
  value: WorkflowRuntimeNodeChromeSource | NodeLogic | null | undefined,
): value is WorkflowRuntimeNodeChromeSource {
  return Boolean(value && typeof value === "object" && "config" in value);
}

function normalizeRuntimeStatusValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "unknown";
  return String(value).trim().toLowerCase().replace(/[\s-]+/g, "_") || "unknown";
}

function humanizeRuntimeStatusValue(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ") || WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT.unknown;
}

function runtimeCatalog(
  catalog?: WorkflowRuntimeUiStringCatalog | null,
): WorkflowRuntimeUiStringCatalog {
  return (
    catalog ??
    (WORKFLOW_RUNTIME_UI_STRING_CATALOG as unknown as WorkflowRuntimeUiStringCatalog)
  );
}

export function normalizeWorkflowRuntimeLocale(
  locale?: string | null,
  catalog?: WorkflowRuntimeUiStringCatalog | null,
): string {
  const activeCatalog = runtimeCatalog(catalog);
  const fallbackLocale = activeCatalog.defaultLocale || "en-US";
  if (!isString(locale)) return fallbackLocale;
  return activeCatalog.supportedLocales.includes(locale) ? locale : fallbackLocale;
}

export function workflowRuntimeValueAtPath(
  source: unknown,
  path?: string | null,
): unknown {
  if (!isString(path)) return undefined;
  return path.split(".").reduce<unknown>((current, segment) => {
    if (current === null || current === undefined || segment.length === 0) {
      return undefined;
    }
    if (Array.isArray(current)) {
      const index = Number(segment);
      return Number.isInteger(index) ? current[index] : undefined;
    }
    if (typeof current === "object") {
      return (current as Record<string, unknown>)[segment];
    }
    return undefined;
  }, source);
}

export function resolveWorkflowRuntimeUiString(
  key?: string | null,
  options: {
    locale?: string | null;
    values?: WorkflowRuntimeUiStringValues;
    fallback?: string | null;
    catalog?: WorkflowRuntimeUiStringCatalog | null;
  } = {},
): string {
  const catalog = runtimeCatalog(options.catalog);
  const locale = normalizeWorkflowRuntimeLocale(options.locale, catalog);
  const entry = isString(key) ? catalog.strings[key] : undefined;
  const template =
    entry?.translations?.[locale] ??
    entry?.translations?.[catalog.defaultLocale] ??
    entry?.defaultMessage ??
    options.fallback ??
    key ??
    "";
  return String(template).replace(/\{([a-zA-Z0-9_.-]+)\}/g, (match, name) => {
    const value = options.values?.[name];
    return value === null || value === undefined ? match : String(value);
  });
}

export function workflowRuntimeAccessibleStatusLabel(
  value: unknown,
  locale?: string | null,
  statusText?: Record<string, string> | null,
  catalog?: WorkflowRuntimeUiStringCatalog | null,
): string {
  const normalized = normalizeRuntimeStatusValue(value);
  const mappedStatusText =
    statusText?.[normalized] ??
    WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT[
      normalized as keyof typeof WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT
    ] ??
    humanizeRuntimeStatusValue(normalized);
  return resolveWorkflowRuntimeUiString(`runtime.status.${normalized}`, {
    locale,
    catalog,
    fallback: mappedStatusText,
  });
}

export function workflowRuntimeNodeChrome(
  source: WorkflowRuntimeNodeChromeSource | NodeLogic | null | undefined,
  options: {
    fallbackLabel?: string | null;
    locale?: string | null;
  } = {},
): WorkflowRuntimeNodeChromeResult {
  const logic = isNodeChromeSource(source) ? source.config?.logic ?? {} : source ?? {};
  const catalog = runtimeCatalog(logic.runtimeUiStringCatalog);
  const locale = normalizeWorkflowRuntimeLocale(
    logic.workflowChromeLocale ?? options.locale,
    catalog,
  );
  const fallbackLabel =
    options.fallbackLabel ??
    (isNodeChromeSource(source)
      ? source.name ?? source.label ?? source.type ?? "Workflow node"
      : "Workflow node");
  const statusValue =
    workflowRuntimeValueAtPath(logic, logic.accessibleStatusField) ??
    (isNodeChromeSource(source) ? source.status : undefined) ??
    workflowRuntimeValueAtPath(logic, "status") ??
    "unknown";
  const statusText = workflowRuntimeAccessibleStatusLabel(
    statusValue,
    locale,
    logic.accessibleStatusText,
    catalog,
  );
  const label = resolveWorkflowRuntimeUiString(logic.localeKey, {
    locale,
    catalog,
    fallback: fallbackLabel,
  });
  const ariaLabel = resolveWorkflowRuntimeUiString(logic.ariaLabelKey, {
    locale,
    catalog,
    fallback: `${label} node`,
  });
  const statusAnnouncement = resolveWorkflowRuntimeUiString(
    logic.statusAnnouncementKey,
    {
      locale,
      catalog,
      values: { status: statusText },
      fallback: `${label} status: ${statusText}`,
    },
  );
  return {
    label,
    ariaLabel,
    statusText,
    statusAnnouncement,
    locale,
    isRuntimeChrome:
      logic.runtimeUiStringCatalogRef === catalog.catalogId ||
      Boolean(logic.localeKey || logic.ariaLabelKey || logic.statusAnnouncementKey),
    modelOutputLocalized: catalog.modelOutputLocalized,
    accessibleStatusValue: normalizeRuntimeStatusValue(statusValue),
    colorIndependentStatus: logic.colorIndependentStatus === true,
  };
}

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
