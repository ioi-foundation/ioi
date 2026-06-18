import {
  type HypervisorLaunchedSessionProjection,
  type HypervisorNewSessionLaunchSummary,
  type HypervisorSessionLaunchRecipe,
  type HypervisorSurfaceId,
} from "./hypervisorShellNavigationModel.ts";

export const HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY =
  "ioi.hypervisor.launched_session_projections.v1";

export const HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT = 12;

interface HypervisorLaunchedSessionStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

const SURFACE_IDS = new Set<HypervisorSurfaceId>([
  "home",
  "sessions",
  "projects",
  "missions",
  "workbench",
  "automations",
  "insights",
  "agents",
  "models",
  "privacy",
  "providers",
  "environments",
  "foundry",
  "authority",
  "receipts",
  "settings",
]);

const RECIPE_KINDS = new Set<HypervisorSessionLaunchRecipe["kind"]>([
  "mission",
  "workbench",
  "agent",
  "automation",
  "foundry_job",
  "provider_environment_job",
  "privacy_workspace",
]);

const ADMISSION_STATES = new Set<HypervisorLaunchedSessionProjection["admission_state"]>([
  "daemon_admitted",
  "daemon_blocked",
  "daemon_unavailable",
  "pending_daemon_admission",
]);

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function nullableStringValue(value: unknown): string | null {
  return value === null ? null : stringValue(value);
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function normalizeLaunchSummary(
  value: unknown,
): HypervisorNewSessionLaunchSummary | null {
  const record = recordValue(value);
  if (
    !record ||
    record.schema_version !== "ioi.hypervisor.new_session_launch_summary.v1" ||
    record.runtimeTruthSource !== "daemon-runtime" ||
    record.requires_daemon_gate !== true
  ) {
    return null;
  }

  return record as unknown as HypervisorNewSessionLaunchSummary;
}

export function normalizeHypervisorLaunchedSessionProjection(
  value: unknown,
): HypervisorLaunchedSessionProjection | null {
  const record = recordValue(value);
  if (
    !record ||
    record.schema_version !== "ioi.hypervisor.launched_session_projection.v1" ||
    record.runtimeTruthSource !== "daemon-runtime"
  ) {
    return null;
  }

  const sessionRef = stringValue(record.session_ref);
  const launchReceiptRef = stringValue(record.launch_receipt_ref);
  const recipeRef = stringValue(record.recipe_ref);
  const projectRef = stringValue(record.project_ref);
  const projectLabel = stringValue(record.project_label);
  const launchedAtMs = numberValue(record.launched_at_ms);
  const branchLabel = nullableStringValue(record.branch_label);
  const relativeTimeLabel = nullableStringValue(record.relative_time_label);
  const activityCount = numberValue(record.activity_count);
  const admissionState = stringValue(record.admission_state);
  const recipeKind = stringValue(record.recipe_kind);
  const surfaceId = stringValue(record.surface_id);
  const launchSummary = normalizeLaunchSummary(record.launch_summary);

  if (
    !sessionRef?.startsWith("session:") ||
    !launchReceiptRef?.startsWith("receipt://") ||
    !recipeRef ||
    !projectRef ||
    !projectLabel ||
    launchedAtMs === null ||
    !admissionState ||
    !ADMISSION_STATES.has(
      admissionState as HypervisorLaunchedSessionProjection["admission_state"],
    ) ||
    !recipeKind ||
    !RECIPE_KINDS.has(recipeKind as HypervisorSessionLaunchRecipe["kind"]) ||
    !surfaceId ||
    !SURFACE_IDS.has(surfaceId as HypervisorSurfaceId) ||
    !launchSummary
  ) {
    return null;
  }

  const codeEditorAdapterAdmission = recordValue(
    record.code_editor_adapter_admission,
  )
    ? (record.code_editor_adapter_admission as HypervisorLaunchedSessionProjection["code_editor_adapter_admission"])
    : null;

  return {
    schema_version: "ioi.hypervisor.launched_session_projection.v1",
    session_ref: sessionRef,
    launch_receipt_ref: launchReceiptRef,
    recipe_ref: recipeRef,
    recipe_kind: recipeKind as HypervisorSessionLaunchRecipe["kind"],
    surface_id: surfaceId as HypervisorSurfaceId,
    project_ref: projectRef,
    project_label: projectLabel,
    launched_at_ms: launchedAtMs,
    branch_label: branchLabel,
    relative_time_label: relativeTimeLabel,
    activity_count: activityCount,
    admission_state:
      admissionState as HypervisorLaunchedSessionProjection["admission_state"],
    code_editor_adapter_admission: codeEditorAdapterAdmission,
    code_editor_adapter_admission_ref: nullableStringValue(
      record.code_editor_adapter_admission_ref,
    ),
    launch_summary: launchSummary,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function mergeHypervisorLaunchedSessionProjection(
  current: readonly HypervisorLaunchedSessionProjection[],
  launchedSession: HypervisorLaunchedSessionProjection,
): HypervisorLaunchedSessionProjection[] {
  return [
    launchedSession,
    ...current
      .map(normalizeHypervisorLaunchedSessionProjection)
      .filter((projection): projection is HypervisorLaunchedSessionProjection =>
        Boolean(projection),
      )
      .filter((projection) => projection.session_ref !== launchedSession.session_ref),
  ].slice(0, HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT);
}

export function loadHypervisorLaunchedSessionProjections({
  storage,
  storageKey = HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
}: {
  storage?: HypervisorLaunchedSessionStorage | null;
  storageKey?: string;
}): HypervisorLaunchedSessionProjection[] {
  if (!storage) {
    return [];
  }

  try {
    const raw = storage.getItem(storageKey);
    const parsed = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .map(normalizeHypervisorLaunchedSessionProjection)
      .filter((projection): projection is HypervisorLaunchedSessionProjection =>
        Boolean(projection),
      )
      .slice(0, HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT);
  } catch {
    return [];
  }
}

export function persistHypervisorLaunchedSessionProjections({
  storage,
  projections,
  storageKey = HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
}: {
  storage?: HypervisorLaunchedSessionStorage | null;
  projections: readonly HypervisorLaunchedSessionProjection[];
  storageKey?: string;
}): void {
  if (!storage) {
    return;
  }

  try {
    const normalized = projections
      .map(normalizeHypervisorLaunchedSessionProjection)
      .filter((projection): projection is HypervisorLaunchedSessionProjection =>
        Boolean(projection),
      )
      .slice(0, HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT);
    storage.setItem(storageKey, JSON.stringify(normalized));
  } catch {
    // Projection cache persistence is best-effort; daemon/Agentgres remains truth.
  }
}
