import {
  type HypervisorLaunchedSessionProjection,
  type HypervisorNewSessionLaunchSummary,
  type HypervisorSessionLaunchRecipe,
  type HypervisorSurfaceId,
} from "./hypervisorShellNavigationModel.ts";
import type { HypervisorHarnessSessionBinding } from "./harnessAdapterModel.ts";

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

  const binding = normalizeHarnessSessionBinding(
    record.harness_session_binding,
  );
  const bindingRef = stringValue(record.harness_session_binding_ref);
  if (!binding || bindingRef !== binding.session_binding_ref) {
    return null;
  }

  return {
    ...(record as unknown as HypervisorNewSessionLaunchSummary),
    harness_session_binding_ref: binding.session_binding_ref,
    harness_session_binding: binding,
  };
}

function normalizeHarnessSessionBinding(
  value: unknown,
): HypervisorHarnessSessionBinding | null {
  const record = recordValue(value);
  if (
    !record ||
    record.schema_version !== "ioi.hypervisor.harness_session_binding.v1" ||
    record.runtimeTruthSource !== "daemon-runtime" ||
    record.requires_daemon_gate !== true
  ) {
    return null;
  }

  const sessionBindingRef = stringValue(record.session_binding_ref);
  const sessionRouteRef = stringValue(record.session_route_ref);
  const harnessSelectionRef = stringValue(record.harness_selection_ref);
  const modelConfigurationRef = stringValue(record.model_configuration_ref);
  const modelRouteRef = stringValue(record.model_route_ref);
  const privacyPostureRef = stringValue(record.privacy_posture_ref);
  const receiptPreviewRef = stringValue(record.receipt_preview_ref);
  if (
    !sessionBindingRef?.startsWith("harness-session-binding:") ||
    !sessionRouteRef?.startsWith("session-route:") ||
    !harnessSelectionRef ||
    !modelConfigurationRef?.startsWith("model-config:") ||
    !modelRouteRef?.startsWith("model-route:") ||
    !privacyPostureRef?.startsWith("privacy:") ||
    !receiptPreviewRef?.startsWith("receipt-preview:")
  ) {
    return null;
  }

  return record as unknown as HypervisorHarnessSessionBinding;
}

function normalizeHarnessSessionBindingAdmission(
  value: unknown,
  binding: HypervisorHarnessSessionBinding,
): HypervisorLaunchedSessionProjection["harness_session_binding_admission"] | null {
  const record = recordValue(value);
  if (!record || record.runtimeTruthSource !== "daemon-runtime") {
    return null;
  }
  const schemaVersion = stringValue(record.schema_version);
  const admissionId = stringValue(record.admission_id);
  const sessionBindingRef = stringValue(record.session_binding_ref);
  const decision = stringValue(record.decision);
  if (
    !admissionId ||
    sessionBindingRef !== binding.session_binding_ref ||
    !decision
  ) {
    return null;
  }
  if (
    schemaVersion === "ioi.runtime.harness_session_binding_admission.v1" &&
    decision === "admitted"
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_binding_admission"];
  }
  if (
    schemaVersion ===
      "ioi.hypervisor.harness_session_binding_admission_failure.v1" &&
    (decision === "blocked" || decision === "daemon_unavailable")
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_binding_admission"];
  }
  return null;
}

function normalizeHarnessSessionLaunch(
  value: unknown,
  binding: HypervisorHarnessSessionBinding,
): HypervisorLaunchedSessionProjection["harness_session_launch"] | null {
  const record = recordValue(value);
  if (!record || record.runtimeTruthSource !== "daemon-runtime") {
    return null;
  }
  const schemaVersion = stringValue(record.schema_version);
  const launchId = stringValue(record.launch_id);
  const sessionBindingRef = stringValue(record.session_binding_ref);
  const decision = stringValue(record.decision);
  if (!launchId || sessionBindingRef !== binding.session_binding_ref || !decision) {
    return null;
  }
  if (
    schemaVersion === "ioi.runtime.harness_session_launch.v1" &&
    decision === "admitted" &&
    stringValue(record.launch_state) === "ready_to_spawn"
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_launch"];
  }
  if (
    schemaVersion === "ioi.hypervisor.harness_session_launch_failure.v1" &&
    (decision === "blocked" || decision === "daemon_unavailable")
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_launch"];
  }
  return null;
}

function normalizeHarnessSessionSpawn(
  value: unknown,
  launch: NonNullable<HypervisorLaunchedSessionProjection["harness_session_launch"]>,
): HypervisorLaunchedSessionProjection["harness_session_spawn"] | null {
  const record = recordValue(value);
  if (!record || record.runtimeTruthSource !== "daemon-runtime") {
    return null;
  }
  const schemaVersion = stringValue(record.schema_version);
  const spawnId = stringValue(record.spawn_id);
  const launchId = stringValue(record.launch_id);
  const sessionBindingRef = stringValue(record.session_binding_ref);
  const decision = stringValue(record.decision);
  const expectedLaunchId = "launch_id" in launch ? launch.launch_id : null;
  const expectedBindingRef =
    "session_binding_ref" in launch ? launch.session_binding_ref : null;
  if (
    !spawnId ||
    launchId !== expectedLaunchId ||
    sessionBindingRef !== expectedBindingRef ||
    !decision
  ) {
    return null;
  }
  if (
    schemaVersion === "ioi.runtime.harness_session_spawn.v1" &&
    decision === "admitted" &&
    stringValue(record.spawn_state) === "ready_for_client_pty_attach"
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_spawn"];
  }
  if (
    schemaVersion === "ioi.hypervisor.harness_session_spawn_failure.v1" &&
    (decision === "blocked" || decision === "daemon_unavailable")
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_spawn"];
  }
  return null;
}

function normalizeHarnessSessionReadiness(
  value: unknown,
  spawn: NonNullable<HypervisorLaunchedSessionProjection["harness_session_spawn"]>,
): HypervisorLaunchedSessionProjection["harness_session_readiness"] | null {
  const record = recordValue(value);
  if (!record || record.runtimeTruthSource !== "daemon-runtime") {
    return null;
  }
  const schemaVersion = stringValue(record.schema_version);
  const readinessId = stringValue(record.readiness_id);
  const spawnId = stringValue(record.spawn_id);
  const decision = stringValue(record.decision);
  const expectedSpawnId = "spawn_id" in spawn ? spawn.spawn_id : null;
  if (!readinessId || spawnId !== expectedSpawnId || !decision) {
    return null;
  }
  if (
    schemaVersion === "ioi.runtime.harness_session_readiness.v1" &&
    (decision === "ready" || decision === "blocked")
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_readiness"];
  }
  if (
    schemaVersion === "ioi.hypervisor.harness_session_readiness_failure.v1" &&
    (decision === "blocked" || decision === "daemon_unavailable")
  ) {
    return record as unknown as HypervisorLaunchedSessionProjection["harness_session_readiness"];
  }
  return null;
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
  const harnessSessionBinding = normalizeHarnessSessionBinding(
    record.harness_session_binding,
  );
  const harnessSessionBindingRef = stringValue(record.harness_session_binding_ref);
  const harnessSessionBindingAdmission = harnessSessionBinding
    ? normalizeHarnessSessionBindingAdmission(
        record.harness_session_binding_admission,
        harnessSessionBinding,
      )
    : null;
  const harnessSessionBindingAdmissionRef = nullableStringValue(
    record.harness_session_binding_admission_ref,
  );
  const harnessSessionLaunch = harnessSessionBinding
    ? normalizeHarnessSessionLaunch(
        record.harness_session_launch,
        harnessSessionBinding,
      )
    : null;
  const harnessSessionLaunchRef = nullableStringValue(
    record.harness_session_launch_ref,
  );
  const harnessSessionSpawn = harnessSessionLaunch
    ? normalizeHarnessSessionSpawn(
        record.harness_session_spawn,
        harnessSessionLaunch,
      )
    : null;
  const harnessSessionSpawnRef = nullableStringValue(
    record.harness_session_spawn_ref,
  );
  const harnessSessionReadiness = harnessSessionSpawn
    ? normalizeHarnessSessionReadiness(
        record.harness_session_readiness,
        harnessSessionSpawn,
      )
    : null;
  const harnessSessionReadinessRef = nullableStringValue(
    record.harness_session_readiness_ref,
  );

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
    !launchSummary ||
    !harnessSessionBinding ||
    harnessSessionBindingRef !== harnessSessionBinding.session_binding_ref ||
    !harnessSessionBindingAdmission ||
    harnessSessionBindingAdmissionRef !==
      harnessSessionBindingAdmission.admission_id ||
    !harnessSessionLaunch ||
    harnessSessionLaunchRef !== harnessSessionLaunch.launch_id ||
    !harnessSessionSpawn ||
    harnessSessionSpawnRef !== harnessSessionSpawn.spawn_id ||
    !harnessSessionReadiness ||
    harnessSessionReadinessRef !== harnessSessionReadiness.readiness_id
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
    harness_session_binding_ref: harnessSessionBinding.session_binding_ref,
    harness_session_binding: harnessSessionBinding,
    harness_session_binding_admission: harnessSessionBindingAdmission,
    harness_session_binding_admission_ref: harnessSessionBindingAdmission.admission_id,
    harness_session_launch: harnessSessionLaunch,
    harness_session_launch_ref: harnessSessionLaunch.launch_id,
    harness_session_spawn: harnessSessionSpawn,
    harness_session_spawn_ref: harnessSessionSpawn.spawn_id,
    harness_session_readiness: harnessSessionReadiness,
    harness_session_readiness_ref: harnessSessionReadiness.readiness_id,
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
