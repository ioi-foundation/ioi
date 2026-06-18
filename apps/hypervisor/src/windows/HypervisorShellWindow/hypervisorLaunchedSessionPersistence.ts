import {
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  buildCodeEditorAdapterLaunchPlan,
  buildHypervisorLaunchedSessionProjection,
  buildHypervisorNewSessionLaunchSummary,
  type CodeEditorAdapterLaunchAdmission,
  type HypervisorLaunchedSessionProjection,
  type HypervisorNewSessionLaunchSummary,
  type HypervisorSessionLaunchRecipe,
  type HypervisorSurfaceId,
} from "./hypervisorShellNavigationModel.ts";
import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessCompatibilityVerdict,
  modelRouteSupportsHypervisorMountFromInventory,
} from "./harnessAdapterModel.ts";

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

const REFERENCE_PROJECT_ID = "hypervisor-core";
const REFERENCE_PROJECT_LABEL = "IOI Workspace";
const REFERENCE_PRIVACY_POSTURE_REF = "privacy:redacted-projection";
const REFERENCE_RECEIPT_PREVIEW_REF = "receipt://hypervisor/reference-session/preview";
const REFERENCE_SESSION_SEEDS = [
  {
    seed_intent: "Write Parent Harness Evidence Boundary Doc",
    recipe_id: "workbench.default",
    launched_at: "2026-06-17T15:30:00.000Z",
    branch_label: "main",
    relative_time_label: "6h ago",
    activity_count: 3,
    admitted: true,
  },
  {
    seed_intent: "Write Harness Tool Call Documentation",
    recipe_id: "mission.default",
    launched_at: "2026-06-17T15:24:00.000Z",
    branch_label: "main",
    relative_time_label: "6h ago",
    activity_count: 4,
    admitted: false,
  },
  {
    seed_intent: "Design Postquantum Computers Website",
    recipe_id: "agent.default",
    launched_at: "2026-06-17T15:18:00.000Z",
    branch_label: "main",
    relative_time_label: "6h ago",
    activity_count: 5,
    admitted: false,
  },
] as const;

const referenceCodeEditorAdapter =
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.find(
    (preference) => preference.default_for_project,
  ) ?? HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES[0]!;

const referenceModelRouteAvailability =
  modelRouteSupportsHypervisorMountFromInventory(
    HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  );

const referenceHarnessVerdict = buildHarnessCompatibilityVerdict(
  DEFAULT_HARNESS_PROFILE_OPTION,
  referenceModelRouteAvailability.available,
  REFERENCE_PRIVACY_POSTURE_REF,
);

function recipeForReferenceSeed(
  recipeId: string,
): HypervisorSessionLaunchRecipe {
  return (
    HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
      (recipe) => recipe.recipe_id === recipeId,
    ) ?? HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!
  );
}

function buildReferenceAdapterAdmission({
  seedIndex,
  admittedAt,
}: {
  seedIndex: number;
  admittedAt: string;
}): CodeEditorAdapterLaunchAdmission {
  const launchPlan = buildCodeEditorAdapterLaunchPlan(referenceCodeEditorAdapter);
  return {
    schema_version: "ioi.runtime.code_editor_adapter_launch_plan_admission.v1",
    admission_id: `${launchPlan.launch_plan_ref}/reference-seed/${seedIndex}`,
    launch_plan_ref: launchPlan.launch_plan_ref,
    adapter_ref: launchPlan.adapter_ref,
    target_ref: launchPlan.target_ref,
    launch_mode: launchPlan.launch_mode,
    connection_kind: launchPlan.connection_kind,
    connection_contract_ref: launchPlan.connection_contract_ref,
    executor_lane: launchPlan.executor_lane,
    control_action: launchPlan.control_action,
    control_channel_ref: launchPlan.control_channel_ref,
    required_access_lease_refs: launchPlan.required_access_lease_refs,
    required_authority_scope_refs: launchPlan.required_authority_scope_refs,
    required_receipt_refs: launchPlan.required_receipt_refs,
    custody_posture: launchPlan.custody_posture,
    secret_release_policy: "no_durable_secret_release",
    wallet_approval_ref: `wallet://approval/reference-session/${seedIndex}`,
    agentgres_operation_refs: [
      `agentgres://operation/reference-session/${seedIndex}`,
    ],
    receipt_refs: [`receipt://hypervisor/reference-session/${seedIndex}`],
    state_root: `agentgres://state-root/reference-session/${seedIndex}`,
    adapter_runtime_truth_claimed: false,
    decision: "admitted",
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: admittedAt,
  };
}

export const HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS: HypervisorLaunchedSessionProjection[] =
  REFERENCE_SESSION_SEEDS.map((seed, seedIndex) => {
    const recipe = recipeForReferenceSeed(seed.recipe_id);
    const launchSummary = buildHypervisorNewSessionLaunchSummary({
      recipe,
      seedIntent: seed.seed_intent,
      projectId: REFERENCE_PROJECT_ID,
      codeEditorAdapter: referenceCodeEditorAdapter,
      harness: DEFAULT_HARNESS_PROFILE_OPTION,
      harnessVerdict: referenceHarnessVerdict,
      modelRouteAvailability: referenceModelRouteAvailability,
      modelRouteRef: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      privacyPostureRef: REFERENCE_PRIVACY_POSTURE_REF,
      authorityScopeRefs: recipe.authority_scope_templates,
      receiptPreviewRef: `${REFERENCE_RECEIPT_PREVIEW_REF}/${seedIndex}`,
    });

    return buildHypervisorLaunchedSessionProjection({
      request: {
        recipe_id: recipe.recipe_id,
        seed_intent: seed.seed_intent,
        project_id: REFERENCE_PROJECT_ID,
        adapter_preference_ref: launchSummary.code_editor_adapter_ref,
        harness_selection_ref: launchSummary.harness_selection_ref,
        model_route_ref: launchSummary.model_route_ref,
        privacy_posture_ref: launchSummary.privacy_posture_ref,
        authority_scope_refs: launchSummary.authority_scope_refs,
        receipt_preview_ref: launchSummary.receipt_preview_ref,
        launch_summary: launchSummary,
      },
      recipe,
      projectLabel: REFERENCE_PROJECT_LABEL,
      launchedAtMs: Date.parse(seed.launched_at),
      displayMeta: {
        branchLabel: seed.branch_label,
        relativeTimeLabel: seed.relative_time_label,
        activityCount: seed.activity_count,
      },
      codeEditorAdapterAdmission: seed.admitted
        ? buildReferenceAdapterAdmission({
            seedIndex,
            admittedAt: seed.launched_at,
          })
        : null,
    });
  })
    .map(normalizeHypervisorLaunchedSessionProjection)
    .filter((projection): projection is HypervisorLaunchedSessionProjection =>
      Boolean(projection),
    );

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
