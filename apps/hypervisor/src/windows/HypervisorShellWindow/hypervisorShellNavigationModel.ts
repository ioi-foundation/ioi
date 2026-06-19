import {
  HYPERVISOR_HARNESS_SELECTION_OPTIONS,
  HarnessSessionBindingAdmissionError,
  HarnessSessionLaunchError,
  HarnessSessionReadinessError,
  HarnessSessionSpawnError,
  HarnessSessionTerminalAttachError,
  buildHypervisorHarnessSessionBinding,
  getHarnessSelectionRef,
  readHypervisorHarnessPublicFixtureDaemonEndpoint,
  type HarnessCompatibilityVerdict,
  type HypervisorHarnessSessionBinding,
  type HypervisorHarnessSessionBindingAdmission,
  type HypervisorHarnessSessionLaunch,
  type HypervisorHarnessSessionReadiness,
  type HypervisorHarnessSessionSpawn,
  type HypervisorHarnessSessionTerminalAttach,
  type HypervisorModelRouteAvailability,
  type HypervisorHarnessSelectionOption,
} from "./harnessAdapterModel.ts";
import {
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  CodeEditorAdapterLaunchAdmissionError,
  buildCodeEditorAdapterLaunchPlan,
  getCodeEditorAdapterPreferenceRef,
  type HypervisorCodeEditorAdapterControlAction,
  type HypervisorCodeEditorAdapterCustodyPosture,
  type HypervisorCodeEditorAdapterExecutorLane,
  type CodeEditorAdapterLaunchAdmission,
  type CodeEditorAdapterLaunchPlan,
  type CodeEditorAdapterPreference,
} from "./codeEditorAdapterPreferences.ts";

export {
  requestHarnessSessionBindingAdmission,
  requestHarnessSessionLaunch,
  requestHarnessSessionReadiness,
  requestHarnessSessionSpawn,
  requestHarnessSessionTerminalAttach,
  HarnessSessionBindingAdmissionError,
  HarnessSessionLaunchError,
  HarnessSessionReadinessError,
  HarnessSessionSpawnError,
  HarnessSessionTerminalAttachError,
  type HypervisorHarnessSessionBindingAdmission,
  type HypervisorHarnessSessionLaunch,
  type HypervisorHarnessSessionReadiness,
  type HypervisorHarnessSessionSpawn,
  type HypervisorHarnessSessionTerminalAttach,
} from "./harnessAdapterModel.ts";

export {
  DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  HYPERVISOR_CODE_EDITOR_ADAPTER_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY,
  buildCodeEditorAdapterLaunchPlan,
  getCodeEditorAdapterPreferenceByRef,
  getCodeEditorAdapterPreferenceRef,
  requestCodeEditorAdapterLaunchPlanAdmission,
  CodeEditorAdapterLaunchAdmissionError,
  type HypervisorCodeEditorAdapterConnectionKind,
  type HypervisorCodeEditorAdapterCustodyPosture,
  type HypervisorCodeEditorAdapterControlAction,
  type HypervisorCodeEditorAdapterExecutorLane,
  type HypervisorCodeEditorAdapterId,
  type HypervisorCodeEditorAdapterLaunchMode,
  type CodeEditorAdapterLaunchAdmission,
  type CodeEditorAdapterLaunchPlan,
  type CodeEditorAdapterPreference,
} from "./codeEditorAdapterPreferences.ts";

export type HypervisorClientKind =
  | "app"
  | "web"
  | "cli_headless"
  | "tui_presentation";

export type HypervisorSurfaceId =
  | "home"
  | "sessions"
  | "projects"
  | "missions"
  | "workbench"
  | "automations"
  | "insights"
  | "agents"
  | "models"
  | "privacy"
  | "providers"
  | "environments"
  | "foundry"
  | "authority"
  | "receipts"
  | "settings";

export type HypervisorShellActionId = "new_session";

export type HypervisorNewSessionSetupSectionId =
  | "intent"
  | "project"
  | "adapter_preference"
  | "harness"
  | "model_route"
  | "privacy_posture"
  | "authority"
  | "receipt_preview";

export type HypervisorSurfaceKind =
  | "core"
  | "application"
  | "governance"
  | "infrastructure"
  | "settings";

export type HypervisorSessionDetailTab =
  | "agent"
  | "code"
  | "environment"
  | "changes"
  | "receipts"
  | "replay";

export type HypervisorSessionWorkspaceMode = "code";

export type HypervisorSessionChangeInspectorMode =
  | "changes"
  | "all_files"
  | "comments";

export type HypervisorInspectorPanelId =
  | "changes"
  | "ports_services"
  | "tasks"
  | "terminal"
  | "logs"
  | "authority"
  | "privacy"
  | "receipts"
  | "model_harness_provider";

export type HypervisorIoiReferenceSurface =
  | "home"
  | "workspaces"
  | "automations"
  | "insights"
  | "ai"
  | "projects"
  | "settings"
  | "logs"
  | "session_detail"
  | "editor";

export type HypervisorShellRegion =
  | "left_nav"
  | "new_session"
  | "session_rail"
  | "main_surface"
  | "session_detail_tabs"
  | "right_inspector"
  | "bottom_inspector"
  | "settings";

export type HypervisorSettingsSectionId =
  | "identity"
  | "secrets"
  | "git_auth"
  | "personal_access_tokens"
  | "integrations";

export interface HypervisorIoiReferenceShellRequirements {
  primaryReference: "internal-docs/reverse-engineering/ioi";
  sourceSurfaces: readonly HypervisorIoiReferenceSurface[];
  translatedHypervisorSurfaces: readonly HypervisorSurfaceId[];
  leftNavSurfaceIds: readonly HypervisorSurfaceId[];
  shellRegions: readonly HypervisorShellRegion[];
  sessionDetailTabs: readonly HypervisorSessionDetailTab[];
  rightInspectorPanels: readonly HypervisorInspectorPanelId[];
  bottomInspectorPanels: readonly HypervisorInspectorPanelId[];
  settingsSections: readonly HypervisorSettingsSectionId[];
  editorAdapterTargets: readonly string[];
  agentHarnessAdapters: readonly string[];
}

export interface HypervisorShellNavigationItem {
  id: HypervisorSurfaceId;
  label: string;
  description: string;
  kind: HypervisorSurfaceKind;
  railGroup: "primary" | "applications" | "governance" | "bottom";
  defaultSessionTab?: HypervisorSessionDetailTab;
  inspectorPanels: HypervisorInspectorPanelId[];
  adapterTargets?: string[];
}

export interface HypervisorShellAction {
  id: HypervisorShellActionId;
  label: string;
  description: string;
}

export interface HypervisorNewSessionSetupSection {
  id: HypervisorNewSessionSetupSectionId;
  label: string;
  description: string;
  required: boolean;
}

export interface HypervisorNewSessionSetupModel {
  action: HypervisorShellAction;
  sections: HypervisorNewSessionSetupSection[];
  harnessOptions: HypervisorHarnessSelectionOption[];
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorSessionLaunchRecipe {
  schema_version: "ioi.hypervisor.session_launch_recipe.v1";
  recipe_id: string;
  label: string;
  description: string;
  kind:
    | "mission"
    | "workbench"
    | "agent"
    | "automation"
    | "foundry_job"
    | "provider_environment_job"
    | "privacy_workspace";
  surface_id: HypervisorSurfaceId;
  required_inputs: string[];
  model_mount_policy: "inherit" | "select" | "required" | "forbidden";
  harness_profile_policy: "default" | "select" | "external_adapter";
  authority_scope_templates: string[];
  privacy_posture_templates: string[];
}

export interface HypervisorSessionLaunchRecipeAdmissionRequest {
  schema_version: "ioi.hypervisor.session_launch_recipe_admission_request.v1";
  recipe: HypervisorSessionLaunchRecipe;
  target_binding: HypervisorNewSessionTargetBinding;
  model_route_ref: string;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_preview_ref: string;
  expected_receipt_refs: string[];
  agentgres_operation_refs: string[];
  receipt_refs: string[];
  requires_daemon_gate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorSessionLaunchRecipeAdmission {
  schema_version: "ioi.runtime.hypervisor_session_launch_recipe_admission.v1";
  admission_id: string;
  decision: "admitted";
  admission_state: "admitted_for_session_binding";
  recipe_ref: string;
  recipe_kind: HypervisorSessionLaunchRecipe["kind"];
  surface_id: HypervisorSurfaceId;
  target_binding_ref: string;
  project_ref: string;
  operator_intent_ref: string | null;
  session_route_ref: string;
  code_editor_adapter_target_ref: string | null;
  model_route_ref: string;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_preview_ref: string;
  expected_receipt_refs: string[];
  agentgres_operation_refs: string[];
  receipt_refs: string[];
  state_root: string | null;
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
  admitted_at: string;
}

export interface HypervisorSessionLaunchRecipeAdmissionFailure {
  schema_version: "ioi.hypervisor.session_launch_recipe_admission_failure.v1";
  admission_id: string;
  recipe_ref: string;
  target_binding_ref: string;
  session_route_ref: string;
  decision: "blocked" | "daemon_unavailable";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorSessionLaunchRecipeAdmissionRecord =
  | HypervisorSessionLaunchRecipeAdmission
  | HypervisorSessionLaunchRecipeAdmissionFailure;

export interface HypervisorNewSessionTargetBinding {
  schema_version: "ioi.hypervisor.new_session_target_binding.v1";
  target_binding_ref: string;
  recipe_ref: string;
  target_kind: HypervisorSessionLaunchRecipe["kind"];
  surface_id: HypervisorSurfaceId;
  project_ref: string;
  operator_intent_ref: string | null;
  session_route_ref: string;
  code_editor_adapter_target_ref: string | null;
  automation_recipe_ref: string | null;
  agent_template_ref: string | null;
  foundry_job_ref: string | null;
  provider_candidate_ref: string | null;
  environment_ref: string | null;
  private_workspace_ref: string | null;
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorNewSessionLaunchSummary {
  schema_version: "ioi.hypervisor.new_session_launch_summary.v1";
  recipe_ref: string;
  seed_intent: string | null;
  target_binding_ref: string;
  target_binding: HypervisorNewSessionTargetBinding;
  project_ref: string;
  code_editor_adapter_ref: string;
  code_editor_adapter_target_ref: string;
  code_editor_adapter_custody_posture: HypervisorCodeEditorAdapterCustodyPosture;
  code_editor_adapter_launch_plan_ref: string;
  code_editor_adapter_connection_contract_ref: string;
  code_editor_adapter_executor_lane: HypervisorCodeEditorAdapterExecutorLane;
  code_editor_adapter_control_action: HypervisorCodeEditorAdapterControlAction;
  code_editor_adapter_control_channel_ref: string;
  code_editor_adapter_access_lease_refs: string[];
  code_editor_adapter_authority_scope_refs: string[];
  code_editor_adapter_receipt_refs: string[];
  harness_selection_ref: string;
  harness_selection_kind: HypervisorHarnessSelectionOption["selection_kind"];
  harness_label: string;
  harness_runtime_truth_source: "daemon-runtime";
  harness_truth_boundary: "daemon-owned" | "proposal_source_only";
  harness_verdict_state: HarnessCompatibilityVerdict["state"];
  harness_session_binding_ref: string;
  harness_session_binding: HypervisorHarnessSessionBinding;
  model_route_ref: string;
  model_route_availability_state: HypervisorModelRouteAvailability["state"];
  model_route_available: boolean;
  model_route_endpoint_refs: string[];
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_preview_ref: string;
  requires_daemon_gate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorNewSessionLaunchRequest {
  recipe_id: string;
  seed_intent: string | null;
  project_id: string;
  adapter_preference_ref: string;
  harness_selection_ref: string;
  model_route_ref: string;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_preview_ref: string;
  launch_summary: HypervisorNewSessionLaunchSummary;
}

export interface HypervisorCodeEditorAdapterLaunchAdmissionFailure {
  schema_version: "ioi.hypervisor.code_editor_adapter_launch_admission_failure.v1";
  admission_id: string;
  launch_plan_ref: string;
  adapter_ref: string;
  target_ref: string;
  decision: "blocked" | "daemon_unavailable";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorCodeEditorAdapterLaunchAdmissionRecord =
  | CodeEditorAdapterLaunchAdmission
  | HypervisorCodeEditorAdapterLaunchAdmissionFailure;

export interface HypervisorHarnessSessionBindingAdmissionFailure {
  schema_version: "ioi.hypervisor.harness_session_binding_admission_failure.v1";
  admission_id: string;
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  decision: "blocked" | "daemon_unavailable";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorHarnessSessionBindingAdmissionRecord =
  | HypervisorHarnessSessionBindingAdmission
  | HypervisorHarnessSessionBindingAdmissionFailure;

export interface HypervisorHarnessSessionLaunchFailure {
  schema_version: "ioi.hypervisor.harness_session_launch_failure.v1";
  launch_id: string;
  session_binding_ref: string;
  session_route_ref: string;
  binding_admission_id: string | null;
  harness_selection_ref: string;
  decision: "blocked" | "daemon_unavailable";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorHarnessSessionLaunchRecord =
  | HypervisorHarnessSessionLaunch
  | HypervisorHarnessSessionLaunchFailure;

export interface HypervisorHarnessSessionSpawnFailure {
  schema_version: "ioi.hypervisor.harness_session_spawn_failure.v1";
  spawn_id: string;
  launch_id: string | null;
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  decision: "blocked" | "daemon_unavailable";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorHarnessSessionSpawnRecord =
  | HypervisorHarnessSessionSpawn
  | HypervisorHarnessSessionSpawnFailure;

export interface HypervisorHarnessSessionReadinessFailure {
  schema_version: "ioi.hypervisor.harness_session_readiness_failure.v1";
  readiness_id: string;
  spawn_id: string | null;
  launch_id: string | null;
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  decision: "blocked" | "daemon_unavailable";
  readiness_state: "daemon_unavailable" | "host_readiness_blocked";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorHarnessSessionReadinessRecord =
  | HypervisorHarnessSessionReadiness
  | HypervisorHarnessSessionReadinessFailure;

export interface HypervisorHarnessSessionTerminalAttachFailure {
  schema_version: "ioi.hypervisor.harness_session_terminal_attach_failure.v1";
  attach_id: string;
  spawn_id: string | null;
  readiness_id: string | null;
  launch_id: string | null;
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  decision: "blocked" | "daemon_unavailable";
  attach_state: "daemon_unavailable" | "attach_blocked";
  error_message: string;
  http_status: number | null;
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorHarnessSessionTerminalAttachRecord =
  | HypervisorHarnessSessionTerminalAttach
  | HypervisorHarnessSessionTerminalAttachFailure;

const HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_PATH =
  "/v1/hypervisor/session-launch-recipe-admissions";

export class HypervisorSessionLaunchRecipeAdmissionError extends Error {
  readonly endpoint: string;
  readonly responseBody: string;
  readonly status: number;

  constructor({
    endpoint,
    responseBody,
    status,
  }: {
    endpoint: string;
    responseBody: string;
    status: number;
  }) {
    super(`Hypervisor session launch recipe admission failed with ${status}`);
    this.name = "HypervisorSessionLaunchRecipeAdmissionError";
    this.endpoint = endpoint;
    this.responseBody = responseBody;
    this.status = status;
  }
}

export interface HypervisorLaunchedSessionProjection {
  schema_version: "ioi.hypervisor.launched_session_projection.v1";
  session_ref: string;
  launch_receipt_ref: string;
  recipe_ref: string;
  recipe_kind: HypervisorSessionLaunchRecipe["kind"];
  surface_id: HypervisorSurfaceId;
  project_ref: string;
  project_label: string;
  launched_at_ms: number;
  branch_label?: string | null;
  relative_time_label?: string | null;
  activity_count?: number | null;
  admission_state:
    | "daemon_admitted"
    | "daemon_blocked"
    | "daemon_unavailable"
    | "pending_daemon_admission";
  code_editor_adapter_admission:
    | HypervisorCodeEditorAdapterLaunchAdmissionRecord
    | null;
  code_editor_adapter_admission_ref: string | null;
  session_launch_recipe_admission:
    | HypervisorSessionLaunchRecipeAdmissionRecord
    | null;
  session_launch_recipe_admission_ref: string | null;
  harness_session_binding_ref: string;
  harness_session_binding: HypervisorHarnessSessionBinding;
  harness_session_binding_admission:
    | HypervisorHarnessSessionBindingAdmissionRecord
    | null;
  harness_session_binding_admission_ref: string | null;
  harness_session_launch: HypervisorHarnessSessionLaunchRecord | null;
  harness_session_launch_ref: string | null;
  harness_session_spawn: HypervisorHarnessSessionSpawnRecord | null;
  harness_session_spawn_ref: string | null;
  harness_session_readiness: HypervisorHarnessSessionReadinessRecord | null;
  harness_session_readiness_ref: string | null;
  harness_session_terminal_attach:
    | HypervisorHarnessSessionTerminalAttachRecord
    | null;
  harness_session_terminal_attach_ref: string | null;
  launch_summary: HypervisorNewSessionLaunchSummary;
  runtimeTruthSource: "daemon-runtime";
}

function safeLaunchId(value: string | number): string {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96) || "launch";
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function nullableStringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function stringArray(value: unknown, fallback: string[] = []): string[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is string =>
          typeof item === "string" && Boolean(item.trim()),
      )
    : fallback;
}

function normalizeSessionLaunchRecipeAdmission(
  value: unknown,
): HypervisorSessionLaunchRecipeAdmission {
  const record = recordValue(value);
  return {
    schema_version: "ioi.runtime.hypervisor_session_launch_recipe_admission.v1",
    admission_id: stringValue(
      record?.admission_id,
      "hypervisor-session-launch-recipe-admission:unknown",
    ),
    decision: "admitted",
    admission_state: "admitted_for_session_binding",
    recipe_ref: stringValue(record?.recipe_ref, "unknown"),
    recipe_kind: stringValue(
      record?.recipe_kind,
      "mission",
    ) as HypervisorSessionLaunchRecipe["kind"],
    surface_id: stringValue(
      record?.surface_id,
      "sessions",
    ) as HypervisorSurfaceId,
    target_binding_ref: stringValue(
      record?.target_binding_ref,
      "target-binding:unknown",
    ),
    project_ref: stringValue(record?.project_ref, "project:unknown"),
    operator_intent_ref: nullableStringValue(record?.operator_intent_ref),
    session_route_ref: stringValue(
      record?.session_route_ref,
      "session-route:unknown",
    ),
    code_editor_adapter_target_ref: nullableStringValue(
      record?.code_editor_adapter_target_ref,
    ),
    model_route_ref: stringValue(
      record?.model_route_ref,
      "model-route:unknown",
    ),
    privacy_posture_ref: stringValue(
      record?.privacy_posture_ref,
      "privacy:unknown",
    ),
    authority_scope_refs: stringArray(record?.authority_scope_refs),
    receipt_preview_ref: stringValue(
      record?.receipt_preview_ref,
      "receipt-preview:unknown",
    ),
    expected_receipt_refs: stringArray(record?.expected_receipt_refs),
    agentgres_operation_refs: stringArray(record?.agentgres_operation_refs),
    receipt_refs: stringArray(record?.receipt_refs),
    state_root: nullableStringValue(record?.state_root),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: stringValue(record?.admitted_at, new Date().toISOString()),
  };
}

export function buildHypervisorSessionLaunchRecipeAdmissionRequest({
  recipe,
  launchSummary,
}: {
  recipe: HypervisorSessionLaunchRecipe;
  launchSummary: HypervisorNewSessionLaunchSummary;
}): HypervisorSessionLaunchRecipeAdmissionRequest {
  const targetBindingRef = launchSummary.target_binding.target_binding_ref;
  const recipeSlug = safeLaunchId(targetBindingRef);
  return {
    schema_version:
      "ioi.hypervisor.session_launch_recipe_admission_request.v1",
    recipe,
    target_binding: launchSummary.target_binding,
    model_route_ref: launchSummary.model_route_ref,
    privacy_posture_ref: launchSummary.privacy_posture_ref,
    authority_scope_refs: [...launchSummary.authority_scope_refs],
    receipt_preview_ref: launchSummary.receipt_preview_ref,
    expected_receipt_refs: [
      ...launchSummary.harness_session_binding.expected_receipt_refs,
    ],
    agentgres_operation_refs: [
      `agentgres://operation/hypervisor/session-launch-recipe/${recipeSlug}`,
    ],
    receipt_refs: [
      `receipt://hypervisor/session-launch-recipe/${recipeSlug}`,
    ],
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function requestHypervisorSessionLaunchRecipeAdmission(
  request: HypervisorSessionLaunchRecipeAdmissionRequest,
  options: {
    endpoint?: string;
    fetchImpl?: typeof fetch;
  } = {},
): Promise<HypervisorSessionLaunchRecipeAdmission> {
  const endpoint =
    options.endpoint ?? readHypervisorHarnessPublicFixtureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error(
      "fetch unavailable for Hypervisor session launch recipe admission",
    );
  }
  const url = `${endpoint.replace(
    /\/+$/,
    "",
  )}${HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_PATH}`;
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify(request),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new HypervisorSessionLaunchRecipeAdmissionError({
      endpoint: url,
      responseBody: text,
      status: response.status,
    });
  }
  return normalizeSessionLaunchRecipeAdmission(text ? JSON.parse(text) : {});
}

function buildHypervisorNewSessionTargetBinding({
  recipe,
  seedIntent,
  projectId,
  codeEditorAdapter,
}: {
  recipe: HypervisorSessionLaunchRecipe;
  seedIntent: string | null;
  projectId: string;
  codeEditorAdapter: CodeEditorAdapterPreference;
}): HypervisorNewSessionTargetBinding {
  const recipeSlug = safeLaunchId(recipe.recipe_id);
  const projectSlug = safeLaunchId(projectId);
  const targetBindingRef = `target-binding:new-session/${recipeSlug}/${projectSlug}`;
  const operatorIntentRef = seedIntent
    ? `${targetBindingRef}/operator-intent`
    : null;
  const sessionRouteRef = `session-route:${recipe.surface_id}/${recipeSlug}/${projectSlug}`;

  return {
    schema_version: "ioi.hypervisor.new_session_target_binding.v1",
    target_binding_ref: targetBindingRef,
    recipe_ref: recipe.recipe_id,
    target_kind: recipe.kind,
    surface_id: recipe.surface_id,
    project_ref: projectId,
    operator_intent_ref: operatorIntentRef,
    session_route_ref: sessionRouteRef,
    code_editor_adapter_target_ref:
      recipe.kind === "workbench" ? codeEditorAdapter.target_ref : null,
    automation_recipe_ref:
      recipe.kind === "automation"
        ? `automation-recipe:${recipeSlug}/${projectSlug}`
        : null,
    agent_template_ref:
      recipe.kind === "agent" ? `agent-template:${recipeSlug}/${projectSlug}` : null,
    foundry_job_ref:
      recipe.kind === "foundry_job"
        ? `foundry-job:${recipeSlug}/${projectSlug}`
        : null,
    provider_candidate_ref:
      recipe.kind === "provider_environment_job"
        ? `provider-candidate:${recipeSlug}/${projectSlug}`
        : null,
    environment_ref:
      recipe.kind === "provider_environment_job"
        ? `environment:${recipeSlug}/${projectSlug}`
        : null,
    private_workspace_ref:
      recipe.kind === "privacy_workspace"
        ? `private-workspace:${recipeSlug}/${projectSlug}`
        : null,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorLaunchedSessionProjection({
  request,
  recipe,
  projectLabel,
  launchedAtMs = Date.now(),
  codeEditorAdapterAdmission = null,
  sessionLaunchRecipeAdmission = null,
  harnessSessionBindingAdmission = null,
  harnessSessionLaunch = null,
  harnessSessionSpawn = null,
  harnessSessionReadiness = null,
  harnessSessionTerminalAttach = null,
  displayMeta = {},
}: {
  request: HypervisorNewSessionLaunchRequest;
  recipe: HypervisorSessionLaunchRecipe;
  projectLabel: string;
  launchedAtMs?: number;
  codeEditorAdapterAdmission?: HypervisorCodeEditorAdapterLaunchAdmissionRecord | null;
  sessionLaunchRecipeAdmission?: HypervisorSessionLaunchRecipeAdmissionRecord | null;
  harnessSessionBindingAdmission?: HypervisorHarnessSessionBindingAdmissionRecord | null;
  harnessSessionLaunch?: HypervisorHarnessSessionLaunchRecord | null;
  harnessSessionSpawn?: HypervisorHarnessSessionSpawnRecord | null;
  harnessSessionReadiness?: HypervisorHarnessSessionReadinessRecord | null;
  harnessSessionTerminalAttach?:
    | HypervisorHarnessSessionTerminalAttachRecord
    | null;
  displayMeta?: {
    branchLabel?: string | null;
    relativeTimeLabel?: string | null;
    activityCount?: number | null;
  };
}): HypervisorLaunchedSessionProjection {
  const routeId = [
    safeLaunchId(recipe.kind),
    safeLaunchId(request.project_id),
    safeLaunchId(request.recipe_id),
    safeLaunchId(launchedAtMs),
  ].join("/");
  const admissionDecisions = [
    codeEditorAdapterAdmission?.decision,
    sessionLaunchRecipeAdmission?.decision,
    harnessSessionBindingAdmission?.decision,
    harnessSessionLaunch?.decision,
    harnessSessionSpawn?.decision,
    harnessSessionReadiness?.decision,
    harnessSessionTerminalAttach?.decision,
  ];
  const admissionState =
    admissionDecisions.includes("blocked")
      ? "daemon_blocked"
      : admissionDecisions.includes("daemon_unavailable")
        ? "daemon_unavailable"
        : admissionDecisions.every(
              (decision) => decision === "admitted" || decision === "ready",
            ) && harnessSessionReadiness?.decision === "ready"
              && harnessSessionTerminalAttach?.decision === "admitted"
          ? "daemon_admitted"
          : "pending_daemon_admission";
  return {
    schema_version: "ioi.hypervisor.launched_session_projection.v1",
    session_ref: `session:launch/${routeId}`,
    launch_receipt_ref: `receipt://hypervisor/new-session/${routeId}`,
    recipe_ref: request.recipe_id,
    recipe_kind: recipe.kind,
    surface_id: recipe.surface_id,
    project_ref: request.project_id,
    project_label: projectLabel,
    launched_at_ms: launchedAtMs,
    branch_label: displayMeta.branchLabel ?? null,
    relative_time_label: displayMeta.relativeTimeLabel ?? null,
    activity_count: displayMeta.activityCount ?? null,
    admission_state: admissionState,
    code_editor_adapter_admission: codeEditorAdapterAdmission,
    code_editor_adapter_admission_ref:
      codeEditorAdapterAdmission?.admission_id ?? null,
    session_launch_recipe_admission: sessionLaunchRecipeAdmission,
    session_launch_recipe_admission_ref:
      sessionLaunchRecipeAdmission?.admission_id ?? null,
    harness_session_binding_ref:
      request.launch_summary.harness_session_binding_ref,
    harness_session_binding: request.launch_summary.harness_session_binding,
    harness_session_binding_admission: harnessSessionBindingAdmission,
    harness_session_binding_admission_ref:
      harnessSessionBindingAdmission?.admission_id ?? null,
    harness_session_launch: harnessSessionLaunch ?? null,
    harness_session_launch_ref:
      harnessSessionLaunch && "launch_id" in harnessSessionLaunch
        ? harnessSessionLaunch.launch_id
        : null,
    harness_session_spawn: harnessSessionSpawn ?? null,
    harness_session_spawn_ref:
      harnessSessionSpawn && "spawn_id" in harnessSessionSpawn
        ? harnessSessionSpawn.spawn_id
        : null,
    harness_session_readiness: harnessSessionReadiness ?? null,
    harness_session_readiness_ref:
      harnessSessionReadiness && "readiness_id" in harnessSessionReadiness
        ? harnessSessionReadiness.readiness_id
        : null,
    harness_session_terminal_attach: harnessSessionTerminalAttach ?? null,
    harness_session_terminal_attach_ref:
      harnessSessionTerminalAttach && "attach_id" in harnessSessionTerminalAttach
        ? harnessSessionTerminalAttach.attach_id
        : null,
    launch_summary: request.launch_summary,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorSessionLaunchRecipeAdmissionFailure({
  request,
  error,
}: {
  request: HypervisorSessionLaunchRecipeAdmissionRequest;
  error: unknown;
}): HypervisorSessionLaunchRecipeAdmissionFailure {
  const httpStatus =
    error instanceof HypervisorSessionLaunchRecipeAdmissionError
      ? error.status
      : null;
  return {
    schema_version: "ioi.hypervisor.session_launch_recipe_admission_failure.v1",
    admission_id: `${request.target_binding.target_binding_ref}/recipe-admission-failure`,
    recipe_ref: request.recipe.recipe_id,
    target_binding_ref: request.target_binding.target_binding_ref,
    session_route_ref: request.target_binding.session_route_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorCodeEditorAdapterAdmissionFailure({
  error,
  launchPlan,
}: {
  error: unknown;
  launchPlan: CodeEditorAdapterLaunchPlan;
}): HypervisorCodeEditorAdapterLaunchAdmissionFailure {
  const httpStatus =
    error instanceof CodeEditorAdapterLaunchAdmissionError ? error.status : null;
  return {
    schema_version: "ioi.hypervisor.code_editor_adapter_launch_admission_failure.v1",
    admission_id: `${launchPlan.launch_plan_ref}/admission-failure`,
    launch_plan_ref: launchPlan.launch_plan_ref,
    adapter_ref: launchPlan.adapter_ref,
    target_ref: launchPlan.target_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorHarnessSessionBindingAdmissionFailure({
  binding,
  error,
}: {
  binding: HypervisorHarnessSessionBinding;
  error: unknown;
}): HypervisorHarnessSessionBindingAdmissionFailure {
  const httpStatus =
    error instanceof HarnessSessionBindingAdmissionError ? error.status : null;
  return {
    schema_version: "ioi.hypervisor.harness_session_binding_admission_failure.v1",
    admission_id: `${binding.session_binding_ref}/admission-failure`,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorHarnessSessionLaunchFailure({
  binding,
  bindingAdmission,
  error,
}: {
  binding: HypervisorHarnessSessionBinding;
  bindingAdmission?: HypervisorHarnessSessionBindingAdmissionRecord | null;
  error: unknown;
}): HypervisorHarnessSessionLaunchFailure {
  const httpStatus =
    error instanceof HarnessSessionLaunchError ? error.status : null;
  const bindingAdmissionId =
    bindingAdmission && "admission_id" in bindingAdmission
      ? bindingAdmission.admission_id
      : null;
  return {
    schema_version: "ioi.hypervisor.harness_session_launch_failure.v1",
    launch_id: `${binding.session_binding_ref}/launch-failure`,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    binding_admission_id: bindingAdmissionId,
    harness_selection_ref: binding.harness_selection_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorHarnessSessionSpawnFailure({
  binding,
  sessionLaunch,
  error,
}: {
  binding: HypervisorHarnessSessionBinding;
  sessionLaunch?: HypervisorHarnessSessionLaunchRecord | null;
  error: unknown;
}): HypervisorHarnessSessionSpawnFailure {
  const httpStatus =
    error instanceof HarnessSessionSpawnError ? error.status : null;
  const launchId =
    sessionLaunch && "launch_id" in sessionLaunch
      ? sessionLaunch.launch_id
      : null;
  return {
    schema_version: "ioi.hypervisor.harness_session_spawn_failure.v1",
    spawn_id: `${binding.session_binding_ref}/spawn-failure`,
    launch_id: launchId,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorHarnessSessionReadinessFailure({
  binding,
  sessionSpawn,
  error,
}: {
  binding: HypervisorHarnessSessionBinding;
  sessionSpawn?: HypervisorHarnessSessionSpawnRecord | null;
  error: unknown;
}): HypervisorHarnessSessionReadinessFailure {
  const httpStatus =
    error instanceof HarnessSessionReadinessError ? error.status : null;
  const spawnId =
    sessionSpawn && "spawn_id" in sessionSpawn ? sessionSpawn.spawn_id : null;
  const launchId =
    sessionSpawn && "launch_id" in sessionSpawn ? sessionSpawn.launch_id : null;
  return {
    schema_version: "ioi.hypervisor.harness_session_readiness_failure.v1",
    readiness_id: `${binding.session_binding_ref}/readiness-failure`,
    spawn_id: spawnId,
    launch_id: launchId,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    readiness_state:
      typeof httpStatus === "number" && httpStatus < 500
        ? "host_readiness_blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorHarnessSessionTerminalAttachFailure({
  binding,
  sessionSpawn,
  sessionReadiness,
  error,
}: {
  binding: HypervisorHarnessSessionBinding;
  sessionSpawn?: HypervisorHarnessSessionSpawnRecord | null;
  sessionReadiness?: HypervisorHarnessSessionReadinessRecord | null;
  error: unknown;
}): HypervisorHarnessSessionTerminalAttachFailure {
  const httpStatus =
    error instanceof HarnessSessionTerminalAttachError ? error.status : null;
  const spawnId =
    sessionSpawn && "spawn_id" in sessionSpawn ? sessionSpawn.spawn_id : null;
  const launchId =
    sessionSpawn && "launch_id" in sessionSpawn ? sessionSpawn.launch_id : null;
  const readinessId =
    sessionReadiness && "readiness_id" in sessionReadiness
      ? sessionReadiness.readiness_id
      : null;
  return {
    schema_version:
      "ioi.hypervisor.harness_session_terminal_attach_failure.v1",
    attach_id: `${binding.session_binding_ref}/terminal-attach-failure`,
    spawn_id: spawnId,
    readiness_id: readinessId,
    launch_id: launchId,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    decision:
      typeof httpStatus === "number" && httpStatus < 500
        ? "blocked"
        : "daemon_unavailable",
    attach_state:
      typeof httpStatus === "number" && httpStatus < 500
        ? "attach_blocked"
        : "daemon_unavailable",
    error_message: error instanceof Error ? error.message : String(error),
    http_status: httpStatus,
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorNewSessionLaunchSummary({
  recipe,
  seedIntent = null,
  projectId,
  codeEditorAdapter,
  harness,
  harnessVerdict,
  modelRouteAvailability,
  modelRouteRef,
  privacyPostureRef,
  authorityScopeRefs,
  receiptPreviewRef,
}: {
  recipe: HypervisorSessionLaunchRecipe;
  seedIntent?: string | null;
  projectId: string;
  codeEditorAdapter: CodeEditorAdapterPreference;
  harness: HypervisorHarnessSelectionOption;
  harnessVerdict: HarnessCompatibilityVerdict;
  modelRouteAvailability: HypervisorModelRouteAvailability;
  modelRouteRef: string;
  privacyPostureRef: string;
  authorityScopeRefs: string[];
  receiptPreviewRef: string;
}): HypervisorNewSessionLaunchSummary {
  const adapterLaunchPlan = buildCodeEditorAdapterLaunchPlan(codeEditorAdapter);
  const normalizedSeedIntent = seedIntent?.trim() || null;
  const targetBinding = buildHypervisorNewSessionTargetBinding({
    recipe,
    seedIntent: normalizedSeedIntent,
    projectId,
    codeEditorAdapter,
  });
  const harnessSessionBinding = buildHypervisorHarnessSessionBinding({
    sessionRouteRef: targetBinding.session_route_ref,
    harness,
    modelRouteAvailability,
    modelRouteRef,
    privacyPostureRef,
    authorityScopeRefs,
    receiptPreviewRef,
  });
  return {
    schema_version: "ioi.hypervisor.new_session_launch_summary.v1",
    recipe_ref: recipe.recipe_id,
    seed_intent: normalizedSeedIntent,
    target_binding_ref: targetBinding.target_binding_ref,
    target_binding: targetBinding,
    project_ref: projectId,
    code_editor_adapter_ref: getCodeEditorAdapterPreferenceRef(codeEditorAdapter),
    code_editor_adapter_target_ref: codeEditorAdapter.target_ref,
    code_editor_adapter_custody_posture: codeEditorAdapter.custody_posture,
    code_editor_adapter_launch_plan_ref: adapterLaunchPlan.launch_plan_ref,
    code_editor_adapter_connection_contract_ref:
      adapterLaunchPlan.connection_contract_ref,
    code_editor_adapter_executor_lane: adapterLaunchPlan.executor_lane,
    code_editor_adapter_control_action: adapterLaunchPlan.control_action,
    code_editor_adapter_control_channel_ref: adapterLaunchPlan.control_channel_ref,
    code_editor_adapter_access_lease_refs:
      adapterLaunchPlan.required_access_lease_refs,
    code_editor_adapter_authority_scope_refs:
      adapterLaunchPlan.required_authority_scope_refs,
    code_editor_adapter_receipt_refs: adapterLaunchPlan.required_receipt_refs,
    harness_selection_ref: getHarnessSelectionRef(harness),
    harness_selection_kind: harness.selection_kind,
    harness_label: harness.label,
    harness_runtime_truth_source: harness.runtimeTruthSource,
    harness_truth_boundary:
      harness.selection_kind === "harness_profile"
        ? "daemon-owned"
        : harness.truth_boundary,
    harness_verdict_state: harnessVerdict.state,
    harness_session_binding_ref: harnessSessionBinding.session_binding_ref,
    harness_session_binding: harnessSessionBinding,
    model_route_ref: modelRouteRef,
    model_route_availability_state: modelRouteAvailability.state,
    model_route_available: modelRouteAvailability.available,
    model_route_endpoint_refs: modelRouteAvailability.endpoint_refs,
    privacy_posture_ref: privacyPostureRef,
    authority_scope_refs: authorityScopeRefs,
    receipt_preview_ref: receiptPreviewRef,
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

export const HYPERVISOR_PRIMARY_ACTION: HypervisorShellAction = {
  id: "new_session",
  label: "New Session",
  description:
    "Launch a governed mission, workbench, agent, automation, foundry, provider, environment, or private workspace session.",
};

export const HYPERVISOR_NEW_SESSION_SETUP_MODEL: HypervisorNewSessionSetupModel =
  {
    action: HYPERVISOR_PRIMARY_ACTION,
    sections: [
      {
        id: "intent",
        label: "Intent",
        description: "Goal, acceptance criteria, task type, and operator notes.",
        required: true,
      },
      {
        id: "project",
        label: "Project",
        description: "Workspace/project root, state refs, and restore posture.",
        required: true,
      },
      {
        id: "adapter_preference",
        label: "Adapter",
        description:
          "Embedded, desktop, or browser-based code editor target mediated by Workbench.",
        required: true,
      },
      {
        id: "harness",
        label: "Harness",
        description:
          "Default Harness Profile or governed AgentHarnessAdapter.",
        required: true,
      },
      {
        id: "model_route",
        label: "Model Route",
        description: "Hypervisor model mount, adapter-native route, or provider-trust route.",
        required: true,
      },
      {
        id: "privacy_posture",
        label: "Privacy",
        description: "Public trunk, redacted projection, cTEE private workspace, or explicit unsafe mount.",
        required: true,
      },
      {
        id: "authority",
        label: "Authority",
        description: "wallet.network scopes, approvals, leases, and connector capabilities.",
        required: true,
      },
      {
        id: "receipt_preview",
        label: "Receipt Preview",
        description: "Expected receipt, Agentgres operation, artifact, and replay refs.",
        required: false,
      },
    ],
    harnessOptions: HYPERVISOR_HARNESS_SELECTION_OPTIONS,
    runtimeTruthSource: "daemon-runtime",
  };

export const HYPERVISOR_SESSION_LAUNCH_RECIPES: HypervisorSessionLaunchRecipe[] =
  [
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "mission.default",
      label: "Mission",
      description:
        "Intent-to-outcome session with acceptance criteria, blockers, receipts, and operator review.",
      kind: "mission",
      surface_id: "sessions",
      required_inputs: ["intent", "project", "harness", "model_route", "authority"],
      model_mount_policy: "select",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:workspace.read", "scope:receipt.write"],
      privacy_posture_templates: ["ctee_private_workspace", "redacted_projection"],
    },
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "workbench.default",
      label: "Workbench",
      description:
        "Governed code/systems session that opens the selected code editor adapter.",
      kind: "workbench",
      surface_id: "workbench",
      required_inputs: [
        "project",
        "adapter_preference",
        "harness",
        "model_route",
        "privacy_posture",
      ],
      model_mount_policy: "inherit",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:workspace.read", "scope:workspace.patch"],
      privacy_posture_templates: ["public_trunk", "redacted_projection"],
    },
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "agent.default",
      label: "Agent",
      description:
        "Persistent worker session with skills, memory, capability leases, and revocation posture.",
      kind: "agent",
      surface_id: "agents",
      required_inputs: ["intent", "project", "harness", "authority"],
      model_mount_policy: "select",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:agent.run", "scope:capability.lease"],
      privacy_posture_templates: ["ctee_private_workspace", "redacted_projection"],
    },
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "automation.default",
      label: "Automation",
      description:
        "Workflow compositor session for templates, graph execution, schedules, and reusable recipes.",
      kind: "automation",
      surface_id: "automations",
      required_inputs: ["intent", "project", "harness", "receipt_preview"],
      model_mount_policy: "inherit",
      harness_profile_policy: "default",
      authority_scope_templates: ["scope:workflow.compose", "scope:receipt.write"],
      privacy_posture_templates: ["public_trunk", "redacted_projection"],
    },
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "foundry.eval",
      label: "Foundry Job",
      description:
        "Eval, benchmark, training, distillation, or promotion job with scorecard evidence.",
      kind: "foundry_job",
      surface_id: "foundry",
      required_inputs: ["project", "harness", "model_route", "receipt_preview"],
      model_mount_policy: "select",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:eval.run", "scope:artifact.write"],
      privacy_posture_templates: ["public_trunk", "redacted_projection"],
    },
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "environment.provider",
      label: "Provider / Environment Job",
      description:
        "Provider, VM, node, port, service, or zero-to-idle infrastructure session.",
      kind: "provider_environment_job",
      surface_id: "environments",
      required_inputs: ["project", "authority", "privacy_posture", "receipt_preview"],
      model_mount_policy: "forbidden",
      harness_profile_policy: "external_adapter",
      authority_scope_templates: ["scope:cloud.deploy", "scope:provider.spend"],
      privacy_posture_templates: ["redacted_projection", "ctee_private_workspace"],
    },
    {
      schema_version: "ioi.hypervisor.session_launch_recipe.v1",
      recipe_id: "privacy.workspace",
      label: "Private Workspace",
      description:
        "cTEE-backed workspace session for encrypted refs, custody state, and declassification review.",
      kind: "privacy_workspace",
      surface_id: "privacy",
      required_inputs: ["project", "privacy_posture", "authority", "receipt_preview"],
      model_mount_policy: "select",
      harness_profile_policy: "default",
      authority_scope_templates: ["scope:decrypt.view", "scope:declassify.request"],
      privacy_posture_templates: ["ctee_private_workspace"],
    },
  ];

export const HYPERVISOR_PRIMARY_SURFACES: HypervisorShellNavigationItem[] = [
  {
    id: "home",
    label: "Home",
    description: "Operator cockpit for active sessions, projects, and next actions.",
    kind: "core",
    railGroup: "primary",
    inspectorPanels: ["logs", "receipts"],
  },
  {
    id: "sessions",
    label: "Sessions",
    description: "Live governed workspaces and runs managed by Hypervisor.",
    kind: "core",
    railGroup: "primary",
    defaultSessionTab: "agent",
    inspectorPanels: ["changes", "authority", "privacy", "receipts"],
  },
  {
    id: "projects",
    label: "Projects",
    description: "Workspace files, repos, state roots, and restore posture.",
    kind: "core",
    railGroup: "primary",
    inspectorPanels: ["changes", "logs", "receipts"],
  },
  {
    id: "missions",
    label: "Missions",
    description: "Intent-to-outcome work with acceptance, budget, and blockers.",
    kind: "application",
    railGroup: "applications",
    defaultSessionTab: "agent",
    inspectorPanels: ["tasks", "authority", "receipts"],
  },
  {
    id: "workbench",
    label: "Workbench",
    description:
      "Code and systems surface; embedded, desktop, and browser code editors are adapter targets.",
    kind: "application",
    railGroup: "applications",
    defaultSessionTab: "code",
    inspectorPanels: ["changes", "ports_services", "terminal", "model_harness_provider"],
    adapterTargets: HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.map(
      (preference) => preference.label,
    ),
  },
  {
    id: "automations",
    label: "Automations",
    description: "Workflow compositor for templates, graphs, schedules, and reusable runs.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["tasks", "logs", "receipts"],
  },
  {
    id: "insights",
    label: "Insights",
    description: "Application surfaces, run history, traces, receipts, and improvement signals.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["logs", "receipts"],
  },
  {
    id: "agents",
    label: "Agents",
    description: "Agent identities, harness adapters, capabilities, memory, and skills.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["authority", "privacy", "model_harness_provider"],
  },
  {
    id: "models",
    label: "Models",
    description: "Model routes, mounts, providers, local models, and inference posture.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["model_harness_provider", "privacy", "receipts"],
  },
  {
    id: "privacy",
    label: "Privacy",
    description: "Private workspace, cTEE posture, declassification, and custody state.",
    kind: "governance",
    railGroup: "governance",
    inspectorPanels: ["privacy", "authority", "receipts"],
  },
  {
    id: "providers",
    label: "Providers",
    description: "Direct integrations for local, cloud, DePIN, customer cloud, and model providers.",
    kind: "infrastructure",
    railGroup: "governance",
    inspectorPanels: ["authority", "privacy", "receipts"],
  },
  {
    id: "environments",
    label: "Environments",
    description: "Managed sessions, VMs, nodes, ports, services, tasks, and restore posture.",
    kind: "infrastructure",
    railGroup: "governance",
    inspectorPanels: ["ports_services", "logs", "receipts"],
  },
  {
    id: "foundry",
    label: "Foundry",
    description: "Evals, training, distillation, benchmarks, and package promotion.",
    kind: "application",
    railGroup: "governance",
    inspectorPanels: ["tasks", "logs", "receipts"],
  },
  {
    id: "authority",
    label: "Authority",
    description: "wallet.network approvals, leases, scopes, policies, and capability exits.",
    kind: "governance",
    railGroup: "governance",
    inspectorPanels: ["authority", "receipts"],
  },
  {
    id: "receipts",
    label: "Receipts",
    description: "Receipt-backed audit, replay, state evidence, and delivery proof.",
    kind: "governance",
    railGroup: "governance",
    inspectorPanels: ["receipts", "logs"],
  },
  {
    id: "settings",
    label: "Settings",
    description: "Client preferences, adapters, tokens, defaults, and compatibility settings.",
    kind: "settings",
    railGroup: "bottom",
    inspectorPanels: ["model_harness_provider", "authority"],
  },
];

export const HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL = [
  "active",
  "pinned",
  "waiting_for_approval",
  "blocked",
  "completed",
] as const;

export const HYPERVISOR_SESSION_DETAIL_TABS: HypervisorSessionDetailTab[] = [
  "agent",
  "code",
  "environment",
  "changes",
  "receipts",
  "replay",
];

export const HYPERVISOR_SESSION_WORKSPACE_MODES = [
  {
    mode_id: "code",
    label: "Code",
    summary: "Adapter-backed workspace view for files, diffs, terminals, and patches.",
  },
] as const satisfies ReadonlyArray<{
  mode_id: HypervisorSessionWorkspaceMode;
  label: string;
  summary: string;
}>;

export const HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES = [
  {
    mode_id: "changes",
    label: "Changes",
    summary: "Uncommitted or proposed patches with receipt and policy evidence.",
  },
  {
    mode_id: "all_files",
    label: "All Files",
    summary: "Read-only project file projection from the current session scope.",
  },
  {
    mode_id: "comments",
    label: "Comments",
    summary: "Review comments, unresolved questions, and verifier notes.",
  },
] as const satisfies ReadonlyArray<{
  mode_id: HypervisorSessionChangeInspectorMode;
  label: string;
  summary: string;
}>;

export const HYPERVISOR_RIGHT_INSPECTOR_PANELS: HypervisorInspectorPanelId[] = [
  "changes",
  "authority",
  "privacy",
  "receipts",
  "model_harness_provider",
];

export const HYPERVISOR_BOTTOM_INSPECTOR_PANELS: HypervisorInspectorPanelId[] = [
  "ports_services",
  "tasks",
  "terminal",
  "logs",
];

export const HYPERVISOR_REFERENCE_LEFT_NAV_SURFACE_IDS = [
  "home",
  "projects",
  "automations",
  "insights",
  "sessions",
] as const satisfies readonly HypervisorSurfaceId[];

export const HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS: HypervisorIoiReferenceShellRequirements =
  {
    primaryReference: "internal-docs/reverse-engineering/ioi",
    sourceSurfaces: [
      "home",
      "workspaces",
      "automations",
      "insights",
      "ai",
      "projects",
      "settings",
      "logs",
      "session_detail",
      "editor",
    ],
    translatedHypervisorSurfaces: [
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
    ],
    leftNavSurfaceIds: HYPERVISOR_REFERENCE_LEFT_NAV_SURFACE_IDS,
    shellRegions: [
      "left_nav",
      "new_session",
      "session_rail",
      "main_surface",
      "session_detail_tabs",
      "right_inspector",
      "bottom_inspector",
      "settings",
    ],
    sessionDetailTabs: HYPERVISOR_SESSION_DETAIL_TABS,
    rightInspectorPanels: HYPERVISOR_RIGHT_INSPECTOR_PANELS,
    bottomInspectorPanels: HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
    settingsSections: [
      "identity",
      "secrets",
      "git_auth",
      "personal_access_tokens",
      "integrations",
    ],
    editorAdapterTargets: [
      ...HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.map(
        (preference) => preference.label,
      ),
      "Workspace substrate",
    ],
    agentHarnessAdapters: [
      "Codex CLI",
      "Claude Code",
      "DeepSeek TUI",
      "Grok Build",
      "Aider",
      "OpenHands",
      "generic CLI harness",
    ],
  };

export function getHypervisorSurfaceById(
  id: HypervisorSurfaceId,
): HypervisorShellNavigationItem {
  const surface = HYPERVISOR_PRIMARY_SURFACES.find((item) => item.id === id);
  if (!surface) {
    throw new Error(`Unknown Hypervisor surface: ${id}`);
  }
  return surface;
}

export function isHypervisorSurfaceId(
  value: string,
): value is HypervisorSurfaceId {
  return HYPERVISOR_PRIMARY_SURFACES.some((item) => item.id === value);
}
