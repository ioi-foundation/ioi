export type HarnessSelectionKind =
  | "harness_profile"
  | "agent_harness_adapter";

export type AgentHarnessAdapterId =
  | "codex_cli"
  | "codex_desktop_linux"
  | "claude_code_cli"
  | "grok_build_cli"
  | "deepseek_tui"
  | "aider_cli"
  | "openhands"
  | "shell_tmux_agent"
  | "generic_cli";

export type AgentHarnessAdapterKind =
  | "cli"
  | "desktop_example"
  | "containerized_cli"
  | "remote_harness"
  | "hosted_agent";

export type HarnessExecutionLane =
  | "host_dev"
  | "docker_container"
  | "podman_container"
  | "microvm_later"
  | "desktop_linux_example"
  | "remote_api";

export type HarnessModelRoutePolicy =
  | "hypervisor_model_mount"
  | "adapter_builtin"
  | "provider_trust"
  | "forbidden";

export type HarnessWorkspaceMountPolicy =
  | "public_trunk"
  | "redacted_projection"
  | "plain_workspace"
  | "ctee_private_workspace";

export type HarnessCompatibilityState =
  | "compatible"
  | "adapter_native_only"
  | "provider_trust"
  | "local_route_unavailable"
  | "blocked";

export interface HypervisorHarnessProfileOption {
  selection_kind: "harness_profile";
  profile_ref: "default_harness_profile";
  label: string;
  description: string;
  runtimeTruthSource: "daemon-runtime";
  role: "reference_scaffold_fallback";
  default_model_route_policy: Extract<
    HarnessModelRoutePolicy,
    "hypervisor_model_mount"
  >;
  default_workspace_mount_policy: Extract<
    HarnessWorkspaceMountPolicy,
    "public_trunk" | "redacted_projection" | "ctee_private_workspace"
  >;
}

export interface AgentHarnessAdapterProfile {
  selection_kind: "agent_harness_adapter";
  adapter_id: AgentHarnessAdapterId;
  label: string;
  description: string;
  adapter_kind: AgentHarnessAdapterKind;
  execution_lane: HarnessExecutionLane;
  model_route_policy: HarnessModelRoutePolicy;
  workspace_mount_policy: HarnessWorkspaceMountPolicy;
  required_authority_scopes: string[];
  receipt_policy_ref: string;
  runtimeTruthSource: "daemon-runtime";
  truth_boundary: "proposal_source_only";
}

export type HypervisorHarnessSelectionOption =
  | HypervisorHarnessProfileOption
  | AgentHarnessAdapterProfile;

export interface HarnessAdapterReceipt {
  schema_version: "ioi.hypervisor.harness_adapter_receipt.v1";
  receipt_id: string;
  selection_ref: string;
  execution_lane: HarnessExecutionLane;
  model_route_ref?: string;
  container_image_ref?: string;
  command_argv_hash?: string;
  workspace_mount_policy: HarnessWorkspaceMountPolicy;
  authority_scope_refs: string[];
  privacy_posture_ref: string;
  agentgres_operation_refs: string[];
  artifact_refs: string[];
  runtimeTruthSource: "daemon-runtime";
}

export interface HarnessComparisonRun {
  schema_version: "ioi.hypervisor.harness_comparison_run.v1";
  run_id: string;
  project_ref: string;
  task_ref: string;
  candidate_selection_refs: string[];
  selected_model_mount_ref?: string;
  comparison_mode: "same_task" | "same_fixture" | "benchmark" | "shadow";
  acceptance_criteria_refs: string[];
  candidate_reports: HarnessComparisonCandidateReport[];
  receipt_refs: string[];
  runtimeTruthSource: "daemon-runtime";
}

export interface HarnessComparisonCandidateReport {
  selection_ref: string;
  label: string;
  execution_lane: HarnessExecutionLane;
  output_summary: string;
  estimated_cost_usd: number;
  verification_status: "passed" | "requires_review" | "blocked";
  receipt_ref: string;
  evidence_refs: string[];
}

export type HypervisorModelMountInventorySource =
  | "daemon-model-mount-inventory"
  | "fixture"
  | "unverified";

export type HypervisorModelRouteAvailabilityState =
  | "daemon_verified"
  | "fixture_available"
  | "unverified"
  | "unavailable";

export interface HypervisorModelMountInventoryRoute {
  id: string;
  role?: string;
  status: "active" | "disabled" | "unknown";
  privacy?: string;
}

export interface HypervisorModelMountInventoryEndpoint {
  id: string;
  providerId?: string;
  modelId?: string;
  status: "mounted" | "unmounted" | "degraded" | "unknown";
  privacyClass?: string;
}

export interface HypervisorModelMountInventoryInstance {
  id: string;
  endpointId?: string;
  providerId?: string;
  modelId?: string;
  status: "loaded" | "unloaded" | "evicted" | "failed" | "unknown";
}

export interface HypervisorModelMountInventorySnapshot {
  schema_version: "ioi.hypervisor.model_mount_inventory_snapshot.v1";
  source: HypervisorModelMountInventorySource;
  checked_at?: string;
  routes: HypervisorModelMountInventoryRoute[];
  endpoints: HypervisorModelMountInventoryEndpoint[];
  loadedInstances: HypervisorModelMountInventoryInstance[];
}

export interface HypervisorModelRouteAvailability {
  model_route_ref: string;
  state: HypervisorModelRouteAvailabilityState;
  available: boolean;
  summary: string;
  route_refs: string[];
  endpoint_refs: string[];
  loaded_instance_refs: string[];
  requiresDaemonInventory: true;
}

export interface HarnessAdapterTestbedFixture {
  schema_version: "ioi.hypervisor.harness_adapter_testbed_fixture.v1";
  fixture_id: string;
  label: string;
  description: string;
  project_ref: string;
  task_ref: string;
  workspace_mount_policy: Extract<HarnessWorkspaceMountPolicy, "public_trunk">;
  candidate_selection_refs: string[];
  comparison_mode: Extract<HarnessComparisonRun["comparison_mode"], "same_fixture">;
  acceptance_criteria_refs: string[];
  expected_receipt_schema: HarnessAdapterReceipt["schema_version"];
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface HarnessPublicFixtureCandidateLane {
  adapter_id: AgentHarnessAdapterId;
  selection_ref: string;
  runtime: "docker" | "podman";
  container_image_ref: string;
}

export interface HarnessPublicFixtureRunRequest {
  source: "hypervisor_foundry.harness_comparison_dashboard";
  fixture_id: string;
  task_ref: string;
  min_installed_adapters: number;
  installed_adapter_ids: AgentHarnessAdapterId[];
  candidate_lanes: HarnessPublicFixtureCandidateLane[];
}

export interface HarnessCompatibilityVerdict {
  selection_ref: string;
  state: HarnessCompatibilityState;
  summary: string;
  requiresDaemonGate: true;
  privacyWarning?: string;
}

export const HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF =
  "model-route:hypervisor/default-local";
export const HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF =
  "privacy:ctee-private-workspace";
export const HYPERVISOR_HARNESS_PUBLIC_FIXTURE_RUN_PATH =
  "/v1/hypervisor/harness-public-fixture-runs";
export const HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";

export const HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE: HypervisorModelMountInventorySnapshot =
  {
    schema_version: "ioi.hypervisor.model_mount_inventory_snapshot.v1",
    source: "fixture",
    checked_at: "2026-06-17T00:00:00.000Z",
    routes: [
      {
        id: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
        role: "default-local",
        status: "active",
        privacy: "local",
      },
    ],
    endpoints: [
      {
        id: "model-endpoint:hypervisor/default-local",
        providerId: "provider:hypervisor-local",
        modelId: "model:local/default",
        status: "mounted",
        privacyClass: "local",
      },
    ],
    loadedInstances: [
      {
        id: "model-instance:hypervisor/default-local",
        endpointId: "model-endpoint:hypervisor/default-local",
        providerId: "provider:hypervisor-local",
        modelId: "model:local/default",
        status: "loaded",
      },
    ],
  };

export const DEFAULT_HARNESS_PROFILE_OPTION: HypervisorHarnessProfileOption = {
  selection_kind: "harness_profile",
  profile_ref: "default_harness_profile",
  label: "Default Harness Profile",
  description:
    "Reference scaffold and fallback HarnessProfile for governed sessions.",
  runtimeTruthSource: "daemon-runtime",
  role: "reference_scaffold_fallback",
  default_model_route_policy: "hypervisor_model_mount",
  default_workspace_mount_policy: "ctee_private_workspace",
};

export const HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES: AgentHarnessAdapterProfile[] =
  [
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "codex_cli",
      label: "Codex CLI",
      description:
        "Codex-style command harness mediated as a proposal source.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "adapter_builtin",
      workspace_mount_policy: "redacted_projection",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/default",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "codex_desktop_linux",
      label: "Codex Desktop Linux",
      description:
        "Desktop/client parity harness for computer-use experiments.",
      adapter_kind: "desktop_example",
      execution_lane: "desktop_linux_example",
      model_route_policy: "adapter_builtin",
      workspace_mount_policy: "public_trunk",
      required_authority_scopes: ["scope:workspace.read"],
      receipt_policy_ref: "receipt-policy:harness-adapter/desktop-example",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "claude_code_cli",
      label: "Claude Code CLI",
      description:
        "Claude Code-style external CLI harness; provider-native paths remain provider-trust lanes unless proven otherwise.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "provider_trust",
      workspace_mount_policy: "redacted_projection",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/provider-trust",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "grok_build_cli",
      label: "Grok Build CLI",
      description:
        "Grok Build-style external command harness; provider-native paths remain provider-trust lanes unless proven otherwise.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "provider_trust",
      workspace_mount_policy: "redacted_projection",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/provider-trust",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "deepseek_tui",
      label: "DeepSeek TUI",
      description:
        "Terminal harness candidate that may use OpenAI-compatible model routes when compatibility is proven.",
      adapter_kind: "containerized_cli",
      execution_lane: "docker_container",
      model_route_policy: "hypervisor_model_mount",
      workspace_mount_policy: "public_trunk",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/container",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "aider_cli",
      label: "Aider CLI",
      description:
        "Patch-oriented CLI harness adapter for public or redacted workspace projections.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "hypervisor_model_mount",
      workspace_mount_policy: "redacted_projection",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/default",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "openhands",
      label: "OpenHands",
      description:
        "Hosted or containerized agent harness adapter for public-trunk tasks and explicit provider-trust lanes.",
      adapter_kind: "remote_harness",
      execution_lane: "remote_api",
      model_route_policy: "provider_trust",
      workspace_mount_policy: "public_trunk",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/provider-trust",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "shell_tmux_agent",
      label: "Shell/tmux Agent",
      description:
        "Terminal or tmux-oriented agent loop with governed commands, mounts, network, and receipts.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "forbidden",
      workspace_mount_policy: "public_trunk",
      required_authority_scopes: ["scope:workspace.read"],
      receipt_policy_ref: "receipt-policy:harness-adapter/shell-tmux",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "generic_cli",
      label: "Generic CLI Harness",
      description:
        "Explicitly configured command harness adapter with governed argv, mounts, network, and receipts.",
      adapter_kind: "cli",
      execution_lane: "docker_container",
      model_route_policy: "forbidden",
      workspace_mount_policy: "public_trunk",
      required_authority_scopes: ["scope:workspace.read"],
      receipt_policy_ref: "receipt-policy:harness-adapter/generic-cli",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
  ];

export const HYPERVISOR_HARNESS_SELECTION_OPTIONS: HypervisorHarnessSelectionOption[] =
  [
    DEFAULT_HARNESS_PROFILE_OPTION,
    ...HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES,
  ];

export function getHarnessSelectionRef(
  option: HypervisorHarnessSelectionOption,
): string {
  return option.selection_kind === "harness_profile"
    ? `harness-profile:${option.profile_ref}`
    : `agent-harness-adapter:${option.adapter_id}`;
}

export function isAgentHarnessAdapterOption(
  option: HypervisorHarnessSelectionOption,
): option is AgentHarnessAdapterProfile {
  return option.selection_kind === "agent_harness_adapter";
}

function routeMatchesDefaultLocalModelMount(
  route: HypervisorModelMountInventoryRoute,
): boolean {
  return (
    route.id === HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF ||
    route.id === "hypervisor/default-local" ||
    route.role === "default-local"
  );
}

function endpointCanSatisfyLocalModelMount(
  endpoint: HypervisorModelMountInventoryEndpoint,
): boolean {
  if (endpoint.status !== "mounted" && endpoint.status !== "degraded") {
    return false;
  }
  const privacyClass = endpoint.privacyClass?.toLowerCase() ?? "";
  return (
    privacyClass.includes("local") ||
    privacyClass.includes("private") ||
    privacyClass.includes("hypervisor")
  );
}

function loadedInstanceCanSatisfyLocalModelMount(
  instance: HypervisorModelMountInventoryInstance,
): boolean {
  return instance.status === "loaded";
}

export function modelRouteSupportsHypervisorMountFromInventory(
  modelRouteRef: string,
  inventory?: HypervisorModelMountInventorySnapshot,
): HypervisorModelRouteAvailability {
  if (modelRouteRef !== HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF) {
    return {
      model_route_ref: modelRouteRef,
      state: "unavailable",
      available: false,
      summary:
        "Selected model route is not the Hypervisor default-local model mount.",
      route_refs: [],
      endpoint_refs: [],
      loaded_instance_refs: [],
      requiresDaemonInventory: true,
    };
  }

  if (!inventory || inventory.source === "unverified") {
    return {
      model_route_ref: modelRouteRef,
      state: "unverified",
      available: false,
      summary:
        "Hypervisor model mount inventory has not been verified.",
      route_refs: [],
      endpoint_refs: [],
      loaded_instance_refs: [],
      requiresDaemonInventory: true,
    };
  }

  const matchingRoutes = inventory.routes.filter(
    (route) =>
      route.status === "active" && routeMatchesDefaultLocalModelMount(route),
  );
  const mountedEndpoints = inventory.endpoints.filter(
    endpointCanSatisfyLocalModelMount,
  );
  const loadedInstances = inventory.loadedInstances.filter(
    loadedInstanceCanSatisfyLocalModelMount,
  );
  const hasMountedExecutionTarget =
    mountedEndpoints.length > 0 || loadedInstances.length > 0;
  const available = matchingRoutes.length > 0 && hasMountedExecutionTarget;

  if (!available) {
    const missingReason =
      matchingRoutes.length === 0
        ? "No active default-local model route was reported."
        : "Default-local route has no mounted endpoint or loaded instance.";
    return {
      model_route_ref: modelRouteRef,
      state: "unavailable",
      available: false,
      summary: missingReason,
      route_refs: matchingRoutes.map((route) => route.id),
      endpoint_refs: mountedEndpoints.map((endpoint) => endpoint.id),
      loaded_instance_refs: loadedInstances.map((instance) => instance.id),
      requiresDaemonInventory: true,
    };
  }

  return {
    model_route_ref: modelRouteRef,
    state:
      inventory.source === "daemon-model-mount-inventory"
        ? "daemon_verified"
        : "fixture_available",
    available: true,
    summary:
      inventory.source === "daemon-model-mount-inventory"
        ? "Model-mount inventory reports an active local route and mounted execution target."
        : "Fixture inventory reports the expected local route contract until live probing is injected.",
    route_refs: matchingRoutes.map((route) => route.id),
    endpoint_refs: mountedEndpoints.map((endpoint) => endpoint.id),
    loaded_instance_refs: loadedInstances.map((instance) => instance.id),
    requiresDaemonInventory: true,
  };
}

export function getHarnessSelectionOption(
  selectionRef: string,
): HypervisorHarnessSelectionOption {
  const option = HYPERVISOR_HARNESS_SELECTION_OPTIONS.find(
    (candidate) => getHarnessSelectionRef(candidate) === selectionRef,
  );
  if (!option) {
    throw new Error(`Unknown Hypervisor harness selection: ${selectionRef}`);
  }
  return option;
}

export function buildHarnessCompatibilityVerdict(
  option: HypervisorHarnessSelectionOption,
  modelMountAvailable: boolean,
  privacyPostureRef = "privacy:redacted-projection",
): HarnessCompatibilityVerdict {
  const selectionRef = getHarnessSelectionRef(option);

  if (option.selection_kind === "harness_profile") {
    return {
      selection_ref: selectionRef,
      state: modelMountAvailable ? "compatible" : "local_route_unavailable",
      summary: modelMountAvailable
        ? "Default Harness Profile can use the selected Hypervisor model mount."
        : "Default Harness Profile needs a verified Hypervisor model route before local execution.",
      requiresDaemonGate: true,
    };
  }

  if (privacyPostureRef === HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF) {
    return {
      selection_ref: selectionRef,
      state: "blocked",
      summary:
        "External harness adapters cannot mount or claim cTEE private workspace custody; choose a redacted/public projection or use the Default Harness Profile.",
      requiresDaemonGate: true,
      privacyWarning:
        "cTEE private workspace state stays behind Hypervisor custody unless an explicit private-workspace policy grants a compatible path.",
    };
  }

  if (option.model_route_policy === "provider_trust") {
    return {
      selection_ref: selectionRef,
      state: "provider_trust",
      summary:
        "Adapter-native model execution is a provider-trust lane and must be disclosed before launch.",
      requiresDaemonGate: true,
      privacyWarning:
        "Do not route protected workspace state into this adapter without a redacted projection or explicit unsafe-mount approval.",
    };
  }

  if (option.model_route_policy === "adapter_builtin") {
    return {
      selection_ref: selectionRef,
      state: "adapter_native_only",
      summary:
        "This adapter currently uses its native model path; Hypervisor must receipt the boundary and prevent silent local-route claims.",
      requiresDaemonGate: true,
    };
  }

  if (option.model_route_policy === "hypervisor_model_mount") {
    return {
      selection_ref: selectionRef,
      state: modelMountAvailable ? "compatible" : "local_route_unavailable",
      summary: modelMountAvailable
        ? "Adapter can use a verified Hypervisor model route."
        : "Local Hypervisor model route is unavailable; do not silently fall back to a provider lane.",
      requiresDaemonGate: true,
    };
  }

  return {
    selection_ref: selectionRef,
    state: "blocked",
    summary:
      "This generic adapter cannot claim a model route until an explicit route policy is configured.",
    requiresDaemonGate: true,
  };
}

export function buildHarnessAdapterReceiptDraft(
  option: HypervisorHarnessSelectionOption,
): HarnessAdapterReceipt {
  return {
    schema_version: "ioi.hypervisor.harness_adapter_receipt.v1",
    receipt_id: `receipt:draft:${getHarnessSelectionRef(option)}`,
    selection_ref: getHarnessSelectionRef(option),
    execution_lane:
      option.selection_kind === "harness_profile"
        ? "host_dev"
        : option.execution_lane,
    workspace_mount_policy:
      option.selection_kind === "harness_profile"
        ? option.default_workspace_mount_policy
        : option.workspace_mount_policy,
    authority_scope_refs:
      option.selection_kind === "harness_profile"
        ? ["scope:workspace.read", "scope:workspace.patch"]
        : option.required_authority_scopes,
    privacy_posture_ref: "privacy-posture:pending-review",
    agentgres_operation_refs: [],
    artifact_refs: [],
    runtimeTruthSource: "daemon-runtime",
  };
}

const HYPERVISOR_HARNESS_TESTBED_SELECTION_REFS =
  HYPERVISOR_HARNESS_SELECTION_OPTIONS.map((option) =>
    getHarnessSelectionRef(option),
  );

function harnessComparisonCandidateReport(
  option: HypervisorHarnessSelectionOption,
  index: number,
): HarnessComparisonCandidateReport {
  const selectionRef = getHarnessSelectionRef(option);
  const adapterLane =
    option.selection_kind === "agent_harness_adapter"
      ? option.execution_lane
      : "host_dev";
  const modelPolicy =
    option.selection_kind === "agent_harness_adapter"
      ? option.model_route_policy
      : option.default_model_route_policy;
  return {
    selection_ref: selectionRef,
    label: option.label,
    execution_lane: adapterLane,
    output_summary:
      option.selection_kind === "harness_profile"
        ? "Reference scaffold owns loop policy and governed model/tool routing."
        : `Adapter proposal source over ${adapterLane} with ${modelPolicy} model policy.`,
    estimated_cost_usd: Number((0.04 + index * 0.015).toFixed(3)),
    verification_status: index === 0 ? "passed" : "requires_review",
    receipt_ref: `receipt:draft:${selectionRef}`,
    evidence_refs: [
      "artifact://fixture/harness-comparison/public-code-edit-smoke",
      `agentgres://projection/harness-comparison/${option.selection_kind}`,
    ],
  };
}

export const HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE: HarnessAdapterTestbedFixture =
  {
    schema_version: "ioi.hypervisor.harness_adapter_testbed_fixture.v1",
    fixture_id: "harness-testbed:public-code-edit-smoke",
    label: "Public code edit smoke",
    description:
      "Non-sensitive fixture for comparing Default Harness Profile and external AgentHarnessAdapters.",
    project_ref: "project:fixture/public-workbench",
    task_ref: "task:fixture/public-code-edit-smoke",
    workspace_mount_policy: "public_trunk",
    candidate_selection_refs: HYPERVISOR_HARNESS_TESTBED_SELECTION_REFS,
    comparison_mode: "same_fixture",
    acceptance_criteria_refs: [
      "acceptance:patch-applies",
      "acceptance:tests-pass",
      "acceptance:receipt-produced",
    ],
    expected_receipt_schema: "ioi.hypervisor.harness_adapter_receipt.v1",
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };

export const HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE: HarnessComparisonRun = {
  schema_version: "ioi.hypervisor.harness_comparison_run.v1",
  run_id: "harness-comparison:public-code-edit-smoke",
  project_ref: HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.project_ref,
  task_ref: HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.task_ref,
  candidate_selection_refs:
    HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.candidate_selection_refs,
  comparison_mode: HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.comparison_mode,
  acceptance_criteria_refs:
    HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.acceptance_criteria_refs,
  candidate_reports: HYPERVISOR_HARNESS_SELECTION_OPTIONS.map(
    harnessComparisonCandidateReport,
  ),
  receipt_refs: HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.candidate_selection_refs.map(
    (selectionRef) => `receipt:draft:${selectionRef}`,
  ),
  runtimeTruthSource: "daemon-runtime",
};

type HarnessFetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface RequestHarnessPublicFixtureRunOptions {
  endpoint?: string;
  fetchImpl?: HarnessFetchLike;
  request?: HarnessPublicFixtureRunRequest;
}

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const values = value
    .filter(
      (item): item is string =>
        typeof item === "string" && item.trim().length > 0,
    )
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
}

function enumValue<T extends string>(
  value: unknown,
  fallback: T,
  allowed: readonly T[],
): T {
  return typeof value === "string" && allowed.includes(value as T)
    ? (value as T)
    : fallback;
}

function maybeHarnessSelectionOption(
  selectionRef: string,
): HypervisorHarnessSelectionOption | undefined {
  return HYPERVISOR_HARNESS_SELECTION_OPTIONS.find(
    (candidate) => getHarnessSelectionRef(candidate) === selectionRef,
  );
}

function containerFixtureAdapterProfiles(): AgentHarnessAdapterProfile[] {
  return HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.filter(
    (profile) =>
      profile.adapter_id === "deepseek_tui" ||
      profile.adapter_id === "generic_cli",
  );
}

function containerRuntimeForLane(
  lane: HarnessExecutionLane,
): HarnessPublicFixtureCandidateLane["runtime"] {
  return lane === "podman_container" ? "podman" : "docker";
}

function containerImageRefForAdapter(adapterId: AgentHarnessAdapterId): string {
  return `container-image:${adapterId.replace(/_/g, "-")}:local`;
}

export function buildHarnessPublicFixtureRunRequest(): HarnessPublicFixtureRunRequest {
  const containerProfiles = containerFixtureAdapterProfiles();
  return {
    source: "hypervisor_foundry.harness_comparison_dashboard",
    fixture_id: "harness-testbed:public-code-edit-fixture",
    task_ref: "task:fixture/public-code-edit-fixture",
    min_installed_adapters: 2,
    installed_adapter_ids: containerProfiles.map(
      (profile) => profile.adapter_id,
    ),
    candidate_lanes: containerProfiles.map((profile) => ({
      adapter_id: profile.adapter_id,
      selection_ref: getHarnessSelectionRef(profile),
      runtime: containerRuntimeForLane(profile.execution_lane),
      container_image_ref: containerImageRefForAdapter(profile.adapter_id),
    })),
  };
}

function harnessComparisonCandidateReportFromAttempt(
  attempt: Record<string, unknown>,
  index: number,
): HarnessComparisonCandidateReport {
  const fallback =
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_reports[index] ??
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_reports[0]!;
  const selectionRef = stringValue(
    attempt.selection_ref,
    fallback.selection_ref,
  );
  const option = maybeHarnessSelectionOption(selectionRef);
  const exitStatus = enumValue(
    attempt.exit_status,
    "not_executed",
    ["success", "failure", "not_executed"],
  );
  const receipt = objectRecord(attempt.receipt);
  const agentgresRefs = stringList(receipt.agentgres_operation_refs, []);
  const artifactRefs = stringList(receipt.artifact_refs, []);
  const commandHash = stringValue(attempt.command_argv_hash, "command hash pending");
  return {
    selection_ref: selectionRef,
    label:
      option?.label ??
      stringValue(attempt.adapter_id, fallback.label).split("_").join(" "),
    execution_lane:
      option?.selection_kind === "agent_harness_adapter"
        ? option.execution_lane
        : fallback.execution_lane,
    output_summary:
      exitStatus === "success"
        ? `Fixture completed under ${commandHash}.`
        : exitStatus === "failure"
          ? `Fixture failed under ${commandHash}.`
          : `Fixture planned under ${commandHash}; executor not mounted.`,
    estimated_cost_usd: numberValue(
      attempt.estimated_cost_usd,
      Number((0.01 + index * 0.005).toFixed(3)),
    ),
    verification_status:
      exitStatus === "success"
        ? "passed"
        : exitStatus === "failure"
          ? "blocked"
          : "requires_review",
    receipt_ref: stringValue(attempt.receipt_id, fallback.receipt_ref),
    evidence_refs:
      [...agentgresRefs, ...artifactRefs].length > 0
        ? [...agentgresRefs, ...artifactRefs]
        : fallback.evidence_refs,
  };
}

export function normalizeHarnessComparisonRunFromPublicFixtureRun(
  response: unknown,
): HarnessComparisonRun {
  const value = objectRecord(response);
  const fallback = HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE;
  const attempts = arrayRecords(value.attempts);
  const candidateReports = attempts.map(harnessComparisonCandidateReportFromAttempt);
  return {
    schema_version: "ioi.hypervisor.harness_comparison_run.v1",
    run_id: stringValue(value.run_id, fallback.run_id),
    project_ref: fallback.project_ref,
    task_ref: stringValue(value.task_ref, fallback.task_ref),
    candidate_selection_refs: stringList(
      value.candidate_selection_refs,
      fallback.candidate_selection_refs,
    ),
    comparison_mode: "same_fixture",
    acceptance_criteria_refs: fallback.acceptance_criteria_refs,
    candidate_reports:
      candidateReports.length > 0 ? candidateReports : fallback.candidate_reports,
    receipt_refs: stringList(value.receipt_refs, fallback.receipt_refs),
    runtimeTruthSource: "daemon-runtime",
  };
}

export function readHypervisorHarnessPublicFixtureDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT;
  }
}

export async function requestHarnessPublicFixtureRun({
  endpoint = readHypervisorHarnessPublicFixtureDaemonEndpoint(),
  fetchImpl = fetch,
  request = buildHarnessPublicFixtureRunRequest(),
}: RequestHarnessPublicFixtureRunOptions = {}): Promise<HarnessComparisonRun> {
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_HARNESS_PUBLIC_FIXTURE_RUN_PATH}`;
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    throw new Error(`Harness public fixture run failed: ${response.status}`);
  }
  const body = await response.text();
  return normalizeHarnessComparisonRunFromPublicFixtureRun(JSON.parse(body));
}
