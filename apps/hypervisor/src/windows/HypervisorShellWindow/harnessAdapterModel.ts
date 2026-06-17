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
  receipt_refs: string[];
  runtimeTruthSource: "daemon-runtime";
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
    "IOI reference scaffold and fallback HarnessProfile executed or mediated by the Hypervisor Daemon.",
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
        "Codex-style command harness mediated as a proposal source under daemon gates.",
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
        "Desktop/client parity harness for computer-use experiments, not Hypervisor runtime truth.",
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
        "Terminal or tmux-oriented agent loop mediated through daemon-gated commands, mounts, network, and receipts.",
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
        "Explicitly configured command harness adapter with daemon-gated argv, mounts, network, and receipts.",
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
        "Hypervisor model mount inventory has not been verified by the daemon.",
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
        ? "Daemon model-mount inventory reports an active local route and mounted execution target."
        : "Fixture inventory reports the expected local route contract until live daemon probing is injected.",
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
        ? "Default Harness Profile can use the selected Hypervisor model mount under daemon gates."
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
        ? "Adapter can use a verified Hypervisor model route when launched through daemon mediation."
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

export const HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE: HarnessAdapterTestbedFixture =
  {
    schema_version: "ioi.hypervisor.harness_adapter_testbed_fixture.v1",
    fixture_id: "harness-testbed:public-code-edit-smoke",
    label: "Public code edit smoke",
    description:
      "Non-sensitive fixture for comparing Default Harness Profile and external AgentHarnessAdapters without granting runtime truth.",
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
  receipt_refs: HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.candidate_selection_refs.map(
    (selectionRef) => `receipt:draft:${selectionRef}`,
  ),
  runtimeTruthSource: "daemon-runtime",
};
