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
  launch_route_ref: string;
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
  launch_route_ref: string;
  example_root_ref?: string;
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

export type HypervisorSessionModelRouteKind =
  | "local_openai_compatible"
  | "adapter_native"
  | "deterministic_none";

export interface HypervisorSessionModelConfiguration {
  schema_version: "ioi.hypervisor.session_model_configuration.v1";
  model_configuration_ref: string;
  label: string;
  description: string;
  model_route_ref: string;
  route_kind: HypervisorSessionModelRouteKind;
  provider_ref: string | null;
  model_ref: string | null;
  endpoint_refs: string[];
  loaded_instance_refs: string[];
  custody_posture:
    | "local_model_mount"
    | "adapter_provider_trust"
    | "deterministic_no_model";
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorHarnessSessionBinding {
  schema_version: "ioi.hypervisor.harness_session_binding.v1";
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  harness_selection_kind: HypervisorHarnessSelectionOption["selection_kind"];
  harness_label: string;
  harness_truth_boundary: "daemon-owned" | "proposal_source_only";
  harness_launch_route_ref: string;
  agent_harness_adapter_id?: AgentHarnessAdapterId;
  harness_profile_ref?: HypervisorHarnessProfileOption["profile_ref"];
  model_configuration_ref: string;
  model_configuration_label: string;
  model_route_ref: string;
  model_route_policy: HarnessModelRoutePolicy;
  model_route_availability_state: HypervisorModelRouteAvailability["state"];
  model_route_endpoint_refs: string[];
  model_route_loaded_instance_refs: string[];
  workspace_mount_policy: HarnessWorkspaceMountPolicy;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_policy_ref: string;
  receipt_preview_ref: string;
  expected_receipt_refs: string[];
  example_root_ref: string | null;
  requires_daemon_gate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorHarnessSessionBindingAdmission {
  schema_version: "ioi.runtime.harness_session_binding_admission.v1";
  admission_id: string;
  decision: "admitted";
  admission_state: "admitted_for_harness_launch";
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  harness_selection_kind: HypervisorHarnessSelectionOption["selection_kind"];
  harness_truth_boundary: "daemon-owned" | "proposal_source_only";
  harness_launch_route_ref: string;
  agent_harness_adapter_id: AgentHarnessAdapterId | null;
  harness_profile_ref: string | null;
  model_configuration_ref: string;
  model_route_ref: string;
  model_route_policy: HarnessModelRoutePolicy;
  model_route_availability_state: HypervisorModelRouteAvailability["state"];
  model_route_endpoint_refs: string[];
  model_route_loaded_instance_refs: string[];
  workspace_mount_policy: HarnessWorkspaceMountPolicy;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_policy_ref: string;
  receipt_preview_ref: string;
  expected_receipt_refs: string[];
  agentgres_operation_refs: string[];
  receipt_refs: string[];
  state_root: string | null;
  harness_runtime_truth_claimed: false;
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
  admitted_at: string;
}

export interface HypervisorHarnessSessionLaunch {
  schema_version: "ioi.runtime.harness_session_launch.v1";
  launch_id: string;
  decision: "admitted";
  launch_state: "ready_to_spawn";
  launch_lane: "host_dev_pty";
  session_binding_ref: string;
  session_route_ref: string;
  binding_admission_id: string;
  harness_selection_ref: string;
  harness_selection_kind: HypervisorHarnessSelectionOption["selection_kind"];
  harness_truth_boundary: "daemon-owned" | "proposal_source_only";
  harness_launch_route_ref: string;
  agent_harness_adapter_id: AgentHarnessAdapterId | null;
  harness_profile_ref: string | null;
  model_configuration_ref: string;
  model_route_ref: string;
  model_route_policy: HarnessModelRoutePolicy;
  model_route_endpoint_refs: string[];
  model_route_loaded_instance_refs: string[];
  model_mount_contract: {
    provider: "ollama";
    api_format: "openai_compatible";
    model_env: string;
    model_default: string;
    endpoint_refs: string[];
    loaded_instance_refs: string[];
  };
  workspace_ref: string;
  workspace_mount_policy: HarnessWorkspaceMountPolicy;
  privacy_posture_ref: string;
  terminal_session_ref: string;
  command_contract: {
    command_ref: string;
    binary_name: "codex";
    argv_template: string[];
    env_policy_ref: string;
    secret_release_policy: "none";
    requires_pty: true;
    workspace_env: string;
    model_env: string;
  };
  authority_scope_refs: string[];
  receipt_policy_ref: string;
  receipt_refs: string[];
  agentgres_operation_refs: string[];
  state_root: string;
  launched_at: string;
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorHarnessSessionSpawn {
  schema_version: "ioi.runtime.harness_session_spawn.v1";
  spawn_id: string;
  decision: "admitted";
  spawn_state: "ready_for_client_pty_attach";
  spawn_lane: "host_terminal_session";
  launch_id: string;
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  agent_harness_adapter_id: AgentHarnessAdapterId | null;
  model_configuration_ref: string;
  model_route_ref: string;
  model_name: string;
  workspace_ref: string;
  workspace_root: string;
  terminal_session_ref: string;
  command_contract_ref: string;
  command_contract: HypervisorHarnessSessionLaunch["command_contract"] & {
    resolved_argv: string[];
    resolved_command_line: string;
    pty_transport: "hypervisor_client_terminal_adapter";
    process_custody: "client_host_pty_after_daemon_spawn_admission";
  };
  terminal_attach_contract: {
    root: string;
    cols: number;
    rows: number;
    command_line: string;
    requires_pty: true;
    launch_after_attach: true;
  };
  model_mount_contract: HypervisorHarnessSessionLaunch["model_mount_contract"];
  workspace_mount_policy: HarnessWorkspaceMountPolicy;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_policy_ref: string;
  receipt_refs: string[];
  agentgres_operation_refs: string[];
  state_root: string;
  spawned_at: string;
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorHarnessSessionReadinessCheck {
  id: string;
  status: "pass" | "fail";
  required: true;
  summary: string;
  evidence_refs: string[];
}

export interface HypervisorHarnessSessionReadiness {
  schema_version: "ioi.runtime.harness_session_readiness.v1";
  readiness_id: string;
  decision: "ready" | "blocked";
  readiness_state:
    | "ready_for_harness_pty_attach"
    | "codex_binary_unavailable"
    | "codex_oss_flags_unavailable"
    | "ollama_provider_unavailable"
    | "qwen_model_unavailable"
    | "host_readiness_blocked";
  spawn_id: string;
  launch_id: string;
  session_binding_ref: string;
  session_route_ref: string;
  harness_selection_ref: string;
  agent_harness_adapter_id: AgentHarnessAdapterId | null;
  model_configuration_ref: string;
  model_route_ref: string;
  model_name: string;
  provider: "ollama";
  codex_binary: string;
  provider_binary: string;
  available_model_names: string[];
  checks: HypervisorHarnessSessionReadinessCheck[];
  operator_next_action: string;
  receipt_refs: string[];
  agentgres_operation_refs: string[];
  state_root: string;
  checked_at: string;
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
}

export class HarnessSessionBindingAdmissionError extends Error {
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
    super(`harness session binding admission failed with ${status}`);
    this.name = "HarnessSessionBindingAdmissionError";
    this.endpoint = endpoint;
    this.responseBody = responseBody;
    this.status = status;
  }
}

export class HarnessSessionLaunchError extends Error {
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
    super(`harness session launch failed with ${status}`);
    this.name = "HarnessSessionLaunchError";
    this.endpoint = endpoint;
    this.responseBody = responseBody;
    this.status = status;
  }
}

export class HarnessSessionSpawnError extends Error {
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
    super(`harness session spawn failed with ${status}`);
    this.name = "HarnessSessionSpawnError";
    this.endpoint = endpoint;
    this.responseBody = responseBody;
    this.status = status;
  }
}

export class HarnessSessionReadinessError extends Error {
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
    super(`harness session readiness failed with ${status}`);
    this.name = "HarnessSessionReadinessError";
    this.endpoint = endpoint;
    this.responseBody = responseBody;
    this.status = status;
  }
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
export const HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF =
  "model-config:local/codex-oss-qwen";
export const HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF =
  "privacy:ctee-private-workspace";
export const HYPERVISOR_HARNESS_SESSION_BINDING_ADMISSION_PATH =
  "/v1/hypervisor/harness-session-binding-admissions";
export const HYPERVISOR_HARNESS_SESSION_LAUNCH_PATH =
  "/v1/hypervisor/harness-session-launches";
export const HYPERVISOR_HARNESS_SESSION_SPAWN_PATH =
  "/v1/hypervisor/harness-session-spawns";
export const HYPERVISOR_HARNESS_SESSION_READINESS_PATH =
  "/v1/hypervisor/harness-session-readiness";
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
        modelId: "model:local/codex-oss-qwen",
        status: "mounted",
        privacyClass: "local",
      },
    ],
    loadedInstances: [
      {
        id: "model-instance:hypervisor/default-local",
        endpointId: "model-endpoint:hypervisor/default-local",
        providerId: "provider:hypervisor-local",
        modelId: "model:local/codex-oss-qwen",
        status: "loaded",
      },
    ],
  };

export const HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION: HypervisorSessionModelConfiguration =
  {
    schema_version: "ioi.hypervisor.session_model_configuration.v1",
    model_configuration_ref:
      HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
    label: "Local Codex OSS / Qwen route",
    description:
      "Local OpenAI-compatible model route for Codex OSS, Claude Code example, and DeepSeek TUI session bring-up.",
    model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    route_kind: "local_openai_compatible",
    provider_ref: "provider:hypervisor-local",
    model_ref: "model:local/codex-oss-qwen",
    endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    loaded_instance_refs: ["model-instance:hypervisor/default-local"],
    custody_posture: "local_model_mount",
    runtimeTruthSource: "daemon-runtime",
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
  launch_route_ref: "harness-route:default-harness-profile/local-model",
};

export const HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS: AgentHarnessAdapterId[] =
  ["codex_cli", "claude_code_cli", "deepseek_tui"];

export const HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES: AgentHarnessAdapterProfile[] =
  [
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "codex_cli",
      label: "Codex CLI",
      description:
        "Codex OSS command harness mediated as a proposal source over a local OpenAI-compatible model route.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "hypervisor_model_mount",
      workspace_mount_policy: "redacted_projection",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/default",
      launch_route_ref: "harness-route:codex-cli/local-model",
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
      launch_route_ref: "harness-route:codex-desktop-linux/example",
      example_root_ref: "examples/codex-desktop-linux",
      runtimeTruthSource: "daemon-runtime",
      truth_boundary: "proposal_source_only",
    },
    {
      selection_kind: "agent_harness_adapter",
      adapter_id: "claude_code_cli",
      label: "Claude Code CLI",
      description:
        "Claude Code-style example harness route backed by examples/claude-code-main and a local OpenAI-compatible model route until provider auth is leased.",
      adapter_kind: "cli",
      execution_lane: "host_dev",
      model_route_policy: "hypervisor_model_mount",
      workspace_mount_policy: "redacted_projection",
      required_authority_scopes: ["scope:workspace.read", "scope:workspace.patch"],
      receipt_policy_ref: "receipt-policy:harness-adapter/local-example",
      launch_route_ref: "harness-route:claude-code-cli/local-example",
      example_root_ref: "examples/claude-code-main",
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
      launch_route_ref: "harness-route:grok-build-cli/provider-trust",
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
      launch_route_ref: "harness-route:deepseek-tui/local-model-container",
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
      launch_route_ref: "harness-route:aider-cli/local-model",
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
      launch_route_ref: "harness-route:openhands/provider-trust",
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
      launch_route_ref: "harness-route:shell-tmux/no-model",
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
      launch_route_ref: "harness-route:generic-cli/no-model",
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

function safeHarnessBindingId(value: string | number): string {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96) || "binding";
}

export function modelConfigurationForRouteRef(
  modelRouteRef: string,
  availability: HypervisorModelRouteAvailability,
): HypervisorSessionModelConfiguration {
  if (modelRouteRef === HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF) {
    return {
      ...HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION,
      endpoint_refs:
        availability.endpoint_refs.length > 0
          ? availability.endpoint_refs
          : HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION.endpoint_refs,
      loaded_instance_refs:
        availability.loaded_instance_refs.length > 0
          ? availability.loaded_instance_refs
          : HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION.loaded_instance_refs,
    };
  }

  if (modelRouteRef === "model-route:adapter-native") {
    return {
      schema_version: "ioi.hypervisor.session_model_configuration.v1",
      model_configuration_ref: "model-config:adapter-native/provider-trust",
      label: "Adapter-native provider route",
      description:
        "Harness-native provider model path; requires provider-trust disclosure and capability leases before protected data is routed.",
      model_route_ref: modelRouteRef,
      route_kind: "adapter_native",
      provider_ref: "provider:adapter-native",
      model_ref: null,
      endpoint_refs: [],
      loaded_instance_refs: [],
      custody_posture: "adapter_provider_trust",
      runtimeTruthSource: "daemon-runtime",
    };
  }

  return {
    schema_version: "ioi.hypervisor.session_model_configuration.v1",
    model_configuration_ref: "model-config:none/deterministic",
    label: "No model route",
    description:
      "Deterministic, infrastructure, or inspection-only session with no model route.",
    model_route_ref: modelRouteRef,
    route_kind: "deterministic_none",
    provider_ref: null,
    model_ref: null,
    endpoint_refs: [],
    loaded_instance_refs: [],
    custody_posture: "deterministic_no_model",
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorHarnessSessionBinding({
  sessionRouteRef,
  harness,
  modelRouteAvailability,
  modelRouteRef,
  privacyPostureRef,
  authorityScopeRefs,
  receiptPreviewRef,
}: {
  sessionRouteRef: string;
  harness: HypervisorHarnessSelectionOption;
  modelRouteAvailability: HypervisorModelRouteAvailability;
  modelRouteRef: string;
  privacyPostureRef: string;
  authorityScopeRefs: string[];
  receiptPreviewRef: string;
}): HypervisorHarnessSessionBinding {
  const selectionRef = getHarnessSelectionRef(harness);
  const modelConfiguration = modelConfigurationForRouteRef(
    modelRouteRef,
    modelRouteAvailability,
  );
  const sessionBindingRef = [
    "harness-session-binding",
    safeHarnessBindingId(sessionRouteRef),
    safeHarnessBindingId(selectionRef),
    safeHarnessBindingId(modelConfiguration.model_configuration_ref),
  ].join(":");

  const modelRoutePolicy =
    harness.selection_kind === "harness_profile"
      ? harness.default_model_route_policy
      : harness.model_route_policy;
  const workspaceMountPolicy =
    harness.selection_kind === "harness_profile"
      ? harness.default_workspace_mount_policy
      : harness.workspace_mount_policy;

  return {
    schema_version: "ioi.hypervisor.harness_session_binding.v1",
    session_binding_ref: sessionBindingRef,
    session_route_ref: sessionRouteRef,
    harness_selection_ref: selectionRef,
    harness_selection_kind: harness.selection_kind,
    harness_label: harness.label,
    harness_truth_boundary:
      harness.selection_kind === "harness_profile"
        ? "daemon-owned"
        : harness.truth_boundary,
    harness_launch_route_ref: harness.launch_route_ref,
    ...(harness.selection_kind === "agent_harness_adapter"
      ? { agent_harness_adapter_id: harness.adapter_id }
      : { harness_profile_ref: harness.profile_ref }),
    model_configuration_ref: modelConfiguration.model_configuration_ref,
    model_configuration_label: modelConfiguration.label,
    model_route_ref: modelRouteRef,
    model_route_policy: modelRoutePolicy,
    model_route_availability_state: modelRouteAvailability.state,
    model_route_endpoint_refs: modelConfiguration.endpoint_refs,
    model_route_loaded_instance_refs: modelConfiguration.loaded_instance_refs,
    workspace_mount_policy: workspaceMountPolicy,
    privacy_posture_ref: privacyPostureRef,
    authority_scope_refs: [...authorityScopeRefs],
    receipt_policy_ref:
      harness.selection_kind === "harness_profile"
        ? "receipt-policy:harness-profile/default"
        : harness.receipt_policy_ref,
    receipt_preview_ref: receiptPreviewRef,
    expected_receipt_refs: [
      receiptPreviewRef,
      harness.selection_kind === "harness_profile"
        ? "receipt-policy:harness-profile/default"
        : harness.receipt_policy_ref,
    ],
    example_root_ref:
      harness.selection_kind === "agent_harness_adapter"
        ? harness.example_root_ref ?? null
        : null,
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
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

interface RequestHarnessSessionBindingAdmissionOptions {
  endpoint?: string;
  fetchImpl?: HarnessFetchLike;
}

interface RequestHarnessSessionLaunchOptions {
  endpoint?: string;
  fetchImpl?: HarnessFetchLike;
  workspaceRef?: string;
  terminalSessionRef?: string;
}

interface RequestHarnessSessionSpawnOptions {
  endpoint?: string;
  fetchImpl?: HarnessFetchLike;
  workspaceRoot?: string;
  modelName?: string;
}

interface RequestHarnessSessionReadinessOptions {
  endpoint?: string;
  fetchImpl?: HarnessFetchLike;
  modelName?: string;
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

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
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

function normalizeHarnessSessionBindingAdmission(
  value: unknown,
): HypervisorHarnessSessionBindingAdmission {
  const record = objectRecord(value);
  return {
    schema_version: "ioi.runtime.harness_session_binding_admission.v1",
    admission_id:
      nullableString(record.admission_id) ??
      "harness-session-binding-admission:unknown",
    decision: "admitted",
    admission_state: "admitted_for_harness_launch",
    session_binding_ref:
      nullableString(record.session_binding_ref) ??
      "harness-session-binding:unknown",
    session_route_ref:
      nullableString(record.session_route_ref) ?? "session-route:unknown",
    harness_selection_ref:
      nullableString(record.harness_selection_ref) ??
      "harness-profile:unknown",
    harness_selection_kind:
      (nullableString(
        record.harness_selection_kind,
      ) as HypervisorHarnessSelectionOption["selection_kind"]) ??
      "harness_profile",
    harness_truth_boundary:
      (nullableString(record.harness_truth_boundary) as
        | "daemon-owned"
        | "proposal_source_only") ?? "proposal_source_only",
    harness_launch_route_ref:
      nullableString(record.harness_launch_route_ref) ??
      "harness-route:unknown",
    agent_harness_adapter_id:
      (nullableString(record.agent_harness_adapter_id) as AgentHarnessAdapterId) ??
      null,
    harness_profile_ref: nullableString(record.harness_profile_ref),
    model_configuration_ref:
      nullableString(record.model_configuration_ref) ?? "model-config:unknown",
    model_route_ref:
      nullableString(record.model_route_ref) ?? "model-route:unknown",
    model_route_policy:
      (nullableString(record.model_route_policy) as HarnessModelRoutePolicy) ??
      "forbidden",
    model_route_availability_state:
      (nullableString(
        record.model_route_availability_state,
      ) as HypervisorModelRouteAvailability["state"]) ?? "unavailable",
    model_route_endpoint_refs: stringList(record.model_route_endpoint_refs, []),
    model_route_loaded_instance_refs: stringList(
      record.model_route_loaded_instance_refs,
      [],
    ),
    workspace_mount_policy:
      (nullableString(record.workspace_mount_policy) as HarnessWorkspaceMountPolicy) ??
      "public_trunk",
    privacy_posture_ref:
      nullableString(record.privacy_posture_ref) ?? "privacy:unknown",
    authority_scope_refs: stringList(record.authority_scope_refs, []),
    receipt_policy_ref:
      nullableString(record.receipt_policy_ref) ?? "receipt-policy:unknown",
    receipt_preview_ref:
      nullableString(record.receipt_preview_ref) ?? "receipt-preview:unknown",
    expected_receipt_refs: stringList(record.expected_receipt_refs, []),
    agentgres_operation_refs: stringList(record.agentgres_operation_refs, []),
    receipt_refs: stringList(record.receipt_refs, []),
    state_root: nullableString(record.state_root),
    harness_runtime_truth_claimed: false,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: nullableString(record.admitted_at) ?? new Date().toISOString(),
  };
}

function normalizeHarnessSessionLaunch(
  value: unknown,
): HypervisorHarnessSessionLaunch {
  const record = objectRecord(value);
  const modelMountContract = objectRecord(record.model_mount_contract);
  const commandContract = objectRecord(record.command_contract);
  return {
    schema_version: "ioi.runtime.harness_session_launch.v1",
    launch_id:
      nullableString(record.launch_id) ?? "harness-session-launch:unknown",
    decision: "admitted",
    launch_state: "ready_to_spawn",
    launch_lane: "host_dev_pty",
    session_binding_ref:
      nullableString(record.session_binding_ref) ??
      "harness-session-binding:unknown",
    session_route_ref:
      nullableString(record.session_route_ref) ?? "session-route:unknown",
    binding_admission_id:
      nullableString(record.binding_admission_id) ??
      "harness-session-binding-admission:unknown",
    harness_selection_ref:
      nullableString(record.harness_selection_ref) ??
      "agent-harness-adapter:codex_cli",
    harness_selection_kind:
      (nullableString(
        record.harness_selection_kind,
      ) as HypervisorHarnessSelectionOption["selection_kind"]) ??
      "agent_harness_adapter",
    harness_truth_boundary:
      (nullableString(record.harness_truth_boundary) as
        | "daemon-owned"
        | "proposal_source_only") ?? "proposal_source_only",
    harness_launch_route_ref:
      nullableString(record.harness_launch_route_ref) ??
      "harness-route:codex-cli/local-model",
    agent_harness_adapter_id:
      (nullableString(record.agent_harness_adapter_id) as AgentHarnessAdapterId) ??
      "codex_cli",
    harness_profile_ref: nullableString(record.harness_profile_ref),
    model_configuration_ref:
      nullableString(record.model_configuration_ref) ??
      HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
    model_route_ref:
      nullableString(record.model_route_ref) ??
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    model_route_policy:
      (nullableString(record.model_route_policy) as HarnessModelRoutePolicy) ??
      "hypervisor_model_mount",
    model_route_endpoint_refs: stringList(record.model_route_endpoint_refs, []),
    model_route_loaded_instance_refs: stringList(
      record.model_route_loaded_instance_refs,
      [],
    ),
    model_mount_contract: {
      provider:
        nullableString(modelMountContract.provider) === "ollama"
          ? "ollama"
          : "ollama",
      api_format:
        nullableString(modelMountContract.api_format) === "openai_compatible"
          ? "openai_compatible"
          : "openai_compatible",
      model_env:
        nullableString(modelMountContract.model_env) ??
        "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
      model_default:
        nullableString(modelMountContract.model_default) ?? "qwen",
      endpoint_refs: stringList(modelMountContract.endpoint_refs, []),
      loaded_instance_refs: stringList(modelMountContract.loaded_instance_refs, []),
    },
    workspace_ref: nullableString(record.workspace_ref) ?? "workspace:unknown",
    workspace_mount_policy:
      (nullableString(record.workspace_mount_policy) as HarnessWorkspaceMountPolicy) ??
      "redacted_projection",
    privacy_posture_ref:
      nullableString(record.privacy_posture_ref) ?? "privacy:redacted-projection",
    terminal_session_ref:
      nullableString(record.terminal_session_ref) ??
      "terminal-session:unknown",
    command_contract: {
      command_ref:
        nullableString(commandContract.command_ref) ??
        "host-command:codex-cli/local-ollama-qwen",
      binary_name: "codex",
      argv_template: stringList(commandContract.argv_template, [
        "codex",
        "--oss",
        "--local-provider",
        "ollama",
        "--model",
        "${HYPERVISOR_LOCAL_CODEX_OSS_MODEL:-qwen}",
        "--sandbox",
        "workspace-write",
        "--ask-for-approval",
        "on-request",
        "--cd",
        "${HYPERVISOR_SESSION_WORKSPACE}",
      ]),
      env_policy_ref:
        nullableString(commandContract.env_policy_ref) ??
        "env-policy:harness-session/codex-oss-local-qwen",
      secret_release_policy: "none",
      requires_pty: true,
      workspace_env:
        nullableString(commandContract.workspace_env) ??
        "HYPERVISOR_SESSION_WORKSPACE",
      model_env:
        nullableString(commandContract.model_env) ??
        "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
    },
    authority_scope_refs: stringList(record.authority_scope_refs, []),
    receipt_policy_ref:
      nullableString(record.receipt_policy_ref) ??
      "receipt-policy:harness-adapter/default",
    receipt_refs: stringList(record.receipt_refs, []),
    agentgres_operation_refs: stringList(record.agentgres_operation_refs, []),
    state_root:
      nullableString(record.state_root) ??
      "agentgres://state-root/harness-session-launch/unknown",
    launched_at: nullableString(record.launched_at) ?? new Date().toISOString(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

function normalizeHarnessSessionSpawn(
  value: unknown,
): HypervisorHarnessSessionSpawn {
  const record = objectRecord(value);
  const commandContract = objectRecord(record.command_contract);
  const terminalAttachContract = objectRecord(record.terminal_attach_contract);
  const modelMountContract = objectRecord(record.model_mount_contract);
  return {
    schema_version: "ioi.runtime.harness_session_spawn.v1",
    spawn_id: nullableString(record.spawn_id) ?? "harness-session-spawn:unknown",
    decision: "admitted",
    spawn_state: "ready_for_client_pty_attach",
    spawn_lane: "host_terminal_session",
    launch_id:
      nullableString(record.launch_id) ?? "harness-session-launch:unknown",
    session_binding_ref:
      nullableString(record.session_binding_ref) ??
      "harness-session-binding:unknown",
    session_route_ref:
      nullableString(record.session_route_ref) ?? "session-route:unknown",
    harness_selection_ref:
      nullableString(record.harness_selection_ref) ??
      "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id:
      (nullableString(record.agent_harness_adapter_id) as AgentHarnessAdapterId) ??
      "codex_cli",
    model_configuration_ref:
      nullableString(record.model_configuration_ref) ??
      HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
    model_route_ref:
      nullableString(record.model_route_ref) ??
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    model_name: nullableString(record.model_name) ?? "qwen",
    workspace_ref: nullableString(record.workspace_ref) ?? "workspace:unknown",
    workspace_root: nullableString(record.workspace_root) ?? ".",
    terminal_session_ref:
      nullableString(record.terminal_session_ref) ??
      "terminal-session:unknown",
    command_contract_ref:
      nullableString(record.command_contract_ref) ??
      "host-command:codex-cli/local-ollama-qwen",
    command_contract: {
      command_ref:
        nullableString(commandContract.command_ref) ??
        "host-command:codex-cli/local-ollama-qwen",
      binary_name: "codex",
      argv_template: stringList(commandContract.argv_template, [
        "codex",
        "--oss",
        "--local-provider",
        "ollama",
        "--model",
        "${HYPERVISOR_LOCAL_CODEX_OSS_MODEL:-qwen}",
        "--sandbox",
        "workspace-write",
        "--ask-for-approval",
        "on-request",
        "--cd",
        "${HYPERVISOR_SESSION_WORKSPACE}",
      ]),
      env_policy_ref:
        nullableString(commandContract.env_policy_ref) ??
        "env-policy:harness-session/codex-oss-local-qwen",
      secret_release_policy: "none",
      requires_pty: true,
      workspace_env:
        nullableString(commandContract.workspace_env) ??
        "HYPERVISOR_SESSION_WORKSPACE",
      model_env:
        nullableString(commandContract.model_env) ??
        "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
      resolved_argv: stringList(commandContract.resolved_argv, []),
      resolved_command_line:
        nullableString(commandContract.resolved_command_line) ?? "codex --oss",
      pty_transport: "hypervisor_client_terminal_adapter",
      process_custody: "client_host_pty_after_daemon_spawn_admission",
    },
    terminal_attach_contract: {
      root: nullableString(terminalAttachContract.root) ?? ".",
      cols:
        typeof terminalAttachContract.cols === "number"
          ? terminalAttachContract.cols
          : 120,
      rows:
        typeof terminalAttachContract.rows === "number"
          ? terminalAttachContract.rows
          : 32,
      command_line:
        nullableString(terminalAttachContract.command_line) ?? "codex --oss",
      requires_pty: true,
      launch_after_attach: true,
    },
    model_mount_contract: {
      provider:
        nullableString(modelMountContract.provider) === "ollama"
          ? "ollama"
          : "ollama",
      api_format:
        nullableString(modelMountContract.api_format) === "openai_compatible"
          ? "openai_compatible"
          : "openai_compatible",
      model_env:
        nullableString(modelMountContract.model_env) ??
        "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
      model_default:
        nullableString(modelMountContract.model_default) ?? "qwen",
      endpoint_refs: stringList(modelMountContract.endpoint_refs, []),
      loaded_instance_refs: stringList(modelMountContract.loaded_instance_refs, []),
    },
    workspace_mount_policy:
      (nullableString(record.workspace_mount_policy) as HarnessWorkspaceMountPolicy) ??
      "redacted_projection",
    privacy_posture_ref:
      nullableString(record.privacy_posture_ref) ?? "privacy:redacted-projection",
    authority_scope_refs: stringList(record.authority_scope_refs, []),
    receipt_policy_ref:
      nullableString(record.receipt_policy_ref) ??
      "receipt-policy:harness-adapter/default",
    receipt_refs: stringList(record.receipt_refs, []),
    agentgres_operation_refs: stringList(record.agentgres_operation_refs, []),
    state_root:
      nullableString(record.state_root) ??
      "agentgres://state-root/harness-session-spawn/unknown",
    spawned_at: nullableString(record.spawned_at) ?? new Date().toISOString(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

function normalizeHarnessSessionReadiness(
  value: unknown,
): HypervisorHarnessSessionReadiness {
  const record = objectRecord(value);
  return {
    schema_version: "ioi.runtime.harness_session_readiness.v1",
    readiness_id:
      nullableString(record.readiness_id) ??
      "harness-session-readiness:unknown",
    decision: record.decision === "ready" ? "ready" : "blocked",
    readiness_state:
      (nullableString(record.readiness_state) as HypervisorHarnessSessionReadiness["readiness_state"]) ??
      "host_readiness_blocked",
    spawn_id: nullableString(record.spawn_id) ?? "harness-session-spawn:unknown",
    launch_id:
      nullableString(record.launch_id) ?? "harness-session-launch:unknown",
    session_binding_ref:
      nullableString(record.session_binding_ref) ??
      "harness-session-binding:unknown",
    session_route_ref:
      nullableString(record.session_route_ref) ?? "session-route:unknown",
    harness_selection_ref:
      nullableString(record.harness_selection_ref) ??
      "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id:
      (nullableString(record.agent_harness_adapter_id) as AgentHarnessAdapterId) ??
      "codex_cli",
    model_configuration_ref:
      nullableString(record.model_configuration_ref) ??
      HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
    model_route_ref:
      nullableString(record.model_route_ref) ??
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    model_name: nullableString(record.model_name) ?? "qwen",
    provider: nullableString(record.provider) === "ollama" ? "ollama" : "ollama",
    codex_binary: nullableString(record.codex_binary) ?? "codex",
    provider_binary: nullableString(record.provider_binary) ?? "ollama",
    available_model_names: stringList(record.available_model_names, []),
    checks: arrayRecords(record.checks).map((check) => ({
      id: nullableString(check.id) ?? "unknown",
      status: check.status === "pass" ? "pass" : "fail",
      required: true,
      summary: nullableString(check.summary) ?? "",
      evidence_refs: stringList(check.evidence_refs, []),
    })),
    operator_next_action:
      nullableString(record.operator_next_action) ??
      "Resolve host readiness before attaching this harness session.",
    receipt_refs: stringList(record.receipt_refs, []),
    agentgres_operation_refs: stringList(record.agentgres_operation_refs, []),
    state_root:
      nullableString(record.state_root) ??
      "agentgres://state-root/harness-session-readiness/unknown",
    checked_at: nullableString(record.checked_at) ?? new Date().toISOString(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function requestHarnessSessionBindingAdmission(
  binding: HypervisorHarnessSessionBinding,
  options: RequestHarnessSessionBindingAdmissionOptions = {},
): Promise<HypervisorHarnessSessionBindingAdmission> {
  const endpoint =
    options.endpoint ?? readHypervisorHarnessPublicFixtureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for harness session binding admission");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_HARNESS_SESSION_BINDING_ADMISSION_PATH}`;
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify(binding),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new HarnessSessionBindingAdmissionError({
      endpoint: url,
      responseBody: text,
      status: response.status,
    });
  }
  return normalizeHarnessSessionBindingAdmission(text ? JSON.parse(text) : {});
}

export async function requestHarnessSessionLaunch(
  bindingAdmission: HypervisorHarnessSessionBindingAdmission,
  options: RequestHarnessSessionLaunchOptions = {},
): Promise<HypervisorHarnessSessionLaunch> {
  const endpoint =
    options.endpoint ?? readHypervisorHarnessPublicFixtureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for harness session launch");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_HARNESS_SESSION_LAUNCH_PATH}`;
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      binding_admission: bindingAdmission,
      ...(options.workspaceRef ? { workspace_ref: options.workspaceRef } : {}),
      ...(options.terminalSessionRef
        ? { terminal_session_ref: options.terminalSessionRef }
        : {}),
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new HarnessSessionLaunchError({
      endpoint: url,
      responseBody: text,
      status: response.status,
    });
  }
  return normalizeHarnessSessionLaunch(text ? JSON.parse(text) : {});
}

export async function requestHarnessSessionSpawn(
  sessionLaunch: HypervisorHarnessSessionLaunch,
  options: RequestHarnessSessionSpawnOptions = {},
): Promise<HypervisorHarnessSessionSpawn> {
  const endpoint =
    options.endpoint ?? readHypervisorHarnessPublicFixtureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for harness session spawn");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_HARNESS_SESSION_SPAWN_PATH}`;
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      session_launch: sessionLaunch,
      ...(options.workspaceRoot
        ? { workspace_root: options.workspaceRoot }
        : {}),
      ...(options.modelName ? { model_name: options.modelName } : {}),
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new HarnessSessionSpawnError({
      endpoint: url,
      responseBody: text,
      status: response.status,
    });
  }
  return normalizeHarnessSessionSpawn(text ? JSON.parse(text) : {});
}

export async function requestHarnessSessionReadiness(
  sessionSpawn: HypervisorHarnessSessionSpawn,
  options: RequestHarnessSessionReadinessOptions = {},
): Promise<HypervisorHarnessSessionReadiness> {
  const endpoint =
    options.endpoint ?? readHypervisorHarnessPublicFixtureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for harness session readiness");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_HARNESS_SESSION_READINESS_PATH}`;
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      session_spawn: sessionSpawn,
      ...(options.modelName ? { model_name: options.modelName } : {}),
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new HarnessSessionReadinessError({
      endpoint: url,
      responseBody: text,
      status: response.status,
    });
  }
  return normalizeHarnessSessionReadiness(text ? JSON.parse(text) : {});
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
