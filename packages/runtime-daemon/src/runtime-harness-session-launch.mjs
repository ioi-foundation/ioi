import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HARNESS_SESSION_LAUNCH_SCHEMA_VERSION =
  "ioi.runtime.harness_session_launch.v1";

const ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.harness_session_binding_admission.v1";

const LOCAL_HARNESS_MODEL_ENV = "HYPERVISOR_LOCAL_HARNESS_MODEL";
const LOCAL_HARNESS_WORKSPACE_ENV = "HYPERVISOR_SESSION_WORKSPACE";

export function buildHarnessSessionLaunch(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const admission = requireAdmittedBinding(request.binding_admission);
  const requestedWorkspaceRef =
    optionalString(request.workspace_ref) ??
    `workspace:${safeId(admission.session_route_ref)}`;
  const requestedTerminalRef =
    optionalString(request.terminal_session_ref) ??
    `terminal-session:${safeId(admission.session_route_ref)}`;

  assertLaunchableLocalModelAdmission(admission);

  const launchProfile = launchProfileForAdmission(admission);
  const launchId =
    optionalString(request.launch_id) ??
    `harness-session-launch:${safeId(admission.admission_id)}:${safeId(
      launchProfile.command_ref,
    )}`;
  const receiptRef =
    optionalString(request.launch_receipt_ref) ??
    `receipt://harness-session-launch/${safeId(launchId)}`;

  return {
    schema_version: HARNESS_SESSION_LAUNCH_SCHEMA_VERSION,
    launch_id: launchId,
    decision: "admitted",
    launch_state: "ready_to_spawn",
    launch_lane: launchProfile.launch_lane,
    session_binding_ref: admission.session_binding_ref,
    session_route_ref: admission.session_route_ref,
    binding_admission_id: admission.admission_id,
    harness_selection_ref: admission.harness_selection_ref,
    harness_selection_kind: admission.harness_selection_kind,
    harness_truth_boundary: admission.harness_truth_boundary,
    harness_launch_route_ref: admission.harness_launch_route_ref,
    agent_harness_adapter_id: admission.agent_harness_adapter_id,
    harness_profile_ref: admission.harness_profile_ref,
    model_configuration_ref: admission.model_configuration_ref,
    model_route_ref: admission.model_route_ref,
    model_route_policy: admission.model_route_policy,
    model_route_endpoint_refs: normalizeArray(
      admission.model_route_endpoint_refs,
    ),
    model_route_loaded_instance_refs: normalizeArray(
      admission.model_route_loaded_instance_refs,
    ),
    model_mount_contract: {
      provider: "ollama",
      api_format: "openai_compatible",
      model_env: LOCAL_HARNESS_MODEL_ENV,
      model_default: "qwen",
      endpoint_refs: normalizeArray(admission.model_route_endpoint_refs),
      loaded_instance_refs: normalizeArray(
        admission.model_route_loaded_instance_refs,
      ),
    },
    workspace_ref: requestedWorkspaceRef,
    workspace_mount_policy: admission.workspace_mount_policy,
    privacy_posture_ref: admission.privacy_posture_ref,
    terminal_session_ref: requestedTerminalRef,
    command_contract: {
      command_ref: launchProfile.command_ref,
      binary_name: launchProfile.binary_name,
      argv_template: launchProfile.argv_template,
      env_policy_ref: launchProfile.env_policy_ref,
      secret_release_policy: "none",
      requires_pty: true,
      workspace_env: LOCAL_HARNESS_WORKSPACE_ENV,
      model_env: LOCAL_HARNESS_MODEL_ENV,
    },
    authority_scope_refs: normalizeArray(admission.authority_scope_refs),
    receipt_policy_ref: admission.receipt_policy_ref,
    receipt_refs: uniqueStrings([
      ...normalizeArray(admission.receipt_refs),
      receiptRef,
    ]),
    agentgres_operation_refs: uniqueStrings([
      ...normalizeArray(admission.agentgres_operation_refs),
      `agentgres://operation/harness-session-launch/${safeId(launchId)}`,
    ]),
    state_root:
      optionalString(admission.state_root) ??
      `agentgres://state-root/harness-session-launch/${safeId(launchId)}`,
    launched_at: optionalString(request.launched_at) ?? nowIso(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    launch_invariant:
      "A launch-ready host harness session is emitted only after daemon admission binds the harness, local model route, workspace mount policy, authority scopes, receipts, and runtime truth boundary.",
  };
}

function requireAdmittedBinding(value) {
  const admission = objectRecord(value);
  if (!admission || admission.schema_version !== ADMISSION_SCHEMA_VERSION) {
    throw launchError({
      status: 400,
      code: "harness_session_launch_admission_required",
      message:
        "Harness session launch requires an admitted harness session binding admission.",
      details: { expected_schema_version: ADMISSION_SCHEMA_VERSION },
    });
  }
  if (admission.decision !== "admitted") {
    throw launchError({
      status: 403,
      code: "harness_session_launch_admission_not_admitted",
      message: "Harness session launch requires an admitted binding decision.",
      details: { decision: admission.decision ?? null },
    });
  }
  if (
    admission.admission_state !== "admitted_for_harness_launch" ||
    admission.requiresDaemonGate !== true ||
    admission.runtimeTruthSource !== "daemon-runtime"
  ) {
    throw launchError({
      status: 403,
      code: "harness_session_launch_admission_boundary_invalid",
      message:
        "Harness session launch requires daemon-gated admission under daemon runtime truth.",
      details: {
        admission_state: admission.admission_state ?? null,
        requiresDaemonGate: admission.requiresDaemonGate ?? null,
        runtimeTruthSource: admission.runtimeTruthSource ?? null,
      },
    });
  }
  return admission;
}

function assertLaunchableLocalModelAdmission(admission) {
  if (admission.model_route_policy !== "hypervisor_model_mount") {
    throw launchError({
      status: 403,
      code: "harness_session_launch_model_route_policy_blocked",
      message:
        "Harness session launch currently supports only Hypervisor local model mounts.",
      details: { model_route_policy: admission.model_route_policy ?? null },
    });
  }
  if (
    !["daemon_verified", "fixture_available"].includes(
      admission.model_route_availability_state,
    )
  ) {
    throw launchError({
      status: 403,
      code: "harness_session_launch_model_route_unavailable",
      message:
        "Harness session launch requires a verified or fixture-available local model route.",
      details: {
        model_route_availability_state:
          admission.model_route_availability_state ?? null,
      },
    });
  }
  if (
    !optionalString(admission.model_configuration_ref)?.startsWith(
      "model-config:local/",
    )
  ) {
    throw launchError({
      status: 403,
      code: "harness_session_launch_local_model_config_required",
      message: "Harness session launch requires a local model configuration.",
      details: {
        model_configuration_ref: admission.model_configuration_ref ?? null,
      },
    });
  }
  if (
    normalizeArray(admission.model_route_endpoint_refs).length === 0 ||
    normalizeArray(admission.model_route_loaded_instance_refs).length === 0
  ) {
    throw launchError({
      status: 403,
      code: "harness_session_launch_model_mount_refs_required",
      message:
        "Harness session launch requires endpoint and loaded-instance refs for the local model mount.",
      details: {},
    });
  }
}

function launchProfileForAdmission(admission) {
  if (
    admission.harness_selection_ref === "agent-harness-adapter:codex_cli" ||
    admission.agent_harness_adapter_id === "codex_cli"
  ) {
    return codexOssLaunchProfile();
  }
  if (
    admission.harness_selection_ref === "agent-harness-adapter:deepseek_tui" ||
    admission.agent_harness_adapter_id === "deepseek_tui"
  ) {
    return deepseekTuiLaunchProfile();
  }
  throw launchError({
    status: 403,
    code: "harness_session_launch_harness_unsupported",
    message:
      "Only the Codex OSS and DeepSeek TUI local-model harnesses are launch-ready in this slice.",
    details: {
      harness_selection_ref: admission.harness_selection_ref ?? null,
      agent_harness_adapter_id: admission.agent_harness_adapter_id ?? null,
    },
  });
}

function codexOssLaunchProfile() {
  return {
    launch_lane: "host_dev_pty",
    command_ref: "host-command:codex-cli/local-ollama-qwen",
    binary_name: "codex",
    env_policy_ref: "env-policy:harness-session/local-ollama-qwen",
    argv_template: [
      "codex",
      "--oss",
      "--local-provider",
      "ollama",
      "--model",
      `\${${LOCAL_HARNESS_MODEL_ENV}:-qwen}`,
      "--sandbox",
      "workspace-write",
      "--ask-for-approval",
      "on-request",
      "--cd",
      `\${${LOCAL_HARNESS_WORKSPACE_ENV}}`,
    ],
  };
}

function deepseekTuiLaunchProfile() {
  return {
    launch_lane: "host_dev_pty",
    command_ref: "host-command:deepseek-tui/local-ollama-qwen",
    binary_name: "deepseek",
    env_policy_ref: "env-policy:harness-session/deepseek-local-qwen",
    argv_template: [
      "deepseek",
      "--provider",
      "ollama",
      "--model",
      `\${${LOCAL_HARNESS_MODEL_ENV}:-qwen}`,
    ],
  };
}

function launchError({ status, code, message, details }) {
  return runtimeError({
    status,
    code,
    message,
    details,
  });
}
