import assert from "node:assert/strict";
import test from "node:test";

import type {
  HypervisorLaunchedSessionProjection,
  HypervisorNewSessionLaunchSummary,
} from "./hypervisorShellNavigationModel.ts";
import type { HypervisorHarnessSessionBinding } from "./harnessAdapterModel.ts";
import {
  HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT,
  HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
  loadHypervisorLaunchedSessionProjections,
  mergeHypervisorLaunchedSessionProjection,
  persistHypervisorLaunchedSessionProjections,
} from "./hypervisorLaunchedSessionPersistence.ts";

class MemoryStorage {
  private readonly values = new Map<string, string>();

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

function harnessSessionBinding(id: string): HypervisorHarnessSessionBinding {
  return {
    schema_version: "ioi.hypervisor.harness_session_binding.v1",
    session_binding_ref: `harness-session-binding:${id}`,
    session_route_ref: `session-route:sessions/${id}`,
    harness_selection_ref: "harness-profile:default_harness_profile",
    harness_selection_kind: "harness_profile",
    harness_label: "Default Harness Profile",
    harness_truth_boundary: "daemon-owned",
    harness_launch_route_ref: "harness-route:default-harness-profile/local-model",
    harness_profile_ref: "default_harness_profile",
    model_configuration_ref: "model-config:local/codex-oss-qwen",
    model_configuration_label: "Local Codex OSS / Qwen route",
    model_route_ref: "model-route:hypervisor/default-local",
    model_route_policy: "hypervisor_model_mount",
    model_route_availability_state: "daemon_verified",
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    model_route_loaded_instance_refs: ["model-instance:hypervisor/default-local"],
    workspace_mount_policy: "ctee_private_workspace",
    privacy_posture_ref: "privacy:ctee-private-workspace",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_policy_ref: "receipt-policy:harness-profile/default",
    receipt_preview_ref: `receipt-preview:new-session/${id}`,
    expected_receipt_refs: [
      `receipt-preview:new-session/${id}`,
      "receipt-policy:harness-profile/default",
    ],
    example_root_ref: null,
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

function harnessSessionBindingAdmission(id: string) {
  const binding = harnessSessionBinding(id);
  return {
    schema_version: "ioi.runtime.harness_session_binding_admission.v1" as const,
    admission_id: `harness-session-binding-admission:${id}`,
    decision: "admitted" as const,
    admission_state: "admitted_for_harness_launch" as const,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    harness_selection_kind: binding.harness_selection_kind,
    harness_truth_boundary: binding.harness_truth_boundary,
    harness_launch_route_ref: binding.harness_launch_route_ref,
    agent_harness_adapter_id: null,
    harness_profile_ref: binding.harness_profile_ref ?? null,
    model_configuration_ref: binding.model_configuration_ref,
    model_route_ref: binding.model_route_ref,
    model_route_policy: binding.model_route_policy,
    model_route_availability_state: binding.model_route_availability_state,
    model_route_endpoint_refs: binding.model_route_endpoint_refs,
    model_route_loaded_instance_refs: binding.model_route_loaded_instance_refs,
    workspace_mount_policy: binding.workspace_mount_policy,
    privacy_posture_ref: binding.privacy_posture_ref,
    authority_scope_refs: binding.authority_scope_refs,
    receipt_policy_ref: binding.receipt_policy_ref,
    receipt_preview_ref: binding.receipt_preview_ref,
    expected_receipt_refs: binding.expected_receipt_refs,
    agentgres_operation_refs: [
      `agentgres://operation/harness-session-binding/${id}`,
    ],
    receipt_refs: [`receipt://harness-session-binding/${id}`],
    state_root: `agentgres://state-root/harness-session-binding/${id}`,
    harness_runtime_truth_claimed: false as const,
    requiresDaemonGate: true as const,
    runtimeTruthSource: "daemon-runtime" as const,
    admitted_at: "2026-06-18T12:00:00.000Z",
  };
}

function harnessSessionLaunch(id: string) {
  const binding = harnessSessionBinding(id);
  const admission = harnessSessionBindingAdmission(id);
  return {
    schema_version: "ioi.runtime.harness_session_launch.v1" as const,
    launch_id: `harness-session-launch:${id}`,
    decision: "admitted" as const,
    launch_state: "ready_to_spawn" as const,
    launch_lane: "host_dev_pty" as const,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    binding_admission_id: admission.admission_id,
    harness_selection_ref: binding.harness_selection_ref,
    harness_selection_kind: binding.harness_selection_kind,
    harness_truth_boundary: binding.harness_truth_boundary,
    harness_launch_route_ref: binding.harness_launch_route_ref,
    agent_harness_adapter_id: null,
    harness_profile_ref: binding.harness_profile_ref ?? null,
    model_configuration_ref: binding.model_configuration_ref,
    model_route_ref: binding.model_route_ref,
    model_route_policy: binding.model_route_policy,
    model_route_endpoint_refs: binding.model_route_endpoint_refs,
    model_route_loaded_instance_refs: binding.model_route_loaded_instance_refs,
    model_mount_contract: {
      provider: "ollama" as const,
      api_format: "openai_compatible" as const,
      model_env: "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
      model_default: "qwen",
      endpoint_refs: binding.model_route_endpoint_refs,
      loaded_instance_refs: binding.model_route_loaded_instance_refs,
    },
    workspace_ref: `workspace:${id}`,
    workspace_mount_policy: binding.workspace_mount_policy,
    privacy_posture_ref: binding.privacy_posture_ref,
    terminal_session_ref: `terminal-session:${id}`,
    command_contract: {
      command_ref: "host-command:codex-cli/local-ollama-qwen",
      binary_name: "codex" as const,
      argv_template: [
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
      ],
      env_policy_ref: "env-policy:harness-session/codex-oss-local-qwen",
      secret_release_policy: "none" as const,
      requires_pty: true as const,
      workspace_env: "HYPERVISOR_SESSION_WORKSPACE",
      model_env: "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
    },
    authority_scope_refs: binding.authority_scope_refs,
    receipt_policy_ref: binding.receipt_policy_ref,
    receipt_refs: [`receipt://harness-session-launch/${id}`],
    agentgres_operation_refs: [
      `agentgres://operation/harness-session-launch/${id}`,
    ],
    state_root: `agentgres://state-root/harness-session-launch/${id}`,
    launched_at: "2026-06-18T12:30:00.000Z",
    requiresDaemonGate: true as const,
    runtimeTruthSource: "daemon-runtime" as const,
  };
}

function harnessSessionSpawn(id: string) {
  const binding = harnessSessionBinding(id);
  const launch = harnessSessionLaunch(id);
  return {
    schema_version: "ioi.runtime.harness_session_spawn.v1" as const,
    spawn_id: `harness-session-spawn:${id}`,
    decision: "admitted" as const,
    spawn_state: "ready_for_client_pty_attach" as const,
    spawn_lane: "host_terminal_session" as const,
    launch_id: launch.launch_id,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    agent_harness_adapter_id: null,
    model_configuration_ref: binding.model_configuration_ref,
    model_route_ref: binding.model_route_ref,
    model_name: "qwen",
    workspace_ref: `workspace:${id}`,
    workspace_root: "/repo",
    terminal_session_ref: `terminal-session:${id}`,
    command_contract_ref: launch.command_contract.command_ref,
    command_contract: {
      ...launch.command_contract,
      resolved_argv: [
        "codex",
        "--oss",
        "--local-provider",
        "ollama",
        "--model",
        "qwen",
        "--sandbox",
        "workspace-write",
        "--ask-for-approval",
        "on-request",
        "--cd",
        "/repo",
      ],
      resolved_command_line:
        "codex --oss --local-provider ollama --model qwen --sandbox workspace-write --ask-for-approval on-request --cd /repo",
      pty_transport: "hypervisor_client_terminal_adapter" as const,
      process_custody: "client_host_pty_after_daemon_spawn_admission" as const,
    },
    terminal_attach_contract: {
      root: "/repo",
      cols: 120,
      rows: 32,
      command_line:
        "codex --oss --local-provider ollama --model qwen --sandbox workspace-write --ask-for-approval on-request --cd /repo",
      requires_pty: true as const,
      launch_after_attach: true as const,
    },
    model_mount_contract: launch.model_mount_contract,
    workspace_mount_policy: binding.workspace_mount_policy,
    privacy_posture_ref: binding.privacy_posture_ref,
    authority_scope_refs: binding.authority_scope_refs,
    receipt_policy_ref: binding.receipt_policy_ref,
    receipt_refs: [`receipt://harness-session-spawn/${id}`],
    agentgres_operation_refs: [
      `agentgres://operation/harness-session-spawn/${id}`,
    ],
    state_root: `agentgres://state-root/harness-session-spawn/${id}`,
    spawned_at: "2026-06-18T12:35:00.000Z",
    requiresDaemonGate: true as const,
    runtimeTruthSource: "daemon-runtime" as const,
  };
}

function harnessSessionReadiness(id: string) {
  const binding = harnessSessionBinding(id);
  const launch = harnessSessionLaunch(id);
  const spawn = harnessSessionSpawn(id);
  return {
    schema_version: "ioi.runtime.harness_session_readiness.v1" as const,
    readiness_id: `harness-session-readiness:${id}`,
    decision: "ready" as const,
    readiness_state: "ready_for_harness_pty_attach" as const,
    spawn_id: spawn.spawn_id,
    launch_id: launch.launch_id,
    session_binding_ref: binding.session_binding_ref,
    session_route_ref: binding.session_route_ref,
    harness_selection_ref: binding.harness_selection_ref,
    agent_harness_adapter_id: null,
    model_configuration_ref: binding.model_configuration_ref,
    model_route_ref: binding.model_route_ref,
    model_name: "qwen",
    provider: "ollama" as const,
    codex_binary: "codex",
    provider_binary: "ollama",
    available_model_names: ["qwen"],
    checks: [
      {
        id: "codex_binary",
        status: "pass" as const,
        required: true as const,
        summary: "Codex binary resolved.",
        evidence_refs: ["host-command:codex:--help"],
      },
      {
        id: "codex_oss_flags",
        status: "pass" as const,
        required: true as const,
        summary: "Codex OSS flags resolved.",
        evidence_refs: ["host-command:codex:oss-flags"],
      },
      {
        id: "ollama_provider",
        status: "pass" as const,
        required: true as const,
        summary: "Ollama provider answered.",
        evidence_refs: ["host-command:ollama:list"],
      },
      {
        id: "qwen_model_available",
        status: "pass" as const,
        required: true as const,
        summary: "Qwen model is available.",
        evidence_refs: ["model:qwen"],
      },
    ],
    operator_next_action:
      "Attach the client PTY using the daemon-resolved command contract.",
    receipt_refs: [`receipt://harness-session-readiness/${id}`],
    agentgres_operation_refs: [
      `agentgres://operation/harness-session-readiness/${id}`,
    ],
    state_root: `agentgres://state-root/harness-session-readiness/${id}`,
    checked_at: "2026-06-18T12:40:00.000Z",
    requiresDaemonGate: true as const,
    runtimeTruthSource: "daemon-runtime" as const,
  };
}

function launchSummary(id: string): HypervisorNewSessionLaunchSummary {
  const binding = harnessSessionBinding(id);
  return {
    schema_version: "ioi.hypervisor.new_session_launch_summary.v1",
    recipe_ref: "mission.default",
    seed_intent: `Run ${id}`,
    target_binding_ref: `target-binding:${id}`,
    target_binding: {
      schema_version: "ioi.hypervisor.new_session_target_binding.v1",
      target_binding_ref: `target-binding:${id}`,
      recipe_ref: "mission.default",
      target_kind: "mission",
      surface_id: "sessions",
      project_ref: "project:ioi",
      operator_intent_ref: `target-binding:${id}/intent`,
      session_route_ref: `session-route:sessions/${id}`,
      code_editor_adapter_target_ref: null,
      automation_recipe_ref: null,
      agent_template_ref: null,
      foundry_job_ref: null,
      provider_candidate_ref: null,
      environment_ref: null,
      private_workspace_ref: null,
      runtimeTruthSource: "daemon-runtime",
    },
    project_ref: "project:ioi",
    code_editor_adapter_ref: "code-editor-adapter:embedded_code_editor",
    code_editor_adapter_target_ref: "code-editor-target:embedded",
    code_editor_adapter_custody_posture: "local_projection",
    code_editor_adapter_launch_plan_ref: `launch-plan:${id}`,
    code_editor_adapter_connection_contract_ref: `connection-contract:${id}`,
    code_editor_adapter_executor_lane: "embedded_code_editor_host",
    code_editor_adapter_control_action: "open_embedded_code_editor",
    code_editor_adapter_control_channel_ref: `control-channel:${id}`,
    code_editor_adapter_access_lease_refs: [`lease:code-editor/${id}`],
    code_editor_adapter_authority_scope_refs: ["scope:workspace.read"],
    code_editor_adapter_receipt_refs: [`receipt://code-editor/${id}`],
    harness_selection_ref: "harness-profile:default_harness_profile",
    harness_selection_kind: "harness_profile",
    harness_label: "Default Harness Profile",
    harness_runtime_truth_source: "daemon-runtime",
    harness_truth_boundary: "daemon-owned",
    harness_verdict_state: "compatible",
    harness_session_binding_ref: binding.session_binding_ref,
    harness_session_binding: binding,
    model_route_ref: "model-route:hypervisor/default-local",
    model_route_availability_state: "daemon_verified",
    model_route_available: true,
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    privacy_posture_ref: "privacy:ctee-private-workspace",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_preview_ref: `receipt-preview:new-session/${id}`,
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

function launchedSession(
  id: string,
  launchedAtMs = 1_718_000,
): HypervisorLaunchedSessionProjection {
  const binding = harnessSessionBinding(id);
  const bindingAdmission = harnessSessionBindingAdmission(id);
  const bindingLaunch = harnessSessionLaunch(id);
  const bindingSpawn = harnessSessionSpawn(id);
  const bindingReadiness = harnessSessionReadiness(id);
  return {
    schema_version: "ioi.hypervisor.launched_session_projection.v1",
    session_ref: `session:launch/${id}`,
    launch_receipt_ref: `receipt://hypervisor/new-session/${id}`,
    recipe_ref: "mission.default",
    recipe_kind: "mission",
    surface_id: "sessions",
    project_ref: "project:ioi",
    project_label: "IOI",
    launched_at_ms: launchedAtMs,
    admission_state: "daemon_admitted",
    code_editor_adapter_admission: null,
    code_editor_adapter_admission_ref: null,
    harness_session_binding_ref: binding.session_binding_ref,
    harness_session_binding: binding,
    harness_session_binding_admission: bindingAdmission,
    harness_session_binding_admission_ref: bindingAdmission.admission_id,
    harness_session_launch: bindingLaunch,
    harness_session_launch_ref: bindingLaunch.launch_id,
    harness_session_spawn: bindingSpawn,
    harness_session_spawn_ref: bindingSpawn.spawn_id,
    harness_session_readiness: bindingReadiness,
    harness_session_readiness_ref: bindingReadiness.readiness_id,
    launch_summary: launchSummary(id),
    runtimeTruthSource: "daemon-runtime",
  };
}

test("launched session cache loads only daemon-runtime projection records", () => {
  const storage = new MemoryStorage();
  storage.setItem(
    HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
    JSON.stringify([
      launchedSession("valid"),
      { schema_version: "ioi.hypervisor.launched_session_projection.v1" },
      {
        ...launchedSession("wrong-truth"),
        runtimeTruthSource: "local-ui-cache",
      },
    ]),
  );

  const loaded = loadHypervisorLaunchedSessionProjections({ storage });
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0]?.session_ref, "session:launch/valid");
  assert.equal(loaded[0]?.runtimeTruthSource, "daemon-runtime");
});

test("launched session merge deduplicates session refs and caps local projection history", () => {
  const current = Array.from(
    { length: HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT + 3 },
    (_, index) => launchedSession(`older-${index}`, index),
  );
  const duplicate = {
    ...launchedSession("older-3", 99),
    project_label: "Updated",
  };

  const merged = mergeHypervisorLaunchedSessionProjection(current, duplicate);
  assert.equal(merged.length, HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT);
  assert.equal(merged[0]?.session_ref, "session:launch/older-3");
  assert.equal(merged[0]?.project_label, "Updated");
  assert.equal(
    merged.filter((projection) => projection.session_ref === "session:launch/older-3")
      .length,
    1,
  );
});

test("launched session cache persists normalized projections only", () => {
  const storage = new MemoryStorage();
  persistHypervisorLaunchedSessionProjections({
    storage,
    projections: [
      launchedSession("persisted"),
      {
        ...launchedSession("bad"),
        session_ref: "not-a-session-ref",
      },
    ],
  });

  const raw = storage.getItem(HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY);
  assert.ok(raw);
  const parsed = JSON.parse(raw) as HypervisorLaunchedSessionProjection[];
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.session_ref, "session:launch/persisted");
  assert.equal(parsed[0]?.launch_summary.requires_daemon_gate, true);
  assert.equal(
    parsed[0]?.harness_session_binding.model_configuration_ref,
    "model-config:local/codex-oss-qwen",
  );
  assert.equal(
    parsed[0]?.harness_session_binding_admission?.schema_version,
    "ioi.runtime.harness_session_binding_admission.v1",
  );
  assert.equal(
    parsed[0]?.harness_session_launch?.schema_version,
    "ioi.runtime.harness_session_launch.v1",
  );
  assert.equal(
    parsed[0]?.harness_session_launch?.command_contract.command_ref,
    "host-command:codex-cli/local-ollama-qwen",
  );
  assert.equal(
    parsed[0]?.harness_session_spawn?.schema_version,
    "ioi.runtime.harness_session_spawn.v1",
  );
  assert.equal(
    parsed[0]?.harness_session_spawn?.command_contract.process_custody,
    "client_host_pty_after_daemon_spawn_admission",
  );
});

test("launched session cache rejects loose sessions without harness admission", () => {
  const storage = new MemoryStorage();
  const looseSession = launchedSession("loose") as unknown as Record<string, unknown>;
  delete looseSession.harness_session_binding_admission;
  delete looseSession.harness_session_binding_admission_ref;
  storage.setItem(
    HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
    JSON.stringify([looseSession]),
  );

  assert.deepEqual(loadHypervisorLaunchedSessionProjections({ storage }), []);
});

test("launched session cache rejects loose sessions without harness launch", () => {
  const storage = new MemoryStorage();
  const looseSession = launchedSession("loose") as unknown as Record<string, unknown>;
  delete looseSession.harness_session_launch;
  delete looseSession.harness_session_launch_ref;
  storage.setItem(
    HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
    JSON.stringify([looseSession]),
  );

  assert.deepEqual(loadHypervisorLaunchedSessionProjections({ storage }), []);
});

test("launched session cache rejects loose sessions without harness spawn", () => {
  const storage = new MemoryStorage();
  const looseSession = launchedSession("loose") as unknown as Record<string, unknown>;
  delete looseSession.harness_session_spawn;
  delete looseSession.harness_session_spawn_ref;
  storage.setItem(
    HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
    JSON.stringify([looseSession]),
  );

  assert.deepEqual(loadHypervisorLaunchedSessionProjections({ storage }), []);
});

test("launched session cache rejects loose sessions without harness binding", () => {
  const storage = new MemoryStorage();
  const looseSession = launchedSession("loose") as unknown as Record<string, unknown>;
  delete looseSession.harness_session_binding;
  delete looseSession.harness_session_binding_ref;
  const looseSummary = looseSession.launch_summary as Record<string, unknown>;
  delete looseSummary.harness_session_binding;
  delete looseSummary.harness_session_binding_ref;
  storage.setItem(
    HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
    JSON.stringify([looseSession]),
  );

  assert.deepEqual(loadHypervisorLaunchedSessionProjections({ storage }), []);
});

test("fresh launched session projection cache starts empty without local restore truth", () => {
  const storage = new MemoryStorage();

  assert.deepEqual(
    loadHypervisorLaunchedSessionProjections({ storage }),
    [],
  );
});
