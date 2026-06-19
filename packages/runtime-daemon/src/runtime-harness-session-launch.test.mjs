import assert from "node:assert/strict";
import test from "node:test";

import {
  HARNESS_SESSION_LAUNCH_SCHEMA_VERSION,
  buildHarnessSessionLaunch,
} from "./runtime-harness-session-launch.mjs";

function bindingAdmission(overrides = {}) {
  return {
    schema_version: "ioi.runtime.harness_session_binding_admission.v1",
    admission_id:
      "harness-session-binding-admission:harness-session-binding-session-route-sessions-mission-default-project-ioi-agent-harness-adapter-codex_cli-model-config-local-codex-oss-qwen",
    decision: "admitted",
    admission_state: "admitted_for_harness_launch",
    session_binding_ref:
      "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen",
    session_route_ref: "session-route:sessions/mission.default/project:ioi",
    harness_selection_ref: "agent-harness-adapter:codex_cli",
    harness_selection_kind: "agent_harness_adapter",
    harness_truth_boundary: "proposal_source_only",
    harness_launch_route_ref: "harness-route:codex-cli/local-model",
    agent_harness_adapter_id: "codex_cli",
    harness_profile_ref: null,
    model_configuration_ref: "model-config:local/codex-oss-qwen",
    model_route_ref: "model-route:hypervisor/default-local",
    model_route_policy: "hypervisor_model_mount",
    model_route_availability_state: "daemon_verified",
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    model_route_loaded_instance_refs: [
      "model-instance:hypervisor/default-local",
    ],
    workspace_mount_policy: "redacted_projection",
    privacy_posture_ref: "privacy:redacted-projection",
    authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
    receipt_policy_ref: "receipt-policy:harness-adapter/default",
    receipt_preview_ref: "receipt-preview:new-session/admitted",
    expected_receipt_refs: [
      "receipt-preview:new-session/admitted",
      "receipt-policy:harness-adapter/default",
    ],
    agentgres_operation_refs: [
      "agentgres://operation/harness-session-binding/admit",
    ],
    receipt_refs: ["receipt://harness-session-binding/admit"],
    state_root: "agentgres://state-root/harness-session-binding/admit",
    harness_runtime_truth_claimed: false,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: "2026-06-18T12:00:00.000Z",
    ...overrides,
  };
}

test("builds a launch-ready Codex OSS contract for local Qwen model mounts", () => {
  const launch = buildHarnessSessionLaunch(
    {
      binding_admission: bindingAdmission(),
      workspace_ref: "workspace://local/ioi",
      terminal_session_ref: "terminal-session:ioi/codex",
    },
    { nowIso: () => "2026-06-18T12:30:00.000Z" },
  );

  assert.equal(launch.schema_version, HARNESS_SESSION_LAUNCH_SCHEMA_VERSION);
  assert.equal(launch.decision, "admitted");
  assert.equal(launch.launch_state, "ready_to_spawn");
  assert.equal(launch.launch_lane, "host_dev_pty");
  assert.equal(
    launch.command_contract.command_ref,
    "host-command:codex-cli/local-ollama-qwen",
  );
  assert.deepEqual(launch.command_contract.argv_template, [
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
  ]);
  assert.equal(launch.model_mount_contract.provider, "ollama");
  assert.equal(launch.model_mount_contract.api_format, "openai_compatible");
  assert.equal(launch.command_contract.secret_release_policy, "none");
  assert.equal(launch.command_contract.requires_pty, true);
  assert.equal(launch.requiresDaemonGate, true);
  assert.equal(launch.runtimeTruthSource, "daemon-runtime");
  assert.ok(
    launch.receipt_refs.some((ref) =>
      ref.startsWith("receipt://harness-session-launch/"),
    ),
  );
  assert.ok(
    launch.agentgres_operation_refs.some((ref) =>
      ref.startsWith("agentgres://operation/harness-session-launch/"),
    ),
  );
});

test("blocks provider-trust and unavailable model route launches", () => {
  assert.throws(
    () =>
      buildHarnessSessionLaunch({
        binding_admission: bindingAdmission({
          model_route_policy: "provider_trust",
          model_configuration_ref: "model-config:adapter-native/provider-trust",
        }),
      }),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_launch_model_route_policy_blocked",
      );
      return true;
    },
  );

  assert.throws(
    () =>
      buildHarnessSessionLaunch({
        binding_admission: bindingAdmission({
          model_route_availability_state: "missing",
        }),
      }),
    (error) => {
      assert.equal(error.code, "harness_session_launch_model_route_unavailable");
      return true;
    },
  );
});

test("blocks unsupported harnesses even when their binding was admitted", () => {
  assert.throws(
    () =>
      buildHarnessSessionLaunch({
        binding_admission: bindingAdmission({
          harness_selection_ref: "agent-harness-adapter:claude_code_cli",
          agent_harness_adapter_id: "claude_code_cli",
          harness_launch_route_ref: "harness-route:claude-code-cli/local-example",
        }),
      }),
    (error) => {
      assert.equal(error.code, "harness_session_launch_harness_unsupported");
      return true;
    },
  );
});
