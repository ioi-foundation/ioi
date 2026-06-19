import assert from "node:assert/strict";
import test from "node:test";

import {
  HARNESS_SESSION_SPAWN_SCHEMA_VERSION,
  buildHarnessSessionSpawn,
} from "./runtime-harness-session-spawn.mjs";
import { buildHarnessSessionLaunch } from "./runtime-harness-session-launch.mjs";

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

function launchContract() {
  return buildHarnessSessionLaunch(
    {
      binding_admission: bindingAdmission(),
      workspace_ref: "workspace:hypervisor-core",
      terminal_session_ref: "terminal-session:hypervisor-core/workbench",
    },
    { nowIso: () => "2026-06-18T12:30:00.000Z" },
  );
}

test("builds a Codex OSS local Qwen spawn contract for client PTY attach", () => {
  const spawn = buildHarnessSessionSpawn(
    {
      session_launch: launchContract(),
      workspace_root: ".",
    },
    {
      baseWorkspaceRoot: "/home/heathledger/Documents/ioi/repos/ioi",
      env: {},
      nowIso: () => "2026-06-18T12:35:00.000Z",
    },
  );

  assert.equal(spawn.schema_version, HARNESS_SESSION_SPAWN_SCHEMA_VERSION);
  assert.equal(spawn.decision, "admitted");
  assert.equal(spawn.spawn_state, "ready_for_client_pty_attach");
  assert.equal(spawn.spawn_lane, "host_terminal_session");
  assert.equal(spawn.model_name, "qwen");
  assert.equal(spawn.workspace_root, "/home/heathledger/Documents/ioi/repos/ioi");
  assert.deepEqual(spawn.command_contract.resolved_argv, [
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
    "/home/heathledger/Documents/ioi/repos/ioi",
  ]);
  assert.equal(
    spawn.terminal_attach_contract.command_line,
    "codex --oss --local-provider ollama --model qwen --sandbox workspace-write --ask-for-approval on-request --cd /home/heathledger/Documents/ioi/repos/ioi",
  );
  assert.equal(
    spawn.command_contract.process_custody,
    "client_host_pty_after_daemon_spawn_admission",
  );
  assert.equal(spawn.requiresDaemonGate, true);
  assert.equal(spawn.runtimeTruthSource, "daemon-runtime");
});

test("honors a configured local model name without allowing shell fragments", () => {
  const spawn = buildHarnessSessionSpawn(
    {
      session_launch: launchContract(),
      workspace_root: "apps/hypervisor",
    },
    {
      baseWorkspaceRoot: "/repo",
      env: { HYPERVISOR_LOCAL_CODEX_OSS_MODEL: "qwen2.5-coder:7b" },
    },
  );
  assert.equal(spawn.model_name, "qwen2.5-coder:7b");
  assert.equal(spawn.workspace_root, "/repo/apps/hypervisor");

  assert.throws(
    () =>
      buildHarnessSessionSpawn(
        {
          session_launch: launchContract(),
          workspace_root: ".",
          model_name: "qwen; rm -rf /",
        },
        { baseWorkspaceRoot: "/repo" },
      ),
    (error) => {
      assert.equal(error.code, "harness_session_spawn_model_name_forbidden");
      return true;
    },
  );
});

test("blocks invalid launch contracts and filesystem root workspaces", () => {
  assert.throws(
    () =>
      buildHarnessSessionSpawn({
        session_launch: { ...launchContract(), launch_state: "blocked" },
        workspace_root: ".",
      }),
    (error) => {
      assert.equal(error.code, "harness_session_spawn_launch_boundary_invalid");
      return true;
    },
  );

  assert.throws(
    () =>
      buildHarnessSessionSpawn({
        session_launch: launchContract(),
        workspace_root: "/",
      }),
    (error) => {
      assert.equal(error.code, "harness_session_spawn_workspace_root_forbidden");
      return true;
    },
  );
});
