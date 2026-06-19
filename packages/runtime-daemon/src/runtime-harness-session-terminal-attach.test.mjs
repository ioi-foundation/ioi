import assert from "node:assert/strict";
import test from "node:test";

import { buildHarnessSessionLaunch } from "./runtime-harness-session-launch.mjs";
import { buildHarnessSessionReadiness } from "./runtime-harness-session-readiness.mjs";
import { buildHarnessSessionSpawn } from "./runtime-harness-session-spawn.mjs";
import {
  HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION,
  admitHarnessSessionTerminalAttach,
} from "./runtime-harness-session-terminal-attach.mjs";

function bindingAdmission(overrides = {}) {
  return {
    schema_version: "ioi.runtime.harness_session_binding_admission.v1",
    admission_id: "harness-session-binding-admission:codex-local",
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

function spawnContract() {
  const launch = buildHarnessSessionLaunch(
    {
      binding_admission: bindingAdmission(),
      workspace_ref: "workspace:hypervisor-core",
      terminal_session_ref: "terminal-session:hypervisor-core/workbench",
    },
    { nowIso: () => "2026-06-18T12:30:00.000Z" },
  );
  return buildHarnessSessionSpawn(
    {
      session_launch: launch,
      workspace_root: ".",
    },
    {
      baseWorkspaceRoot: "/home/heathledger/Documents/ioi/repos/ioi",
      env: {},
      nowIso: () => "2026-06-18T12:35:00.000Z",
    },
  );
}

async function readinessContract(spawn, commandOverrides = {}) {
  return buildHarnessSessionReadiness(
    { session_spawn: spawn },
    {
      nowIso: () => "2026-06-18T12:40:00.000Z",
      runCommand: async (command, args) => {
        if (commandOverrides[command]) {
          return commandOverrides[command](args);
        }
        if (command === "codex" && args[0] === "--help") {
          return {
            status: 0,
            stdout:
              "Codex CLI\nOptions:\n  --oss\n  --local-provider <OSS_PROVIDER>\n  --model <MODEL>\n  --cd <DIR>\n",
            stderr: "",
          };
        }
        if (command === "ollama" && args[0] === "list") {
          return {
            status: 0,
            stdout: "NAME ID SIZE MODIFIED\nqwen 123 4 GB now\n",
            stderr: "",
          };
        }
        return { status: 127, stdout: "", stderr: "not found" };
      },
    },
  );
}

test("admits Codex OSS Qwen terminal attach after spawn and readiness", async () => {
  const spawn = spawnContract();
  const readiness = await readinessContract(spawn);
  const attach = admitHarnessSessionTerminalAttach(
    {
      session_spawn: spawn,
      session_readiness: readiness,
    },
    { nowIso: () => "2026-06-18T12:41:00.000Z" },
  );

  assert.equal(
    attach.schema_version,
    HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION,
  );
  assert.equal(attach.decision, "admitted");
  assert.equal(attach.attach_state, "client_pty_attach_admitted");
  assert.equal(attach.attach_lane, "hypervisor_client_terminal_adapter");
  assert.equal(attach.spawn_id, spawn.spawn_id);
  assert.equal(attach.readiness_id, readiness.readiness_id);
  assert.equal(attach.model_name, "qwen");
  assert.equal(
    attach.client_attach_contract.pty_transport,
    "hypervisor_client_terminal_adapter",
  );
  assert.equal(
    attach.client_attach_contract.process_custody,
    "client_host_pty_after_daemon_attach_admission",
  );
  assert.equal(
    attach.client_attach_contract.initial_write,
    `${spawn.terminal_attach_contract.command_line}\n`,
  );
  assert.equal(
    attach.terminal_transcript_projection.transcript_state,
    "awaiting_client_stream",
  );
  assert.deepEqual(
    attach.terminal_transcript_projection.lines.map((line) => line.stream),
    ["system", "stdin"],
  );
  assert.ok(
    attach.agentgres_operation_refs.some((ref) =>
      ref.includes("harness-session-terminal-attach"),
    ),
  );
  assert.equal(attach.requiresDaemonGate, true);
  assert.equal(attach.runtimeTruthSource, "daemon-runtime");
});

test("rejects terminal attach when readiness is blocked", async () => {
  const spawn = spawnContract();
  const readiness = await readinessContract(spawn, {
    ollama: () => ({
      status: 1,
      stdout: "",
      stderr: "could not connect to ollama server",
    }),
  });

  assert.equal(readiness.decision, "blocked");
  assert.throws(
    () =>
      admitHarnessSessionTerminalAttach({
        session_spawn: spawn,
        session_readiness: readiness,
      }),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_terminal_attach_readiness_boundary_invalid",
      );
      return true;
    },
  );
});

test("rejects terminal attach when readiness belongs to another spawn", async () => {
  const spawn = spawnContract();
  const readiness = {
    ...(await readinessContract(spawn)),
    spawn_id: "harness-session-spawn:other",
  };

  assert.throws(
    () =>
      admitHarnessSessionTerminalAttach({
        session_spawn: spawn,
        session_readiness: readiness,
      }),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_terminal_attach_readiness_boundary_invalid",
      );
      return true;
    },
  );
});
