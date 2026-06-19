import assert from "node:assert/strict";
import test from "node:test";

import { buildHarnessSessionLaunch } from "./runtime-harness-session-launch.mjs";
import { buildHarnessSessionReadiness } from "./runtime-harness-session-readiness.mjs";
import { buildHarnessSessionSpawn } from "./runtime-harness-session-spawn.mjs";

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

function deepseekSpawnContract() {
  const launch = buildHarnessSessionLaunch(
    {
      binding_admission: bindingAdmission({
        admission_id: "harness-session-binding-admission:deepseek-local",
        session_binding_ref:
          "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-deepseek_tui:model-config-local-codex-oss-qwen",
        harness_selection_ref: "agent-harness-adapter:deepseek_tui",
        harness_launch_route_ref: "harness-route:deepseek-tui/local-model",
        agent_harness_adapter_id: "deepseek_tui",
        receipt_policy_ref: "receipt-policy:harness-adapter/default",
      }),
      workspace_ref: "workspace:hypervisor-core",
      terminal_session_ref: "terminal-session:hypervisor-core/deepseek",
    },
    { nowIso: () => "2026-06-18T12:31:00.000Z" },
  );
  return buildHarnessSessionSpawn(
    {
      session_launch: launch,
      workspace_root: ".",
    },
    {
      baseWorkspaceRoot: "/home/heathledger/Documents/ioi/repos/ioi",
      env: {},
      nowIso: () => "2026-06-18T12:36:00.000Z",
    },
  );
}

test("admits Codex OSS Qwen readiness when host commands and model are available", async () => {
  const readiness = await buildHarnessSessionReadiness(
    {
      session_spawn: spawnContract(),
    },
    {
      nowIso: () => "2026-06-18T12:40:00.000Z",
      runCommand: async (command, args) => {
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

  assert.equal(
    readiness.schema_version,
    "ioi.runtime.harness_session_readiness.v1",
  );
  assert.equal(readiness.decision, "ready");
  assert.equal(
    readiness.readiness_state,
    "ready_for_harness_pty_attach",
  );
  assert.equal(readiness.spawn_id, spawnContract().spawn_id);
  assert.equal(readiness.model_name, "qwen");
  assert.equal(readiness.harness_binary, "codex");
  assert.equal(readiness.provider_binary, "ollama");
  assert.deepEqual(
    readiness.checks.map((check) => `${check.id}:${check.status}`),
    [
      "harness_binary:pass",
      "harness_local_model_flags:pass",
      "ollama_provider:pass",
      "qwen_model_available:pass",
    ],
  );
  assert.equal(readiness.requiresDaemonGate, true);
  assert.equal(readiness.runtimeTruthSource, "daemon-runtime");
});

test("blocks readiness when Ollama is not reachable", async () => {
  const readiness = await buildHarnessSessionReadiness(
    {
      session_spawn: spawnContract(),
    },
    {
      runCommand: async (command, args) => {
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
            status: 1,
            stdout: "",
            stderr: "could not connect to ollama server",
          };
        }
        return { status: 127, stdout: "", stderr: "not found" };
      },
    },
  );

  assert.equal(readiness.decision, "blocked");
  assert.equal(
    readiness.readiness_state,
    "ollama_provider_unavailable",
  );
  assert.match(
    readiness.operator_next_action,
    /Start the Ollama server/,
  );
  assert.deepEqual(
    readiness.checks.map((check) => `${check.id}:${check.status}`),
    [
      "harness_binary:pass",
      "harness_local_model_flags:pass",
      "ollama_provider:fail",
      "qwen_model_available:fail",
    ],
  );
});

test("admits DeepSeek TUI local Qwen readiness when binary and model are available", async () => {
  const readiness = await buildHarnessSessionReadiness(
    {
      session_spawn: deepseekSpawnContract(),
    },
    {
      runCommand: async (command, args) => {
        if (command === "deepseek" && args[0] === "--help") {
          return {
            status: 0,
            stdout:
              "DeepSeek TUI\nOptions:\n  --provider <PROVIDER>\n  --model <MODEL>\n",
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

  assert.equal(readiness.decision, "ready");
  assert.equal(
    readiness.readiness_state,
    "ready_for_harness_pty_attach",
  );
  assert.equal(readiness.harness_binary, "deepseek");
  assert.equal(readiness.model_name, "qwen");
  assert.deepEqual(
    readiness.checks.map((check) => `${check.id}:${check.status}`),
    [
      "harness_binary:pass",
      "harness_local_model_flags:pass",
      "ollama_provider:pass",
      "qwen_model_available:pass",
    ],
  );
});

test("rejects non-spawn contracts", async () => {
  await assert.rejects(
    () =>
      buildHarnessSessionReadiness({
        session_spawn: { schema_version: "ioi.runtime.other.v1" },
      }),
    (error) => {
      assert.equal(error.code, "harness_session_readiness_spawn_required");
      return true;
    },
  );
});
