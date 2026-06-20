import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { buildHarnessSessionLaunch } from "./runtime-harness-session-launch.mjs";
import { buildHarnessSessionSpawn } from "./runtime-harness-session-spawn.mjs";
import { executeHarnessSpawnLane } from "./runtime-harness-spawn-executor.mjs";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

function genericCliBindingAdmission() {
  return {
    schema_version: "ioi.runtime.harness_session_binding_admission.v1",
    admission_id: "harness-session-binding-admission:generic-cli-local",
    decision: "admitted",
    admission_state: "admitted_for_harness_launch",
    session_binding_ref:
      "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-generic_cli:model-config-local-codex-oss-qwen",
    session_route_ref: "session-route:sessions/mission.default/project:ioi",
    harness_selection_ref: "agent-harness-adapter:generic_cli",
    harness_selection_kind: "agent_harness_adapter",
    harness_truth_boundary: "proposal_source_only",
    harness_launch_route_ref: "harness-route:generic-cli/local-model",
    agent_harness_adapter_id: "generic_cli",
    harness_profile_ref: null,
    model_configuration_ref: "model-config:local/codex-oss-qwen",
    model_route_ref: "model-route:hypervisor/default-local",
    model_route_policy: "hypervisor_model_mount",
    model_route_availability_state: "daemon_verified",
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    model_route_loaded_instance_refs: ["model-instance:hypervisor/default-local"],
    workspace_mount_policy: "plain_workspace",
    privacy_posture_ref: "privacy:plain-workspace",
    authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
    receipt_policy_ref: "receipt-policy:harness-adapter/generic-cli",
    receipt_preview_ref: "receipt-preview:new-session/admitted",
    expected_receipt_refs: ["receipt-preview:new-session/admitted"],
    agentgres_operation_refs: ["agentgres://operation/harness-session-binding/admit"],
    receipt_refs: ["receipt://harness-session-binding/admit"],
    state_root: "agentgres://state-root/harness-session-binding/admit",
    harness_runtime_truth_claimed: false,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: "2026-06-18T12:00:00.000Z",
  };
}

function genericCliSpawn(workspaceRoot) {
  const launch = buildHarnessSessionLaunch(
    {
      binding_admission: genericCliBindingAdmission(),
      workspace_ref: "workspace:hypervisor-core",
      terminal_session_ref: "terminal-session:hypervisor-core/generic-cli",
    },
    { nowIso: () => "2026-06-18T12:30:00.000Z" },
  );
  return buildHarnessSessionSpawn(
    { session_launch: launch, workspace_root: workspaceRoot },
    { baseWorkspaceRoot: REPO_ROOT, env: {}, nowIso: () => "2026-06-18T12:35:00.000Z" },
  );
}

function startStubModel(manifest) {
  return new Promise((resolve) => {
    const server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => {
        body += chunk;
      });
      request.on("end", () => {
        response.setHeader("content-type", "application/json");
        response.end(
          JSON.stringify({
            choices: [{ message: { content: JSON.stringify(manifest) } }],
          }),
        );
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, url: `http://127.0.0.1:${port}/v1` });
    });
  });
}

async function withWorkspace(run) {
  const workspace = await fs.mkdtemp(
    path.join(os.tmpdir(), "ioi-spawn-lane-test-"),
  );
  try {
    await run(workspace);
  } finally {
    await fs.rm(workspace, { recursive: true, force: true });
  }
}

test("runs the harness lane and writes the model's files into the workspace", async () => {
  await withWorkspace(async (workspace) => {
    const manifest = {
      summary: "Created a static PQC explainer site.",
      files: [
        {
          path: "index.html",
          content:
            "<!doctype html><html><head><title>Post-Quantum Computers</title></head>" +
            "<body><h1>Post-Quantum Computers</h1><p>Quantum-resistant cryptography.</p></body></html>",
        },
        { path: "styles.css", content: "body{font-family:system-ui}" },
      ],
    };
    const stub = await startStubModel(manifest);
    try {
      const chunks = [];
      const result = await executeHarnessSpawnLane(
        {
          spawn: genericCliSpawn(workspace),
          intent: "create a website that explains post-quantum computers",
          model_endpoint: stub.url,
        },
        { onChunk: (line) => chunks.push(line), timeoutMs: 15_000 },
      );
      assert.equal(result.exit_status, "success", result.stderr || result.error);
      assert.deepEqual(result.files_written.sort(), ["index.html", "styles.css"]);
      // Real files on disk in the isolated workspace.
      assert.ok(existsSync(path.join(workspace, "index.html")));
      const html = await fs.readFile(path.join(workspace, "index.html"), "utf8");
      assert.match(html, /Post-Quantum Computers/);
      // The transcript is the harness's real stdout, not canned prose.
      assert.ok(chunks.some((line) => line.includes("wrote index.html")));
      assert.equal(result.runtimeTruthSource, "daemon-runtime");
    } finally {
      stub.server.close();
    }
  });
});

test("emits an honest no-model result (no files) when the model route is unreachable", async () => {
  await withWorkspace(async (workspace) => {
    const result = await executeHarnessSpawnLane(
      {
        spawn: genericCliSpawn(workspace),
        intent: "create a website that explains post-quantum computers",
        // Port 1 is unreachable: the harness must report an honest no-model
        // result instead of faking files.
        model_endpoint: "http://127.0.0.1:1/v1",
      },
      { timeoutMs: 15_000 },
    );
    assert.equal(result.exit_status, "failure");
    assert.equal(result.error, "no_model_route");
    assert.deepEqual(result.files_written, []);
    assert.equal(existsSync(path.join(workspace, "index.html")), false);
  });
});

test("rejects an unadmitted spawn contract", async () => {
  await assert.rejects(
    () =>
      executeHarnessSpawnLane({
        spawn: { schema_version: "ioi.runtime.harness_session_spawn.v1", decision: "blocked" },
        intent: "do work",
      }),
    (error) => {
      assert.equal(error.code, "harness_spawn_lane_spawn_boundary_invalid");
      return true;
    },
  );
});
