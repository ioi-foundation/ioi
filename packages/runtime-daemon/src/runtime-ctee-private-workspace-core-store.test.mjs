import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function modelMountCore() {
  return {
    planReadProjection(request) {
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        projection: {
          source: "agentgres_model_mounting_projection",
        },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

test("runtime store mounts cTEE private workspace core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-ctee-private-workspace-core-store-"));
  const cteePrivateWorkspaceCore = { executeAction() {} };
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      cteePrivateWorkspaceCore,
      modelMountCore: modelMountCore(),
    });
    try {
      assert.equal(store.cteePrivateWorkspaceCore, cteePrivateWorkspaceCore);
      assert.equal(Object.hasOwn(store, "cteePrivateWorkspaceRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires cTEE private workspace to typed Rust cTEE API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-ctee-private-workspace-typed-core-store-"));
  const calls = [];
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      daemonCoreInvoker(request) {
        throw new Error(`generic command invoker must not run for cTEE: ${request?.operation}`);
      },
      daemonCoreCteeApi: {
        executePrivateWorkspaceCteeAction(request, context) {
          calls.push({ request, context });
          return {
            schema_version: "ioi.runtime.ctee_private_workspace_admission.v1",
            source: "rust_ctee_private_workspace_protocol",
            backend: "ctee_operator",
            thread_id: context.thread_id,
            agent_id: context.agent_id,
            invocation_id: request.invocation.invocation_id,
          };
        },
      },
    });
    try {
      const result = store.cteePrivateWorkspaceCore.executeAction(
        {
          invocation: {
            invocation_id: "invocation://ctee/store-typed-api",
          },
          node_trust: {
            runtime_node_ref: "node://private-workspace",
            trusted_for_plaintext: false,
          },
        },
        {
          thread_id: "thread_ctee_store",
          agent_id: "agent_ctee_store",
        },
      );

      assert.equal(result.source, "rust_ctee_private_workspace_protocol");
      assert.equal(calls.length, 1);
      assert.equal(calls[0].request.invocation.invocation_id, "invocation://ctee/store-typed-api");
      assert.deepEqual(calls[0].context, {
        thread_id: "thread_ctee_store",
        agent_id: "agent_ctee_store",
      });
      assert.equal(Object.hasOwn(calls[0], "operation"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
