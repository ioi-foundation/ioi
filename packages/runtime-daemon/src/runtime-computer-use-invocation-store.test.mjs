import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function withStore(fn) {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-computer-use-invocation-store-"));
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountAdmissionRunner: modelMountAdmissionRunnerForComputerUseTest(),
  });
  try {
    return fn(store);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
}

function modelMountAdmissionRunnerForComputerUseTest() {
  return {
    planReadProjection(request) {
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
        projection_kind: request.projection_kind,
        projection: { source: "agentgres_model_mounting_projection" },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

function poisonJsComputerUseTruthPaths(store) {
  store.agentForThread = () => {
    throw new Error("agentForThread must not be called by retired computer-use JS facade");
  };
  store.runtimeEventStream = () => {
    throw new Error("runtimeEventStream must not be read by retired computer-use JS facade");
  };
  store.admitComputerUseRuntimeEvent = () => {
    throw new Error("admitComputerUseRuntimeEvent must not be reached by retired computer-use JS facade");
  };
}

function assertComputerUseRustCoreRequired(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_computer_use_invocation_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.computer_use_invocation");
  assert.equal(error.details.operation, "computer_use_invocation_admission");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.thread_id, "thread_alpha");
  assert.equal(error.details.tool_name, `ioi.${operationKind}`);
  assert.equal(error.details.tool_call_id, "tool_alpha");
  assert.equal(error.details.workflow_graph_id, "graph_alpha");
  assert.equal(error.details.workflow_node_id, "node_alpha");
  assert.deepEqual(error.details.evidence_refs, [
    "computer_use_invocation_js_facade_retired",
    "rust_daemon_core_computer_use_invocation_required",
    "wallet_network_computer_use_authority_required",
    "agentgres_computer_use_expected_head_required",
  ]);
  for (const key of ["threadId", "toolName", "toolCallId", "workflowGraphId", "workflowNodeId"]) {
    assert.equal(Object.hasOwn(error.details, key), false, `${key} detail alias must be absent`);
  }
  return true;
}

test("computer-use browser discovery JS facade fails closed before JS truth lookup", () => {
  withStore((store) => {
    poisonJsComputerUseTruthPaths(store);
    assert.throws(
      () =>
        store.invokeComputerUseBrowserDiscoveryTool("thread_alpha", "ioi.computer_use.browser_discovery", {
          tool_call_id: "tool_alpha",
          workflow_graph_id: "graph_alpha",
          workflow_node_id: "node_alpha",
        }),
      (error) => assertComputerUseRustCoreRequired(error, "computer_use.browser_discovery"),
    );
  });
});

test("computer-use control JS facade fails closed before JS truth lookup", () => {
  withStore((store) => {
    poisonJsComputerUseTruthPaths(store);
    assert.throws(
      () =>
        store.invokeComputerUseControlTool("thread_alpha", "ioi.computer_use.control", {
          tool_call_id: "tool_alpha",
          workflow_graph_id: "graph_alpha",
          workflow_node_id: "node_alpha",
        }),
      (error) => assertComputerUseRustCoreRequired(error, "computer_use.control"),
    );
  });
});

test("computer-use native browser JS facade fails closed before JS truth lookup", async () => {
  await withStore(async (store) => {
    poisonJsComputerUseTruthPaths(store);
    await assert.rejects(
      () =>
        store.invokeComputerUseNativeBrowserTool("thread_alpha", "ioi.computer_use.native_browser", {
          tool_call_id: "tool_alpha",
          workflow_graph_id: "graph_alpha",
          workflow_node_id: "node_alpha",
        }),
      (error) => assertComputerUseRustCoreRequired(error, "computer_use.native_browser"),
    );
  });
});

test("computer-use visual GUI JS facade fails closed before JS truth lookup", async () => {
  await withStore(async (store) => {
    poisonJsComputerUseTruthPaths(store);
    await assert.rejects(
      () =>
        store.invokeComputerUseVisualGuiTool("thread_alpha", "ioi.computer_use.visual_gui", {
          tool_call_id: "tool_alpha",
          workflow_graph_id: "graph_alpha",
          workflow_node_id: "node_alpha",
        }),
      (error) => assertComputerUseRustCoreRequired(error, "computer_use.visual_gui"),
    );
  });
});

test("computer-use sandboxed hosted JS facade fails closed before JS truth lookup", async () => {
  await withStore(async (store) => {
    poisonJsComputerUseTruthPaths(store);
    await assert.rejects(
      () =>
        store.invokeComputerUseSandboxedHostedTool("thread_alpha", "ioi.computer_use.sandboxed_hosted", {
          tool_call_id: "tool_alpha",
          workflow_graph_id: "graph_alpha",
          workflow_node_id: "node_alpha",
        }),
      (error) => assertComputerUseRustCoreRequired(error, "computer_use.sandboxed_hosted"),
    );
  });
});
