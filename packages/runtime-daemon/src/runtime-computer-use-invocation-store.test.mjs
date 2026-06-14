import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

async function withStore(fn) {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-computer-use-invocation-store-"));
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: modelMountCoreForComputerUseTest(),
  });
  try {
    return await fn(store);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
}

function modelMountCoreForComputerUseTest() {
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
    throw new Error("agentForThread must not be called by computer-use public Rust lease adapter");
  };
  store.runtimeEventStream = () => {
    throw new Error("runtimeEventStream must not be read by computer-use public Rust lease adapter");
  };
  store.admitComputerUseRuntimeEvent = () => {
    throw new Error("admitComputerUseRuntimeEvent must not be reached by computer-use public Rust lease adapter");
  };
}

function mountRustLeaseRequestSurface(store) {
  const calls = [];
  store.codingToolInvocationSurface = {
    invokeThreadTool(surfaceStore, threadId, toolId, request) {
      calls.push({ surfaceStore, threadId, toolId, request });
      return {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        object: "ioi.runtime_coding_tool_result",
        tool_name: toolId,
        status: "completed",
        receipt_refs: ["receipt://rust/computer-use-lease"],
        result: {
          rust_workload: true,
          request_ref: "computer_use_lease_request_test",
          lease_request: {
            lane: request.input?.lane ?? null,
            session_mode: request.input?.session_mode ?? null,
            action_kind: request.input?.action_kind ?? null,
            sandbox_provider: request.input?.sandbox_provider ?? null,
          },
          thread_tool: {
            tool_pack: "computer_use",
            tool_name: request.computer_use_public_tool_id,
            input: request.input,
          },
          wallet_network_authority_boundary: {
            authority_layer: "wallet.network",
            required_before_execution: true,
            grant_refs: [],
            receipt_refs: [],
          },
          evidence_refs: [
            "rust_daemon_core_computer_use_request_lease",
            "wallet.network.authority_boundary",
          ],
          receipt_refs: ["receipt://rust/computer-use-lease"],
          shell_fallback_used: false,
        },
      };
    },
  };
  return calls;
}

test("computer-use public invocation facades route to Rust request-lease StepModule", async () => {
  await withStore(async (store) => {
    poisonJsComputerUseTruthPaths(store);
    const calls = mountRustLeaseRequestSurface(store);
    store.pathFor = () => {
      throw new Error("pathFor must not be called by computer-use public Rust lease adapter");
    };

    const request = {
      tool_call_id: "tool_alpha",
      workflow_graph_id: "graph_alpha",
    };
    const results = [
      store.invokeComputerUseBrowserDiscoveryTool(
        "thread_alpha",
        "ioi.computer_use.browser_discovery",
        request,
      ),
      store.invokeComputerUseControlTool("thread_alpha", "ioi.computer_use.control", request),
      await store.invokeComputerUseNativeBrowserTool(
        "thread_alpha",
        "ioi.computer_use.native_browser",
        request,
      ),
      await store.invokeComputerUseVisualGuiTool("thread_alpha", "ioi.computer_use.visual_gui", request),
      await store.invokeComputerUseSandboxedHostedTool(
        "thread_alpha",
        "ioi.computer_use.sandboxed_hosted",
        request,
      ),
      await store.invokeComputerUseVisualGuiObserveTool(
        "thread_alpha",
        "ioi.computer_use.visual_gui.observe",
        request,
      ),
    ];

    assert.equal(calls.length, 6);
    assert.deepEqual(
      calls.map((call) => call.toolId),
      Array(6).fill("computer_use.request_lease"),
    );
    assert.deepEqual(
      calls.map((call) => call.request.computer_use_operation_kind),
      [
        "computer_use.browser_discovery",
        "computer_use.control",
        "computer_use.native_browser",
        "computer_use.visual_gui",
        "computer_use.sandboxed_hosted",
        "computer_use.visual_gui.observe",
      ],
    );
    assert.ok(calls.every((call) => call.surfaceStore === store));
    assert.ok(calls.every((call) => call.threadId === "thread_alpha"));
    assert.ok(results.every((result) => result.status === "completed"));
    assert.ok(results.every((result) => result.result.rust_workload === true));
    assert.ok(
      results.every((result) =>
        result.result.receipt_refs.includes("receipt://rust/computer-use-lease"),
      ),
    );
    assert.ok(
      results.every(
        (result) => result.result.wallet_network_authority_boundary.authority_layer === "wallet.network",
      ),
    );
  });
});

test("computer-use public invocation adapter preserves canonical lease request fields", async () => {
  await withStore(async (store) => {
    const calls = mountRustLeaseRequestSurface(store);

    await store.invokeComputerUseNativeBrowserTool("thread_alpha", "ioi.computer_use.native_browser", {
      tool_call_id: "tool_alpha",
      workflow_graph_id: "graph_alpha",
      workflow_node_id: "node_alpha",
      input: {
        prompt: "Click the sign-in button.",
        lane: "native_browser",
        session_mode: "attached_browser",
        action_kind: "click",
        url: "https://example.test",
        target_ref: "target_alpha",
        selector: "#sign-in",
      },
    });
    await store.invokeComputerUseVisualGuiTool("thread_alpha", "ioi.computer_use.visual_gui", {
      input: {},
    });
    await store.invokeComputerUseSandboxedHostedTool("thread_alpha", "ioi.computer_use.sandboxed_hosted", {
      input: {},
    });
    store.invokeComputerUseBrowserDiscoveryTool("thread_alpha", "ioi.computer_use.browser_discovery", {
      prompt: "List governed browser sessions.",
      lane: "native_browser",
      action_kind: "inspect",
      url: "https://example.test/start",
    });

    assert.equal(calls[0].request.tool_call_id, "tool_alpha");
    assert.equal(calls[0].request.workflow_graph_id, "graph_alpha");
    assert.equal(calls[0].request.workflow_node_id, "node_alpha");
    assert.deepEqual(calls[0].request.input, {
      prompt: "Click the sign-in button.",
      lane: "native_browser",
      session_mode: "attached_browser",
      action_kind: "click",
      url: "https://example.test",
      target_ref: "target_alpha",
      selector: "#sign-in",
    });
    assert.equal(calls[1].request.input.lane, "visual_gui");
    assert.equal(calls[1].request.input.session_mode, "visual_fallback");
    assert.equal(calls[1].request.input.action_kind, "inspect");
    assert.equal(calls[2].request.input.lane, "sandboxed_hosted");
    assert.equal(calls[2].request.input.session_mode, "local_sandbox");
    assert.equal(calls[2].request.input.action_kind, "inspect");
    assert.equal(calls[2].request.input.sandbox_provider, "local_fixture");
    assert.deepEqual(calls[3].request.input, {
      prompt: "List governed browser sessions.",
      lane: "native_browser",
      action_kind: "inspect",
      url: "https://example.test/start",
    });
    for (const call of calls) {
      for (const key of [
        "toolCallId",
        "workflowGraphId",
        "workflowNodeId",
        "computerUseLane",
        "computerUseSessionMode",
        "actionKind",
        "sandboxProvider",
      ]) {
        assert.equal(Object.hasOwn(call.request, key), false, `${key} request alias must be absent`);
        assert.equal(Object.hasOwn(call.request.input, key), false, `${key} input alias must be absent`);
      }
    }
  });
});
