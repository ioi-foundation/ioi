import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlWorkspaceChangeForThread,
  inspectWorkspaceChangeReviewsForThread,
} from "./workspace-change-state.mjs";

function deps() {
  return {};
}

function fakeStore({ agent, runtimeBridge = {} }) {
  const calls = [];
  return {
    calls,
    runtimeBridge,
    agentForThread(threadId) {
      calls.push({ operation: "agent_for_thread", threadId });
      return agent;
    },
    assertRuntimeBridgeAvailable(input) {
      calls.push({ operation: "assert_bridge", input });
    },
    runtimeBridgeUnavailable(input) {
      const error = new Error("runtime bridge unavailable");
      error.input = input;
      return error;
    },
  };
}

test("workspace change inspection fails closed for fixture threads before JS fallback projection", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_fixture",
      cwd: "/workspace",
      runtimeProfile: "fixture",
    },
  });

  await assert.rejects(
    inspectWorkspaceChangeReviewsForThread(store, "thread_fixture", {}, deps()),
    assertWorkspaceChangeInspectionRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});

test("workspace change inspection fails closed before JS bridge projection", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async inspectThread(input) {
        assert.fail(`workspace change JS inspection bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
    },
  });

  await assert.rejects(
    inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {}, deps()),
    assertWorkspaceChangeInspectionRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});

test("workspace change inspection fails closed before retired request alias handling", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
  });

  await assert.rejects(
    inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {
      sessionId: "session_retired",
      threadId: "thread_retired",
      workspaceRoot: "/retired",
      requestedAt: "2026-06-03T00:00:00.000Z",
    }, deps()),
    assertWorkspaceChangeInspectionRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});

function assertWorkspaceChangeInspectionRustCoreRequired(error) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_workspace_change_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
  assert.equal(error.details.operation, "workspace_change_inspection");
  assert.equal(error.details.operation_kind, "workspace_change.inspect");
  assert.match(error.details.thread_id, /^thread_(fixture|runtime)$/);
  assert.deepEqual(error.details.evidence_refs, [
    "workspace_change_inspection_js_facade_retired",
    "workspace_change_inspection_bridge_projection_retired",
    "rust_daemon_core_workspace_change_projection_required",
    "agentgres_workspace_change_truth_required",
  ]);
  for (const key of ["threadId", "operationKind", "rustCoreBoundary", "evidenceRefs", "retiredAliases"]) {
    assert.equal(Object.hasOwn(error.details, key), false);
  }
  return true;
}

function assertWorkspaceChangeControlRustCoreRequired(error) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_workspace_change_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
  assert.equal(error.details.operation, "workspace_change_control");
  assert.equal(error.details.operation_kind, "workspace_change_control");
  assert.equal(error.details.thread_id, "thread_runtime");
  assert.deepEqual(error.details.evidence_refs, [
    "workspace_change_control_js_facade_retired",
    "workspace_change_control_bridge_dispatch_retired",
    "workspace_change_control_receipt_synthesis_js_retired",
    "rust_daemon_core_workspace_change_control_required",
    "agentgres_workspace_change_truth_required",
  ]);
  for (const key of ["threadId", "operationKind", "rustCoreBoundary", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(error.details, key), false);
  }
  return true;
}

test("workspace change control facade fails closed before JS bridge dispatch or result envelope", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async controlThread(input) {
        assert.fail(`workspace change JS control bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
    },
  });

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", {
      tool_id: "workspace_change__reject",
      toolId: "workspace_change__accept",
      input: {
        change_id: "workspace_change:file:0",
        changeId: "workspace_change:file:1",
        workspace_change_id: "workspace_change:file:2",
      },
      created_at: "2026-06-03T00:00:00.000Z",
      requestHash: "retired_hash",
    }, deps()),
    assertWorkspaceChangeControlRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});
