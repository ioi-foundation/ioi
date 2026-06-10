import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlManagedSessionForThread,
  inspectManagedSessionsForThread,
} from "./managed-session-state.mjs";

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

test("managed session thread inspection fails closed for fixture threads before JS fallback projection", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_fixture",
      cwd: "/workspace",
      runtimeProfile: "fixture",
    },
  });

  await assert.rejects(
    inspectManagedSessionsForThread(store, "thread_fixture", {}, deps()),
    assertManagedSessionInspectionRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});

test("managed session thread inspection fails closed before JS bridge projection", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async inspectThread(input) {
        assert.fail(`managed session JS inspection bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
    },
  });

  await assert.rejects(
    inspectManagedSessionsForThread(store, "thread_runtime", {}, deps()),
    assertManagedSessionInspectionRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});

test("managed session thread inspection fails closed before retired request alias handling", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
  });

  for (const alias of ["sessionId", "threadId", "workspaceRoot", "managedSessionsOnly", "requestedAt"]) {
    await assert.rejects(
      inspectManagedSessionsForThread(store, "thread_runtime", { [alias]: "retired" }, deps()),
      assertManagedSessionInspectionRustCoreRequired,
    );
  }
  assert.deepEqual(store.calls, []);
});

function assertManagedSessionInspectionRustCoreRequired(error) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_managed_session_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.managed_session_control");
  assert.equal(error.details.operation, "managed_session_inspection");
  assert.equal(error.details.operation_kind, "managed_session.inspect");
  assert.match(error.details.thread_id, /^thread_(fixture|runtime)$/);
  assert.deepEqual(error.details.evidence_refs, [
    "managed_session_inspection_js_facade_retired",
    "managed_session_inspection_bridge_projection_retired",
    "rust_daemon_core_managed_session_projection_required",
    "agentgres_managed_session_truth_required",
  ]);
  for (const key of ["threadId", "operationKind", "rustCoreBoundary", "evidenceRefs", "retiredAliases"]) {
    assert.equal(Object.hasOwn(error.details, key), false);
  }
  return true;
}

function assertManagedSessionControlRustCoreRequired(error) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_managed_session_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.managed_session_control");
  assert.equal(error.details.operation, "managed_session_control");
  assert.equal(error.details.operation_kind, "managed_session_control");
  assert.equal(error.details.thread_id, "thread_runtime");
  assert.deepEqual(error.details.evidence_refs, [
    "managed_session_control_js_facade_retired",
    "managed_session_control_bridge_dispatch_retired",
    "managed_session_control_result_envelope_js_retired",
    "rust_daemon_core_managed_session_control_required",
    "agentgres_managed_session_truth_required",
  ]);
  for (const key of ["threadId", "operationKind", "rustCoreBoundary", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(error.details, key), false);
  }
  return true;
}

test("managed session control facade fails closed before JS bridge dispatch or result envelope", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async controlThread(input) {
        assert.fail(`managed session JS control bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
    },
  });

  await assert.rejects(
    controlManagedSessionForThread(store, "thread_runtime", {
      managed_session_id: "sandbox_browser:test",
      managedSessionId: "retired_session",
      sessionCardId: "retired_card",
      action: "take over",
      createdAt: "2026-06-03T00:00:00.000Z",
      requestHash: "retired_hash",
    }, deps()),
    assertManagedSessionControlRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});
