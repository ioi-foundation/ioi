import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlManagedSessionForThread,
  inspectManagedSessionsForThread,
} from "./managed-session-state.mjs";

class BridgeUnavailableError extends Error {
  constructor(details = {}) {
    super("bridge unavailable");
    this.details = details;
  }
}

function deps() {
  return {
    RuntimeApiBridgeUnavailableError: BridgeUnavailableError,
    doctorHash: (value) => `hash-${String(value).length}`.padEnd(24, "0"),
    isRuntimeBackedAgent: (agent) => agent.runtimeProfile === "runtime_service",
    optionalString: (value) => {
      if (value === undefined || value === null) return null;
      const text = String(value).trim();
      return text ? text : null;
    },
    runtimeSessionIdForAgent: (agent) => agent.runtimeSessionId ?? `session_${agent.id}`,
  };
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

function assertNoRetiredContractDetailAliases(details) {
  for (const field of ["threadId"]) {
    assert.equal(Object.hasOwn(details, field), false, `retired managed session detail alias ${field}`);
  }
}

test("managed session thread inspection returns replay-safe empty snapshot for fixture threads", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_fixture",
      cwd: "/workspace",
      runtimeProfile: "fixture",
    },
  });

  const inspected = await inspectManagedSessionsForThread(store, "thread_fixture", {}, deps());

  assert.equal(inspected.status, "not_runtime_backed");
  assert.equal(inspected.session_id, "session_agent_fixture");
  assert.equal(inspected.managed_sessions.thread_id, "thread_fixture");
  assert.deepEqual(inspected.managed_sessions.sessions, []);
  for (const field of ["threadId", "sessionId", "runtimeProfile", "managedSessions"]) {
    assert.equal(Object.hasOwn(inspected, field), false, `retired managed session alias ${field}`);
  }
});

test("managed session thread inspection calls runtime bridge and normalizes result", async () => {
  const bridgeCalls = [];
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async inspectThread(input) {
        bridgeCalls.push(input);
        return {
          bridge_id: "bridge_runtime",
          managed_sessions: {
            sessions: [{ id: "sandbox_browser:test", kind: "sandbox_browser" }],
          },
        };
      },
    },
  });

  const inspected = await inspectManagedSessionsForThread(store, "thread_runtime", {}, deps());

  assert.equal(bridgeCalls[0].projection, "managed_sessions");
  assert.equal(bridgeCalls[0].managed_sessions_only, true);
  assert.equal(bridgeCalls[0].session_id, "session_runtime");
  assert.equal(bridgeCalls[0].thread_id, "thread_runtime");
  assert.equal(bridgeCalls[0].workspace_root, "/workspace");
  assert.equal(typeof bridgeCalls[0].requested_at, "string");
  for (const field of ["sessionId", "threadId", "workspaceRoot", "managedSessionsOnly", "requestedAt"]) {
    assert.equal(Object.hasOwn(bridgeCalls[0], field), false, `retired managed session bridge alias ${field}`);
  }
  assert.equal(inspected.bridge_id, "bridge_runtime");
  assert.equal(inspected.managed_sessions.sessions[0].id, "sandbox_browser:test");
  assert.equal(Object.hasOwn(inspected, "managedSessions"), false);
});

test("managed session thread inspection rejects retired bridge request aliases", async () => {
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
      (error) => {
        assert.equal(error.code, "managed_session_inspection_request_aliases_retired");
        assert.equal(error.details.thread_id, "thread_runtime");
        assert.deepEqual(error.details.retired_aliases, [alias]);
        assertNoRetiredContractDetailAliases(error.details);
        return true;
      },
    );
  }
});

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
