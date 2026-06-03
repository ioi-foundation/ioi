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
  assert.equal(bridgeCalls[0].managedSessionsOnly, true);
  assert.equal(inspected.bridge_id, "bridge_runtime");
  assert.equal(inspected.managed_sessions.sessions[0].id, "sandbox_browser:test");
});

test("managed session control builds normalized bridge command and inspection envelope", async () => {
  const bridgeCalls = [];
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async controlThread(input) {
        bridgeCalls.push(input);
        return {
          action: input.action,
          status: "completed",
          inspection: {
            bridge_id: "bridge_runtime",
            managed_sessions: {
              sessions: [{ id: input.managedSessionId, control_state: "take_over" }],
            },
          },
        };
      },
    },
  });

  const controlled = await controlManagedSessionForThread(store, "thread_runtime", {
    managedSessionId: "sandbox_browser:test",
    action: "take over",
    createdAt: "2026-06-03T00:00:00.000Z",
  }, deps());

  assert.equal(bridgeCalls[0].action, "take_over_session");
  assert.equal(bridgeCalls[0].sessionId, "session_runtime");
  assert.equal(bridgeCalls[0].managedSessionId, "sandbox_browser:test");
  assert.equal(controlled.schema_version, "ioi.runtime.managed-session-control.daemon.v1");
  assert.equal(controlled.inspection.managed_sessions.sessions[0].control_state, "take_over");
});

test("managed session control requires managed session id", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
  });

  await assert.rejects(
    controlManagedSessionForThread(store, "thread_runtime", { action: "observe" }, deps()),
    /Managed session control requires managedSessionId/,
  );
});
