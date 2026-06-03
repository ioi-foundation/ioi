import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createRuntimeBridgeThread,
  normalizeRuntimeBridgeThreadStart,
} from "./runtime-bridge-thread.mjs";

class BridgeUnavailableError extends Error {
  constructor(details = {}) {
    super("bridge unavailable");
    this.details = details;
  }
}

function deps() {
  return {
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    normalizeArray: (value) => Array.isArray(value) ? value : [],
    RuntimeApiBridgeUnavailableError: BridgeUnavailableError,
    runtimeError: (input) => {
      const error = new Error(input.message);
      Object.assign(error, input);
      return error;
    },
    threadIdForAgent: (agentId) => `thread_${agentId}`,
  };
}

function fakeStore({ bridgeResult, bridgeError } = {}) {
  const calls = [];
  const agents = new Map();
  return {
    calls,
    agents,
    runtimeBridge: {
      bridgeId: "bridge_default",
      async startThread(input) {
        calls.push({ operation: "start_thread", input });
        if (bridgeError) throw bridgeError;
        return bridgeResult ?? {
          session_id: "session_runtime",
          bridge_id: "bridge_runtime",
          status: "active",
          source: "runtime_service",
          events: [{ event_kind: "thread.started" }],
        };
      },
    },
    assertRuntimeBridgeAvailable(input) {
      calls.push({ operation: "assert_bridge", input });
    },
    createAgent(options) {
      calls.push({ operation: "create_agent", options });
      const agent = {
        id: "agent_runtime",
        cwd: "/workspace",
        createdAt: "2026-06-03T00:00:00.000Z",
        modelRouteDecision: { routeId: "route.local-first" },
      };
      agents.set(agent.id, agent);
      return agent;
    },
    writeAgent(agent, operationKind) {
      calls.push({ operation: "write_agent", agent, operationKind });
    },
    appendRuntimeEvent(event) {
      calls.push({ operation: "append_event", event });
    },
    threadForAgent(agent) {
      calls.push({ operation: "thread_for_agent", agent });
      return {
        thread_id: `thread_${agent.id}`,
        agent_id: agent.id,
        runtime_session_id: agent.runtimeSessionId,
      };
    },
    runtimeBridgeUnavailable(input) {
      const error = new Error("runtime bridge unavailable");
      error.input = input;
      return error;
    },
  };
}

test("runtime bridge thread creation starts bridge and persists updated agent", async () => {
  const store = fakeStore();

  const thread = await createRuntimeBridgeThread(store, {
    request: { runtime_profile: "runtime_service" },
    options: { local: { cwd: "/workspace" } },
    runtimeProfile: "runtime_service",
  }, deps());

  const start = store.calls.find((call) => call.operation === "start_thread");
  assert.equal(start.input.threadId, "thread_agent_runtime");
  assert.equal(start.input.workspaceRoot, "/workspace");
  assert.deepEqual(start.input.modelRouteDecision, { routeId: "route.local-first" });

  const write = store.calls.find((call) => call.operation === "write_agent");
  assert.equal(write.operationKind, "thread.runtime_bridge.start");
  assert.equal(write.agent.runtimeSessionId, "session_runtime");
  assert.equal(write.agent.runtimeBridgeId, "bridge_runtime");
  assert.equal(write.agent.fixtureProfile, null);

  assert.equal(store.calls.some((call) => call.operation === "append_event"), true);
  assert.equal(thread.runtime_session_id, "session_runtime");
});

test("runtime bridge thread creation maps bridge unavailable errors", async () => {
  const store = fakeStore({ bridgeError: new BridgeUnavailableError({ reason: "not configured" }) });

  await assert.rejects(
    createRuntimeBridgeThread(store, {
      request: { runtime_profile: "runtime_service" },
      options: {},
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => {
      assert.equal(error.input.operation, "start_thread");
      assert.equal(error.input.details.reason, "not configured");
      return true;
    },
  );
});

test("runtime bridge thread start normalization fills event defaults", () => {
  const projection = normalizeRuntimeBridgeThreadStart({
    bridgeResult: {
      session_id: "session_runtime",
      events: [{ event_kind: "thread.started", payload_summary: { goal: "start" } }],
    },
    agent: { id: "agent_runtime", cwd: "/workspace" },
    threadId: "thread_agent_runtime",
    runtimeProfile: "runtime_service",
  }, {
    bridgeId: "bridge_default",
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    normalizeArray: (value) => Array.isArray(value) ? value : [],
    runtimeError: deps().runtimeError,
  });

  assert.equal(projection.sessionId, "session_runtime");
  assert.equal(projection.bridgeId, "bridge_default");
  assert.equal(projection.status, "active");
  assert.equal(projection.events[0].event_stream_id, "stream_thread_agent_runtime");
  assert.equal(projection.events[0].thread_id, "thread_agent_runtime");
  assert.equal(projection.events[0].workspace_root, "/workspace");
  assert.equal(projection.events[0].fixture_profile, null);
  assert.deepEqual(projection.events[0].payload, {
    agent_id: "agent_runtime",
    session_id: "session_runtime",
    goal: "start",
  });
});

test("runtime bridge thread start normalization rejects missing session id", () => {
  assert.throws(
    () => normalizeRuntimeBridgeThreadStart({
      bridgeResult: { events: [{ event_kind: "thread.started" }] },
      agent: { id: "agent_runtime", cwd: "/workspace" },
      threadId: "thread_agent_runtime",
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => {
      assert.equal(error.code, "runtime_bridge_contract");
      assert.equal(error.details.operation, "start_thread");
      return true;
    },
  );
});

test("runtime bridge thread start normalization rejects missing thread started event", () => {
  assert.throws(
    () => normalizeRuntimeBridgeThreadStart({
      bridgeResult: { session_id: "session_runtime", events: [{ event_kind: "turn.started" }] },
      agent: { id: "agent_runtime", cwd: "/workspace" },
      threadId: "thread_agent_runtime",
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => {
      assert.equal(error.code, "runtime_bridge_contract");
      assert.equal(error.details.sessionId, "session_runtime");
      return true;
    },
  );
});
