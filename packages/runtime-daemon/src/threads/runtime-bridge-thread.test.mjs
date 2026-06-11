import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlRuntimeBridgeThread,
  createRuntimeBridgeThread,
  createRuntimeBridgeTurn,
} from "./runtime-bridge-thread.mjs";

const retiredRuntimeBridgeErrorDetailAliasKeys = [
  "threadId",
  "runId",
  "turnId",
  "sessionId",
  "runtimeProfile",
  "operationKind",
  "expectedOperationKind",
];

function assertNoRetiredRuntimeBridgeErrorDetailAliases(details) {
  for (const key of retiredRuntimeBridgeErrorDetailAliasKeys) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

function assertRuntimeBridgeThreadRustCoreRequired(error, {
  operation,
  operationKind,
  runtimeProfile,
  evidenceRef,
  threadId,
  agentId,
  action,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_bridge_thread_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.bridge_thread");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.runtime_profile, runtimeProfile);
  if (threadId) assert.equal(error.details.thread_id, threadId);
  if (agentId) assert.equal(error.details.agent_id, agentId);
  if (action) assert.equal(error.details.action, action);
  assert.equal(error.details.evidence_refs.includes(evidenceRef), true);
  assertNoRetiredRuntimeBridgeErrorDetailAliases(error.details);
  return true;
}

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
    optionalPositiveInteger: (value) => {
      const number = Number(value);
      return Number.isInteger(number) && number > 0 ? number : null;
    },
    optionalString: (value) => typeof value === "string" && value.trim() ? value.trim() : null,
    runIdForTurn: (turnId) => `run_${turnId}`,
    RuntimeApiBridgeUnavailableError: BridgeUnavailableError,
    runtimeError: (input) => {
      const error = new Error(input.message);
      Object.assign(error, input);
      return error;
    },
    runtimeSessionIdForAgent: (agent) => agent.runtimeSessionId ?? "session_runtime",
    threadIdForAgent: (agentId) => `thread_${agentId}`,
  };
}

function fakeStore({ bridgeResult, bridgeError, bridgeStartStateUpdate } = {}) {
  const calls = [];
  const agents = new Map();
  return {
    calls,
    agents,
    contextPolicyRunner: {
      planRuntimeBridgeThreadStartAgentStateUpdate(request = {}) {
        calls.push({ operation: "plan_runtime_bridge_thread_start_agent_state_update", input: request });
        return bridgeStartStateUpdate ?? {
          status: "planned",
          operation_kind: "thread.runtime_bridge.start",
          agent: {
            ...request.agent,
            runtimeProfile: request.runtime_profile,
            runtimeSessionId: request.session_id,
            runtimeBridgeId: request.bridge_id,
            runtimeBridgeStatus: request.status,
            runtimeBridgeSource: request.source,
            fixtureProfile: null,
            updatedAt: request.updated_at,
          },
        };
      },
    },
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

function fakeTurnStore({ bridgeResult, bridgeError, liveEvent, bridgeTurnRunStateUpdate } = {}) {
  const calls = [];
  const runs = new Map();
  return {
    calls,
    runs,
    contextPolicyRunner: {
      planRuntimeBridgeTurnRunStateUpdate(request = {}) {
        calls.push({ operation: "plan_runtime_bridge_turn_run_state_update", input: request });
        return bridgeTurnRunStateUpdate ?? {
          status: "planned",
          operation_kind: "turn.runtime_bridge.submit",
          run: request.run,
        };
      },
    },
    runtimeBridge: {
      bridgeId: "bridge_default",
      async submitTurn(input, handlers = {}) {
        calls.push({ operation: "submit_turn", input });
        if (liveEvent) handlers.onRuntimeEvent?.(liveEvent);
        if (bridgeError) throw bridgeError;
        return bridgeResult ?? {
          turn_id: "turn_runtime",
          run_id: "run_runtime",
          status: "completed",
          result: "done",
          events: [{ event_kind: "turn.started" }],
        };
      },
    },
    assertRuntimeBridgeAvailable(input) {
      calls.push({ operation: "assert_bridge", input });
    },
    appendRuntimeEvent(event) {
      calls.push({ operation: "append_event", event });
    },
    registerInFlightRuntimeTurn(input) {
      calls.push({ operation: "register_in_flight", input });
    },
    unregisterInFlightRuntimeTurn(threadId, turnId) {
      calls.push({ operation: "unregister_in_flight", threadId, turnId });
    },
    appendOperation(operationKind, payload) {
      calls.push({ operation: "append_operation", operationKind, payload });
    },
    writeRun(run, operationKind) {
      calls.push({ operation: "write_run", run, operationKind });
    },
    turnForRun(run) {
      calls.push({ operation: "turn_for_run", run });
      return { turn_id: run.turnId, run_id: run.id };
    },
    runtimeBridgeUnavailable(input) {
      const error = new Error("runtime bridge unavailable");
      error.input = input;
      return error;
    },
  };
}

function fakeControlStore({ bridgeResult, bridgeError } = {}) {
  const calls = [];
  return {
    calls,
    runtimeBridge: {
      async controlThread(input) {
        calls.push({ operation: "control_thread", input });
        if (bridgeError) throw bridgeError;
        return bridgeResult ?? { status: "accepted", action: input.action };
      },
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

function turnDeps() {
  return {
    ...deps(),
    RUNTIME_BRIDGE_AGENT_TURN_MIN_STEPS: 8,
    insertRuntimeBridgeComputerUseDerivedEvents: ({ projection }) => projection.events,
    insertRuntimeBridgeDiagnosticsInjectionEvent: ({ projection }) => [
      { event_kind: "lsp.diagnostics.injected" },
      ...projection.events,
    ],
    insertRuntimeBridgeUsageDeltaEvents: ({ projection }) => projection.events,
    runtimeBridgeRunRecord: ({ agent, request, projection }) => ({
      id: projection.runId,
      agentId: agent.id,
      turnId: projection.turnId,
      request,
      projection,
    }),
  };
}

test("runtime bridge thread creation fails closed before JS bridge dispatch and agent persistence", async () => {
  const store = fakeStore();

  await assert.rejects(
    createRuntimeBridgeThread(store, {
      request: { runtime_profile: "runtime_service" },
      options: { local: { cwd: "/workspace" } },
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => {
      return assertRuntimeBridgeThreadRustCoreRequired(error, {
        operation: "runtime_bridge_thread_start",
        operationKind: "thread.runtime_bridge.start",
        runtimeProfile: "runtime_service",
        evidenceRef: "runtime_bridge_thread_start_js_facade_retired",
      });
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "assert_bridge"), false);
  assert.equal(store.calls.some((call) => call.operation === "create_agent"), false);
  assert.equal(store.calls.some((call) => call.operation === "start_thread"), false);
  assert.equal(
    store.calls.some((call) => call.operation === "plan_runtime_bridge_thread_start_agent_state_update"),
    false,
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_event"), false);
  assert.equal(store.agents.size, 0);
});

test("runtime bridge turn creation fails closed before JS bridge dispatch and run persistence", async () => {
  const store = fakeTurnStore({
    liveEvent: { event_kind: "turn.delta", turn_id: "turn_live", run_id: "run_live" },
  });
  const agent = {
    id: "agent_runtime",
    cwd: "/workspace",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_runtime",
  };

  await assert.rejects(
    createRuntimeBridgeTurn(store, {
      agent,
      threadId: "thread_agent_runtime",
      request: { prompt: "hello", max_steps: 2, options: { maxSteps: 4 } },
      diagnosticsFeedback: { injectionId: "diag_1" },
    }, turnDeps()),
    (error) => {
      assert.equal(error.details.thread_id, "thread_agent_runtime");
      assert.equal(error.details.agent_id, "agent_runtime");
      return assertRuntimeBridgeThreadRustCoreRequired(error, {
        operation: "runtime_bridge_turn_submit",
        operationKind: "turn.runtime_bridge.submit",
        runtimeProfile: "runtime_service",
        evidenceRef: "runtime_bridge_turn_submit_js_facade_retired",
      });
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "assert_bridge"), false);
  assert.equal(store.calls.some((call) => call.operation === "submit_turn"), false);
  assert.equal(store.calls.some((call) => call.operation === "register_in_flight"), false);
  assert.equal(store.calls.some((call) => call.operation === "unregister_in_flight"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_event"), false);
  assert.equal(
    store.calls.some((call) => call.operation === "plan_runtime_bridge_turn_run_state_update"),
    false,
  );
  assert.equal(store.calls.some((call) => call.operation === "write_run"), false);
  assert.equal(store.runs.size, 0);
  assert.equal(store.calls.some((call) => call.operation === "append_operation"), false);
});

test("runtime bridge thread control fails closed before JS bridge dispatch", async () => {
  const store = fakeControlStore({ bridgeError: new BridgeUnavailableError({ reason: "not configured" }) });
  const agent = {
    id: "agent_runtime",
    cwd: "/workspace",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_runtime",
  };

  await assert.rejects(
    controlRuntimeBridgeThread(store, {
      agent,
      threadId: "thread_agent_runtime",
      action: "resume",
      reason: "operator requested resume",
    }, deps()),
    (error) => {
      return assertRuntimeBridgeThreadRustCoreRequired(error, {
        operation: "runtime_bridge_thread_control",
        operationKind: "thread.runtime_bridge.control",
        runtimeProfile: "runtime_service",
        threadId: "thread_agent_runtime",
        agentId: "agent_runtime",
        action: "resume",
        evidenceRef: "runtime_bridge_thread_control_js_facade_retired",
      });
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "assert_bridge"), false);
  assert.equal(store.calls.some((call) => call.operation === "control_thread"), false);
});
