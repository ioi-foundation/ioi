import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlRuntimeBridgeThread,
  createRuntimeBridgeThread,
  createRuntimeBridgeTurn,
  normalizeRuntimeBridgeLiveEvent,
  normalizeRuntimeBridgeThreadStart,
  normalizeRuntimeBridgeTurnSubmit,
} from "./runtime-bridge-thread.mjs";

const retiredRuntimeBridgeTurnUsageAliasKeys = [
  "usageTelemetry",
  "runtime_usage",
  "runtimeUsage",
];

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
  const planner = store.calls.find((call) => call.operation === "plan_runtime_bridge_thread_start_agent_state_update");
  assert.equal(planner.input.thread_id, "thread_agent_runtime");
  assert.equal(planner.input.session_id, "session_runtime");
  assert.equal(planner.input.bridge_id, "bridge_runtime");

  assert.equal(store.calls.some((call) => call.operation === "append_event"), true);
  assert.equal(thread.runtime_session_id, "session_runtime");
});

test("runtime bridge thread creation fails closed without Rust-planned agent projection", async () => {
  const store = fakeStore({
    bridgeStartStateUpdate: {
      status: "planned",
      operation_kind: "thread.runtime_bridge.start",
      agent: null,
    },
  });

  await assert.rejects(
    createRuntimeBridgeThread(store, {
      request: { runtime_profile: "runtime_service" },
      options: { local: { cwd: "/workspace" } },
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => error.code === "runtime_bridge_thread_start_state_update_planner_invalid",
  );
  assert.equal(
    store.calls.some((call) => call.operation === "write_agent"),
    false,
  );
  assert.equal(
    store.calls.some((call) => call.operation === "append_event"),
    false,
  );
});

test("runtime bridge thread creation fails closed without Rust-planned operation kind", async () => {
  const store = fakeStore({
    bridgeStartStateUpdate: {
      status: "planned",
      agent: {
        id: "agent_runtime",
        runtimeSessionId: "session_runtime",
      },
    },
  });

  await assert.rejects(
    createRuntimeBridgeThread(store, {
      request: { runtime_profile: "runtime_service" },
      options: { local: { cwd: "/workspace" } },
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => {
      assert.equal(error.code, "runtime_bridge_thread_start_state_update_operation_kind_missing");
      assert.equal(error.details.operation_kind, "thread.runtime_bridge.start");
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_event"), false);
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

test("runtime bridge turn creation submits clamped bridge request and persists run", async () => {
  const store = fakeTurnStore({
    liveEvent: { event_kind: "turn.delta", turn_id: "turn_live", run_id: "run_live" },
  });
  const agent = {
    id: "agent_runtime",
    cwd: "/workspace",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_runtime",
  };

  const turn = await createRuntimeBridgeTurn(store, {
    agent,
    threadId: "thread_agent_runtime",
    request: { prompt: "hello", max_steps: 2, options: { max_steps: 4 } },
    diagnosticsFeedback: { injectionId: "diag_1" },
  }, turnDeps());

  const submit = store.calls.find((call) => call.operation === "submit_turn");
  assert.equal(submit.input.request.max_steps, 8);
  assert.equal(submit.input.options.maxSteps, 8);
  assert.equal(submit.input.sessionId, "session_runtime");
  assert.equal(submit.input.streamedEventsOnly, true);

  assert.equal(store.calls.some((call) => call.operation === "register_in_flight"), true);
  assert.equal(store.calls.filter((call) => call.operation === "append_event").length, 3);

  const write = store.calls.find((call) => call.operation === "write_run");
  assert.equal(write.operationKind, "turn.runtime_bridge.submit");
  assert.equal(write.run.id, "run_runtime");
  assert.equal(write.run.projection.events[0].event_kind, "lsp.diagnostics.injected");
  const planner = store.calls.find((call) => call.operation === "plan_runtime_bridge_turn_run_state_update");
  assert.equal(planner.input.thread_id, "thread_agent_runtime");
  assert.equal(planner.input.projection.runId, "run_runtime");
  assert.equal(planner.input.run.id, "run_runtime");

  assert.equal(store.calls.some((call) => call.operation === "append_operation"), false);
  assert.deepEqual(turn, { turn_id: "turn_runtime", run_id: "run_runtime" });
});

test("runtime bridge turn creation fails closed without Rust-planned run projection", async () => {
  const store = fakeTurnStore({
    bridgeTurnRunStateUpdate: {
      status: "planned",
      operation_kind: "turn.runtime_bridge.submit",
      run: null,
    },
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
      request: { prompt: "hello" },
    }, turnDeps()),
    (error) => error.code === "runtime_bridge_turn_run_state_update_planner_invalid",
  );
  assert.equal(store.calls.some((call) => call.operation === "write_run"), false);
});

test("runtime bridge turn creation fails closed without Rust-planned operation kind", async () => {
  const store = fakeTurnStore({
    bridgeTurnRunStateUpdate: {
      status: "planned",
      run: {
        id: "run_runtime",
        turnId: "turn_runtime",
      },
    },
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
      request: { prompt: "hello" },
    }, turnDeps()),
    (error) => {
      assert.equal(error.code, "runtime_bridge_turn_run_state_update_operation_kind_missing");
      assert.equal(error.details.operation_kind, "turn.runtime_bridge.submit");
      return true;
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "write_run"), false);
  assert.equal(store.runs.size, 0);
});

test("runtime bridge turn creation maps bridge unavailable errors and cleans in-flight turn", async () => {
  const store = fakeTurnStore({
    liveEvent: { event_kind: "turn.delta", turn_id: "turn_live", run_id: "run_live" },
    bridgeError: new BridgeUnavailableError({ reason: "not configured" }),
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
      request: { prompt: "hello" },
    }, turnDeps()),
    (error) => {
      assert.equal(error.input.operation, "submit_turn");
      assert.equal(error.input.details.reason, "not configured");
      return true;
    },
  );

  assert.equal(store.calls.some((call) => call.operation === "unregister_in_flight"), true);
  assert.equal(store.calls.some((call) => call.operation === "append_operation"), false);
});

test("runtime bridge thread control sends action to bridge", async () => {
  const store = fakeControlStore();
  const agent = {
    id: "agent_runtime",
    cwd: "/workspace",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_runtime",
  };

  const result = await controlRuntimeBridgeThread(store, {
    agent,
    threadId: "thread_agent_runtime",
    action: "resume",
    reason: "operator requested resume",
  }, deps());

  const control = store.calls.find((call) => call.operation === "control_thread");
  assert.equal(control.input.sessionId, "session_runtime");
  assert.equal(control.input.threadId, "thread_agent_runtime");
  assert.equal(control.input.workspaceRoot, "/workspace");
  assert.equal(control.input.action, "resume");
  assert.equal(control.input.reason, "operator requested resume");
  assert.equal(result.status, "accepted");
});

test("runtime bridge thread control maps bridge unavailable errors", async () => {
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
      action: "stop",
      reason: "operator requested interrupt",
    }, deps()),
    (error) => {
      assert.equal(error.input.operation, "control_thread");
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

test("runtime bridge turn submit normalization fills run and event defaults", () => {
  const projection = normalizeRuntimeBridgeTurnSubmit({
    bridgeResult: {
      turn_id: "turn_runtime",
      result: "done",
      usage_telemetry: { total_tokens: 42 },
      usageTelemetry: { total_tokens: 100 },
      runtime_usage: { total_tokens: 200 },
      runtimeUsage: { total_tokens: 300 },
      events: [{ event_kind: "turn.started", payload_summary: { step: "submit" } }],
    },
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    threadId: "thread_agent_runtime",
    request: { mode: "send", prompt: "hello" },
  }, deps());

  assert.equal(projection.turnId, "turn_runtime");
  assert.equal(projection.runId, "run_turn_runtime");
  assert.equal(projection.status, "completed");
  assert.equal(projection.result, "done");
  assert.deepEqual(projection.usage, { total_tokens: 42 });
  assert.equal(projection.mode, "send");
  assert.equal(projection.prompt, "hello");
  assert.equal(projection.stopReason, "runtime_bridge_completed");
  assert.equal(projection.events[0].event_stream_id, "stream_thread_agent_runtime");
  assert.equal(projection.events[0].thread_id, "thread_agent_runtime");
  assert.equal(projection.events[0].turn_id, "turn_runtime");
  assert.equal(projection.events[0].workspace_root, "/workspace");
  assert.equal(projection.events[0].fixture_profile, null);
  assert.deepEqual(projection.events[0].payload, {
    agent_id: "agent_runtime",
    run_id: "run_turn_runtime",
    session_id: "session_runtime",
    step: "submit",
  });
});

test("runtime bridge turn submit normalization ignores retired usage aliases", () => {
  const bridgeResult = {
    turn_id: "turn_runtime",
    events: [{ event_kind: "turn.started" }],
  };
  for (const key of retiredRuntimeBridgeTurnUsageAliasKeys) {
    bridgeResult[key] = { total_tokens: 100 };
  }

  const projection = normalizeRuntimeBridgeTurnSubmit({
    bridgeResult,
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    threadId: "thread_agent_runtime",
    request: { mode: "send", prompt: "hello" },
  }, deps());

  assert.equal(projection.usage, null);
});

test("runtime bridge turn submit normalization rejects missing turn id", () => {
  assert.throws(
    () => normalizeRuntimeBridgeTurnSubmit({
      bridgeResult: { events: [{ event_kind: "turn.started" }] },
      agent: { id: "agent_runtime", cwd: "/workspace", runtimeProfile: "runtime_service" },
      threadId: "thread_agent_runtime",
      request: {},
    }, deps()),
    (error) => {
      assert.equal(error.code, "runtime_bridge_contract");
      assert.equal(error.details.operation, "submit_turn");
      return true;
    },
  );
});

test("runtime bridge turn submit normalization rejects missing turn started event", () => {
  assert.throws(
    () => normalizeRuntimeBridgeTurnSubmit({
      bridgeResult: { turn_id: "turn_runtime", events: [{ event_kind: "turn.completed" }] },
      agent: { id: "agent_runtime", cwd: "/workspace", runtimeProfile: "runtime_service" },
      threadId: "thread_agent_runtime",
      request: {},
    }, deps()),
    (error) => {
      assert.equal(error.code, "runtime_bridge_contract");
      assert.equal(error.details.turnId, "turn_runtime");
      return true;
    },
  );
});

test("runtime bridge live event normalization fills defaults from thread and agent", () => {
  const normalized = normalizeRuntimeBridgeLiveEvent({
    event: { event_kind: "turn.delta", turnId: "turn_runtime", payload_summary: { text: "chunk" } },
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeSessionId: "session_runtime",
    },
    threadId: "thread_agent_runtime",
  }, deps());

  assert.equal(normalized.event_stream_id, "stream_thread_agent_runtime");
  assert.equal(normalized.thread_id, "thread_agent_runtime");
  assert.equal(normalized.turn_id, "turn_runtime");
  assert.equal(normalized.workspace_root, "/workspace");
  assert.equal(normalized.source, "runtime_service");
  assert.equal(normalized.source_event_kind, "RuntimeAgentService");
  assert.equal(normalized.fixture_profile, null);
  assert.deepEqual(normalized.payload, {
    agent_id: "agent_runtime",
    run_id: "run_turn_runtime",
    session_id: "session_runtime",
    text: "chunk",
  });
});

test("runtime bridge live event normalization preserves explicit envelope fields", () => {
  const normalized = normalizeRuntimeBridgeLiveEvent({
    event: {
      event_stream_id: "stream_existing",
      thread_id: "thread_existing",
      turn_id: "turn_existing",
      run_id: "run_existing",
      workspace_root: "/other-workspace",
      source: "bridge",
      source_event_kind: "custom",
      fixture_profile: "fixture",
      payload: { existing: true },
    },
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeSessionId: "session_runtime",
    },
    threadId: "thread_agent_runtime",
  }, deps());

  assert.equal(normalized.event_stream_id, "stream_existing");
  assert.equal(normalized.thread_id, "thread_existing");
  assert.equal(normalized.turn_id, "turn_existing");
  assert.equal(normalized.workspace_root, "/other-workspace");
  assert.equal(normalized.source, "bridge");
  assert.equal(normalized.source_event_kind, "custom");
  assert.equal(normalized.fixture_profile, "fixture");
  assert.deepEqual(normalized.payload, {
    agent_id: "agent_runtime",
    run_id: "run_existing",
    session_id: "session_runtime",
    existing: true,
  });
});
