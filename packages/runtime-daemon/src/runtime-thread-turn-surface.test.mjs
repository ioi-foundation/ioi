import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeThreadTurnSurface } from "./runtime-thread-turn-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  throw error;
}

function createStore(overrides = {}) {
  const calls = [];
  const agent = overrides.agent ?? {
    id: "agent_alpha",
    runtimeProfile: "fixture",
  };
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ method: "agentForThread", threadId });
      return agent;
    },
    updateAgent(agentId, status, operationKind) {
      calls.push({ method: "updateAgent", agentId, status, operationKind });
      return { ...agent, id: agentId, status };
    },
    threadForAgent(updatedAgent) {
      calls.push({ method: "threadForAgent", agentId: updatedAgent.id });
      return {
        thread_id: "thread_alpha",
        agent_id: updatedAgent.id,
        status: updatedAgent.status,
      };
    },
    pendingDiagnosticsFeedbackForNextTurn(threadId, request) {
      calls.push({ method: "pendingDiagnosticsFeedbackForNextTurn", threadId, request });
      return overrides.diagnosticsFeedback ?? null;
    },
    createRun(agentId, request) {
      calls.push({ method: "createRun", agentId, request });
      return { id: "run_alpha", agentId, request };
    },
    turnForRun(run) {
      calls.push({ method: "turnForRun", runId: run.id });
      return { turn_id: "turn_alpha", run_id: run.id, request: run.request };
    },
    createRuntimeBridgeTurn(request) {
      calls.push({ method: "createRuntimeBridgeTurn", request });
      return { turn_id: "turn_runtime", runtime_bridge: request };
    },
  };
}

function assertThreadTurnRustCoreRequired(error, {
  operation,
  operationKind,
  threadId = "thread_alpha",
  agentId = "agent_alpha",
  runtimeProfile = "fixture",
} = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_thread_turn_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.thread_turn");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.thread_id, threadId);
  assert.equal(error.details.agent_id, agentId);
  assert.equal(error.details.runtime_profile, runtimeProfile);
  assert.equal(Array.isArray(error.details.evidence_refs), true);
  assert.equal(Object.hasOwn(error.details, "threadId"), false);
  assert.equal(Object.hasOwn(error.details, "agentId"), false);
  assert.equal(Object.hasOwn(error.details, "runtimeProfile"), false);
  return true;
}

test("thread turn surface resumes runtime threads through mounted runtime bridge control path", async () => {
  const controlCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    controlRuntimeBridgeThread(_store, input) {
      controlCalls.push(input);
      return { status: "accepted", action: input.action };
    },
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtimeProfile: "runtime_service" },
  });

  const result = await surface.resumeThread(store, "thread_alpha", { reason: "continue" });

  assert.equal(result.status, "accepted");
  assert.deepEqual(controlCalls, [{
    agent: { id: "agent_runtime", runtimeProfile: "runtime_service" },
    threadId: "thread_alpha",
    action: "resume",
    reason: "continue",
  }]);
  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(store.calls.some((call) => call.method === "threadForAgent"), false);
});

test("thread turn surface fails closed for non-runtime resume before JS mutation", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  await assert.rejects(
    () => surface.resumeThread(store, "thread_alpha", { reason: "continue" }),
    (error) => assertThreadTurnRustCoreRequired(error, {
      operation: "thread_resume",
      operationKind: "thread.resume",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(store.calls.some((call) => call.method === "threadForAgent"), false);
});

test("thread turn surface fails closed for non-runtime turns before JS run creation", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  await assert.rejects(
    () => surface.createTurn(store, "thread_alpha", {
      prompt: "ship it",
      options: {},
    }),
    (error) => assertThreadTurnRustCoreRequired(error, {
      operation: "thread_turn_create",
      operationKind: "turn.create",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "turnForRun"), false);
});

test("thread turn surface fails closed for diagnostics-blocked turns before JS run creation", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => true,
    runtimeError,
  });
  const store = createStore({
    diagnosticsFeedback: { status: "blocked" },
  });

  await assert.rejects(
    () => surface.createTurn(store, "thread_alpha", {
      prompt: "ship it",
      options: {},
    }),
    (error) => assertThreadTurnRustCoreRequired(error, {
      operation: "thread_turn_diagnostics_block",
      operationKind: "turn.diagnostics_block",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "turnForRun"), false);
});

test("thread turn surface fails closed for operator turn controls", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  await assert.rejects(
    () => surface.interruptTurn(store, "thread_alpha", "turn_alpha", { runtime_control_action: "stop" }),
    (error) =>
      error.code === "runtime_operator_turn_control_rust_core_required" &&
      error.details.operation === "operator_interrupt" &&
      error.details.operation_kind === "turn.interrupt" &&
      error.details.thread_id === "thread_alpha" &&
      error.details.turn_id === "turn_alpha" &&
      error.details.requested_action === "stop" &&
      !Object.hasOwn(error.details, "threadId") &&
      !Object.hasOwn(error.details, "turnId"),
  );

  assert.throws(
    () => surface.steerTurn(store, "thread_alpha", "turn_alpha", { guidance: "focus" }),
    (error) =>
      error.code === "runtime_operator_turn_control_rust_core_required" &&
      error.details.operation === "operator_steer" &&
      error.details.operation_kind === "turn.steer" &&
      error.details.thread_id === "thread_alpha" &&
      error.details.turn_id === "turn_alpha" &&
      error.details.requested_action === null &&
      !Object.hasOwn(error.details, "threadId") &&
      !Object.hasOwn(error.details, "turnId"),
  );
});
