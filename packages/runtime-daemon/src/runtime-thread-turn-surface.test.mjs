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

test("thread turn surface resumes through mounted runtime bridge control path", async () => {
  const controlCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    controlRuntimeBridgeThread(_store, input) {
      controlCalls.push(input);
      return { status: "accepted", action: input.action };
    },
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    requestWithDiagnosticsFeedback: (request) => request,
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtimeProfile: "runtime_service" },
  });

  const result = await surface.resumeThread(store, "thread_alpha", { reason: "continue" });

  assert.equal(result.status, "active");
  assert.equal(result.runtime_control.status, "accepted");
  assert.deepEqual(controlCalls, [{
    agent: { id: "agent_runtime", runtimeProfile: "runtime_service" },
    threadId: "thread_alpha",
    action: "resume",
    reason: "continue",
  }]);
});

test("thread turn surface creates non-runtime turns without runtime bridge dispatch", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    requestWithDiagnosticsFeedback: (request) => request,
    runtimeError,
  });
  const store = createStore();

  const result = await surface.createTurn(store, "thread_alpha", {
    prompt: "ship it",
    options: {},
  });

  assert.equal(result.turn_id, "turn_alpha");
  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(store.calls.find((call) => call.method === "createRun").request.prompt, "ship it");
});

test("thread turn surface fails closed for operator turn controls", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    requestWithDiagnosticsFeedback: (request) => request,
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
