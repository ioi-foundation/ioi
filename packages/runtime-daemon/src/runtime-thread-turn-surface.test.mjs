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
    agentRunLifecycleSurface: Object.hasOwn(overrides, "agentRunLifecycleSurface")
      ? overrides.agentRunLifecycleSurface
      : {
          updateAgent(surfaceStore, agentId, status, operationKind) {
            calls.push({
              method: "agentRunLifecycleSurface.updateAgent",
              surfaceStore,
              agentId,
              status,
              operationKind,
            });
            return { ...agent, id: agentId, status, rust_planned: true };
          },
          createRun(surfaceStore, agentId, request) {
            calls.push({
              method: "agentRunLifecycleSurface.createRun",
              surfaceStore,
              agentId,
              request,
            });
            return { id: "run_alpha", agentId, request, rust_planned: true };
          },
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
      return {
        turn_id: "turn_alpha",
        thread_id: "thread_alpha",
        request_id: run.id,
        run_id: run.id,
        request: run.request,
      };
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

function assertRuntimeBridgeThreadRustCoreRequired(error, {
  operation,
  operationKind,
  runtimeProfile = "runtime_service",
  threadId = "thread_alpha",
  agentId = "agent_runtime",
  action = null,
  evidenceRef,
} = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_bridge_thread_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.bridge_thread");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.thread_id, threadId);
  assert.equal(error.details.agent_id, agentId);
  assert.equal(error.details.runtime_profile, runtimeProfile);
  if (action !== null) assert.equal(error.details.action, action);
  assert.equal(error.details.evidence_refs.includes(evidenceRef), true);
  assert.equal(Object.hasOwn(error.details, "threadId"), false);
  assert.equal(Object.hasOwn(error.details, "agentId"), false);
  assert.equal(Object.hasOwn(error.details, "runtimeProfile"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
}

function createThreadTurnAdmissionRunner(calls) {
  return {
    planThreadTurnAdmissionRequired(request) {
      calls.push(request);
      return {
        source: "rust_thread_turn_admission_required_command",
        backend: "rust_policy",
        record: {
          status: "rust_core_required",
          status_code: 501,
          code: "runtime_thread_turn_rust_core_required",
          message:
            "Thread resume and turn creation require direct Rust daemon-core admission and persistence.",
          details: {
            rust_core_boundary: "runtime.thread_turn",
            operation: request.operation,
            operation_kind: request.operation_kind,
            thread_id: request.thread_id,
            agent_id: request.agent_id,
            runtime_profile: request.runtime_profile,
            evidence_refs: request.evidence_refs,
          },
        },
      };
    },
  };
}

test("thread turn surface fails closed for runtime thread resume before bridge control dispatch", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtimeProfile: "runtime_service" },
  });

  await assert.rejects(
    () => surface.resumeThread(store, "thread_alpha", { reason: "continue" }),
    (error) => assertRuntimeBridgeThreadRustCoreRequired(error, {
      operation: "runtime_bridge_thread_control",
      operationKind: "thread.runtime_bridge.control",
      action: "resume",
      evidenceRef: "runtime_bridge_thread_control_js_facade_retired",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(store.calls.some((call) => call.method === "threadForAgent"), false);
});

test("thread turn surface fails closed for runtime turns before bridge submit dispatch", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtimeProfile: "runtime_service" },
  });

  await assert.rejects(
    () => surface.createTurn(store, "thread_alpha", {
      prompt: "ship it",
      options: {},
    }),
    (error) => assertRuntimeBridgeThreadRustCoreRequired(error, {
      operation: "runtime_bridge_turn_submit",
      operationKind: "turn.runtime_bridge.submit",
      evidenceRef: "runtime_bridge_turn_submit_js_facade_retired",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "turnForRun"), false);
});

test("thread turn surface resumes non-runtime threads through Rust lifecycle status and projection", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  const thread = await surface.resumeThread(store, "thread_alpha", { reason: "continue" });

  assert.equal(thread.thread_id, "thread_alpha");
  assert.equal(thread.agent_id, "agent_alpha");
  assert.equal(thread.status, "active");
  assert.deepEqual(
    store.calls.map((call) => call.method),
    ["agentForThread", "agentRunLifecycleSurface.updateAgent", "threadForAgent"],
  );
  assert.equal(store.calls[1].surfaceStore, store);
  assert.equal(store.calls[1].agentId, "agent_alpha");
  assert.equal(store.calls[1].status, "active");
  assert.equal(store.calls[1].operationKind, "agent.resume");
  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
});

test("thread turn surface fails closed for non-runtime resume when mounted Rust lifecycle boundary is missing", async () => {
  const admissionRequiredCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyRunner: createThreadTurnAdmissionRunner(admissionRequiredCalls),
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore({ agentRunLifecycleSurface: null });

  await assert.rejects(
    () => surface.resumeThread(store, "thread_alpha", { reason: "continue" }),
    (error) => assertThreadTurnRustCoreRequired(error, {
      operation: "thread_resume",
      operationKind: "thread.resume",
    }),
  );

  assert.equal(admissionRequiredCalls.length, 1);
  assert.deepEqual(admissionRequiredCalls[0], {
    operation: "thread_resume",
    operation_kind: "thread.resume",
    thread_id: "thread_alpha",
    agent_id: "agent_alpha",
    runtime_profile: "fixture",
    evidence_refs: [
      "thread_resume_js_state_mutation_retired",
      "rust_daemon_core_thread_resume_required",
      "agentgres_thread_resume_truth_required",
    ],
  });
  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(store.calls.some((call) => call.method === "threadForAgent"), false);
});

test("thread turn surface creates non-runtime turns through Rust-planned run and projection", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  const turn = await surface.createTurn(store, "thread_alpha", {
    prompt: "ship it",
    options: {},
  });

  assert.equal(turn.turn_id, "turn_alpha");
  assert.equal(turn.thread_id, "thread_alpha");
  assert.equal(turn.request_id, "run_alpha");
  assert.deepEqual(
    store.calls.map((call) => call.method),
    [
      "agentForThread",
      "pendingDiagnosticsFeedbackForNextTurn",
      "agentRunLifecycleSurface.createRun",
      "turnForRun",
    ],
  );
  assert.equal(store.calls[2].surfaceStore, store);
  assert.equal(store.calls[2].agentId, "agent_alpha");
  assert.equal(store.calls[2].request.prompt, "ship it");
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
});

test("thread turn surface fails closed for non-runtime turns when mounted Rust run boundary is missing", async () => {
  const admissionRequiredCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyRunner: createThreadTurnAdmissionRunner(admissionRequiredCalls),
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore({ agentRunLifecycleSurface: null });

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

  assert.equal(admissionRequiredCalls.length, 1);
  assert.deepEqual(admissionRequiredCalls[0], {
    operation: "thread_turn_create",
    operation_kind: "turn.create",
    thread_id: "thread_alpha",
    agent_id: "agent_alpha",
    runtime_profile: "fixture",
    evidence_refs: [
      "thread_turn_create_js_run_creation_retired",
      "rust_daemon_core_thread_turn_create_required",
      "agentgres_thread_turn_create_truth_required",
    ],
  });
  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "turnForRun"), false);
});

test("thread turn surface fails closed for diagnostics-blocked turns before Rust run creation", async () => {
  const admissionRequiredCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyRunner: createThreadTurnAdmissionRunner(admissionRequiredCalls),
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

  assert.equal(admissionRequiredCalls.length, 1);
  assert.deepEqual(admissionRequiredCalls[0], {
    operation: "thread_turn_diagnostics_block",
    operation_kind: "turn.diagnostics_block",
    thread_id: "thread_alpha",
    agent_id: "agent_alpha",
    runtime_profile: "fixture",
    evidence_refs: [
      "thread_turn_diagnostics_block_js_run_creation_retired",
      "rust_daemon_core_thread_turn_create_required",
      "agentgres_thread_turn_create_truth_required",
    ],
  });
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
