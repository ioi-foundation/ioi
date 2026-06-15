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

function assertNoRetiredOperatorTurnControlDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "turnId",
    "requestedAction",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function createStore(overrides = {}) {
  const calls = [];
  const agent = overrides.agent ?? {
    id: "agent_alpha",
    runtime_profile: "fixture",
  };
  const run = overrides.run ?? {
    id: "run_alpha",
    agentId: agent.id,
    status: "running",
    turnStatus: "running",
    createdAt: "2026-06-13T12:00:00.000Z",
    updatedAt: "2026-06-13T12:01:00.000Z",
    trace: {},
  };
  return {
    calls,
    runs: new Map([[run.id, run]]),
    contextPolicyCore: Object.hasOwn(overrides, "contextPolicyCore")
      ? overrides.contextPolicyCore
      : {
          planRuntimeBridgeThreadControlAgentStateUpdate(request) {
            calls.push({ method: "planRuntimeBridgeThreadControlAgentStateUpdate", request });
            return {
              source: "rust_runtime_bridge_thread_control_agent_state_update_api",
              backend: "rust_policy",
              status: "planned",
              operation_kind: "thread.runtime_bridge.control",
              thread_id: request.thread_id,
              agent_id: request.agent.id,
              control: {
                action: request.action,
                reason: request.reason,
                runtime_bridge_status: "active",
                evidence_refs: request.evidence_refs,
              },
              agent: {
                ...request.agent,
                status: "active",
                runtime_bridge_status: "active",
                updatedAt: request.updated_at,
                rust_runtime_bridge_controlled: true,
              },
            };
          },
          planRuntimeBridgeTurnRunStateUpdate(request) {
            calls.push({ method: "planRuntimeBridgeTurnRunStateUpdate", request });
            return {
              source: "rust_runtime_bridge_turn_run_state_update_api",
              backend: "rust_policy",
              status: "planned",
              operation_kind: "turn.runtime_bridge.submit",
              thread_id: request.thread_id,
              run_id: request.run.id,
              agent_id: request.agent.id,
              run: {
                ...request.run,
                rust_runtime_bridge_submitted: true,
              },
            };
          },
        },
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
        rust_projected: true,
      };
    },
    writeAgent(plannedAgent, operationKind) {
      calls.push({ method: "writeAgent", plannedAgent, operationKind });
      return {
        operation_kind: operationKind,
        receipt_refs: [`receipt://${operationKind}/${plannedAgent.id}`],
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
    resolveRunModelRoute(agentRecord, request) {
      calls.push({ method: "resolveRunModelRoute", agentId: agentRecord.id, request });
      return {
        selectedModel: "model.runtime",
        requestedModelId: request.model?.id ?? "auto",
        routeId: "route.runtime",
        endpointId: "endpoint.runtime",
        providerId: "provider.runtime",
        receiptId: "receipt.runtime-route",
      };
    },
    resolveRunMemory(agentRecord, request, prompt) {
      calls.push({ method: "resolveRunMemory", agentId: agentRecord.id, request, prompt });
      return { records: [] };
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
    latestRuntimeEventSeq(eventStreamId) {
      calls.push({ method: "latestRuntimeEventSeq", eventStreamId });
      return overrides.latestSeq ?? 7;
    },
    resolveRunForThreadTurn(resolvedAgent, threadId, turnId) {
      calls.push({ method: "resolveRunForThreadTurn", agentId: resolvedAgent?.id, threadId, turnId });
      return {
        run,
        runId: run.id,
        turnId,
        inFlight: null,
      };
    },
    writeRun(plannedRun, operationKind) {
      calls.push({ method: "writeRun", plannedRun, operationKind });
      this.runs.set(plannedRun.id, plannedRun);
      return {
        operation_kind: operationKind,
        receipt_refs: [`receipt://${operationKind}/${plannedRun.id}`],
        policy_decision_refs: [`policy://${operationKind}/${plannedRun.id}`],
      };
    },
  };
}

function runtimeBridgeTurnDeps() {
  return {
    buildRun({ agent, mode, prompt, request }) {
      return {
        id: "run_runtime",
        agentId: agent.id,
        status: "completed",
        mode,
        objective: prompt,
        request,
        createdAt: "2026-06-13T12:02:00.000Z",
        updatedAt: "2026-06-13T12:02:00.000Z",
        events: [],
        conversation: [],
        receipts: [],
        artifacts: [],
        trace: {},
      };
    },
    ensureProviderAvailable() {},
    threadModeForRunMode(_mode, fallback = "agent") {
      return fallback ?? "agent";
    },
    approvalModeForThreadMode() {
      return "suggest";
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
      };
    },
  };
}

function createOperatorTurnControlRunner(calls) {
  return {
    planOperatorInterruptStateUpdate(request) {
      calls.push({ method: "planOperatorInterruptStateUpdate", request });
      return {
        source: "rust_operator_interrupt_state_update_command",
        backend: "rust_policy",
        status: "planned",
        operation_kind: "turn.interrupt",
        updated_at: request.created_at,
        operator_control: {
          control: "interrupt",
          source: request.source,
          reason: request.reason,
          event_id: request.event_id,
          seq: 8,
          created_at: request.created_at,
        },
        stop_condition: {
          reason: "operator_interrupt",
        },
        run: {
          ...request.run,
          status: "canceled",
          turnStatus: "interrupted",
          updatedAt: request.created_at,
          trace: {
            ...(request.run.trace ?? {}),
            operatorControls: [{
              control: "interrupt",
              event_id: request.event_id,
            }],
          },
        },
      };
    },
    planOperatorSteerStateUpdate(request) {
      calls.push({ method: "planOperatorSteerStateUpdate", request });
      return {
        source: "rust_operator_steer_state_update_command",
        backend: "rust_policy",
        status: "planned",
        operation_kind: "turn.steer",
        updated_at: request.created_at,
        operator_control: {
          control: "steer",
          source: request.source,
          guidance: request.guidance,
          event_id: request.event_id,
          seq: 9,
          created_at: request.created_at,
        },
        run: {
          ...request.run,
          updatedAt: request.created_at,
          trace: {
            ...(request.run.trace ?? {}),
            operatorControls: [{
              control: "steer",
              event_id: request.event_id,
            }],
          },
        },
      };
    },
  };
}

test("thread turn surface controls runtime thread resume through Rust bridge-control state planning", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    ...runtimeBridgeTurnDeps(),
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtime_profile: "runtime_service" },
  });

  const thread = await surface.resumeThread(store, "thread_alpha", { reason: "continue" });

  assert.equal(thread.thread_id, "thread_alpha");
  assert.equal(thread.agent_id, "agent_runtime");
  assert.equal(thread.rust_projected, true);
  assert.deepEqual(
    store.calls.map((call) => call.method),
    [
      "agentForThread",
      "planRuntimeBridgeThreadControlAgentStateUpdate",
      "writeAgent",
      "threadForAgent",
    ],
  );
  assert.equal(store.calls[1].request.thread_id, "thread_alpha");
  assert.equal(store.calls[1].request.agent.id, "agent_runtime");
  assert.equal(store.calls[1].request.action, "resume");
  assert.equal(store.calls[1].request.reason, "continue");
  assert.equal(store.calls[2].operationKind, "thread.runtime_bridge.control");

  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
});

test("thread turn surface fails closed for runtime thread resume when Rust bridge-control boundary is missing", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    ...runtimeBridgeTurnDeps(),
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtime_profile: "runtime_service" },
    contextPolicyCore: {},
  });

  await assert.rejects(
    () => surface.resumeThread(store, "thread_alpha", { reason: "continue" }),
    (error) => assertRuntimeBridgeThreadRustCoreRequired(error, {
      operation: "runtime_bridge_thread_control",
      operationKind: "thread.runtime_bridge.control",
      action: "resume",
      evidenceRef: "runtime_bridge_thread_control_rust_owned",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(store.calls.some((call) => call.method === "threadForAgent"), false);
});

test("thread turn surface submits runtime turns through Rust bridge-turn state planning", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    ...runtimeBridgeTurnDeps(),
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtime_profile: "runtime_service" },
  });

  const turn = await surface.createTurn(store, "thread_alpha", {
    prompt: "ship it",
    options: {},
  });

  assert.equal(turn.thread_id, "thread_alpha");
  assert.equal(turn.request_id, "run_runtime");
  assert.equal(turn.run_id, "run_runtime");
  assert.deepEqual(
    store.calls.map((call) => call.method),
    [
      "agentForThread",
      "resolveRunModelRoute",
      "resolveRunMemory",
      "planRuntimeBridgeTurnRunStateUpdate",
      "writeRun",
      "turnForRun",
    ],
  );
  assert.equal(store.calls[3].request.thread_id, "thread_alpha");
  assert.equal(store.calls[3].request.agent.id, "agent_runtime");
  assert.equal(store.calls[3].request.run.objective, "ship it");
  assert.equal(store.calls[4].operationKind, "turn.runtime_bridge.submit");
  assert.equal(store.calls[5].runId, "run_runtime");
  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
});

test("thread turn surface fails closed for runtime turns when Rust bridge-turn lifecycle boundary is missing", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    isRuntimeBackedAgent: () => true,
    ...runtimeBridgeTurnDeps(),
    runtimeError,
  });
  const store = createStore({
    agent: { id: "agent_runtime", runtime_profile: "runtime_service" },
    contextPolicyCore: {},
  });

  await assert.rejects(
    () => surface.createTurn(store, "thread_alpha", {
      prompt: "ship it",
      options: {},
    }),
    (error) => assertRuntimeBridgeThreadRustCoreRequired(error, {
      operation: "runtime_bridge_turn_submit",
      operationKind: "turn.runtime_bridge.submit",
      evidenceRef: "runtime_bridge_turn_submit_rust_owned",
    }),
  );

  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "turnForRun"), false);
});

test("thread turn surface resumes non-runtime threads through Rust lifecycle status and projection", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    lifecycleAgentStatusUpdate(state, agentId, status, operationKind, deps) {
      state.calls.push({ method: "lifecycleAgentStatusUpdate", state, agentId, status, operationKind, deps });
      return { id: agentId, status, rust_planned: true };
    },
    runtimeError,
  });
  const store = createStore();

  const thread = await surface.resumeThread(store, "thread_alpha", { reason: "continue" });

  assert.equal(thread.thread_id, "thread_alpha");
  assert.equal(thread.agent_id, "agent_alpha");
  assert.equal(thread.status, "active");
  assert.deepEqual(
    store.calls.map((call) => call.method),
    ["agentForThread", "lifecycleAgentStatusUpdate", "threadForAgent"],
  );
  assert.equal(store.calls[1].state, store);
  assert.equal(store.calls[1].agentId, "agent_alpha");
  assert.equal(store.calls[1].status, "active");
  assert.equal(store.calls[1].operationKind, "agent.resume");
  assert.equal(store.calls[1].deps.statusStateUpdateRunner, null);
  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
});

test("thread turn surface fails closed for non-runtime resume when direct Rust lifecycle API is missing", async () => {
  const admissionRequiredCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyCore: createThreadTurnAdmissionRunner(admissionRequiredCalls),
    diagnosticsFeedbackBlocksContinuation: () => false,
    lifecycleAgentStatusUpdate: null,
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
    lifecycleRunCreate(state, agentId, request, deps) {
      state.calls.push({ method: "lifecycleRunCreate", state, agentId, request, deps });
      return { id: "run_alpha", agentId, request, rust_planned: true };
    },
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
      "lifecycleRunCreate",
      "turnForRun",
    ],
  );
  assert.equal(store.calls[2].state, store);
  assert.equal(store.calls[2].agentId, "agent_alpha");
  assert.equal(store.calls[2].request.prompt, "ship it");
  assert.equal(store.calls[2].deps.lifecycleAdmissionRunner, null);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
});

test("thread turn surface fails closed for non-runtime turns when direct Rust run API is missing", async () => {
  const admissionRequiredCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyCore: createThreadTurnAdmissionRunner(admissionRequiredCalls),
    diagnosticsFeedbackBlocksContinuation: () => false,
    lifecycleRunCreate: null,
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

test("thread turn surface creates diagnostics-blocked turns through Rust-planned run creation", async () => {
  const admissionRequiredCalls = [];
  const diagnosticsFeedback = {
    blocking: true,
    diagnostic_status: "findings",
    diagnostic_count: 2,
    injection_id: "diag_injection_alpha",
  };
  const runner = createThreadTurnAdmissionRunner(admissionRequiredCalls);
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyCore: runner,
    diagnosticsFeedbackBlocksContinuation: () => true,
    lifecycleRunCreate(state, agentId, request, deps) {
      state.calls.push({ method: "lifecycleRunCreate", state, agentId, request, deps });
      return { id: "run_alpha", agentId, request, rust_planned: true };
    },
    runtimeError,
  });
  const store = createStore({
    diagnosticsFeedback,
  });

  const turn = await surface.createTurn(store, "thread_alpha", {
    prompt: "ship it",
    options: {},
  });

  assert.equal(turn.turn_id, "turn_alpha");
  assert.equal(turn.thread_id, "thread_alpha");
  assert.equal(admissionRequiredCalls.length, 0);
  assert.deepEqual(
    store.calls.map((call) => call.method),
    [
      "agentForThread",
      "pendingDiagnosticsFeedbackForNextTurn",
      "lifecycleRunCreate",
      "turnForRun",
    ],
  );
  assert.deepEqual(store.calls[2].request.diagnostics_feedback, diagnosticsFeedback);
  assert.deepEqual(store.calls[2].request.context.diagnostics_feedback, diagnosticsFeedback);
  assert.equal(store.calls[2].deps.lifecycleAdmissionRunner, runner);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
  assert.equal(store.calls.some((call) => call.method === "updateAgent"), false);
  assert.equal(store.calls.some((call) => call.method === "createRuntimeBridgeTurn"), false);
});

test("thread turn surface plans operator interrupt and steer through Rust before run persistence", async () => {
  const operatorCalls = [];
  const surface = createRuntimeThreadTurnSurface({
    contextPolicyCore: createOperatorTurnControlRunner(operatorCalls),
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  const interrupt = await surface.interruptTurn(store, "thread_alpha", "turn_alpha", {
    runtime_control_action: "stop",
    created_at: "2026-06-13T12:02:00.000Z",
  });
  assert.equal(interrupt.status, "completed");
  assert.equal(interrupt.operation, "operator_interrupt");
  assert.equal(interrupt.operation_kind, "turn.interrupt");
  assert.equal(interrupt.thread_id, "thread_alpha");
  assert.equal(interrupt.turn_id, "turn_alpha");
  assert.equal(interrupt.run_id, "run_alpha");
  assert.equal(interrupt.seq, 8);
  assert.equal(interrupt.operator_control.control, "interrupt");
  assert.equal(interrupt.operator_control.reason, "stop");
  assert.equal(interrupt.run.turnStatus, "interrupted");
  assert.equal(interrupt.stop_condition.reason, "operator_interrupt");
  assert.equal(interrupt.receipt_refs[0], "receipt://turn.interrupt/run_alpha");
  assert.equal(interrupt.evidence_refs.includes("rust_daemon_core_operator_interrupt_state_update"), true);

  const steer = surface.steerTurn(store, "thread_alpha", "turn_alpha", {
    guidance: "focus on Rust-owned state",
    createdAt: "2026-06-13T12:03:00.000Z",
  });
  assert.equal(steer.status, "completed");
  assert.equal(steer.operation, "operator_steer");
  assert.equal(steer.operation_kind, "turn.steer");
  assert.equal(steer.operator_control.control, "steer");
  assert.equal(steer.operator_control.guidance, "focus on Rust-owned state");
  assert.equal(steer.receipt_refs[0], "receipt://turn.steer/run_alpha");
  assert.equal(steer.evidence_refs.includes("rust_daemon_core_operator_steer_state_update"), true);

  assert.deepEqual(operatorCalls.map((call) => call.method), [
    "planOperatorInterruptStateUpdate",
    "planOperatorSteerStateUpdate",
  ]);
  assert.equal(operatorCalls[0].request.run_id, "run_alpha");
  assert.equal(operatorCalls[0].request.reason, "stop");
  assert.equal(operatorCalls[0].request.event_id, "event_operator_interrupt_thread_alpha_turn_alpha_2026-06-13T12:02:00.000Z");
  assert.equal(operatorCalls[1].request.guidance, "focus on Rust-owned state");
  assert.equal(store.calls.filter((call) => call.method === "writeRun").length, 2);
  assert.equal(store.calls.some((call) => call.method === "createRun"), false);
});

test("thread turn surface fails closed for operator turn controls without state-update planner", async () => {
  const surface = createRuntimeThreadTurnSurface({
    diagnosticsFeedbackBlocksContinuation: () => false,
    runtimeError,
  });
  const store = createStore();

  await assert.rejects(
    () => surface.interruptTurn(store, "thread_alpha", "turn_alpha", { runtime_control_action: "stop" }),
    (error) => {
      assert.equal(error.code, "runtime_operator_turn_control_rust_core_required");
      assert.equal(error.details.operation, "operator_interrupt");
      assert.equal(error.details.operation_kind, "turn.interrupt");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.turn_id, "turn_alpha");
      assert.equal(error.details.requested_action, "stop");
      assertNoRetiredOperatorTurnControlDetailAliases(error.details);
      return true;
    },
  );

  assert.throws(
    () => surface.steerTurn(store, "thread_alpha", "turn_alpha", { guidance: "focus" }),
    (error) => {
      assert.equal(error.code, "runtime_operator_turn_control_rust_core_required");
      assert.equal(error.details.operation, "operator_steer");
      assert.equal(error.details.operation_kind, "turn.steer");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.turn_id, "turn_alpha");
      assert.equal(error.details.requested_action, null);
      assertNoRetiredOperatorTurnControlDetailAliases(error.details);
      return true;
    },
  );
});
