import {
  isRuntimeServiceProfile,
  runtimeProfileForRequest,
} from "./runtime-api-bridge.mjs";
import {
  isRuntimeBackedAgent,
} from "./runtime-identifiers.mjs";
import {
  requestWithThreadRuntimeControls,
} from "./threads/thread-runtime-controls.mjs";
import {
  controlRuntimeBridgeThread,
} from "./threads/runtime-bridge-thread.mjs";
import {
  optionalString,
} from "./runtime-value-helpers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";

export function createRuntimeThreadTurnSurface({
  controlRuntimeBridgeThread: controlRuntimeBridgeThreadDep = controlRuntimeBridgeThread,
  diagnosticsFeedbackBlocksContinuation,
  isRuntimeBackedAgent: isRuntimeBackedAgentDep = isRuntimeBackedAgent,
  isRuntimeServiceProfile: isRuntimeServiceProfileDep = isRuntimeServiceProfile,
  optionalString: optionalStringDep = optionalString,
  requestWithDiagnosticsFeedback,
  requestWithThreadRuntimeControls: requestWithThreadRuntimeControlsDep = requestWithThreadRuntimeControls,
  runtimeError: runtimeErrorDep = runtimeError,
  runtimeProfileForRequest: runtimeProfileForRequestDep = runtimeProfileForRequest,
} = {}) {
  return {
    async resumeThread(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      let runtimeControl = null;
      if (isRuntimeBackedAgentDep(agent)) {
        runtimeControl = await controlRuntimeBridgeThreadDep(
          store,
          {
            agent,
            threadId,
            action: "resume",
            reason:
              optionalStringDep(request.reason ?? request.message ?? request.input) ??
              "operator requested resume",
          },
          {
            RuntimeApiBridgeUnavailableError: store.RuntimeApiBridgeUnavailableError,
            runtimeError: runtimeErrorDep,
            runtimeSessionIdForAgent: store.runtimeSessionIdForAgent,
          },
        );
      }
      const updated = store.updateAgent(agent.id, "active", "thread.resume");
      const thread = store.threadForAgent(updated);
      return runtimeControl
        ? {
            ...thread,
            runtime_control: runtimeControl,
            runtimeControl,
          }
        : thread;
    },

    async createTurn(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const controlledRequest = requestWithThreadRuntimeControlsDep(agent, request);
      const diagnosticsFeedback = store.pendingDiagnosticsFeedbackForNextTurn(threadId, controlledRequest);
      if (diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)) {
        const prompt = controlledRequest.prompt ?? controlledRequest.message ?? controlledRequest.input ?? "";
        const run = store.createRun(agent.id, {
          mode: controlledRequest.mode ?? "send",
          threadMode: controlledRequest.threadMode,
          approvalMode: controlledRequest.approvalMode,
          prompt,
          options: controlledRequest.options ?? {},
          memory: controlledRequest.memory,
          remember: controlledRequest.remember,
          diagnosticsFeedback,
        });
        return store.turnForRun(run);
      }
      if (isRuntimeBackedAgentDep(agent)) {
        return store.createRuntimeBridgeTurn({
          agent,
          threadId,
          request: requestWithDiagnosticsFeedback(controlledRequest, diagnosticsFeedback),
          diagnosticsFeedback,
        });
      }
      const requestedRuntimeProfile = runtimeProfileForRequestDep(
        controlledRequest,
        controlledRequest.options ?? {},
      );
      if (isRuntimeServiceProfileDep(requestedRuntimeProfile)) {
        throw runtimeErrorDep({
          status: 409,
          code: "runtime_thread_profile_mismatch",
          message:
            "Agent requested runtime_service execution on a non-runtime thread. Start a runtime_service thread before submitting governed Agent work.",
          details: {
            thread_id: threadId,
            agent_id: agent.id,
            agent_runtime_profile: agent.runtimeProfile ?? "fixture",
            requested_runtime_profile: requestedRuntimeProfile,
            synthetic_fallback_allowed: false,
          },
        });
      }
      const prompt = controlledRequest.prompt ?? controlledRequest.message ?? controlledRequest.input ?? "";
      const run = store.createRun(agent.id, {
        mode: controlledRequest.mode ?? "send",
        threadMode: controlledRequest.threadMode,
        approvalMode: controlledRequest.approvalMode,
        prompt,
        options: controlledRequest.options ?? {},
        memory: controlledRequest.memory,
        remember: controlledRequest.remember,
        diagnosticsFeedback,
      });
      return store.turnForRun(run);
    },

    async interruptTurn(store, threadId, turnId, request = {}) {
      void store;
      throwOperatorTurnControlRustCoreRequired({
        operation: "operator_interrupt",
        operationKind: "turn.interrupt",
        threadId,
        turnId,
        requestedAction: request.runtime_control_action ?? request.control_action ?? null,
      });
    },

    steerTurn(store, threadId, turnId, request = {}) {
      void store;
      void request;
      throwOperatorTurnControlRustCoreRequired({
        operation: "operator_steer",
        operationKind: "turn.steer",
        threadId,
        turnId,
      });
    },
  };

  function throwOperatorTurnControlRustCoreRequired({
    operation,
    operationKind,
    threadId,
    turnId,
    requestedAction = null,
  }) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_operator_turn_control_rust_core_required",
      message: "Operator turn control requires direct Rust daemon-core state admission and persistence.",
      details: {
        rust_core_boundary: "runtime.operator_turn_control",
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        turn_id: turnId,
        requested_action: requestedAction,
        evidence_refs: [
          operation === "operator_interrupt"
            ? "operator_interrupt_js_facade_retired"
            : "operator_steer_js_facade_retired",
          operation === "operator_interrupt"
            ? "rust_daemon_core_operator_interrupt_required"
            : "rust_daemon_core_operator_steer_required",
          operation === "operator_interrupt"
            ? "agentgres_operator_interrupt_state_truth_required"
            : "agentgres_operator_steer_state_truth_required",
        ],
      },
    });
  }
}
