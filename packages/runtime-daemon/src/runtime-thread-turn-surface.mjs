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

export function createRuntimeThreadTurnSurface(deps = {}) {
  const {
    controlRuntimeBridgeThread: controlRuntimeBridgeThreadDep = controlRuntimeBridgeThread,
    diagnosticsFeedbackBlocksContinuation,
    isRuntimeBackedAgent: isRuntimeBackedAgentDep = isRuntimeBackedAgent,
    isRuntimeServiceProfile: isRuntimeServiceProfileDep = isRuntimeServiceProfile,
    optionalString: optionalStringDep = optionalString,
    operatorTurnControlAdmissionRunner = deps.contextPolicyRunner ?? null,
    requestWithThreadRuntimeControls: requestWithThreadRuntimeControlsDep = requestWithThreadRuntimeControls,
    runtimeError: runtimeErrorDep = runtimeError,
    runtimeProfileForRequest: runtimeProfileForRequestDep = runtimeProfileForRequest,
  } = deps;
  return {
    async resumeThread(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      if (isRuntimeBackedAgentDep(agent)) {
        return controlRuntimeBridgeThreadDep(
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
      throwThreadTurnRustCoreRequired({
        operation: "thread_resume",
        operationKind: "thread.resume",
        threadId,
        agentId: agent?.id ?? null,
        runtimeProfile: agent?.runtimeProfile ?? null,
        evidenceRefs: [
          "thread_resume_js_state_mutation_retired",
          "rust_daemon_core_thread_resume_required",
          "agentgres_thread_resume_truth_required",
        ],
      });
    },

    async createTurn(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const controlledRequest = requestWithThreadRuntimeControlsDep(agent, request);
      if (isRuntimeBackedAgentDep(agent)) {
        return store.createRuntimeBridgeTurn({
          agent,
          threadId,
          request: controlledRequest,
          diagnosticsFeedback: null,
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
      const diagnosticsFeedback = store.pendingDiagnosticsFeedbackForNextTurn?.(threadId, controlledRequest) ?? null;
      throwThreadTurnRustCoreRequired({
        operation: diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)
          ? "thread_turn_diagnostics_block"
          : "thread_turn_create",
        operationKind: diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)
          ? "turn.diagnostics_block"
          : "turn.create",
        threadId,
        agentId: agent?.id ?? null,
        runtimeProfile: agent?.runtimeProfile ?? null,
        evidenceRefs: [
          diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)
            ? "thread_turn_diagnostics_block_js_run_creation_retired"
            : "thread_turn_create_js_run_creation_retired",
          "rust_daemon_core_thread_turn_create_required",
          "agentgres_thread_turn_create_truth_required",
        ],
      });
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
    if (operatorTurnControlAdmissionRunner?.planOperatorTurnControlAdmissionRequired) {
      const record = operatorTurnControlAdmissionRunner.planOperatorTurnControlAdmissionRequired({
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        turn_id: turnId,
        requested_action: requestedAction,
        evidence_refs: operatorTurnControlEvidenceRefs(operation),
      });
      const planned = record?.record ?? record;
      throw runtimeErrorDep({
        status: Number(planned?.status_code ?? record?.status_code ?? 501),
        code: optionalStringDep(planned?.code ?? record?.code) ??
          "runtime_operator_turn_control_rust_core_required",
        message:
          optionalStringDep(planned?.message ?? record?.message) ??
          "Operator turn control requires direct Rust daemon-core state admission and persistence.",
        details: planned?.details ?? record?.details ?? {
          rust_core_boundary: "runtime.operator_turn_control",
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          turn_id: turnId,
          requested_action: requestedAction,
          evidence_refs: operatorTurnControlEvidenceRefs(operation),
        },
      });
    }
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
          ...operatorTurnControlEvidenceRefs(operation),
        ],
      },
    });
  }

  function operatorTurnControlEvidenceRefs(operation) {
    return operation === "operator_interrupt"
      ? [
          "operator_interrupt_js_facade_retired",
          "rust_daemon_core_operator_interrupt_required",
          "agentgres_operator_interrupt_state_truth_required",
        ]
      : [
          "operator_steer_js_facade_retired",
          "rust_daemon_core_operator_steer_required",
          "agentgres_operator_steer_state_truth_required",
        ];
  }

  function throwThreadTurnRustCoreRequired({
    operation,
    operationKind,
    threadId,
    agentId,
    runtimeProfile,
    evidenceRefs,
  }) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_thread_turn_rust_core_required",
      message: "Thread resume and turn creation require direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.thread_turn",
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        agent_id: agentId,
        runtime_profile: runtimeProfile,
        evidence_refs: evidenceRefs,
      },
    });
  }
}
