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
  optionalString,
} from "./runtime-value-helpers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";

export function createRuntimeThreadTurnSurface(deps = {}) {
  const {
    diagnosticsFeedbackBlocksContinuation,
    isRuntimeBackedAgent: isRuntimeBackedAgentDep = isRuntimeBackedAgent,
    isRuntimeServiceProfile: isRuntimeServiceProfileDep = isRuntimeServiceProfile,
    optionalString: optionalStringDep = optionalString,
    operatorTurnControlAdmissionRunner = deps.contextPolicyRunner ?? null,
    requestWithThreadRuntimeControls: requestWithThreadRuntimeControlsDep = requestWithThreadRuntimeControls,
    runtimeError: runtimeErrorDep = runtimeError,
    runtimeProfileForRequest: runtimeProfileForRequestDep = runtimeProfileForRequest,
    threadTurnAdmissionRunner = deps.contextPolicyRunner ?? null,
  } = deps;
  return {
    async resumeThread(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      if (isRuntimeBackedAgentDep(agent)) {
        return throwRuntimeBridgeThreadRustCoreRequired({
          operation: "runtime_bridge_thread_control",
          operationKind: "thread.runtime_bridge.control",
          details: {
            thread_id: threadId,
            agent_id: agent?.id ?? null,
            runtime_profile: agent?.runtimeProfile ?? null,
            action: "resume",
            reason:
              optionalStringDep(request.reason ?? request.message ?? request.input) ??
              "operator requested resume",
            evidence_refs: [
              "runtime_bridge_thread_control_js_facade_retired",
              "rust_daemon_core_runtime_bridge_thread_control_required",
              "agentgres_runtime_bridge_thread_control_truth_required",
            ],
          },
        });
      }
      if (
        typeof store.agentRunLifecycleSurface?.updateAgent !== "function" ||
        typeof store.threadForAgent !== "function"
      ) {
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
      }
      const updatedAgent = await store.agentRunLifecycleSurface.updateAgent(
        store,
        agent.id,
        "active",
        "agent.resume",
      );
      const threadProjection = store.threadForAgent(updatedAgent);
      if (
        optionalStringDep(threadProjection?.thread_id) !== threadId ||
        optionalStringDep(threadProjection?.agent_id) !== optionalStringDep(updatedAgent?.id)
      ) {
        throwThreadTurnProjectionMismatch({
          operation: "thread_resume",
          operationKind: "thread.resume",
          threadId,
          agentId: optionalStringDep(updatedAgent?.id) ?? agent?.id ?? null,
          actualThreadId: optionalStringDep(threadProjection?.thread_id) ?? null,
          actualAgentId: optionalStringDep(threadProjection?.agent_id) ?? null,
        });
      }
      return threadProjection;
    },

    async createTurn(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const controlledRequest = requestWithThreadRuntimeControlsDep(agent, request);
      if (isRuntimeBackedAgentDep(agent)) {
        return throwRuntimeBridgeThreadRustCoreRequired({
          operation: "runtime_bridge_turn_submit",
          operationKind: "turn.runtime_bridge.submit",
          details: {
            thread_id: threadId,
            agent_id: agent?.id ?? null,
            runtime_profile: agent?.runtimeProfile ?? null,
            evidence_refs: [
              "runtime_bridge_turn_submit_js_facade_retired",
              "rust_daemon_core_runtime_bridge_turn_required",
              "agentgres_runtime_bridge_turn_truth_required",
            ],
          },
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
      if (diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)) {
        throwThreadTurnRustCoreRequired({
          operation: "thread_turn_diagnostics_block",
          operationKind: "turn.diagnostics_block",
          threadId,
          agentId: agent?.id ?? null,
          runtimeProfile: agent?.runtimeProfile ?? null,
          evidenceRefs: [
            "thread_turn_diagnostics_block_js_run_creation_retired",
            "rust_daemon_core_thread_turn_create_required",
            "agentgres_thread_turn_create_truth_required",
          ],
        });
      }
      if (
        typeof store.agentRunLifecycleSurface?.createRun !== "function" ||
        typeof store.turnForRun !== "function"
      ) {
        throwThreadTurnRustCoreRequired({
          operation: "thread_turn_create",
          operationKind: "turn.create",
          threadId,
          agentId: agent?.id ?? null,
          runtimeProfile: agent?.runtimeProfile ?? null,
          evidenceRefs: [
            "thread_turn_create_js_run_creation_retired",
            "rust_daemon_core_thread_turn_create_required",
            "agentgres_thread_turn_create_truth_required",
          ],
        });
      }
      const run = await store.agentRunLifecycleSurface.createRun(store, agent.id, controlledRequest);
      const turnProjection = store.turnForRun(run);
      if (
        optionalStringDep(turnProjection?.thread_id) !== threadId ||
        optionalStringDep(turnProjection?.request_id ?? turnProjection?.run_id) !== optionalStringDep(run?.id)
      ) {
        throwThreadTurnProjectionMismatch({
          operation: "thread_turn_create",
          operationKind: "turn.create",
          threadId,
          agentId: agent?.id ?? null,
          runId: optionalStringDep(run?.id) ?? null,
          actualThreadId: optionalStringDep(turnProjection?.thread_id) ?? null,
          actualRunId: optionalStringDep(turnProjection?.request_id ?? turnProjection?.run_id) ?? null,
        });
      }
      return turnProjection;
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

  function throwThreadTurnProjectionMismatch({
    operation,
    operationKind,
    threadId,
    agentId,
    runId = null,
    actualThreadId = null,
    actualAgentId = null,
    actualRunId = null,
  }) {
    throw runtimeErrorDep({
      status: 502,
      code: "runtime_thread_turn_projection_mismatch",
      message: "Rust daemon-core thread/turn projection did not match the admitted lifecycle state.",
      details: {
        rust_core_boundary: "runtime.thread_turn",
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        agent_id: agentId,
        run_id: runId,
        actual_thread_id: actualThreadId,
        actual_agent_id: actualAgentId,
        actual_run_id: actualRunId,
      },
    });
  }

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
    if (threadTurnAdmissionRunner?.planThreadTurnAdmissionRequired) {
      const record = threadTurnAdmissionRunner.planThreadTurnAdmissionRequired({
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        agent_id: agentId,
        runtime_profile: runtimeProfile,
        evidence_refs: evidenceRefs,
      });
      const planned = record?.record ?? record;
      throw runtimeErrorDep({
        status: Number(planned?.status_code ?? record?.status_code ?? 501),
        code: optionalStringDep(planned?.code ?? record?.code) ??
          "runtime_thread_turn_rust_core_required",
        message:
          optionalStringDep(planned?.message ?? record?.message) ??
          "Thread resume and turn creation require direct Rust daemon-core admission and persistence.",
        details: planned?.details ?? record?.details ?? {
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

  function throwRuntimeBridgeThreadRustCoreRequired({ operation, operationKind, details = {} }) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_bridge_thread_rust_core_required",
      message:
        "Runtime bridge thread start and turn submission require direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.bridge_thread",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }
}
