import {
  isRuntimeServiceProfile,
  runtimeProfileForRequest,
} from "./runtime-profile.mjs";
import {
  eventStreamIdForThread,
  isRuntimeBackedAgent,
} from "./runtime-identifiers.mjs";
import {
  requestWithThreadRuntimeControls,
} from "./threads/thread-runtime-controls.mjs";
import {
  createRun as createLifecycleRun,
  createRuntimeBridgeThreadControl,
  createRuntimeBridgeTurnRun,
} from "./runtime-agent-run-lifecycle.mjs";
import {
  updateAgent as updateLifecycleAgent,
} from "./threads/thread-store.mjs";
import {
  objectRecord,
  optionalString,
} from "./runtime-value-helpers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";

export function createRuntimeThreadTurnSurface(deps = {}) {
  const {
    approvalModeForThreadMode = null,
    buildRun = null,
    contextPolicyCore = null,
    diagnosticsFeedbackBlocksContinuation,
    ensureProviderAvailable = null,
    isRuntimeBackedAgent: isRuntimeBackedAgentDep = isRuntimeBackedAgent,
    isRuntimeServiceProfile: isRuntimeServiceProfileDep = isRuntimeServiceProfile,
    optionalString: optionalStringDep = optionalString,
    requestWithThreadRuntimeControls: requestWithThreadRuntimeControlsDep = requestWithThreadRuntimeControls,
    lifecycleAgentStatusUpdate = updateLifecycleAgent,
    lifecycleRunCreate = createLifecycleRun,
    runtimeError: runtimeErrorDep = runtimeError,
    runtimeProfileForRequest: runtimeProfileForRequestDep = runtimeProfileForRequest,
    threadModeForRunMode = null,
  } = deps;
  return {
    async resumeThread(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      if (isRuntimeBackedAgentDep(agent)) {
        const threadProjection = await createRuntimeBridgeThreadControl(
          store,
          threadId,
          agent,
          {
            ...request,
            action: "resume",
          },
          {
            lifecycleAdmissionRunner: contextPolicyCore,
            runtimeError: runtimeErrorDep,
          },
        );
        if (
          optionalStringDep(threadProjection?.thread_id) !== threadId ||
          optionalStringDep(threadProjection?.agent_id) !== optionalStringDep(agent?.id)
        ) {
          throwThreadTurnProjectionMismatch({
            operation: "runtime_bridge_thread_control",
            operationKind: "thread.runtime_bridge.control",
            threadId,
            agentId: agent?.id ?? null,
            actualThreadId: optionalStringDep(threadProjection?.thread_id) ?? null,
            actualAgentId: optionalStringDep(threadProjection?.agent_id) ?? null,
          });
        }
        return threadProjection;
      }
      if (
        typeof lifecycleAgentStatusUpdate !== "function" ||
        typeof store.threadForAgent !== "function"
      ) {
        throwThreadTurnRustCoreRequired({
          operation: "thread_resume",
          operationKind: "thread.resume",
          threadId,
          agentId: agent?.id ?? null,
          runtime_profile: agent?.runtime_profile ?? null,
          evidenceRefs: [
            "thread_resume_js_state_mutation_retired",
            "rust_daemon_core_thread_resume_required",
            "agentgres_thread_resume_truth_required",
          ],
        });
      }
      const updatedAgent = await lifecycleAgentStatusUpdate(
        store,
        agent.id,
        "active",
        "agent.resume",
        {
          runtimeError: runtimeErrorDep,
          statusStateUpdateRunner: contextPolicyCore,
        },
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
        const turnProjection = await createRuntimeBridgeTurnRun(
          store,
          threadId,
          agent,
          controlledRequest,
          {
            approvalModeForThreadMode,
            buildRun,
            ensureProviderAvailable,
            lifecycleAdmissionRunner: contextPolicyCore,
            repositoryWorkflowProjector: contextPolicyCore,
            runtimeError: runtimeErrorDep,
            threadModeForRunMode,
          },
        );
        const projectionRunId = optionalStringDep(turnProjection?.run_id ?? turnProjection?.request_id);
        if (
          optionalStringDep(turnProjection?.thread_id) !== threadId ||
          !projectionRunId
        ) {
          throwThreadTurnProjectionMismatch({
            operation: "runtime_bridge_turn_submit",
            operationKind: "turn.runtime_bridge.submit",
            threadId,
            agentId: agent?.id ?? null,
            actualThreadId: optionalStringDep(turnProjection?.thread_id) ?? null,
            actualRunId: projectionRunId ?? null,
          });
        }
        return turnProjection;
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
            agent_runtime_profile: agent.runtime_profile ?? "fixture",
            requested_runtime_profile: requestedRuntimeProfile,
            synthetic_fallback_allowed: false,
          },
        });
      }
      const diagnosticsFeedback = store.pendingDiagnosticsFeedbackForNextTurn?.(threadId, controlledRequest) ?? null;
      const turnRequest = diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)
        ? {
            ...controlledRequest,
            diagnostics_feedback: diagnosticsFeedback,
            context: {
              ...(controlledRequest.context ?? {}),
              diagnostics_feedback: diagnosticsFeedback,
            },
          }
        : controlledRequest;
      if (
        typeof lifecycleRunCreate !== "function" ||
        typeof store.turnForRun !== "function"
      ) {
        throwThreadTurnRustCoreRequired({
          operation: "thread_turn_create",
          operationKind: "turn.create",
          threadId,
          agentId: agent?.id ?? null,
          runtime_profile: agent?.runtime_profile ?? null,
          evidenceRefs: [
            "thread_turn_create_js_run_creation_retired",
            "rust_daemon_core_thread_turn_create_required",
            "agentgres_thread_turn_create_truth_required",
          ],
        });
      }
      const run = await lifecycleRunCreate(store, agent.id, turnRequest, {
        approvalModeForThreadMode,
        buildRun,
        ensureProviderAvailable,
        lifecycleAdmissionRunner: contextPolicyCore,
        repositoryWorkflowProjector: contextPolicyCore,
        runtimeError: runtimeErrorDep,
        threadModeForRunMode,
      });
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
      return applyOperatorTurnControl(store, threadId, turnId, request, {
        operation: "operator_interrupt",
        operationKind: "turn.interrupt",
        plannerMethod: "planOperatorInterruptStateUpdate",
        controlKind: "interrupt",
        controlRequest: {
          reason:
            optionalStringDep(request.reason ?? request.runtime_control_action ?? request.control_action ?? request.message) ??
            "operator requested interrupt",
        },
      });
    },

    steerTurn(store, threadId, turnId, request = {}) {
      return applyOperatorTurnControl(store, threadId, turnId, request, {
        operation: "operator_steer",
        operationKind: "turn.steer",
        plannerMethod: "planOperatorSteerStateUpdate",
        controlKind: "steer",
        controlRequest: {
          guidance:
            optionalStringDep(request.guidance ?? request.message ?? request.input) ??
            "operator provided steering guidance",
        },
      });
    },
  };

  function applyOperatorTurnControl(
    store,
    threadId,
    turnId,
    request,
    { operation, operationKind, plannerMethod, controlKind, controlRequest = {} },
  ) {
    const planner = contextPolicyCore?.[plannerMethod];
    const requestedAction =
      operation === "operator_interrupt"
        ? request.runtime_control_action ?? request.control_action ?? null
        : null;
    if (typeof planner !== "function") {
      throwOperatorTurnControlRustCoreRequired({
        operation,
        operationKind,
        threadId,
        turnId,
        requestedAction,
      });
    }
    if (
      typeof store?.writeRun !== "function"
    ) {
      throwOperatorTurnControlStateUpdateError({
        code: "runtime_operator_turn_control_state_store_unavailable",
        message: "Operator turn control requires Rust-owned run replay and Agentgres run persistence.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          turn_id: turnId,
          evidence_refs: operatorTurnControlEvidenceRefs(operation),
        },
      });
    }
    const streamId = eventStreamIdForThread(threadId);
    const createdAt = optionalStringDep(request.created_at ?? request.createdAt) ?? new Date().toISOString();
    const eventId =
      optionalStringDep(request.event_id ?? request.eventId) ??
      operatorTurnControlEventId(operation, threadId, turnId, createdAt);
    const plan = planner.call(contextPolicyCore, {
      thread_id: threadId,
      state_dir: optionalStringDep(store?.stateDir) ?? null,
      event_stream_id: streamId,
      turn_id: turnId,
      event_id: eventId,
      created_at: createdAt,
      source: optionalStringDep(request.source) ?? "hypervisor_daemon",
      ...controlRequest,
    });
    const plannedRun = objectRecord(plan?.run);
    const plannedRunId = optionalStringDep(plannedRun?.id);
    const plannedOperationKind = optionalStringDep(plan?.operation_kind);
    const operatorControl = objectRecord(plan?.operator_control);
    if (
      optionalStringDep(plan?.status) !== "planned" ||
      plannedOperationKind !== operationKind ||
      !plannedRun ||
      !plannedRunId ||
      !operatorControl ||
      optionalStringDep(operatorControl.control) !== controlKind ||
      optionalStringDep(operatorControl.event_id) !== eventId
    ) {
      throwOperatorTurnControlStateUpdateError({
        code: "runtime_operator_turn_control_projection_incomplete",
        message: "Rust daemon-core operator turn control did not return a complete run projection.",
        details: {
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          turn_id: turnId,
          run_id: plannedRunId ?? null,
          expected_operation_kind: operationKind,
          actual_operation_kind: plannedOperationKind ?? null,
          actual_status: optionalStringDep(plan?.status) ?? null,
        },
      });
    }
    const commit = store.writeRun(plannedRun, plannedOperationKind);
    return {
      schema_version: "ioi.runtime.operator_turn_control.v1",
      object: "ioi.runtime_operator_turn_control",
      status: "completed",
      operation,
      operation_kind: plannedOperationKind,
      thread_id: threadId,
      turn_id: turnId,
      run_id: plannedRunId,
      event_id: eventId,
      seq: positiveInteger(operatorControl.seq) ?? null,
      operator_control: operatorControl,
      stop_condition: objectRecord(plan?.stop_condition) ?? null,
      run: plannedRun,
      commit,
      receipt_refs: stringRefs(commit?.receipt_refs),
      policy_decision_refs: stringRefs(commit?.policy_decision_refs),
      evidence_refs: operatorTurnControlPositiveEvidenceRefs(operation),
    };
  }

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
    if (contextPolicyCore?.planOperatorTurnControlAdmissionRequired) {
      const record = contextPolicyCore.planOperatorTurnControlAdmissionRequired({
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

  function operatorTurnControlPositiveEvidenceRefs(operation) {
    return operation === "operator_interrupt"
      ? [
          "operator_interrupt_js_facade_retired",
          "rust_daemon_core_operator_interrupt_state_update",
          "agentgres_operator_interrupt_state_truth_required",
        ]
      : [
          "operator_steer_js_facade_retired",
          "rust_daemon_core_operator_steer_state_update",
          "agentgres_operator_steer_state_truth_required",
        ];
  }

  function operatorTurnControlEventId(operation, threadId, turnId, suffix) {
    return [
      "event",
      operation,
      safeRuntimeEventIdSegment(threadId),
      safeRuntimeEventIdSegment(turnId),
      safeRuntimeEventIdSegment(suffix),
    ].join("_");
  }

  function safeRuntimeEventIdSegment(value) {
    return optionalStringDep(value)?.replace(/[^a-zA-Z0-9_.:-]/g, "_") ?? "unknown";
  }

  function positiveInteger(value) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : null;
  }

  function stringRefs(value) {
    return Array.isArray(value)
      ? value.filter((item) => typeof item === "string" && item.length > 0)
      : [];
  }

  function throwOperatorTurnControlStateUpdateError({ code, message, details = {} }) {
    throw runtimeErrorDep({
      status: code.endsWith("_unavailable") ? 404 : 502,
      code,
      message,
      details: {
        rust_core_boundary: "runtime.operator_turn_control",
        ...details,
      },
    });
  }

  function throwThreadTurnRustCoreRequired({
    operation,
    operationKind,
    threadId,
    agentId,
    runtime_profile,
    evidenceRefs,
  }) {
    if (contextPolicyCore?.planThreadTurnAdmissionRequired) {
      const record = contextPolicyCore.planThreadTurnAdmissionRequired({
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        agent_id: agentId,
        runtime_profile,
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
          runtime_profile,
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
        runtime_profile,
        evidence_refs: evidenceRefs,
      },
    });
  }

}
