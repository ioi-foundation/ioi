import { runtimeError as defaultRuntimeError } from "./runtime-http-utils.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  createRun as createLifecycleRun,
} from "./runtime-agent-run-lifecycle.mjs";
import {
  DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import { normalizeArray, objectRecord, optionalString } from "./runtime-value-helpers.mjs";

const DIAGNOSTICS_REPAIR_CONTROL_EVENT_EVIDENCE_REFS = [
  "runtime_diagnostics_repair_control_event_rust_owned",
  "agentgres_runtime_thread_event_truth_required",
];

const DIAGNOSTICS_REPAIR_RETRY_RUN_EVIDENCE_REFS = [
  "runtime_diagnostics_repair_retry_run_request_rust_owned",
  "diagnostics_repair_retry_run_create_rust_owned",
  "runtime_run_create_js_facade_retired",
  "agentgres_run_create_state_truth_required",
];

const DIAGNOSTICS_REPAIR_RETRY_RESULT_EVIDENCE_REFS = [
  "runtime_diagnostics_repair_retry_result_projection_rust_owned",
  "runtime_diagnostics_repair_retry_event_replay_required",
  "runtime_diagnostics_repair_js_result_helper_retired",
];

const DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_EVIDENCE_REFS = [
  "diagnostics_operator_override_state_update_rust_owned",
  "rust_daemon_core_operator_override_state_required",
  "agentgres_operator_override_state_truth_required",
  "rust_agentgres_runtime_run_state_commit",
];

const DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS = [
  "runtime_diagnostics_repair_decision_projection_rust_owned",
  "rust_daemon_core_diagnostics_repair_projection_required",
  "rust_daemon_core_diagnostics_repair_replay_required",
  "agentgres_diagnostics_repair_projection_truth_required",
];

const DIAGNOSTICS_REPAIR_DECISION_EXECUTION_RETIRED_REQUEST_ALIASES = [
  "schemaVersion",
  "decisionId",
  "gateId",
  "snapshotId",
  "workflowGraphId",
  "workflowNodeId",
  "approvalDecision",
  "policyDecision",
  "approvalGranted",
  "allowConflicts",
  "overrideConflicts",
  "restoreConflictPolicy",
  "conflictPolicy",
  "restorePolicy",
  "restorePreviewIdempotencyKey",
  "restoreApplyIdempotencyKey",
  "repairRetryIdempotencyKey",
  "operatorOverrideIdempotencyKey",
  "idempotencyKey",
  "repairPromptText",
  "operatorOverrideApproved",
  "operatorOverrideApproval",
  "confirmRestoreApply",
  "applyConfirmed",
  "eventKind",
  "componentKind",
  "payloadSchemaVersion",
];

export function createRuntimeDiagnosticsRepairApi(deps = {}) {
  const {
    approvalModeForThreadMode = null,
    buildRun = null,
    contextPolicyCore = null,
    createLifecycleRun: createLifecycleRunDep = createLifecycleRun,
    ensureProviderAvailable = null,
    eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
    runtimeError = defaultRuntimeError,
    threadModeForRunMode = null,
  } = deps;

  function diagnosticsRepairControlEvidenceRefs(operationKind) {
    const refs = [...DIAGNOSTICS_REPAIR_CONTROL_EVENT_EVIDENCE_REFS];
    if (operationKind === "diagnostics.repair_retry.created") {
      refs.unshift("runtime_diagnostics_repair_retry_event_rust_owned");
    } else if (operationKind === "diagnostics.operator_override.event") {
      refs.unshift("runtime_diagnostics_operator_override_event_rust_owned");
    } else if (operationKind === "diagnostics.repair_decision.executed") {
      refs.unshift("runtime_diagnostics_repair_decision_event_rust_owned");
    } else {
      refs.unshift("runtime_diagnostics_repair_decision_execution_rust_owned");
    }
    return refs;
  }

  function throwDiagnosticsRepairControlRustCoreRequired({
    operation,
    operation_kind,
    thread_id,
    decision_id = null,
  }) {
    throw runtimeError({
      status: 501,
      code: "runtime_diagnostics_repair_control_rust_core_required",
      message:
        "Runtime diagnostics repair control requires Rust daemon-core planning and runtime-event admission.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair",
        operation,
        operation_kind,
        thread_id: thread_id ?? null,
        decision_id: decision_id ?? null,
        evidence_refs: diagnosticsRepairControlEvidenceRefs(operation_kind),
      },
    });
  }

  function requireDiagnosticsRepairControlCore(store, request = {}) {
    if (
      contextPolicyCore?.planRuntimeDiagnosticsRepairControl &&
      typeof store?.appendRuntimeEvent === "function"
    ) {
      return contextPolicyCore;
    }
    throwDiagnosticsRepairControlRustCoreRequired({
      operation: request.operation,
      operation_kind: request.operation_kind,
      thread_id: request.thread_id,
      decision_id: request.decision_id,
    });
  }

  function throwDiagnosticsRepairRetryRunRustCoreRequired(details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_diagnostics_repair_retry_run_rust_core_required",
      message:
        "Diagnostics repair retry creation requires Rust daemon-core retry-run planning.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair.retry_run",
        operation: "diagnostics_repair_retry_run_create",
        operation_kind: "diagnostics.repair_retry.run_create",
        ...details,
        evidence_refs: DIAGNOSTICS_REPAIR_RETRY_RUN_EVIDENCE_REFS,
      },
    });
  }

  function requireDiagnosticsRepairRetryRunCore(details = {}) {
    if (
      contextPolicyCore?.planRuntimeDiagnosticsRepairRetryRun &&
      contextPolicyCore?.planRuntimeDiagnosticsRepairControl
    ) {
      return contextPolicyCore;
    }
    throwDiagnosticsRepairRetryRunRustCoreRequired(details);
  }

  function throwDiagnosticsRepairRetryResultRustCoreRequired(details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_diagnostics_repair_retry_result_rust_core_required",
      message:
        "Diagnostics repair retry result projection requires Rust daemon-core retry-result projection.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair.retry_result",
        operation: "project_runtime_diagnostics_repair_retry_result",
        operation_kind: "runtime.diagnostics_repair_retry.result",
        ...details,
        evidence_refs: DIAGNOSTICS_REPAIR_RETRY_RESULT_EVIDENCE_REFS,
      },
    });
  }

  function requireDiagnosticsRepairRetryResultProjectionCore(details = {}) {
    if (contextPolicyCore?.projectRuntimeDiagnosticsRepairRetryResult) {
      return contextPolicyCore;
    }
    throwDiagnosticsRepairRetryResultRustCoreRequired(details);
  }

  function requireDiagnosticsRepairProjectionCore(details = {}) {
    if (contextPolicyCore?.projectRuntimeDiagnosticsRepairProjection) {
      return contextPolicyCore;
    }
    throwDiagnosticsRepairRustCoreRequired(
      "diagnostics_repair_decision_projection",
      "runtime.diagnostics_repair_projection.decision",
      {
        ...details,
        evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
      },
    );
  }

  function diagnosticsRepairControlRequestPayload(request = {}) {
    const payload = {};
    for (const key of [
      "schema_version",
      "object",
      "source",
      "status",
      "message",
      "event_id",
      "event_kind",
      "component_kind",
      "payload_schema_version",
      "turn_id",
      "decision_id",
      "gate_event_id",
      "gate_id",
      "snapshot_id",
      "workspace_root",
      "workflow_graph_id",
      "workflow_node_id",
      "action",
      "repair_action",
      "approval_id",
      "approval_decision",
      "policy_decision",
      "approval_granted",
      "operator_override_approved",
      "allow_conflicts",
      "override_conflicts",
      "restore_conflict_policy",
      "diagnostic_refs",
      "target_paths",
      "retry_turn_id",
      "retry_request_id",
      "retry_run_id",
      "target_run_id",
      "summary",
      "artifact_refs",
      "rollback_refs",
      "receipt_refs",
      "policy_decision_refs",
      "authority_grant_refs",
      "authority_receipt_refs",
      "idempotency_key",
      "restore_preview_idempotency_key",
      "restore_apply_idempotency_key",
      "repair_retry_idempotency_key",
      "operator_override_idempotency_key",
      "repair_prompt_text",
    ]) {
      if (Object.hasOwn(request, key)) payload[key] = request[key];
    }
    return payload;
  }

  function rejectDiagnosticsRepairDecisionExecutionRetiredAliases(request = {}, details = {}) {
    const record = objectRecord(request) ?? {};
    const retiredInputs = DIAGNOSTICS_REPAIR_DECISION_EXECUTION_RETIRED_REQUEST_ALIASES
      .filter((key) => Object.hasOwn(record, key));
    if (retiredInputs.length === 0) return;
    throw runtimeError({
      status: 400,
      code: "runtime_diagnostics_repair_decision_request_aliases_retired",
      message:
        "Runtime diagnostics repair decision execution requires canonical daemon protocol request fields.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair",
        operation: "diagnostics_repair_decision_execution",
        operation_kind: "diagnostics.repair_decision.execute",
        ...details,
        retired_inputs: retiredInputs,
        evidence_refs: diagnosticsRepairControlEvidenceRefs(
          "diagnostics.repair_decision.execute",
        ),
      },
    });
  }

  function rejectDiagnosticsRepairProjectionCandidateTransport(request = {}, details = {}) {
    const retiredInputs = ["projection", "decision", "decisions", "repair_decisions"]
      .filter((key) => Object.hasOwn(request, key));
    if (retiredInputs.length === 0) return;
    throw runtimeError({
      status: 400,
      code: "runtime_diagnostics_repair_projection_candidate_transport_retired",
      message:
        "Runtime diagnostics repair decision projection rejects retired JS decision candidate transport.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair.projection",
        operation: "diagnostics_repair_decision_projection",
        operation_kind: "runtime.diagnostics_repair_projection.decision",
        ...details,
        retired_inputs: retiredInputs,
        evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
      },
    });
  }

  function stringRefs(values) {
    return normalizeArray(values).map((value) => String(value)).filter(Boolean);
  }

  function mergedStringRefs(...values) {
    const refs = [];
    for (const value of values) {
      for (const ref of stringRefs(value)) {
        if (!refs.includes(ref)) refs.push(ref);
      }
    }
    return refs;
  }

  function positiveInteger(value) {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 ? number : null;
  }

  function throwDiagnosticsOperatorOverrideStateUpdateError({
    status = 502,
    code,
    message,
    details,
  }) {
    throw runtimeError({
      status,
      code,
      message,
      details: {
        rust_core_boundary: "runtime.diagnostics_repair.operator_override",
        evidence_refs: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_EVIDENCE_REFS,
        ...details,
      },
    });
  }

  function requireDiagnosticsOperatorOverrideStateUpdateCore(store, details = {}) {
    if (
      contextPolicyCore?.planDiagnosticsOperatorOverrideStateUpdate &&
      typeof store?.getRun === "function" &&
      typeof store?.writeRun === "function"
    ) {
      return contextPolicyCore;
    }
    throwDiagnosticsRepairRustCoreRequired(
      "diagnostics_operator_override_execution",
      "diagnostics.operator_override.execute",
      {
        ...details,
        evidence_refs: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_EVIDENCE_REFS,
      },
    );
  }

  function planDiagnosticsRepairControlEvent(store, threadId, request = {}, {
    operation,
    operationKind,
    decision_id = null,
  }) {
    const normalizedRequest = objectRecord(request) ?? {};
    const normalizedDecisionId =
      optionalString(decision_id) ??
      optionalString(normalizedRequest.decision_id) ??
      null;
    const core = requireDiagnosticsRepairControlCore(store, {
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      decision_id: normalizedDecisionId,
    });
    return core.planRuntimeDiagnosticsRepairControl({
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      event_stream_id: eventStreamIdForThreadDep(threadId),
      turn_id: optionalString(normalizedRequest.turn_id) ?? null,
      decision_id: normalizedDecisionId,
      gate_event_id: optionalString(normalizedRequest.gate_event_id) ?? null,
      gate_id: optionalString(normalizedRequest.gate_id) ?? null,
      snapshot_id: optionalString(normalizedRequest.snapshot_id) ?? null,
      workspace_root: optionalString(normalizedRequest.workspace_root) ?? null,
      source: optionalString(normalizedRequest.source) ?? null,
      status: optionalString(normalizedRequest.status) ?? null,
      request: diagnosticsRepairControlRequestPayload(normalizedRequest),
      receipt_refs: stringRefs(normalizedRequest.receipt_refs),
      policy_decision_refs: stringRefs(normalizedRequest.policy_decision_refs),
      evidence_refs: diagnosticsRepairControlEvidenceRefs(operationKind),
    });
  }

  function appendPlannedDiagnosticsRepairControlEvent(store, plannedControl) {
    const event = objectRecord(plannedControl?.event);
    if (!event) {
      throw runtimeError({
        status: 502,
        code: "runtime_diagnostics_repair_control_event_missing",
        message: "Rust diagnostics repair control planning did not return a runtime event.",
        details: { operation_kind: plannedControl?.operation_kind ?? null },
      });
    }
    return store.appendRuntimeEvent(event);
  }

  function throwDiagnosticsRepairRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_diagnostics_repair_rust_core_required",
      message: "Runtime diagnostics repair control requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function executeDiagnosticsRepairDecision(store, threadId, decisionRef, request = {}) {
    const normalizedRequest = objectRecord(request) ?? {};
    const decisionId =
      optionalString(decisionRef ?? normalizedRequest.decision_id ?? normalizedRequest.action) ??
      null;
    rejectDiagnosticsRepairDecisionExecutionRetiredAliases(normalizedRequest, {
      thread_id: threadId,
      decision_id: decisionId,
    });
    const plannedControl = planDiagnosticsRepairControlEvent(store, threadId, request, {
      operation: "diagnostics_repair_decision_execution",
      operationKind: "diagnostics.repair_decision.execute",
      decision_id: decisionId,
    });
    return appendPlannedDiagnosticsRepairControlEvent(store, plannedControl);
  }

  function executeDiagnosticsOperatorOverride(store, threadId, { request = {}, gateEvent, decision, snapshotId = null } = {}) {
    const normalizedRequest = objectRecord(request) ?? {};
    const decisionId =
      optionalString(decision?.decision_id ?? normalizedRequest.decision_id) ??
      "operator_override";
    const gateEventId =
      optionalString(gateEvent?.event_id ?? normalizedRequest.gate_event_id) ?? null;
    const normalizedSnapshotId =
      optionalString(snapshotId ?? normalizedRequest.snapshot_id) ?? null;
    const details = {
      thread_id: threadId,
      decision_id: decisionId,
      gate_event_id: gateEventId,
      snapshot_id: normalizedSnapshotId,
    };
    const core = requireDiagnosticsOperatorOverrideStateUpdateCore(store, details);
    const runId = optionalString(
      normalizedRequest.run_id ??
        normalizedRequest.target_run_id ??
        gateEvent?.run_id ??
        gateEvent?.target_run_id ??
        gateEvent?.payload?.run_id ??
        gateEvent?.payload?.target_run_id ??
        decision?.run_id ??
        decision?.target_run_id,
    );
    const eventId = optionalString(normalizedRequest.event_id);
    const seq = positiveInteger(normalizedRequest.seq);
    const createdAt = optionalString(normalizedRequest.created_at);
    if (!runId || !eventId || !seq || !createdAt) {
      throwDiagnosticsOperatorOverrideStateUpdateError({
        status: 400,
        code: "diagnostics_operator_override_state_update_input_required",
        message:
          "Diagnostics operator override requires canonical run_id, event_id, seq, and created_at inputs.",
        details: {
          ...details,
          run_id: runId ?? null,
          event_id: eventId ?? null,
          seq: seq ?? null,
          created_at: createdAt ?? null,
        },
      });
    }
    const run = store.getRun(runId);
    if (!objectRecord(run)) {
      throwDiagnosticsOperatorOverrideStateUpdateError({
        status: 404,
        code: "diagnostics_operator_override_run_not_found",
        message: "Diagnostics operator override requires an admitted run record.",
        details: { ...details, run_id: runId },
      });
    }
    const planned = core.planDiagnosticsOperatorOverrideStateUpdate({
      thread_id: threadId,
      run_id: runId,
      run,
      event_id: eventId,
      seq,
      created_at: createdAt,
      decision_id: decisionId,
      gate_event_id: gateEventId,
      source: optionalString(normalizedRequest.source) ?? "agent_studio",
      operator_override_request: normalizedRequest,
      decision: objectRecord(decision) ?? {},
      repair_policy:
        objectRecord(normalizedRequest.repair_policy) ??
        objectRecord(decision?.repair_policy) ??
        objectRecord(gateEvent?.payload?.repair_policy) ??
        {},
      authority_grant_refs: mergedStringRefs(
        normalizedRequest.authority_grant_refs,
        decision?.authority_grant_refs,
        gateEvent?.payload?.authority_grant_refs,
      ),
      authority_receipt_refs: mergedStringRefs(
        normalizedRequest.authority_receipt_refs,
        decision?.authority_receipt_refs,
        gateEvent?.payload?.authority_receipt_refs,
      ),
      policy_decision_refs: mergedStringRefs(
        normalizedRequest.policy_decision_refs,
        decision?.policy_decision_refs,
        gateEvent?.payload?.policy_decision_refs,
      ),
      authority_context: objectRecord(normalizedRequest.authority_context) ?? {},
      snapshot_id: normalizedSnapshotId,
    });
    const plannedRun = objectRecord(planned?.run);
    const plannedOperationKind = optionalString(planned?.operation_kind);
    const operatorControl = objectRecord(planned?.operator_control);
    const operatorControlWalletGrantRefs = stringRefs(operatorControl?.wallet_network_grant_refs);
    const operatorControlAuthorityReceiptRefs = stringRefs(operatorControl?.authority_receipt_refs);
    if (
      optionalString(planned?.status) !== "planned" ||
      plannedOperationKind !== "diagnostics.operator_override.event" ||
      !plannedRun ||
      optionalString(plannedRun.id) !== runId ||
      !operatorControl ||
      optionalString(operatorControl.control) !== "diagnostics_operator_override" ||
      optionalString(operatorControl.decision_id) !== decisionId ||
      !objectRecord(plannedRun.diagnosticsBlockingGate) ||
      optionalString(plannedRun.diagnosticsBlockingGate.status) !== "overridden" ||
      plannedRun.diagnosticsBlockingGate.continuation_allowed !== true ||
      (
        operatorControl.approval_required === true &&
        (
          !optionalString(operatorControl.authority_hash) ||
          operatorControlWalletGrantRefs.length === 0 ||
          operatorControlAuthorityReceiptRefs.length === 0
        )
      )
    ) {
      throwDiagnosticsOperatorOverrideStateUpdateError({
        code: "diagnostics_operator_override_state_update_projection_incomplete",
        message:
          "Rust diagnostics operator override planning did not return a complete run projection.",
        details: {
          ...details,
          run_id: runId,
          expected_operation_kind: "diagnostics.operator_override.event",
          actual_operation_kind: plannedOperationKind ?? null,
          actual_status: optionalString(planned?.status) ?? null,
        },
      });
    }
    const commit = store.writeRun(plannedRun, plannedOperationKind);
    return {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_operator_override",
      thread_id: threadId,
      run_id: runId,
      decision_id: decisionId,
      status: "completed",
      override_status: "overridden",
      continuation_allowed: true,
      operation_kind: plannedOperationKind,
      operator_control: operatorControl,
      run: plannedRun,
      commit,
      receipt_refs: stringRefs(commit?.receipt_refs),
      policy_decision_refs: stringRefs(commit?.policy_decision_refs),
      evidence_refs: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_EVIDENCE_REFS,
    };
  }

  async function createDiagnosticsRepairRetryTurn(store, threadId, { request = {}, gateEvent, decision, snapshotId = null } = {}) {
    const normalizedRequest = objectRecord(request) ?? {};
    const decisionId =
      optionalString(decision?.decision_id ?? normalizedRequest.decision_id) ?? "repair_retry";
    const gateEventId =
      optionalString(gateEvent?.event_id ?? normalizedRequest.gate_event_id) ?? null;
    const normalizedSnapshotId =
      optionalString(snapshotId ?? normalizedRequest.snapshot_id) ?? null;
    const details = {
      thread_id: threadId,
      decision_id: decisionId,
      gate_event_id: gateEventId,
      snapshot_id: normalizedSnapshotId,
    };
    const retryRunCore = requireDiagnosticsRepairRetryRunCore(details);
    const retryResultProjector = requireDiagnosticsRepairRetryResultProjectionCore(details);
    if (
      typeof createLifecycleRunDep !== "function" ||
      typeof store?.agentForThread !== "function"
    ) {
      throwDiagnosticsRepairRetryRunRustCoreRequired(details);
    }
    const agent = objectRecord(store.agentForThread(threadId));
    const agentId = optionalString(agent?.id ?? agent?.agent_id);
    if (!agentId) {
      throw runtimeError({
        status: 404,
        code: "diagnostics_repair_retry_agent_not_found",
        message: "Diagnostics repair retry requires an admitted agent for the thread.",
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.retry",
          ...details,
        },
      });
    }
    const targetRunId =
      optionalString(
        normalizedRequest.target_run_id ??
          gateEvent?.target_run_id ??
          gateEvent?.payload?.target_run_id ??
          decision?.target_run_id,
      ) ?? null;
    const plannedRetryRun = retryRunCore.planRuntimeDiagnosticsRepairRetryRun({
      operation: "diagnostics_repair_retry_run_create",
      operation_kind: "diagnostics.repair_retry.run_create",
      thread_id: threadId,
      agent_id: agentId,
      decision_id: decisionId,
      gate_event_id: gateEventId,
      snapshot_id: normalizedSnapshotId,
      target_run_id: targetRunId,
      request: normalizedRequest,
      receipt_refs: stringRefs(normalizedRequest.receipt_refs),
      policy_decision_refs: stringRefs(normalizedRequest.policy_decision_refs),
      evidence_refs: DIAGNOSTICS_REPAIR_RETRY_RUN_EVIDENCE_REFS,
    });
    const plannedRunRequest = objectRecord(plannedRetryRun?.run_request);
    const plannedEventRequest = objectRecord(plannedRetryRun?.retry_event_request);
    const plannedRunOptions = objectRecord(plannedRunRequest?.options);
    const plannedRunDiagnosticsRepair = objectRecord(plannedRunOptions?.diagnostics_repair);
    const plannedDiagnosticsFeedback = objectRecord(plannedRunRequest?.diagnostics_feedback);
    if (
      optionalString(plannedRetryRun?.status) !== "planned" ||
      optionalString(plannedRetryRun?.operation_kind) !== "diagnostics.repair_retry.run_create" ||
      optionalString(plannedRetryRun?.thread_id) !== threadId ||
      optionalString(plannedRetryRun?.agent_id) !== agentId ||
      optionalString(plannedRetryRun?.decision_id) !== decisionId ||
      !plannedRunRequest ||
      optionalString(plannedRunRequest.mode) !== "send" ||
      optionalString(plannedRunRequest.prompt) == null ||
      !plannedRunDiagnosticsRepair ||
      optionalString(plannedRunDiagnosticsRepair.action) !== "repair_retry" ||
      optionalString(plannedRunDiagnosticsRepair.decision_id) !== decisionId ||
      !plannedDiagnosticsFeedback ||
      optionalString(plannedDiagnosticsFeedback.mode) !== "repair_retry" ||
      optionalString(plannedDiagnosticsFeedback.decision_id) !== decisionId ||
      !plannedEventRequest ||
      optionalString(plannedEventRequest.action) !== "repair_retry" ||
      optionalString(plannedEventRequest.decision_id) !== decisionId
    ) {
      throw runtimeError({
        status: 502,
        code: "runtime_diagnostics_repair_retry_run_projection_incomplete",
        message:
          "Rust diagnostics repair retry-run planning did not return a complete run-create request.",
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.retry_run",
          ...details,
          agent_id: agentId,
          actual_operation_kind: optionalString(plannedRetryRun?.operation_kind) ?? null,
          evidence_refs: DIAGNOSTICS_REPAIR_RETRY_RUN_EVIDENCE_REFS,
        },
      });
    }
    const retryRun = await createLifecycleRunDep(store, agentId, plannedRunRequest, {
      approvalModeForThreadMode,
      buildRun,
      ensureProviderAvailable,
      lifecycleAdmissionRunner: contextPolicyCore,
      runtimeError,
      threadModeForRunMode,
    });
    const retryRunId = optionalString(retryRun?.id);
    if (!retryRunId) {
      throw runtimeError({
        status: 502,
        code: "diagnostics_repair_retry_run_create_invalid",
        message: "Rust-owned diagnostics repair retry run creation did not return a run projection.",
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.retry",
          ...details,
          agent_id: agentId,
        },
      });
    }
    const retryTurnId = optionalString(retryRun?.turn_id ?? retryRun?.turnId) ?? retryRunId;
    const summary =
      optionalString(plannedEventRequest.summary) ??
      "Diagnostics repair retry turn created.";
    const admittedEvent = appendPlannedDiagnosticsRepairControlEvent(
      store,
      planDiagnosticsRepairControlEvent(store, threadId, {
        ...plannedEventRequest,
        retry_turn_id: retryTurnId,
        retry_request_id: retryRunId,
        retry_run_id: retryRunId,
        summary,
      }, {
        operation: "diagnostics_repair_retry_event_append",
        operationKind: "diagnostics.repair_retry.created",
        decision_id: decisionId,
      }),
    );
    const projectedRetryResult =
      retryResultProjector.projectRuntimeDiagnosticsRepairRetryResult({
        operation: "project_runtime_diagnostics_repair_retry_result",
        operation_kind: "runtime.diagnostics_repair_retry.result",
        thread_id: threadId,
        event: admittedEvent,
        run: retryRun,
        evidence_refs: DIAGNOSTICS_REPAIR_RETRY_RESULT_EVIDENCE_REFS,
      });
    const projectedEvent = objectRecord(projectedRetryResult?.event);
    const projectedRetryEvent = objectRecord(projectedRetryResult?.repair_retry_event);
    const projectedStatus = optionalString(projectedRetryResult?.status);
    const projectedThreadId = optionalString(projectedRetryResult?.thread_id);
    const projectedTurnId = optionalString(projectedRetryResult?.turn_id);
    const projectedRequestId = optionalString(projectedRetryResult?.request_id);
    const projectedSummary = optionalString(projectedRetryResult?.summary);
    const projectedEvidenceRefs = stringRefs(projectedRetryResult?.evidence_refs);
    if (
      projectedStatus !== "created" ||
      projectedThreadId !== threadId ||
      projectedTurnId !== retryTurnId ||
      projectedRequestId !== retryRunId ||
      !projectedEvent ||
      !projectedRetryEvent ||
      optionalString(projectedRetryEvent.event_id) !== optionalString(admittedEvent.event_id) ||
      optionalString(projectedRetryEvent.thread_id) !== threadId ||
      optionalString(projectedRetryEvent.event_kind) !== "diagnostics.repair_retry.created" ||
      !Array.isArray(projectedRetryResult?.receipt_refs) ||
      !Array.isArray(projectedRetryResult?.artifact_refs) ||
      !Array.isArray(projectedRetryResult?.policy_decision_refs) ||
      !Array.isArray(projectedRetryResult?.rollback_refs) ||
      !Array.isArray(projectedRetryResult?.evidence_refs) ||
      !projectedSummary ||
      !projectedEvidenceRefs.includes("runtime_diagnostics_repair_retry_result_projection_rust_owned") ||
      !projectedEvidenceRefs.includes("runtime_diagnostics_repair_js_result_helper_retired")
    ) {
      throw runtimeError({
        status: 502,
        code: "runtime_diagnostics_repair_retry_result_projection_invalid",
        message: "Rust diagnostics repair retry result projection returned mismatched retry truth.",
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.retry.result",
          operation: "project_runtime_diagnostics_repair_retry_result",
          operation_kind: "runtime.diagnostics_repair_retry.result",
          thread_id: threadId,
          decision_id: decisionId,
          retry_turn_id: retryTurnId,
          retry_run_id: retryRunId,
          actual_status: projectedStatus ?? null,
          actual_thread_id: projectedThreadId ?? null,
          actual_turn_id: projectedTurnId ?? null,
          actual_request_id: projectedRequestId ?? null,
          evidence_refs: DIAGNOSTICS_REPAIR_RETRY_RESULT_EVIDENCE_REFS,
        },
      });
    }
    return {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_repair_retry",
      thread_id: threadId,
      status: projectedStatus,
      turn_id: projectedTurnId,
      request_id: projectedRequestId,
      repair_turn: objectRecord(projectedRetryResult?.repair_turn) ?? null,
      event: projectedEvent,
      repair_retry_event: projectedRetryEvent,
      receipt_refs: stringRefs(projectedRetryResult?.receipt_refs),
      artifact_refs: stringRefs(projectedRetryResult?.artifact_refs),
      policy_decision_refs: stringRefs(projectedRetryResult?.policy_decision_refs),
      rollback_refs: stringRefs(projectedRetryResult?.rollback_refs),
      summary: projectedSummary,
      evidence_refs: projectedEvidenceRefs,
      projection: projectedRetryResult,
    };
  }

  function appendDiagnosticsOperatorOverrideEvent(store, { threadId, gateEvent, decision, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id) ?? "operator_override";
    const authorityGrantRefs = mergedStringRefs(
      decision?.authority_grant_refs,
      gateEvent?.payload?.authority_grant_refs,
    );
    const authorityReceiptRefs = mergedStringRefs(
      decision?.authority_receipt_refs,
      gateEvent?.payload?.authority_receipt_refs,
    );
    const policyDecisionRefs = mergedStringRefs(
      decision?.policy_decision_refs,
      gateEvent?.payload?.policy_decision_refs,
    );
    const plannedControl = planDiagnosticsRepairControlEvent(store, threadId, {
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id) ?? null,
      snapshot_id: optionalString(snapshotId) ?? null,
      action: "operator_override",
      approval_id: optionalString(decision?.approval_id ?? gateEvent?.payload?.approval_id) ?? null,
      authority_grant_refs: authorityGrantRefs,
      authority_receipt_refs: authorityReceiptRefs,
      policy_decision_refs: policyDecisionRefs,
    }, {
      operation: "diagnostics_operator_override_event_append",
      operationKind: "diagnostics.operator_override.event",
      decision_id: decisionId,
    });
    return appendPlannedDiagnosticsRepairControlEvent(store, plannedControl);
  }

  function appendDiagnosticsRepairRetryTurnEvent(store, { threadId, gateEvent, decision, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id) ?? "repair_retry";
    const plannedControl = planDiagnosticsRepairControlEvent(store, threadId, {
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id) ?? null,
      snapshot_id: optionalString(snapshotId) ?? null,
      action: "repair_retry",
    }, {
      operation: "diagnostics_repair_retry_event_append",
      operationKind: "diagnostics.repair_retry.created",
      decision_id: decisionId,
    });
    return appendPlannedDiagnosticsRepairControlEvent(store, plannedControl);
  }

  function appendDiagnosticsRepairDecisionExecutedEvent(store, { threadId, gateEvent, decision, action, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id ?? action) ?? null;
    const plannedControl = planDiagnosticsRepairControlEvent(store, threadId, {
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id) ?? null,
      snapshot_id: optionalString(snapshotId) ?? null,
      action: optionalString(action) ?? null,
    }, {
      operation: "diagnostics_repair_decision_event_append",
      operationKind: "diagnostics.repair_decision.executed",
      decision_id: decisionId,
    });
    return appendPlannedDiagnosticsRepairControlEvent(store, plannedControl);
  }

  function resolveDiagnosticsRepairDecision(store, threadId, decisionRef, request = {}) {
    const decisionId = optionalString(decisionRef ?? request.decision_id) ?? null;
    const gateId = optionalString(request.gate_id) ?? null;
    const details = {
      thread_id: threadId,
      decision_id: decisionId,
      gate_id: gateId,
    };
    rejectDiagnosticsRepairProjectionCandidateTransport(request, details);
    const core = requireDiagnosticsRepairProjectionCore(details);
    const projectionRequest = {
      operation: "runtime_diagnostics_repair_projection",
      operation_kind: "runtime.diagnostics_repair_projection.decision",
      projection_kind: "decision",
      thread_id: threadId,
      decision_id: decisionId,
      gate_id: gateId,
      state_dir: store?.stateDir ?? null,
      evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
    };
    let projected;
    try {
      projected = core.projectRuntimeDiagnosticsRepairProjection(projectionRequest);
    } catch (error) {
      throw mapDiagnosticsRepairProjectionError(error, projectionRequest);
    }
    const decision = objectRecord(projected?.projection);
    if (
      optionalString(projected?.status) !== "projected" ||
      optionalString(projected?.projection_kind) !== "decision" ||
      optionalString(projected?.thread_id) !== threadId ||
      optionalString(projected?.decision_id) !== decisionId ||
      !decision ||
      optionalString(decision.decision_id) !== decisionId ||
      optionalString(decision.thread_id) !== threadId ||
      (gateId && optionalString(decision.gate_id) !== gateId)
    ) {
      throw runtimeError({
        status: decision ? 502 : 404,
        code: decision
          ? "runtime_diagnostics_repair_decision_projection_invalid"
          : "runtime_diagnostics_repair_decision_projection_not_found",
        message: decision
          ? "Rust diagnostics repair decision projection returned mismatched decision truth."
          : "Rust diagnostics repair decision projection did not return an admitted decision.",
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.projection",
          operation: "diagnostics_repair_decision_projection",
          operation_kind: "runtime.diagnostics_repair_projection.decision",
          ...details,
          actual_thread_id: optionalString(projected?.thread_id) ?? null,
          actual_decision_id: optionalString(projected?.decision_id) ?? null,
          actual_projection_kind: optionalString(projected?.projection_kind) ?? null,
          evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
        },
      });
    }
    return {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_repair_decision_resolution",
      thread_id: threadId,
      decision_id: decisionId,
      gate_id: gateId,
      status: "projected",
      decision,
      projection: projected,
      receipt_refs: stringRefs(projected?.receipt_refs),
      evidence_refs: stringRefs(projected?.evidence_refs),
    };
  }

  function mapDiagnosticsRepairProjectionError(error, request = {}) {
    if (error?.code === "runtime_diagnostics_repair_projection_candidate_transport_retired") {
      throw runtimeError({
        status: 400,
        code: error.code,
        message: error.message,
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.projection",
          operation: request.operation ?? null,
          operation_kind: request.operation_kind ?? null,
          thread_id: request.thread_id ?? null,
          decision_id: request.decision_id ?? null,
          gate_id: request.gate_id ?? null,
          evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
        },
      });
    }
    if (error?.code === "runtime_diagnostics_repair_projection_state_dir_required") {
      throw runtimeError({
        status: 501,
        code: error.code,
        message: error.message,
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.projection",
          operation: request.operation ?? null,
          operation_kind: request.operation_kind ?? null,
          thread_id: request.thread_id ?? null,
          decision_id: request.decision_id ?? null,
          gate_id: request.gate_id ?? null,
          evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
        },
      });
    }
    if (
      [
        "runtime_diagnostics_repair_projection_replay_read_failed",
        "runtime_diagnostics_repair_projection_replay_record_invalid",
      ].includes(error?.code)
    ) {
      throw runtimeError({
        status: 502,
        code: error.code,
        message: error.message,
        details: {
          rust_core_boundary: "runtime.diagnostics_repair.projection",
          operation: request.operation ?? null,
          operation_kind: request.operation_kind ?? null,
          thread_id: request.thread_id ?? null,
          decision_id: request.decision_id ?? null,
          gate_id: request.gate_id ?? null,
          state_dir: request.state_dir ?? null,
          evidence_refs: DIAGNOSTICS_REPAIR_DECISION_PROJECTION_EVIDENCE_REFS,
        },
      });
    }
    throw error;
  }

  function turnForOperatorOverrideEvent() {
    return null;
  }

  function turnForRepairRetryEvent() {
    return null;
  }

  return {
    appendDiagnosticsOperatorOverrideEvent,
    appendDiagnosticsRepairDecisionExecutedEvent,
    appendDiagnosticsRepairRetryTurnEvent,
    createDiagnosticsRepairRetryTurn,
    executeDiagnosticsRepairDecision,
    executeDiagnosticsOperatorOverride,
    resolveDiagnosticsRepairDecision,
    turnForOperatorOverrideEvent,
    turnForRepairRetryEvent,
  };
}
