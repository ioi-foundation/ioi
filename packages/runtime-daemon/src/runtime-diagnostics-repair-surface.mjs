import { runtimeError as defaultRuntimeError } from "./runtime-http-utils.mjs";
import { optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeDiagnosticsRepairSurface(deps = {}) {
  const { runtimeError = defaultRuntimeError } = deps;

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
    const decisionId = optionalString(decisionRef ?? request.decision_id ?? request.action) ?? null;
    throwDiagnosticsRepairRustCoreRequired("diagnostics_repair_decision_execution", "diagnostics.repair_decision.execute", {
      thread_id: threadId,
      decision_id: decisionId,
      evidence_refs: [
        "diagnostics_repair_decision_execution_js_facade_retired",
        "rust_daemon_core_diagnostics_repair_admission_required",
        "agentgres_diagnostics_repair_state_truth_required",
      ],
    });
  }

  function executeDiagnosticsOperatorOverride(store, threadId, { request = {}, gateEvent, decision, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id ?? request.decision_id) ?? "operator_override";
    throwDiagnosticsRepairRustCoreRequired("diagnostics_operator_override_execution", "diagnostics.operator_override.execute", {
      thread_id: threadId,
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id ?? request.gate_event_id) ?? null,
      snapshot_id: optionalString(snapshotId ?? request.snapshot_id) ?? null,
      evidence_refs: [
        "diagnostics_operator_override_js_facade_retired",
        "rust_daemon_core_operator_override_state_required",
        "agentgres_operator_override_state_truth_required",
      ],
    });
  }

  function createDiagnosticsRepairRetryTurn(store, threadId, { request = {}, gateEvent, decision, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id ?? request.decision_id) ?? "repair_retry";
    throwDiagnosticsRepairRustCoreRequired("diagnostics_repair_retry_turn_creation", "diagnostics.repair_retry.create", {
      thread_id: threadId,
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id ?? request.gate_event_id) ?? null,
      snapshot_id: optionalString(snapshotId ?? request.snapshot_id) ?? null,
      evidence_refs: [
        "diagnostics_repair_retry_js_create_run_facade_retired",
        "rust_daemon_core_repair_retry_run_admission_required",
        "agentgres_repair_retry_state_truth_required",
      ],
    });
  }

  function appendDiagnosticsOperatorOverrideEvent(store, { threadId, gateEvent, decision, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id) ?? "operator_override";
    throwDiagnosticsRepairRustCoreRequired("diagnostics_operator_override_event_append", "diagnostics.operator_override.event", {
      thread_id: threadId ?? null,
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id) ?? null,
      snapshot_id: optionalString(snapshotId) ?? null,
      evidence_refs: [
        "diagnostics_operator_override_event_js_append_retired",
        "rust_daemon_core_operator_override_receipt_required",
        "agentgres_operator_override_expected_head_required",
      ],
    });
  }

  function appendDiagnosticsRepairRetryTurnEvent(store, { threadId, gateEvent, decision, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id) ?? "repair_retry";
    throwDiagnosticsRepairRustCoreRequired("diagnostics_repair_retry_event_append", "diagnostics.repair_retry.created", {
      thread_id: threadId ?? null,
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id) ?? null,
      snapshot_id: optionalString(snapshotId) ?? null,
      evidence_refs: [
        "diagnostics_repair_retry_event_js_append_retired",
        "rust_daemon_core_repair_retry_receipt_required",
        "agentgres_repair_retry_expected_head_required",
      ],
    });
  }

  function appendDiagnosticsRepairDecisionExecutedEvent(store, { threadId, gateEvent, decision, action, snapshotId = null } = {}) {
    const decisionId = optionalString(decision?.decision_id ?? action) ?? null;
    throwDiagnosticsRepairRustCoreRequired("diagnostics_repair_decision_event_append", "diagnostics.repair_decision.executed", {
      thread_id: threadId ?? null,
      decision_id: decisionId,
      gate_event_id: optionalString(gateEvent?.event_id) ?? null,
      snapshot_id: optionalString(snapshotId) ?? null,
      evidence_refs: [
        "diagnostics_repair_decision_event_js_append_retired",
        "rust_daemon_core_diagnostics_repair_receipt_required",
        "agentgres_diagnostics_repair_expected_head_required",
      ],
    });
  }

  function resolveDiagnosticsRepairDecision(store, threadId, decisionRef, request = {}) {
    const decisionId = optionalString(decisionRef ?? request.decision_id ?? request.action) ?? null;
    throwDiagnosticsRepairRustCoreRequired("diagnostics_repair_decision_resolution", "diagnostics.repair_decision.resolve", {
      thread_id: threadId,
      decision_id: decisionId,
      gate_id: optionalString(request.gate_id) ?? null,
      evidence_refs: [
        "diagnostics_repair_decision_resolution_js_projection_retired",
        "rust_daemon_core_diagnostics_repair_projection_required",
        "agentgres_diagnostics_repair_projection_truth_required",
      ],
    });
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
