import {
  objectRecord,
  optionalString,
} from "./runtime-value-helpers.mjs";

export function cancelRun(state, runId, { contextPolicyCore = null } = {}) {
  const run = state.getRun(runId);
  const operationDetails = {
    operation: "run_cancel",
    operation_kind: "run.cancel",
    run_id: run?.id ?? runId,
    run_status: run?.status ?? null,
  };
  if (!objectRecord(run)) {
    throwRunCancelRustCoreRequired({
      contextPolicyCore,
      ...operationDetails,
    });
  }
  if (typeof contextPolicyCore?.planRunCancelStateUpdate !== "function") {
    throwRunCancelRustCoreRequired({
      contextPolicyCore,
      ...operationDetails,
    });
  }
  if (typeof state.writeRun !== "function") {
    throwRunCancelStateUpdateError({
      status: 501,
      code: "runtime_run_cancel_persistence_unavailable",
      message:
        "Run cancellation requires Rust Agentgres run-state persistence.",
      details: {
        rust_core_boundary: "runtime.run_cancel",
        ...operationDetails,
        evidence_refs: runCancelEvidenceRefs(),
      },
    });
  }
  const canceledAt = state.nowIso?.() ?? new Date().toISOString();
  const planned = contextPolicyCore.planRunCancelStateUpdate({
    run_id: run?.id ?? runId,
    run,
    canceled_at: canceledAt,
  });
  const plannedRun = objectRecord(planned?.run);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedRun) {
    throwRunCancelStateUpdateError({
      status: 502,
      code: "run_cancel_state_update_run_missing",
      message:
        "Rust daemon-core run cancellation did not return a run projection.",
      details: {
        rust_core_boundary: "runtime.run_cancel",
        ...operationDetails,
      },
    });
  }
  if (plannedOperationKind !== "run.cancel") {
    throwRunCancelStateUpdateError({
      status: 502,
      code: "run_cancel_state_update_operation_kind_mismatch",
      message:
        "Rust daemon-core run cancellation returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.run_cancel",
        ...operationDetails,
        expected_operation_kind: "run.cancel",
        actual_operation_kind: plannedOperationKind,
      },
    });
  }
  if (
    optionalString(planned?.status) !== "planned" ||
    optionalString(plannedRun.id) !== optionalString(run?.id ?? runId) ||
    optionalString(plannedRun.status) !== "canceled" ||
    !optionalString(plannedRun.updatedAt) ||
    !objectRecord(planned?.stop_condition) ||
    !objectRecord(planned?.runtime_task) ||
    !objectRecord(planned?.runtime_job) ||
    !objectRecord(planned?.runtime_checklist) ||
    !Array.isArray(plannedRun.events) ||
    !plannedRun.events.some((event) => optionalString(event?.type) === "job_canceled") ||
    !plannedRun.events.some((event) => optionalString(event?.type) === "canceled") ||
    !Array.isArray(plannedRun.receipts) ||
    !Array.isArray(plannedRun.artifacts)
  ) {
    throwRunCancelStateUpdateError({
      status: 502,
      code: "run_cancel_state_update_projection_incomplete",
      message:
        "Rust daemon-core run cancellation did not return a complete canceled projection.",
      details: {
        rust_core_boundary: "runtime.run_cancel",
        ...operationDetails,
        expected_operation_kind: "run.cancel",
        actual_operation_kind: plannedOperationKind,
        actual_run_id: optionalString(plannedRun.id) ?? null,
        actual_run_status: optionalString(plannedRun.status) ?? null,
      },
    });
  }
  state.writeRun(plannedRun, plannedOperationKind);
  return plannedRun;
}

function throwRunCancelRustCoreRequired(details = {}) {
  const { contextPolicyCore = null, ...errorDetails } = details;
  if (contextPolicyCore?.planRunCancelAdmissionRequired) {
    const record = contextPolicyCore.planRunCancelAdmissionRequired({
      operation: errorDetails.operation,
      operation_kind: errorDetails.operation_kind,
      run_id: errorDetails.run_id,
      run_status: errorDetails.run_status,
      source: errorDetails.source,
      evidence_refs: runCancelEvidenceRefs(),
    });
    const planned = record?.record ?? record;
    const error = new Error(
      optionalString(planned?.message ?? record?.message) ??
        "Run cancellation requires direct Rust daemon-core state admission and persistence.",
    );
    error.status = Number(planned?.status_code ?? record?.status_code ?? 501);
    error.code =
      optionalString(planned?.code ?? record?.code) ??
      "runtime_run_cancel_rust_core_required";
    error.details = planned?.details ?? record?.details ?? {
      rust_core_boundary: "runtime.run_cancel",
      ...errorDetails,
      evidence_refs: runCancelEvidenceRefs(),
    };
    throw error;
  }
  const error = new Error("Run cancellation requires direct Rust daemon-core state admission and persistence.");
  error.status = 501;
  error.code = "runtime_run_cancel_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.run_cancel",
    ...errorDetails,
    evidence_refs: runCancelEvidenceRefs(),
  };
  throw error;
}

function throwRunCancelStateUpdateError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  throw error;
}

function runCancelEvidenceRefs() {
  return [
    "runtime_run_cancel_js_facade_retired",
    "rust_daemon_core_run_cancel_required",
    "agentgres_run_cancel_state_truth_required",
  ];
}
