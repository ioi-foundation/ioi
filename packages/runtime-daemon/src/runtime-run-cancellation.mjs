import { optionalString } from "./runtime-value-helpers.mjs";

export function cancelRun(state, runId) {
  const run = state.getRun(runId);
  throwRunCancelRustCoreRequired({
    runCancelRunner: state?.runCancelRunner ?? state?.contextPolicyRunner ?? null,
    operation: "run_cancel",
    operation_kind: "run.cancel",
    run_id: run?.id ?? runId,
    run_status: run?.status ?? null,
  });
}

function throwRunCancelRustCoreRequired(details = {}) {
  const { runCancelRunner = null, ...errorDetails } = details;
  if (runCancelRunner?.planRunCancelAdmissionRequired) {
    const record = runCancelRunner.planRunCancelAdmissionRequired({
      operation: errorDetails.operation,
      operation_kind: errorDetails.operation_kind,
      run_id: errorDetails.run_id,
      run_status: errorDetails.run_status,
      source: errorDetails.source,
      evidence_refs: [
        "runtime_run_cancel_js_facade_retired",
        "rust_daemon_core_run_cancel_required",
        "agentgres_run_cancel_state_truth_required",
      ],
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
      evidence_refs: [
        "runtime_run_cancel_js_facade_retired",
        "rust_daemon_core_run_cancel_required",
        "agentgres_run_cancel_state_truth_required",
      ],
    };
    throw error;
  }
  const error = new Error("Run cancellation requires direct Rust daemon-core state admission and persistence.");
  error.status = 501;
  error.code = "runtime_run_cancel_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.run_cancel",
    ...errorDetails,
    evidence_refs: [
      "runtime_run_cancel_js_facade_retired",
      "rust_daemon_core_run_cancel_required",
      "agentgres_run_cancel_state_truth_required",
    ],
  };
  throw error;
}
