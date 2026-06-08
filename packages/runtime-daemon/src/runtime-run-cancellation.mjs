export function cancelRun(state, runId) {
  const run = state.getRun(runId);
  throwRunCancelRustCoreRequired({
    operation: "run_cancel",
    operation_kind: "run.cancel",
    run_id: run?.id ?? runId,
    run_status: run?.status ?? null,
  });
}

function throwRunCancelRustCoreRequired(details = {}) {
  const error = new Error("Run cancellation requires direct Rust daemon-core state admission and persistence.");
  error.status = 501;
  error.code = "runtime_run_cancel_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.run_cancel",
    ...details,
    evidence_refs: [
      "runtime_run_cancel_js_facade_retired",
      "rust_daemon_core_run_cancel_required",
      "agentgres_run_cancel_state_truth_required",
    ],
  };
  throw error;
}
