export function cancelRun(state, runId, deps) {
  const {
    contextPolicyRunner,
    now = () => new Date().toISOString(),
  } = deps;
  const run = state.getRun(runId);
  if (typeof contextPolicyRunner?.planRunCancelStateUpdate !== "function") {
    throw new Error("Run cancellation requires Rust policy state-update planning.");
  }
  const stateUpdate = contextPolicyRunner.planRunCancelStateUpdate({
    run_id: run.id,
    run,
    canceled_at: now(),
  });
  const updated = plannedRunCancelRecord(stateUpdate, run.id);
  const operationKind = plannedRunCancelOperationKind(stateUpdate, run.id);
  state.runs.set(runId, updated);
  state.writeRun(updated, operationKind);
  return updated;
}

function plannedRunCancelRecord(stateUpdate, runId) {
  const updatedRun = stateUpdate.run;
  if (!updatedRun?.id) {
    const error = new Error("Rust run cancellation state planning did not return a run record.");
    error.code = "run_cancel_state_update_planner_invalid";
    error.details = { runId };
    throw error;
  }
  return updatedRun;
}

function plannedRunCancelOperationKind(stateUpdate, runId) {
  const operationKind =
    typeof stateUpdate?.operation_kind === "string" && stateUpdate.operation_kind.trim()
      ? stateUpdate.operation_kind
      : null;
  if (!operationKind) {
    const error = new Error("Rust run cancellation state planning did not return an operation kind.");
    error.code = "run_cancel_state_update_operation_kind_missing";
    error.details = { runId, operation_kind: "run.cancel" };
    throw error;
  }
  if (operationKind !== "run.cancel") {
    const error = new Error("Rust run cancellation state planning returned an unexpected operation kind.");
    error.code = "run_cancel_state_update_operation_kind_mismatch";
    error.details = { runId, expected_operation_kind: "run.cancel", operation_kind: operationKind };
    throw error;
  }
  return operationKind;
}
