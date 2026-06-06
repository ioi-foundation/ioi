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
  state.runs.set(runId, updated);
  state.writeRun(updated, stateUpdate.operation_kind ?? "run.cancel");
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
