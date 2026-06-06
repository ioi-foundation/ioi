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
  const updated = stateUpdate.run ?? run;
  state.runs.set(runId, updated);
  state.writeRun(updated, stateUpdate.operation_kind ?? "run.cancel");
  return updated;
}
