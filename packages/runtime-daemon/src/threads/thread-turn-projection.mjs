export function createThreadTurnProjection({
  eventStreamIdForThread,
  runtimeThreadSchemaVersion,
  runtimeTurnIdForRun,
  runtimeTurnSchemaVersion,
  runtimeError,
  threadIdForAgent,
} = {}) {
  function threadForAgent(store, agent) {
    const threadId = threadIdForAgent(agent.id);
    return projectRustThreadTurnProjection(store, {
      projection_kind: "thread",
      thread_schema_version: runtimeThreadSchemaVersion,
      thread_id: threadId,
      event_stream_id: eventStreamIdForThread(threadId),
      state_dir: store.stateDir ?? null,
    });
  }

  function turnForRun(store, run) {
    const turnId = runtimeTurnIdForRun(run);
    const agentId = run.agentId ?? run.agent_id;
    const threadId = run.thread_id ?? threadIdForAgent(agentId);
    return projectRustThreadTurnProjection(store, {
      projection_kind: "turn",
      turn_schema_version: runtimeTurnSchemaVersion,
      thread_id: threadId,
      turn_id: turnId,
      run_id: run.id ?? run.run_id,
      event_stream_id: eventStreamIdForThread(threadId),
      state_dir: store.stateDir ?? null,
    });
  }

  function projectRustThreadTurnProjection(store, request) {
    if (typeof store.projectRuntimeThreadTurnProjectionForThread === "function") {
      return store.projectRuntimeThreadTurnProjectionForThread(store, request).record;
    }
    const errorFactory = typeof runtimeError === "function"
      ? runtimeError
      : (input) => Object.assign(new Error(input.message), input);
    throw errorFactory({
      status: 501,
      code: "runtime_thread_turn_projection_rust_core_required",
      message: "Runtime thread and turn projection requires direct Rust daemon-core projection.",
      details: {
        rust_core_boundary: "runtime.thread_turn_projection",
        operation: "project_runtime_thread_turn_projection",
        projection_kind: request.projection_kind,
        thread_id: request.thread_id ?? null,
        turn_id: request.turn_id ?? null,
        evidence_refs: [
          "runtime_thread_turn_js_projection_retired",
          "rust_daemon_core_thread_turn_projection_required",
          "agentgres_thread_turn_projection_truth_required",
        ],
      },
    });
  }

  return {
    threadForAgent,
    turnForRun,
  };
}
