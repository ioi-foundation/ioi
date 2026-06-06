export function createThreadForkState({
  eventStreamIdForThread,
  fixtureProfileForAgent,
  operatorControlSource,
  optionalString,
} = {}) {
  function forkThread(store, threadId, request = {}) {
    const sourceThread = store.getThread(threadId);
    const sourceAgent = store.agentForThread(threadId);
    const options = {
      ...(request.options ?? {}),
      local: {
        cwd: request.options?.local?.cwd ?? sourceThread.workspace ?? store.defaultCwd,
      },
      model: request.options?.model ? request.options.model : { id: sourceThread.model_route },
    };
    const idempotencyKey = request.idempotency_key;
    const streamId = eventStreamIdForThread(threadId);
    if (idempotencyKey) {
      const duplicate = store.runtimeEventStream(streamId).idempotency.get(String(idempotencyKey));
      const duplicateForkThreadId =
        duplicate?.payload_summary?.fork_thread_id ?? duplicate?.payload?.fork_thread_id;
      if (duplicateForkThreadId) {
        return {
          ...store.getThread(String(duplicateForkThreadId)),
          source_thread_id: sourceThread.thread_id,
          forked_from_seq:
            Number(duplicate?.payload_summary?.source_latest_seq ?? sourceThread.latest_seq) ||
            sourceThread.latest_seq,
        };
      }
    }
    const fork = store.createAgent(options);
    const thread = store.threadForAgent(fork);
    const sourceLatestSeq = sourceThread.latest_seq;
    const sourceLatestTurnId = sourceThread.latest_turn_id ?? "";
    const controlSource = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "operator";
    const reason = optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested thread fork";
    const now = new Date().toISOString();
    store.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: threadId,
      turn_id: sourceLatestTurnId,
      item_id: `${threadId}:item:thread-fork:${thread.thread_id}`,
      idempotency_key: idempotencyKey ? String(idempotencyKey) : `thread:${threadId}:operator.fork:${thread.thread_id}`,
      source: controlSource,
      source_event_kind: "OperatorControl.Fork",
      event_kind: "thread.forked",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: sourceAgent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? null,
      workflow_node_id: request.workflow_node_id ?? "runtime.thread-fork",
      component_kind: "thread_fork",
      payload_schema_version: "ioi.runtime.thread-fork.v1",
      payload: {
        event_kind: "OperatorControl.Fork",
        reason,
        requested_by: requestedBy,
        control_surface: controlSource,
        source_thread_id: sourceThread.thread_id,
        source_agent_id: sourceThread.agent_id,
        source_latest_seq: sourceLatestSeq,
        source_latest_turn_id: sourceLatestTurnId || null,
        fork_thread_id: thread.thread_id,
        fork_agent_id: thread.agent_id,
        fork_session_id: thread.session_id,
        session_id: sourceThread.session_id,
      },
      receipt_refs: [`receipt_${sourceThread.agent_id}_thread_fork_${thread.agent_id}`],
      policy_decision_refs: [`policy_${sourceThread.agent_id}_thread_fork_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(sourceAgent),
    });
    return {
      ...thread,
      source_thread_id: sourceThread.thread_id,
      forked_from_seq: sourceLatestSeq,
    };
  }

  return {
    forkThread,
  };
}
