export function createThreadTurnProjection({
  eventStreamIdForThread,
  fixtureProfileForAgent,
  lifecycleStatusForRun,
  normalizedAgentRuntimeControls,
  runtimeSessionIdForAgent,
  runtimeThreadSchemaVersion,
  runtimeTurnIdForRun,
  runtimeTurnSchemaVersion,
  runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread,
  runtimeError,
  threadIdForAgent,
  threadModeForRunMode,
  threadStatusForAgent,
  turnIdForRun,
} = {}) {
  function threadForAgent(store, agent) {
    const runs = store.listRuns(agent.id);
    const latestRun = runs.at(-1);
    store.projectThreadEvents(agent);
    const threadId = threadIdForAgent(agent.id);
    const runtimeControls = normalizedAgentRuntimeControls(agent);
    const latestSeq = store.latestRuntimeEventSeq(eventStreamIdForThread(threadId));
    const updatedAt = Math.max(
      Date.parse(agent.updatedAt) || 0,
      ...runs.map((run) => Date.parse(run.updatedAt) || 0),
    );
    const usage_telemetry = runtimeUsageTelemetryForThread({
      threadId,
      agent,
      runs,
      subagents: [...store.subagents.values()].filter(
        (record) => record.parent_thread_id === threadId,
      ),
    });
    return projectRustThreadTurnProjection(store, threadForRustProjection({
      agent,
      runs,
      threadId,
      eventStreamId: eventStreamIdForThread(threadId),
      runtimeControls,
      usage_telemetry,
      memoryCount: store.memory.list({
        agent,
        threadId,
        workspace: agent.cwd,
      }).length,
      subagent_ids: [...store.subagents.values()]
        .filter((record) => record.parent_thread_id === threadId)
        .map((record) => record.id),
      latest_seq: latestSeq,
      thread_schema_version: runtimeThreadSchemaVersion,
      session_id: runtimeSessionIdForAgent(agent),
      fixture_profile: fixtureProfileForAgent(agent),
      created_at_ms: Date.parse(agent.createdAt) || 0,
      updated_at_ms: updatedAt,
    }));
  }

  function turnForRun(store, run) {
    const agent = store.getAgent(run.agentId);
    store.projectRunEvents(run, agent);
    const turnId = runtimeTurnIdForRun(run);
    const turnEvents = store.runtimeEventsForTurn(turnId);
    const status = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const isOpen = status === "queued" || status === "running" || status === "waiting_for_approval" || status === "waiting_for_input";
    const completedAt = isOpen ? null : run.updatedAt;
    const usage_telemetry =
      run.usage_telemetry ??
      run.usage ??
      runtimeUsageTelemetryForRun({ run, agent, threadId: threadIdForAgent(run.agentId) });
    return projectRustThreadTurnProjection(store, {
      projection_kind: "turn",
      turn_schema_version: runtimeTurnSchemaVersion,
      thread_id: threadIdForAgent(run.agentId),
      turn_id: turnId,
      run: runForRustProjection(run),
      events: turnEvents,
      fixture_profile: fixtureProfileForAgent(agent),
      status,
      completed_at: completedAt,
      mode: run.threadMode ?? threadModeForRunMode(run.mode, agent.runtimeControls?.mode),
      approval_mode: agent.runtimeControls?.approval_mode ?? "suggest",
      usage_telemetry,
      created_at_ms: Date.parse(run.createdAt) || 0,
      updated_at_ms: completedAt ? Date.parse(completedAt) || 0 : null,
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

function threadForRustProjection({
  agent,
  runs,
  threadId,
  eventStreamId,
  runtimeControls,
  usage_telemetry,
  memoryCount,
  subagent_ids,
  latest_seq,
  thread_schema_version,
  session_id,
  fixture_profile,
  created_at_ms,
  updated_at_ms,
}) {
  return {
    projection_kind: "thread",
    thread_schema_version,
    thread_id: threadId,
    event_stream_id: eventStreamId,
    session_id,
    fixture_profile,
    runtime_profile: agent.runtime_profile ?? "fixture",
    runtime_bridge_id: agent.runtime_bridge_id ?? null,
    runtime_bridge_source: agent.runtime_bridge_source ?? null,
    agent: agentForRustProjection(agent),
    runs: runs.map(runForRustProjection),
    runtime_controls: runtimeControlsForRustProjection(runtimeControls),
    usage_telemetry,
    memory_count: memoryCount,
    subagent_ids,
    latest_seq,
    created_at_ms,
    updated_at_ms,
  };
}

function agentForRustProjection(agent = {}) {
  const modelRouteDecision = agent.modelRouteDecision ?? agent.model_route_decision ?? null;
  return {
    agent_id: agent.id ?? agent.agent_id ?? null,
    workspace_root: agent.cwd ?? agent.workspace_root ?? null,
    status: agent.status ?? null,
    model_id: agent.modelId ?? agent.model_id ?? null,
    requested_model_id: agent.requestedModelId ?? agent.requested_model_id ?? null,
    model_route_id: agent.modelRouteId ?? agent.model_route_id ?? null,
    model_route_receipt_id: agent.modelRouteReceiptId ?? agent.model_route_receipt_id ?? null,
    model_route_decision: canonicalModelRouteDecisionForRustProjection(
      modelRouteDecision,
      agent.modelRouteDecision?.reasoning_effort ?? agent.model_route_decision?.reasoning_effort ?? null,
    ),
    created_at: agent.createdAt ?? agent.created_at ?? null,
    updated_at: agent.updatedAt ?? agent.updated_at ?? null,
  };
}

function runForRustProjection(run = {}) {
  return {
    run_id: run.id ?? run.run_id ?? null,
    agent_id: run.agentId ?? run.agent_id ?? null,
    turn_id: run.runtimeTurnId ?? run.turn_id ?? null,
    objective: run.objective ?? null,
    status: run.status ?? null,
    turn_status: run.turnStatus ?? run.turn_status ?? null,
    result: run.result ?? null,
    mode: run.mode ?? null,
    created_at: run.createdAt ?? run.created_at ?? null,
    updated_at: run.updatedAt ?? run.updated_at ?? null,
    model_route_decision_id: run.modelRouteDecision?.decision_id ?? run.trace?.modelRouteDecision?.decision_id ?? null,
    model_route_decision: run.modelRouteDecision ?? run.trace?.modelRouteDecision ?? null,
    model_route_receipt_id: run.modelRouteReceiptId ?? run.model_route_receipt_id ?? null,
    trace: {
      stop_condition: run.trace?.stopCondition ?? run.trace?.stop_condition ?? null,
      quality_ledger: run.trace?.qualityLedger ?? run.trace?.quality_ledger ?? null,
    },
    conversation: Array.isArray(run.conversation) ? run.conversation : [],
    active_skill_hook_manifest_ref: run.activeSkillHookManifest?.manifestId ?? null,
    active_skill_set_hash: run.activeSkillHookManifest?.activeSkillSetHash ?? null,
    active_hook_set_hash: run.activeSkillHookManifest?.activeHookSetHash ?? null,
    memory_refs: run.memoryRecords?.map((record) => record.id) ?? [],
    memory_write_receipt_ids: run.memoryWriteReceipts?.map((receipt) => receipt.id) ?? [],
  };
}

function runtimeControlsForRustProjection(runtimeControls = {}) {
  return {
    mode: runtimeControls.mode ?? null,
    approval_mode: runtimeControls.approval_mode ?? null,
    model: canonicalRuntimeControlModelForRustProjection(runtimeControls.model),
  };
}

function canonicalModelRouteDecisionForRustProjection(decision, reasoning_effort) {
  if (!decision || typeof decision !== "object") {
    return decision ?? null;
  }
  return Object.fromEntries(
    Object.entries({
      ...decision,
      reasoning_effort,
    }).filter(([key]) => key === key.toLowerCase()),
  );
}

function canonicalRuntimeControlModelForRustProjection(modelControls = {}) {
  if (!modelControls || typeof modelControls !== "object") {
    return {};
  }
  return Object.fromEntries(
    Object.entries(modelControls).filter(([key]) => key === key.toLowerCase()),
  );
}
