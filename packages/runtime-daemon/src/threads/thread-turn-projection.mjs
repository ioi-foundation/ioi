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
    const usageTelemetry = runtimeUsageTelemetryForThread({
      threadId,
      agent,
      runs,
      subagents: [...store.subagents.values()].filter(
        (record) => (record.parent_thread_id ?? record.parentThreadId) === threadId,
      ),
    });
    return {
      schema_version: runtimeThreadSchemaVersion,
      thread_id: threadId,
      session_id: runtimeSessionIdForAgent(agent),
      agent_id: agent.id,
      workspace_root: agent.cwd,
      title: latestRun?.objective ?? agent.cwd,
      mode: runtimeControls.mode,
      approval_mode: runtimeControls.approvalMode,
      trust_profile: "local_private",
      model_route: agent.modelId,
      status: latestRun?.turnStatus === "interrupted" ? "interrupted" : threadStatusForAgent(agent.status),
      latest_turn_id: latestRun ? turnIdForRun(latestRun.id) : null,
      latest_seq: latestSeq,
      event_stream_id: eventStreamIdForThread(threadId),
      workflow_graph_id: null,
      harness_binding_id: null,
      agentgres_projection_ref: `agents/${agent.id}.json`,
      created_at: agent.createdAt,
      updated_at: new Date(updatedAt || Date.parse(agent.updatedAt) || Date.now()).toISOString(),
      archived_at: agent.status === "archived" ? agent.updatedAt : null,
      fixture_profile: fixtureProfileForAgent(agent),
      created_at_ms: Date.parse(agent.createdAt) || 0,
      updated_at_ms: updatedAt,
      workspace: agent.cwd,
      requested_model: agent.requestedModelId ?? agent.modelId,
      model_route_id: agent.modelRouteId ?? null,
      model_route_receipt_id: agent.modelRouteReceiptId ?? null,
      model_route_decision: agent.modelRouteDecision ?? null,
      selected_model: agent.modelId,
      reasoning_effort:
        agent.modelRouteDecision?.reasoningEffort ??
        runtimeControls.model?.reasoningEffort ??
        null,
      runtime_controls: runtimeControls,
      memory_count: store.memory.list({
        agent,
        threadId,
        workspace: agent.cwd,
      }).length,
      archived: agent.status === "archived",
      evidence_refs: ["agentgres_canonical_state_projection", "runtime_tti_projection"],
      runtime_profile: agent.runtimeProfile ?? "fixture",
      runtime_bridge_id: agent.runtimeBridgeId ?? null,
      runtime_bridge_source: agent.runtimeBridgeSource ?? null,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
    };
  }

  function turnForRun(store, run) {
    const agent = store.getAgent(run.agentId);
    store.projectRunEvents(run, agent);
    const turnId = runtimeTurnIdForRun(run);
    const turnEvents = store.runtimeEventsForTurn(turnId);
    const seqStart = turnEvents.at(0)?.seq ?? null;
    const status = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const isOpen = status === "queued" || status === "running" || status === "waiting_for_approval" || status === "waiting_for_input";
    const seqEnd = isOpen ? null : (turnEvents.at(-1)?.seq ?? null);
    const completedAt = isOpen ? null : run.updatedAt;
    const usageTelemetry =
      run.usage_telemetry ??
      run.usage ??
      runtimeUsageTelemetryForRun({ run, agent, threadId: threadIdForAgent(run.agentId) });
    return {
      schema_version: runtimeTurnSchemaVersion,
      turn_id: turnId,
      thread_id: threadIdForAgent(run.agentId),
      parent_turn_id: null,
      request_id: run.id,
      status,
      input_item_ids: turnEvents
        .filter((event) => event.event_kind === "turn.started")
        .map((event) => event.item_id),
      output_item_ids: turnEvents
        .filter((event) => event.event_kind !== "turn.started")
        .map((event) => event.item_id),
      events: turnEvents,
      seq_start: seqStart,
      seq_end: seqEnd,
      started_at: run.createdAt,
      completed_at: completedAt,
      mode: run.threadMode ?? threadModeForRunMode(run.mode, agent.runtimeControls?.mode),
      approval_mode: run.approvalMode ?? agent.runtimeControls?.approvalMode ?? "suggest",
      model_route_decision_id: run.modelRouteDecision?.decisionId ?? run.trace?.modelRouteDecision?.decisionId ?? null,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      result: run.result ?? "",
      output: run.result ?? "",
      text: run.result ?? "",
      stop_reason: run.trace?.stopCondition?.reason ?? null,
      error: run.status === "failed" ? run.result : null,
      conversation: Array.isArray(run.conversation) ? run.conversation : [],
      rollback_snapshot_id: null,
      quality_ledger_ref: run.trace?.qualityLedger?.ledgerId ?? null,
      workflow_execution_ref: null,
      fixture_profile: fixtureProfileForAgent(agent),
      started_at_ms: Date.parse(run.createdAt) || 0,
      completed_at_ms: completedAt ? Date.parse(completedAt) || 0 : null,
      error_summary: run.status === "failed" ? run.result : null,
      model_route_decision: run.modelRouteDecision ?? run.trace?.modelRouteDecision ?? null,
      model_route_receipt_id: run.modelRouteReceiptId ?? null,
      active_skill_hook_manifest_ref: run.activeSkillHookManifest?.manifestId ?? null,
      active_skill_set_hash: run.activeSkillHookManifest?.activeSkillSetHash ?? null,
      active_hook_set_hash: run.activeSkillHookManifest?.activeHookSetHash ?? null,
      memory_refs: run.memoryRecords?.map((record) => record.id) ?? [],
      memory_write_receipt_ids: run.memoryWriteReceipts?.map((receipt) => receipt.id) ?? [],
      evidence_refs: [
        "agentgres_canonical_state_projection",
        `run:${run.id}`,
        run.activeSkillHookManifest?.manifestId,
      ].filter(Boolean),
    };
  }

  return {
    threadForAgent,
    turnForRun,
  };
}
