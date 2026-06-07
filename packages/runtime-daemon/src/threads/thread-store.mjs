export function listAgents(store) {
  return [...store.agents.values()].sort((left, right) =>
    left.createdAt.localeCompare(right.createdAt),
  );
}

export function getAgent(store, agentId, deps = {}) {
  const { notFound } = deps;
  const agent = store.agents.get(agentId);
  if (!agent) {
    throw notFound(`Agent not found: ${agentId}`, { agentId });
  }
  return agent;
}

export function updateAgent(store, agentId, status, operationKind, deps = {}) {
  const {
    runtimeError = ({ status: errorStatus = 500, code = "agent_status_state_update_error", message, details }) =>
      Object.assign(new Error(message), { status: errorStatus, code, details }),
  } = deps;
  const agent = store.getAgent(agentId);
  const contextPolicyRunner = store.contextPolicyRunner;
  if (typeof contextPolicyRunner?.planAgentStatusStateUpdate !== "function") {
    throw runtimeError({
      status: 500,
      code: "agent_status_state_update_planner_unavailable",
      message: "Agent status updates require Rust policy state-update planning.",
      details: { agent_id: agentId, status, operation_kind: operationKind },
    });
  }
  const stateUpdate = contextPolicyRunner.planAgentStatusStateUpdate({
    agent,
    status,
    operation_kind: operationKind,
    updated_at: new Date().toISOString(),
  });
  const updated = stateUpdate.agent;
  if (!updated?.id) {
    throw runtimeError({
      status: 502,
      code: "agent_status_state_update_planner_invalid",
      message: "Rust agent status state planning did not return an agent record.",
      details: { agent_id: agentId, status, operation_kind: operationKind },
    });
  }
  const plannedOperationKind =
    typeof stateUpdate.operation_kind === "string" && stateUpdate.operation_kind.trim()
      ? stateUpdate.operation_kind
      : null;
  if (!plannedOperationKind) {
    throw runtimeError({
      status: 502,
      code: "agent_status_state_update_operation_kind_missing",
      message: "Rust agent status state planning did not return an operation kind.",
      details: { agent_id: agentId, status, operation_kind: operationKind },
    });
  }
  if (plannedOperationKind !== operationKind) {
    throw runtimeError({
      status: 502,
      code: "agent_status_state_update_operation_kind_mismatch",
      message: "Rust agent status state planning returned an unexpected operation kind.",
      details: {
        agent_id: agentId,
        status,
        expected_operation_kind: operationKind,
        operation_kind: plannedOperationKind,
      },
    });
  }
  store.agents.set(updated.id, updated);
  store.writeAgent(updated, plannedOperationKind);
  return updated;
}

export function deleteAgent(store, agentId, deps = {}) {
  const { path, policyError } = deps;
  const agent = store.getAgent(agentId);
  const runCount = store.listRuns(agentId).length;
  if (runCount > 0) {
    throw policyError(
      "Permanent agent deletion requires retention review when canonical runs exist; archive instead.",
      { agentId, runCount },
    );
  }
  store.agents.delete(agentId);
  store.removeQuiet(path.join(store.stateDir, "agents", `${agentId}.json`));
}

export function getRun(store, runId, deps = {}) {
  const { notFound } = deps;
  const run = store.runs.get(runId);
  if (!run) {
    throw notFound(`Run not found: ${runId}`, { runId });
  }
  return run;
}

export function listRuns(store, agentId = null) {
  return [...store.runs.values()]
    .filter((run) => !agentId || run.agentId === agentId)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
}

export function usageForRun(store, runId, deps = {}) {
  const {
    runtimeUsageTelemetryForRun,
    threadIdForAgent,
  } = deps;
  const run = store.getRun(runId);
  return runtimeUsageTelemetryForRun({
    run,
    agent: store.getAgent(run.agentId),
    threadId: threadIdForAgent(run.agentId),
  });
}

export function usageForThread(store, threadId, deps = {}) {
  const {
    runtimeUsageTelemetryForThread,
  } = deps;
  const agent = store.agentForThread(threadId);
  const subagents = [...store.subagents.values()].filter(
    (record) => record.parent_thread_id === threadId,
  );
  return runtimeUsageTelemetryForThread({
    threadId,
    agent,
    runs: store.listRuns(agent.id),
    subagents,
  });
}

export function agentForThread(store, threadId, deps = {}) {
  const { agentIdForThread } = deps;
  return store.getAgent(agentIdForThread(threadId));
}

export function inFlightRuntimeTurnKey(threadId, turnId) {
  return `${threadId}:${turnId}`;
}

export function registerInFlightRuntimeTurn(store, { agent, threadId, turnId, runId = null, request = {} }, deps = {}) {
  const { runIdForTurn } = deps;
  const now = new Date().toISOString();
  const key = store.inFlightRuntimeTurnKey(threadId, turnId);
  const existing = store.inFlightRuntimeTurns.get(key) ?? {};
  store.inFlightRuntimeTurns.set(key, {
    ...existing,
    agentId: agent.id,
    threadId,
    turnId,
    runId: runId ?? runIdForTurn(turnId),
    prompt: request.prompt ?? request.message ?? request.input ?? existing.prompt ?? "",
    createdAt: existing.createdAt ?? now,
    updatedAt: now,
  });
}

export function unregisterInFlightRuntimeTurn(store, threadId, turnId) {
  store.inFlightRuntimeTurns.delete(store.inFlightRuntimeTurnKey(threadId, turnId));
}

export function resolveRunForThreadTurn(store, agent, threadId, turnId, deps = {}) {
  const {
    notFound,
    runIdForTurn,
    runtimeTurnIdForRun,
    turnIdForRun,
  } = deps;
  const runId = runIdForTurn(turnId);
  const directRun = store.runs.get(runId);
  if (directRun) {
    if (directRun.agentId !== agent.id) {
      throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId });
    }
    return { run: directRun, runId: directRun.id, turnId: runtimeTurnIdForRun(directRun), inFlight: null };
  }
  const runtimeTurnRun = store.listRuns(agent.id).find((candidate) =>
    runtimeTurnIdForRun(candidate) === turnId || turnIdForRun(candidate.id) === turnId,
  );
  if (runtimeTurnRun) {
    return {
      run: runtimeTurnRun,
      runId: runtimeTurnRun.id,
      turnId: runtimeTurnIdForRun(runtimeTurnRun),
      inFlight: null,
    };
  }
  const inFlight = store.inFlightRuntimeTurns.get(store.inFlightRuntimeTurnKey(threadId, turnId));
  if (inFlight?.agentId === agent.id) {
    return {
      run: null,
      runId: inFlight.runId,
      turnId: inFlight.turnId,
      inFlight,
    };
  }
  throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId });
}
