import {
  objectRecord,
  optionalString,
} from "../runtime-value-helpers.mjs";

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
    statusStateUpdateRunner = null,
    runtimeError = ({ status: errorStatus = 500, code = "agent_status_control_error", message, details }) =>
      Object.assign(new Error(message), { status: errorStatus, code, details }),
  } = deps;
  const agent = store.agents.get(agentId);
  if (!agent) {
    throw runtimeError({
      status: 404,
      code: "runtime_agent_status_control_agent_not_found",
      message: `Agent not found: ${agentId}`,
      details: {
        rust_core_boundary: "runtime.agent_status_control",
        operation: "agent_status_control",
        operation_kind: "agent_status_update",
        requested_operation_kind: operationKind,
        agent_id: agentId,
        requested_status: status ?? null,
        evidence_refs: agentStatusControlEvidenceRefs(),
      },
    });
  }
  if (typeof statusStateUpdateRunner?.planAgentStatusStateUpdate !== "function") {
    throw runtimeError({
      status: 501,
      code: "runtime_agent_status_control_rust_core_required",
      message:
        "Agent lifecycle/status control requires direct Rust daemon-core state planning and Agentgres persistence.",
      details: {
        rust_core_boundary: "runtime.agent_status_control",
        operation: "agent_status_control",
        operation_kind: "agent_status_update",
        requested_operation_kind: operationKind,
        agent_id: agentId,
        requested_status: status ?? null,
        evidence_refs: agentStatusControlEvidenceRefs(),
      },
    });
  }
  const requestedStatus = optionalString(status) ?? optionalString(agent.status) ?? "active";
  const planned = statusStateUpdateRunner.planAgentStatusStateUpdate({
    agent,
    status: requestedStatus,
    operation_kind: operationKind,
    updated_at: new Date().toISOString(),
  });
  const plannedAgent = objectRecord(planned?.agent);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedAgent) {
    throw runtimeError({
      status: 502,
      code: "agent_status_state_update_agent_missing",
      message: "Rust daemon-core agent status control did not return an agent projection.",
      details: {
        rust_core_boundary: "runtime.agent_status_control",
        operation: "agent_status_control",
        operation_kind: "agent_status_update",
        requested_operation_kind: operationKind,
        agent_id: agentId,
        requested_status: requestedStatus,
      },
    });
  }
  if (plannedOperationKind !== operationKind) {
    throw runtimeError({
      status: 502,
      code: "agent_status_state_update_operation_kind_mismatch",
      message: "Rust daemon-core agent status control returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.agent_status_control",
        operation: "agent_status_control",
        operation_kind: "agent_status_update",
        expected_operation_kind: operationKind,
        actual_operation_kind: plannedOperationKind,
        agent_id: agentId,
        requested_status: requestedStatus,
      },
    });
  }
  store.writeAgent(plannedAgent, plannedOperationKind);
  return plannedAgent;
}

export function deleteAgent(store, agentId, deps = {}) {
  const {
    deleteStateUpdateRunner = null,
    runtimeError = ({ status: errorStatus = 500, code = "agent_delete_control_error", message, details }) =>
      Object.assign(new Error(message), { status: errorStatus, code, details }),
  } = deps;
  const agent = store.agents.get(agentId);
  if (!agent) {
    throw runtimeError({
      status: 404,
      code: "runtime_agent_delete_agent_not_found",
      message: `Agent not found: ${agentId}`,
      details: {
        rust_core_boundary: "runtime.agent_delete",
        operation: "agent_delete",
        operation_kind: "agent_deletion",
        requested_operation_kind: "agent.delete",
        agent_id: agentId,
        evidence_refs: agentDeleteControlEvidenceRefs(),
      },
    });
  }
  if (typeof deleteStateUpdateRunner?.planAgentDeleteStateUpdate !== "function") {
    throw runtimeError({
      status: 501,
      code: "runtime_agent_delete_rust_core_required",
      message:
        "Permanent agent deletion requires direct Rust daemon-core state planning and Agentgres persistence.",
      details: {
        rust_core_boundary: "runtime.agent_delete",
        operation: "agent_delete",
        operation_kind: "agent_deletion",
        requested_operation_kind: "agent.delete",
        agent_id: agentId,
        evidence_refs: agentDeleteControlEvidenceRefs(),
      },
    });
  }
  const deletedAt = new Date().toISOString();
  const planned = deleteStateUpdateRunner.planAgentDeleteStateUpdate({
    agent,
    operation_kind: "agent.delete",
    deleted_at: deletedAt,
  });
  const plannedAgent = objectRecord(planned?.agent);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedAgent) {
    throw runtimeError({
      status: 502,
      code: "agent_delete_state_update_agent_missing",
      message: "Rust daemon-core agent delete control did not return an agent tombstone projection.",
      details: {
        rust_core_boundary: "runtime.agent_delete",
        operation: "agent_delete",
        operation_kind: "agent_deletion",
        requested_operation_kind: "agent.delete",
        agent_id: agentId,
      },
    });
  }
  if (plannedOperationKind !== "agent.delete") {
    throw runtimeError({
      status: 502,
      code: "agent_delete_state_update_operation_kind_mismatch",
      message: "Rust daemon-core agent delete control returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.agent_delete",
        operation: "agent_delete",
        operation_kind: "agent_deletion",
        expected_operation_kind: "agent.delete",
        actual_operation_kind: plannedOperationKind,
        agent_id: agentId,
      },
    });
  }
  if (optionalString(plannedAgent.status) !== "deleted" || !optionalString(plannedAgent.deletedAt)) {
    throw runtimeError({
      status: 502,
      code: "agent_delete_state_update_tombstone_missing",
      message: "Rust daemon-core agent delete control did not return a complete deletion tombstone.",
      details: {
        rust_core_boundary: "runtime.agent_delete",
        operation: "agent_delete",
        operation_kind: "agent_deletion",
        expected_operation_kind: "agent.delete",
        agent_id: agentId,
      },
    });
  }
  store.writeAgent(plannedAgent, plannedOperationKind);
  return plannedAgent;
}

function agentStatusControlEvidenceRefs() {
  return [
    "runtime_agent_status_control_js_facade_retired",
    "runtime_agent_archive_js_facade_retired",
    "runtime_agent_unarchive_js_facade_retired",
    "runtime_agent_resume_js_facade_retired",
    "runtime_agent_close_js_facade_retired",
    "runtime_agent_reload_js_facade_retired",
    "rust_daemon_core_agent_status_control_required",
    "agentgres_agent_status_state_truth_required",
  ];
}

function agentDeleteControlEvidenceRefs() {
  return [
    "runtime_agent_delete_js_facade_retired",
    "rust_daemon_core_agent_delete_required",
    "agentgres_agent_delete_state_truth_required",
  ];
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
