export function createThreadMemoryState({
  agentIdForThread,
  memoryListFilters,
  memoryPolicyOverrides,
  memoryStatusForProjection,
  optionalString,
  threadIdForAgent,
  validateMemoryProjection,
} = {}) {
  function listMemoryForThread(store, threadId, options = {}) {
    const agent = store.agentForThread(threadId);
    return store.memory.projection({
      agent,
      threadId,
      workspace: agent.cwd,
      filters: memoryListFilters(options),
    });
  }

  function memoryPolicyForThread(store, threadId) {
    const agent = store.agentForThread(threadId);
    return store.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  function setMemoryPolicyForThread(store, threadId, body = {}) {
    const agent = store.agentForThread(threadId);
    const mutation = store.memory.setPolicy({
      targetType: "thread",
      targetId: threadId,
      agent,
      threadId,
      workspace: agent.cwd,
      source: body.source ?? "thread_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
    return store.recordThreadMemoryMutation(threadId, mutation, body, "policy_update");
  }

  function memoryPathForThread(store, threadId) {
    const agent = store.agentForThread(threadId);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function listMemoryForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return store.memory.projection({
      agent,
      threadId,
      workspace: agent.cwd,
      filters: memoryListFilters(options),
    });
  }

  function memoryPolicyForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return store.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  function setMemoryPolicyForAgent(store, agentId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    return store.memory.setPolicy({
      targetType: body.targetType ?? body.target_type ?? "thread",
      targetId: body.targetId ?? body.target_id ?? threadId,
      agent,
      threadId,
      workspace: agent.cwd,
      source: body.source ?? "agent_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
  }

  function memoryPathForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function memoryProjectionForContext(store, options = {}) {
    const threadId = optionalString(options.thread_id ?? options.threadId);
    const agentId =
      optionalString(options.agent_id ?? options.agentId) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    if (threadId) return store.listMemoryForThread(threadId, options);
    if (agentId) return store.listMemoryForAgent(agentId, options);
    return store.memory.projection({
      workspace: store.defaultCwd,
      filters: memoryListFilters(options),
    });
  }

  function memoryStatus(store, options = {}) {
    const projection = store.memoryProjectionForContext(options);
    return {
      ...memoryStatusForProjection(projection),
      thread_id: projection.threadId ?? null,
      threadId: projection.threadId ?? null,
      agent_id: projection.agentId ?? null,
      agentId: projection.agentId ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  function validateMemory(store, input = {}) {
    const projection =
      input.projection && typeof input.projection === "object"
        ? input.projection
        : store.memoryProjectionForContext(input);
    const validation = validateMemoryProjection(projection);
    return {
      ...validation,
      thread_id: projection.threadId ?? null,
      threadId: projection.threadId ?? null,
      agent_id: projection.agentId ?? null,
      agentId: projection.agentId ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  return {
    listMemoryForAgent,
    listMemoryForThread,
    memoryPathForAgent,
    memoryPathForThread,
    memoryPolicyForAgent,
    memoryPolicyForThread,
    memoryProjectionForContext,
    memoryStatus,
    setMemoryPolicyForAgent,
    setMemoryPolicyForThread,
    validateMemory,
  };
}
