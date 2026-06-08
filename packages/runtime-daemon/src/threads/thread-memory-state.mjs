export function createThreadMemoryState({
  doctorHash,
  eventStreamIdForThread,
  fixtureProfileForAgent,
  memoryControlKind,
  memoryEventKind,
  memoryMutationRawInput,
  memoryMutationRowLabel,
  memoryMutationSummary,
  memoryOperatorControlKind,
  memoryRowsForStatus,
  memoryRuntimeEventKind,
  memoryWorkflowNodeId,
  agentIdForThread,
  memoryListFilters,
  memoryPolicyOverrides,
  memoryStatusForProjection,
  memoryWriteBlockReason,
  normalizeArray,
  operatorControlSource,
  optionalString,
  policyError,
  runtimeError,
  safeId,
  threadIdForAgent,
  validateMemoryProjection,
  contextPolicyRunner,
} = {}) {
  const memoryRuntimeError = runtimeError ?? (({ status = 500, code = "thread_memory_state_error", message, details }) =>
    Object.assign(new Error(message), { status, code, details }));

  function throwThreadMemoryRustCoreRequired({
    operation,
    controlKind = memoryControlKind(operation),
    threadId = null,
    agentId = null,
    memoryId = null,
  } = {}) {
    throw memoryRuntimeError({
      status: 501,
      code: "runtime_thread_memory_control_rust_core_required",
      message:
        "Thread memory mutation/control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: "runtime.thread_memory_control",
        operation: "thread_memory_control",
        operation_kind: "thread_memory_control",
        requested_operation: operation ?? null,
        requested_control_kind: controlKind ?? null,
        thread_id: threadId,
        agent_id: agentId,
        memory_id: memoryId,
        evidence_refs: [
          "runtime_thread_memory_control_js_facade_retired",
          "runtime_thread_memory_write_js_facade_retired",
          "runtime_thread_memory_policy_js_facade_retired",
          "runtime_thread_memory_status_validation_js_facade_retired",
          "runtime_memory_state_store_js_mutation_retired",
          "rust_daemon_core_thread_memory_control_required",
          "agentgres_thread_memory_state_truth_required",
        ],
      },
    });
  }

  function rememberForAgent(store, agent, { text, threadId = threadIdForAgent(agent.id), scope = "thread", source = "operator_remember", workflow = {} } = {}) {
    void store;
    void text;
    void scope;
    void source;
    void workflow;
    throwThreadMemoryRustCoreRequired({
      operation: "write",
      threadId,
      agentId: agent?.id ?? null,
    });
  }

  function rememberForThread(store, threadId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "write", threadId });
  }

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
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "policy_update", threadId });
  }

  function memoryPathForThread(store, threadId) {
    const agent = store.agentForThread(threadId);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function updateMemoryForThread(store, threadId, memoryId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "edit", threadId, memoryId });
  }

  function deleteMemoryForThread(store, threadId, memoryId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "delete", threadId, memoryId });
  }

  function rememberForAgentId(store, agentId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "write", agentId });
  }

  function listMemoryForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? threadIdForAgent(agent.id);
    return store.memory.projection({
      agent,
      threadId,
      workspace: agent.cwd,
      filters: memoryListFilters(options),
    });
  }

  function memoryPolicyForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? threadIdForAgent(agent.id);
    return store.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  function setMemoryPolicyForAgent(store, agentId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "policy_update", agentId });
  }

  function memoryPathForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? threadIdForAgent(agent.id);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function updateMemoryForAgentId(store, agentId, memoryId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "edit", agentId, memoryId });
  }

  function deleteMemoryForAgentId(store, agentId, memoryId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "delete", agentId, memoryId });
  }

  function updateMemoryRecord(store, memoryId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "edit", memoryId });
  }

  function deleteMemoryRecord(store, memoryId, body = {}) {
    void store;
    void body;
    throwThreadMemoryRustCoreRequired({ operation: "delete", memoryId });
  }

  function memoryProjectionForContext(store, options = {}) {
    const threadId = optionalString(options.thread_id);
    const agentId =
      optionalString(options.agent_id) ??
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
    const runner = store.contextPolicyRunner ?? contextPolicyRunner;
    return {
      ...memoryStatusForProjection(projection, { contextPolicyRunner: runner }),
      thread_id: projection.thread_id ?? null,
      agent_id: projection.agent_id ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  function validateMemory(store, input = {}) {
    const projection =
      input.projection && typeof input.projection === "object"
        ? input.projection
        : store.memoryProjectionForContext(input);
    const runner = store.contextPolicyRunner ?? contextPolicyRunner;
    const validation = validateMemoryProjection(projection, { contextPolicyRunner: runner });
    return {
      ...validation,
      thread_id: projection.thread_id ?? null,
      agent_id: projection.agent_id ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  function recordThreadMemoryStatus(store, threadId, request = {}, schemaVersion) {
    void store;
    void request;
    void schemaVersion;
    throwThreadMemoryRustCoreRequired({ operation: "status", controlKind: "memory_status", threadId });
  }

  function validateThreadMemory(store, threadId, request = {}, schemaVersion) {
    void store;
    void request;
    void schemaVersion;
    throwThreadMemoryRustCoreRequired({ operation: "validate", controlKind: "memory_validate", threadId });
  }

  function recordThreadMemoryMutation(store, threadId, mutation = {}, request = {}, operation = "write", schemaVersion) {
    void store;
    void mutation;
    void request;
    void schemaVersion;
    throwThreadMemoryRustCoreRequired({ operation, threadId });
  }

  function appendThreadMemoryControlEvent(store, {
    threadId,
    agent,
    request,
    controlKind,
    sourceEventKind,
    eventKind,
    componentKind,
    workflowNodeId,
    payloadSchemaVersion,
    status,
    payload,
    receiptRefs,
    policyDecisionRefs,
    policyDecisionKind = "read",
  }) {
    void store;
    void agent;
    void request;
    void sourceEventKind;
    void eventKind;
    void componentKind;
    void workflowNodeId;
    void payloadSchemaVersion;
    void status;
    void payload;
    void receiptRefs;
    void policyDecisionRefs;
    void policyDecisionKind;
    throwThreadMemoryRustCoreRequired({ operation: controlKind, controlKind, threadId });
  }

  return {
    appendThreadMemoryControlEvent,
    deleteMemoryForAgentId,
    deleteMemoryForThread,
    deleteMemoryRecord,
    listMemoryForAgent,
    listMemoryForThread,
    memoryPathForAgent,
    memoryPathForThread,
    memoryPolicyForAgent,
    memoryPolicyForThread,
    memoryProjectionForContext,
    memoryStatus,
    recordThreadMemoryMutation,
    recordThreadMemoryStatus,
    rememberForAgent,
    rememberForAgentId,
    rememberForThread,
    setMemoryPolicyForAgent,
    setMemoryPolicyForThread,
    updateMemoryForAgentId,
    updateMemoryForThread,
    updateMemoryRecord,
    validateThreadMemory,
    validateMemory,
  };
}
