const PUBLIC_MEMORY_PROJECTION_EVIDENCE_REFS = [
  "runtime_memory_public_projection_rust_owned",
  "agentgres_thread_memory_projection_truth_required",
];

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

  function publicMemoryProjectionRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (runner?.projectRuntimeMemoryProjection) return runner;
    throw memoryRuntimeError({
      status: 501,
      code: "runtime_public_memory_projection_rust_projection_missing",
      message:
        "Public memory route projections require Rust daemon-core projection over Agentgres memory truth.",
      details: {
        rust_core_boundary: "runtime.memory_projection",
        operation: "runtime_memory_projection",
        operation_kind: request.operation_kind ?? null,
        projection_kind: request.projection_kind ?? null,
        thread_id: request.thread_id ?? null,
        agent_id: request.agent_id ?? null,
        workspace_root: request.workspace_root ?? null,
        source: "runtime.thread_memory_state.public_projection",
        evidence_refs: PUBLIC_MEMORY_PROJECTION_EVIDENCE_REFS,
      },
    });
  }

  function projectPublicMemory(store, projectionKind, projection = {}, context = {}) {
    const request = {
      operation: "runtime_memory_projection",
      operation_kind: `runtime.memory_projection.${projectionKind}`,
      projection_kind: projectionKind,
      thread_id: context.threadId ?? projection?.thread_id ?? null,
      agent_id: context.agentId ?? projection?.agent_id ?? null,
      workspace_root: context.workspaceRoot ?? projection?.workspace ?? null,
      source: "runtime.thread_memory_state.public_projection",
      projection,
      evidence_refs: PUBLIC_MEMORY_PROJECTION_EVIDENCE_REFS,
    };
    const runner = publicMemoryProjectionRunner(store, request);
    const result = runner.projectRuntimeMemoryProjection(request);
    if (result?.projection_kind !== projectionKind || !objectRecord(result?.projection)) {
      throw memoryRuntimeError({
        status: 502,
        code: "runtime_public_memory_projection_rust_projection_invalid",
        message: "Rust public memory projection returned an invalid route projection.",
        details: {
          rust_core_boundary: "runtime.memory_projection",
          expected_projection_kind: projectionKind,
          actual_projection_kind: result?.projection_kind ?? null,
          operation: request.operation,
          operation_kind: request.operation_kind,
          source: "runtime.thread_memory_state.public_projection",
        },
      });
    }
    return result.projection;
  }

  function publicListMemoryForThread(store, threadId, options = {}) {
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.records",
      projection_kind: "records",
      thread_id: threadId,
    });
    const projection = listMemoryForThread(store, threadId, options);
    return projectPublicMemory(store, "records", projection, {
      threadId,
      agentId: projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryPolicyForThread(store, threadId, options = {}) {
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.policy",
      projection_kind: "policy",
      thread_id: threadId,
    });
    const projection = listMemoryForThread(store, threadId, options);
    return projectPublicMemory(store, "policy", projection, {
      threadId,
      agentId: projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryPathForThread(store, threadId, options = {}) {
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.path",
      projection_kind: "path",
      thread_id: threadId,
    });
    const projection = listMemoryForThread(store, threadId, options);
    return projectPublicMemory(store, "path", projection, {
      threadId,
      agentId: projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicListMemoryForAgent(store, agentId, options = {}) {
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.records",
      projection_kind: "records",
      agent_id: agentId,
    });
    const projection = listMemoryForAgent(store, agentId, options);
    return projectPublicMemory(store, "records", projection, {
      threadId: projection.thread_id ?? null,
      agentId,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryPolicyForAgent(store, agentId, options = {}) {
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.policy",
      projection_kind: "policy",
      agent_id: agentId,
    });
    const projection = listMemoryForAgent(store, agentId, options);
    return projectPublicMemory(store, "policy", projection, {
      threadId: projection.thread_id ?? null,
      agentId,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryPathForAgent(store, agentId, options = {}) {
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.path",
      projection_kind: "path",
      agent_id: agentId,
    });
    const projection = listMemoryForAgent(store, agentId, options);
    return projectPublicMemory(store, "path", projection, {
      threadId: projection.thread_id ?? null,
      agentId,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryProjectionForContext(store, options = {}) {
    const threadId = optionalString(options.thread_id);
    const agentId =
      optionalString(options.agent_id) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.records",
      projection_kind: "records",
      thread_id: threadId ?? null,
      agent_id: agentId ?? null,
    });
    const projection = memoryProjectionForContext(store, options);
    return projectPublicMemory(store, "records", projection, {
      threadId: threadId ?? projection.thread_id ?? null,
      agentId: agentId ?? projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryStatus(store, options = {}) {
    const threadId = optionalString(options.thread_id);
    const agentId =
      optionalString(options.agent_id) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.status",
      projection_kind: "status",
      thread_id: threadId ?? null,
      agent_id: agentId ?? null,
    });
    const projection = memoryProjectionForContext(store, options);
    return projectPublicMemory(store, "status", projection, {
      threadId: threadId ?? projection.thread_id ?? null,
      agentId: agentId ?? projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryPolicyForContext(store, options = {}) {
    const threadId = optionalString(options.thread_id);
    const agentId =
      optionalString(options.agent_id) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.policy",
      projection_kind: "policy",
      thread_id: threadId ?? null,
      agent_id: agentId ?? null,
    });
    const projection = memoryProjectionForContext(store, options);
    return projectPublicMemory(store, "policy", projection, {
      threadId: threadId ?? projection.thread_id ?? null,
      agentId: agentId ?? projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicMemoryPathForContext(store, options = {}) {
    const threadId = optionalString(options.thread_id);
    const agentId =
      optionalString(options.agent_id) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.path",
      projection_kind: "path",
      thread_id: threadId ?? null,
      agent_id: agentId ?? null,
    });
    const projection = memoryProjectionForContext(store, options);
    return projectPublicMemory(store, "path", projection, {
      threadId: threadId ?? projection.thread_id ?? null,
      agentId: agentId ?? projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
  }

  function publicValidateMemory(store, input = {}) {
    const threadId = optionalString(input.thread_id);
    const agentId =
      optionalString(input.agent_id) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    publicMemoryProjectionRunner(store, {
      operation_kind: "runtime.memory_projection.validation",
      projection_kind: "validation",
      thread_id: threadId ?? null,
      agent_id: agentId ?? null,
    });
    const projection = objectRecord(input.projection)
      ? input.projection
      : memoryProjectionForContext(store, input);
    return projectPublicMemory(store, "validation", projection, {
      threadId: threadId ?? projection.thread_id ?? null,
      agentId: agentId ?? projection.agent_id ?? null,
      workspaceRoot: projection.workspace ?? null,
    });
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

  function objectRecord(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
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
    publicListMemoryForAgent,
    publicListMemoryForThread,
    publicMemoryPathForAgent,
    publicMemoryPathForContext,
    publicMemoryPathForThread,
    publicMemoryPolicyForAgent,
    publicMemoryPolicyForContext,
    publicMemoryPolicyForThread,
    publicMemoryProjectionForContext,
    publicMemoryStatus,
    publicValidateMemory,
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
