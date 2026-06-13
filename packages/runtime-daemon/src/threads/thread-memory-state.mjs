const PUBLIC_MEMORY_PROJECTION_EVIDENCE_REFS = [
  "runtime_memory_public_projection_rust_owned",
  "agentgres_thread_memory_projection_truth_required",
];
const MEMORY_CONTROL_EVIDENCE_REFS = [
  "runtime_memory_control_rust_owned",
  "runtime_memory_state_store_js_mutation_retired",
  "agentgres_thread_memory_state_truth_required",
];
const MEMORY_CONTROL_EVENT_EVIDENCE_REFS = [
  "runtime_memory_control_event_rust_owned",
  "runtime_memory_status_validation_control_rust_owned",
  "runtime_memory_status_validation_js_facade_retired",
  "agentgres_runtime_thread_event_truth_required",
];
const RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_memory_state_commit.v1";
const RUST_AGENTGRES_STORAGE_BACKEND = "rust_agentgres_storage";

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
  nowIso = () => new Date().toISOString(),
} = {}) {
  const memoryRuntimeError = runtimeError ?? (({ status = 500, code = "thread_memory_state_error", message, details }) =>
    Object.assign(new Error(message), { status, code, details }));

  function throwThreadMemoryRustCoreRequired({
    operation,
    controlKind = memoryControlKind(operation),
    threadId = null,
    agentId = null,
    memoryId = null,
    evidenceRefs = [
      "runtime_thread_memory_control_js_facade_retired",
      "runtime_thread_memory_write_js_facade_retired",
      "runtime_thread_memory_policy_js_facade_retired",
      "runtime_memory_state_store_js_mutation_retired",
      "rust_daemon_core_thread_memory_control_required",
      "agentgres_thread_memory_state_truth_required",
    ],
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
        evidence_refs: evidenceRefs,
      },
    });
  }

  function rememberForAgent(store, agent, { text, threadId = threadIdForAgent(agent.id), scope = "thread", source = "operator_remember", workflow = {} } = {}) {
    return commitMemoryControl(store, {
      operation: "write",
      operationKind: "memory.write",
      threadId,
      agentId: agent?.id ?? null,
      workspaceRoot: agent?.cwd ?? null,
      request: { text, scope, source, ...workflow },
    });
  }

  function rememberForThread(store, threadId, body = {}) {
    const agent = store.agentForThread(threadId);
    return commitMemoryControl(store, {
      operation: "write",
      operationKind: "memory.write",
      threadId,
      agentId: agent?.id ?? null,
      workspaceRoot: agent?.cwd ?? null,
      request: body,
    });
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
    const agent = store.agentForThread(threadId);
    return commitMemoryControl(store, {
      operation: "policy",
      operationKind: "memory.policy",
      threadId,
      agentId: agent?.id ?? null,
      workspaceRoot: agent?.cwd ?? null,
      targetType: "thread",
      targetId: threadId,
      request: body,
      currentPolicy: memoryPolicyForThread(store, threadId),
    });
  }

  function memoryPathForThread(store, threadId) {
    const agent = store.agentForThread(threadId);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function updateMemoryForThread(store, threadId, memoryId, body = {}) {
    const agent = store.agentForThread(threadId);
    return commitMemoryControl(store, {
      operation: "edit",
      operationKind: "memory.edit",
      threadId,
      agentId: agent?.id ?? null,
      memoryId,
      workspaceRoot: agent?.cwd ?? null,
      request: body,
      currentRecord: memoryRecordForId(store, memoryId),
    });
  }

  function deleteMemoryForThread(store, threadId, memoryId, body = {}) {
    const agent = store.agentForThread(threadId);
    return commitMemoryControl(store, {
      operation: "delete",
      operationKind: "memory.delete",
      threadId,
      agentId: agent?.id ?? null,
      memoryId,
      workspaceRoot: agent?.cwd ?? null,
      request: body,
      currentRecord: memoryRecordForId(store, memoryId),
    });
  }

  function rememberForAgentId(store, agentId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = optionalString(body.thread_id) ?? threadIdForAgent(agent.id);
    return commitMemoryControl(store, {
      operation: "write",
      operationKind: "memory.write",
      threadId,
      agentId,
      workspaceRoot: agent?.cwd ?? null,
      request: body,
    });
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
    const agent = store.getAgent(agentId);
    const threadId = optionalString(body.thread_id) ?? threadIdForAgent(agent.id);
    return commitMemoryControl(store, {
      operation: "policy",
      operationKind: "memory.policy",
      threadId,
      agentId,
      workspaceRoot: agent?.cwd ?? null,
      targetType: optionalString(body.target_type) ?? "agent",
      targetId: optionalString(body.target_id) ?? agentId,
      request: body,
      currentPolicy: memoryPolicyForAgent(store, agentId, { thread_id: threadId }),
    });
  }

  function memoryPathForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? threadIdForAgent(agent.id);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function updateMemoryForAgentId(store, agentId, memoryId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = optionalString(body.thread_id) ?? threadIdForAgent(agent.id);
    return commitMemoryControl(store, {
      operation: "edit",
      operationKind: "memory.edit",
      threadId,
      agentId,
      memoryId,
      workspaceRoot: agent?.cwd ?? null,
      request: body,
      currentRecord: memoryRecordForId(store, memoryId),
    });
  }

  function deleteMemoryForAgentId(store, agentId, memoryId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = optionalString(body.thread_id) ?? threadIdForAgent(agent.id);
    return commitMemoryControl(store, {
      operation: "delete",
      operationKind: "memory.delete",
      threadId,
      agentId,
      memoryId,
      workspaceRoot: agent?.cwd ?? null,
      request: body,
      currentRecord: memoryRecordForId(store, memoryId),
    });
  }

  function updateMemoryRecord(store, memoryId, body = {}) {
    const currentRecord = memoryRecordForId(store, memoryId);
    const threadId = optionalString(body.thread_id) ?? optionalString(currentRecord?.thread_id);
    const agentId = optionalString(body.agent_id) ?? optionalString(currentRecord?.agent_id);
    return commitMemoryControl(store, {
      operation: "edit",
      operationKind: "memory.edit",
      threadId,
      agentId,
      memoryId,
      workspaceRoot: optionalString(currentRecord?.workspace) ?? store.defaultCwd ?? null,
      request: body,
      currentRecord,
    });
  }

  function deleteMemoryRecord(store, memoryId, body = {}) {
    const currentRecord = memoryRecordForId(store, memoryId);
    const threadId = optionalString(body.thread_id) ?? optionalString(currentRecord?.thread_id);
    const agentId = optionalString(body.agent_id) ?? optionalString(currentRecord?.agent_id);
    return commitMemoryControl(store, {
      operation: "delete",
      operationKind: "memory.delete",
      threadId,
      agentId,
      memoryId,
      workspaceRoot: optionalString(currentRecord?.workspace) ?? store.defaultCwd ?? null,
      request: body,
      currentRecord,
    });
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

  function memoryControlRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (
      runner?.planRuntimeMemoryControl &&
      runner?.projectRuntimeMemoryProjection &&
      typeof store?.commitRuntimeMemoryState === "function"
    ) {
      return runner;
    }
    throwThreadMemoryRustCoreRequired({
      operation: request.operation,
      controlKind: request.operation_kind,
      threadId: request.thread_id,
      agentId: request.agent_id,
      memoryId: request.memory_id,
    });
  }

  function memoryControlEventRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (runner?.planRuntimeMemoryControl && typeof store?.appendRuntimeEvent === "function") {
      return runner;
    }
    throwThreadMemoryRustCoreRequired({
      operation: request.operation,
      controlKind: request.operation_kind,
      threadId: request.thread_id,
      agentId: request.agent_id,
      evidenceRefs: memoryControlEventEvidenceRefs(request.operation_kind),
    });
  }

  function memoryControlEventEvidenceRefs(operationKind) {
    const refs = [...MEMORY_CONTROL_EVENT_EVIDENCE_REFS];
    if (operationKind === "memory.status") {
      refs.unshift("runtime_memory_status_control_rust_owned");
    } else if (operationKind === "memory.validate") {
      refs.unshift("runtime_memory_validation_control_rust_owned");
    }
    return uniqueMemoryStrings(refs);
  }

  function memoryControlEventOperation({ operation, controlKind, eventKind } = {}) {
    const fromEvent = optionalString(eventKind);
    if (fromEvent?.startsWith("memory.")) {
      const eventOperation = fromEvent.slice("memory.".length);
      return eventOperation === "validation" ? "validate" : eventOperation;
    }
    const fromControl = optionalString(controlKind);
    if (fromControl?.startsWith("memory_")) {
      const controlOperation = fromControl.slice("memory_".length);
      return controlOperation === "validation" ? "validate" : controlOperation;
    }
    return optionalString(operation) ?? "status";
  }

  function memoryControlEventOperationKind(operation) {
    if (operation === "validation") return "memory.validate";
    return `memory.${operation}`;
  }

  function memoryControlEventSourceKind(operation) {
    if (operation === "validate") return "OperatorControl.MemoryValidate";
    if (operation === "status") return "OperatorControl.MemoryStatus";
    return memoryOperatorControlKind(operation);
  }

  function planMemoryControlEvent(store, {
    threadId,
    agent,
    request = {},
    operation,
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
  } = {}) {
    const resolvedOperation = memoryControlEventOperation({ operation, controlKind, eventKind });
    const operationKind = memoryControlEventOperationKind(resolvedOperation);
    const resolvedAgent = agent ?? store.agentForThread(threadId);
    const thread = resolvedAgent && typeof store.threadForAgent === "function"
      ? store.threadForAgent(resolvedAgent)
      : {};
    const planRequest = {
      operation: resolvedOperation,
      operation_kind: operationKind,
      thread_id: threadId ?? null,
      agent_id: resolvedAgent?.id ?? null,
      workspace_root: resolvedAgent?.cwd ?? null,
      source: optionalString(request.source) ?? "agent_studio",
      now: nowIso(),
      request: {
        ...request,
        control_kind: controlKind ?? memoryControlKind(resolvedOperation),
        event_stream_id: eventStreamIdForThread(threadId),
        turn_id: optionalString(request.turn_id) ?? thread?.latest_turn_id ?? null,
        source_event_kind:
          sourceEventKind ?? memoryControlEventSourceKind(resolvedOperation),
        event_kind: eventKind ?? operationKind,
        component_kind: componentKind ?? "memory_manager",
        workflow_node_id:
          workflowNodeId ?? `runtime.memory-manager.${resolvedOperation}`,
        payload_schema_version:
          payloadSchemaVersion ?? `ioi.runtime.memory-${resolvedOperation}.v1`,
        status: status ?? "completed",
        payload: objectRecord(payload) ?? {},
        receipt_refs: normalizeArray(receiptRefs),
        policy_decision_refs: normalizeArray(policyDecisionRefs),
        policy_decision_kind: policyDecisionKind,
      },
      evidence_refs: memoryControlEventEvidenceRefs(operationKind),
    };
    const runner = memoryControlEventRunner(store, planRequest);
    return runner.planRuntimeMemoryControl(planRequest);
  }

  function appendPlannedMemoryControlEvent(store, plannedControl) {
    const event = objectRecord(plannedControl?.payload);
    if (!event) {
      throw memoryRuntimeError({
        status: 502,
        code: "runtime_memory_control_event_planner_invalid",
        message: "Rust memory control planning did not return a runtime event payload.",
        details: {
          operation_kind: plannedControl?.operation_kind ?? null,
          memory_state_kind: plannedControl?.memory_state_kind ?? null,
        },
      });
    }
    return store.appendRuntimeEvent(event);
  }

  function commitMemoryControl(store, {
    operation,
    operationKind,
    threadId = null,
    agentId = null,
    memoryId = null,
    workspaceRoot = null,
    targetType = null,
    targetId = null,
    request = {},
    currentRecord = null,
    currentPolicy = null,
  } = {}) {
    const planRequest = {
      operation,
      operation_kind: operationKind,
      thread_id: threadId ?? null,
      agent_id: agentId ?? null,
      memory_id: memoryId ?? null,
      workspace_root: workspaceRoot ?? null,
      target_type: targetType ?? null,
      target_id: targetId ?? null,
      source: optionalString(request.source) ?? "agent_studio",
      now: nowIso(),
      request,
      current_record: currentRecord ?? {},
      current_policy: currentPolicy ?? {},
      evidence_refs: MEMORY_CONTROL_EVIDENCE_REFS,
    };
    const runner = memoryControlRunner(store, planRequest);
    const planned = runner.planRuntimeMemoryControl(planRequest);
    const commit = store.commitRuntimeMemoryState({
      schema_version: RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION,
      memory_state_kind: planned.memory_state_kind,
      state_id: planned.state_id,
      operation_kind: planned.operation_kind,
      storage_backend_ref: RUST_AGENTGRES_STORAGE_BACKEND,
      payload: planned.payload,
      receipt_refs: planned.receipt_refs,
    });
    store.memory?.load?.();
    const projection =
      planned.memory_state_kind === "policy"
        ? memoryControlPolicyProjection(store, planned)
        : memoryControlRecordsProjection(store, planned);
    return {
      schema_version: "ioi.runtime.memory-control-result.v1",
      object: "ioi.runtime_memory_control_result",
      status: "committed",
      operation: planned.operation,
      operation_kind: planned.operation_kind,
      memory_state_kind: planned.memory_state_kind,
      state_id: planned.state_id,
      memory_id: planned.memory_state_kind === "record" ? planned.state_id : null,
      thread_id: planned.thread_id ?? null,
      agent_id: planned.agent_id ?? null,
      workspace_root: planned.workspace_root ?? null,
      payload: planned.payload,
      record: planned.memory_state_kind === "record" ? planned.payload : null,
      policy: planned.memory_state_kind === "policy" ? planned.payload : null,
      projection,
      commit,
      receipt_refs: uniqueMemoryStrings([
        ...normalizeArray(planned.receipt_refs),
        ...normalizeArray(commit?.receipt_refs),
      ]),
      evidence_refs: uniqueMemoryStrings([
        ...normalizeArray(planned.evidence_refs),
        ...normalizeArray(commit?.evidence_refs),
      ]),
    };
  }

  function memoryControlRecordsProjection(store, planned = {}) {
    if (planned.thread_id) {
      return publicListMemoryForThread(store, planned.thread_id, {});
    }
    if (planned.agent_id) {
      return publicListMemoryForAgent(store, planned.agent_id, {
        thread_id: planned.thread_id ?? undefined,
      });
    }
    return publicMemoryProjectionForContext(store, {});
  }

  function memoryControlPolicyProjection(store, planned = {}) {
    if (planned.thread_id) {
      return publicMemoryPolicyForThread(store, planned.thread_id, {});
    }
    if (planned.agent_id) {
      return publicMemoryPolicyForAgent(store, planned.agent_id, {
        thread_id: planned.thread_id ?? undefined,
      });
    }
    return publicMemoryPolicyForContext(store, {});
  }

  function memoryRecordForId(store, memoryId) {
    return optionalString(memoryId) ? store.memory?.records?.get(memoryId) ?? null : null;
  }

  function uniqueMemoryStrings(values = []) {
    const output = [];
    for (const value of values) {
      const text = optionalString(value);
      if (text && !output.includes(text)) output.push(text);
    }
    return output;
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
    const agent = store.agentForThread(threadId);
    const payload = publicMemoryStatus(store, { thread_id: threadId });
    return appendThreadMemoryControlEvent(store, {
      threadId,
      agent,
      request,
      operation: "status",
      controlKind: "memory_status",
      sourceEventKind: "OperatorControl.MemoryStatus",
      eventKind: "memory.status",
      componentKind: "memory_manager",
      workflowNodeId: "runtime.memory-manager.status",
      payloadSchemaVersion: schemaVersion,
      status: "completed",
      payload,
      receiptRefs: payload.receipt_refs,
      policyDecisionRefs: payload.policy_decision_refs,
    });
  }

  function validateThreadMemory(store, threadId, request = {}, schemaVersion) {
    const agent = store.agentForThread(threadId);
    const payload = publicValidateMemory(store, { ...request, thread_id: threadId });
    return appendThreadMemoryControlEvent(store, {
      threadId,
      agent,
      request,
      operation: "validate",
      controlKind: "memory_validate",
      sourceEventKind: "OperatorControl.MemoryValidate",
      eventKind: "memory.validate",
      componentKind: "memory_manager",
      workflowNodeId: "runtime.memory-manager.validate",
      payloadSchemaVersion: schemaVersion,
      status: payload.ok === false ? "failed" : "completed",
      payload,
      receiptRefs: payload.receipt_refs,
      policyDecisionRefs: payload.policy_decision_refs,
    });
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
    const plannedControl = planMemoryControlEvent(store, {
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
      policyDecisionKind,
    });
    return appendPlannedMemoryControlEvent(store, plannedControl);
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
