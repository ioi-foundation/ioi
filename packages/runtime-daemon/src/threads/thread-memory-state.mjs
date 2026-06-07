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
} = {}) {
  const memoryRuntimeError = runtimeError ?? (({ status = 500, code = "thread_memory_state_error", message, details }) =>
    Object.assign(new Error(message), { status, code, details }));

  function rememberForAgent(store, agent, { text, threadId = threadIdForAgent(agent.id), scope = "thread", source = "operator_remember", workflow = {} } = {}) {
    return store.memory.remember({
      text,
      agent,
      threadId,
      scope,
      source,
      workflow,
    });
  }

  function rememberForThread(store, threadId, body = {}) {
    const agent = store.agentForThread(threadId);
    const policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory write blocked by policy.", { threadId, reason: blocked, policy });
    }
    const mutation = store.rememberForAgent(agent, {
      text: body.text ?? body.fact ?? body.memory,
      threadId,
      scope: body.scope ?? "thread",
      source: body.source ?? "thread_memory_api",
      workflow: body.workflow ?? body,
    });
    return store.recordThreadMemoryMutation(threadId, mutation, body, "write");
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
    const mutation = store.memory.setPolicy({
      target_type: "thread",
      target_id: threadId,
      agent,
      thread_id: threadId,
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

  function updateMemoryForThread(store, threadId, memoryId, body = {}) {
    const agent = store.agentForThread(threadId);
    const policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory edit blocked by policy.", { threadId, memoryId, reason: blocked, policy });
    }
    const mutation = store.updateMemoryRecord(memoryId, body);
    return store.recordThreadMemoryMutation(threadId, mutation, body, "edit");
  }

  function deleteMemoryForThread(store, threadId, memoryId, body = {}) {
    const agent = store.agentForThread(threadId);
    const policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory delete blocked by policy.", { threadId, memoryId, reason: blocked, policy });
    }
    const mutation = store.deleteMemoryRecord(memoryId, body);
    return store.recordThreadMemoryMutation(threadId, mutation, body, "delete");
  }

  function rememberForAgentId(store, agentId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = body.thread_id ?? threadIdForAgent(agent.id);
    const policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory write blocked by policy.", { agentId, threadId, reason: blocked, policy });
    }
    return store.rememberForAgent(agent, {
      text: body.text ?? body.fact ?? body.memory,
      threadId,
      scope: body.scope ?? "thread",
      source: body.source ?? "agent_memory_api",
      workflow: body.workflow ?? body,
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
    const threadId = body.thread_id ?? threadIdForAgent(agent.id);
    return store.memory.setPolicy({
      target_type: body.target_type ?? "thread",
      target_id: body.target_id ?? threadId,
      agent,
      thread_id: threadId,
      workspace: agent.cwd,
      source: body.source ?? "agent_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
  }

  function memoryPathForAgent(store, agentId, options = {}) {
    const agent = store.getAgent(agentId);
    const threadId = options.thread_id ?? threadIdForAgent(agent.id);
    return store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  function updateMemoryForAgentId(store, agentId, memoryId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = body.thread_id ?? threadIdForAgent(agent.id);
    const policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory edit blocked by policy.", { agentId, threadId, memoryId, reason: blocked, policy });
    }
    return store.updateMemoryRecord(memoryId, body);
  }

  function deleteMemoryForAgentId(store, agentId, memoryId, body = {}) {
    const agent = store.getAgent(agentId);
    const threadId = body.thread_id ?? threadIdForAgent(agent.id);
    const policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory delete blocked by policy.", { agentId, threadId, memoryId, reason: blocked, policy });
    }
    return store.deleteMemoryRecord(memoryId, body);
  }

  function updateMemoryRecord(store, memoryId, body = {}) {
    return store.memory.updateRecord({
      id: memoryId,
      text: body.text ?? body.fact ?? body.memory,
      source: body.source ?? "memory_edit_api",
    });
  }

  function deleteMemoryRecord(store, memoryId, body = {}) {
    return store.memory.deleteRecord({
      id: memoryId,
      source: body.source ?? "memory_delete_api",
    });
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
      agent_id: projection.agentId ?? null,
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
      agent_id: projection.agentId ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  function recordThreadMemoryStatus(store, threadId, request = {}, schemaVersion) {
    const agent = store.agentForThread(threadId);
    const status = store.memoryStatus({ ...request, thread_id: threadId });
    return store.appendThreadMemoryControlEvent({
      threadId,
      agent,
      request,
      controlKind: "memory_status",
      sourceEventKind: "OperatorControl.Memory",
      eventKind: "memory.status",
      componentKind: "memory_policy",
      workflowNodeId: "runtime.memory-manager",
      payloadSchemaVersion: schemaVersion,
      status: status.status === "needs_review" ? "blocked" : "completed",
      payload: {
        ...status,
        event_kind: "MemoryStatus",
        control_kind: "memory_status",
        thread_id: threadId,
        agent_id: agent.id,
        rows: memoryRowsForStatus(status),
        summary: `Memory has ${status.record_count} record(s); policy ${status.policy?.id ?? "default"} is ${status.status}.`,
      },
    });
  }

  function validateThreadMemory(store, threadId, request = {}, schemaVersion) {
    const agent = store.agentForThread(threadId);
    const validation = store.validateMemory({ ...request, thread_id: threadId });
    return store.appendThreadMemoryControlEvent({
      threadId,
      agent,
      request,
      controlKind: "memory_validate",
      sourceEventKind: "OperatorControl.MemoryValidate",
      eventKind: "memory.validation",
      componentKind: "memory_policy",
      workflowNodeId: "runtime.memory-manager.validate",
      payloadSchemaVersion: schemaVersion,
      status: validation.ok ? "completed" : "blocked",
      payload: {
        ...validation,
        event_kind: "MemoryValidationReport",
        control_kind: "memory_validate",
        thread_id: threadId,
        agent_id: agent.id,
        summary: validation.ok
          ? `Memory validation passed for ${validation.record_count} record(s).`
          : `Memory validation found ${validation.issue_count} issue(s).`,
      },
    });
  }

  function recordThreadMemoryMutation(store, threadId, mutation = {}, request = {}, operation = "write", schemaVersion) {
    const agent = store.agentForThread(threadId);
    const status = store.memoryStatus({ ...request, thread_id: threadId });
    const record = mutation.record ?? null;
    const policy = mutation.policy ?? status.policy ?? null;
    const receipt = mutation.receipt ?? null;
    const receiptRefs = receipt?.id ? [receipt.id] : [];
    const memoryRecordId = record?.id ?? null;
    const memoryPolicyId = policy?.id ?? null;
    const controlKind = memoryControlKind(operation);
    const payloadRecordList = record ? [record] : status.records;
    const mutationRows = memoryRowsForStatus({
      ...status,
      records: payloadRecordList,
      receipt_refs: receiptRefs,
    }).map((row) =>
      row.row_kind === "memory_record" && (!memoryRecordId || row.memory_record_id === memoryRecordId)
        ? {
            ...row,
            label: memoryMutationRowLabel(operation),
            raw_input: memoryMutationRawInput(operation),
            memory_operation: operation,
            workflow_node_id: record?.workflow_node_id ?? memoryWorkflowNodeId(operation),
          }
        : row,
    );
    const payload = {
      ...status,
      schema_version: schemaVersion,
      object: "ioi.runtime_memory_manager_mutation",
      event_kind: memoryEventKind(operation),
      control_kind: controlKind,
      memory_operation: operation,
      mutation_status: "completed",
      thread_id: threadId,
      agent_id: agent.id,
      record,
      records: payloadRecordList,
      policy,
      receipt,
      memory_record_id: memoryRecordId,
      memory_policy_id: memoryPolicyId,
      receipt_refs: receiptRefs,
      rows: mutationRows,
      memory_rows: mutationRows,
      summary: memoryMutationSummary(operation, { record, policy }),
    };
    const result = store.appendThreadMemoryControlEvent({
      threadId,
      agent,
      request,
      controlKind,
      sourceEventKind: memoryOperatorControlKind(operation),
      eventKind: memoryRuntimeEventKind(operation),
      componentKind: operation === "policy_update" ? "memory_policy" : "memory_write",
      workflowNodeId: memoryWorkflowNodeId(operation),
      payloadSchemaVersion: schemaVersion,
      status: "completed",
      payload,
      receiptRefs,
      policyDecisionKind: operation,
    });
    return {
      ...result,
      record,
      policy,
      receipt,
      operation,
    };
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
    const thread = store.threadForAgent(agent);
    const turnId =
      optionalString(request.turn_id) ??
      optionalString(thread.latest_turn_id) ??
      "";
    const source = operatorControlSource(request.source);
    const graphId = optionalString(request.workflow_graph_id) ?? null;
    const nodeId =
      optionalString(request.workflow_node_id) ??
      workflowNodeId;
    const eventHash = doctorHash(`${threadId}:${controlKind}:${JSON.stringify(payload)}:${Date.now()}`).slice(0, 12);
    const resolvedReceiptRefs = normalizeArray(receiptRefs).length
      ? normalizeArray(receiptRefs)
      : [`receipt_memory_${safeId(controlKind)}_${eventHash}`];
    const resolvedPolicyDecisionRefs = normalizeArray(policyDecisionRefs).length
      ? normalizeArray(policyDecisionRefs)
      : [`policy_memory_${safeId(controlKind)}_${safeId(policyDecisionKind)}_${eventHash}`];
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:memory:${safeId(controlKind)}:${eventHash}`,
      idempotency_key:
        optionalString(request.idempotency_key) ??
        `thread:${threadId}:memory:${controlKind}:${eventHash}`,
      source,
      source_event_kind: sourceEventKind,
      event_kind: eventKind,
      status,
      actor: "operator",
      workspace_root: agent.cwd,
      workflow_graph_id: graphId,
      workflow_node_id: nodeId,
      component_kind: componentKind,
      payload_schema_version: payloadSchemaVersion,
      payload_summary: payload,
      receipt_refs: resolvedReceiptRefs,
      policy_decision_refs: resolvedPolicyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const result = {
      ...payload,
      event,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
    const contextPolicyRunner = store.contextPolicyRunner;
    if (typeof contextPolicyRunner?.planThreadMemoryAgentStateUpdate !== "function") {
      throw memoryRuntimeError({
        status: 500,
        code: "thread_memory_state_update_planner_unavailable",
        message: "Thread memory updates require Rust policy state-update planning.",
        details: { thread_id: threadId, control_kind: controlKind },
      });
    }
    const stateUpdate = contextPolicyRunner.planThreadMemoryAgentStateUpdate({
      thread_id: threadId,
      agent,
      control_kind: controlKind,
      event_id: event.event_id,
      seq: event.seq,
      created_at: event.created_at,
    });
    const updatedAgent = stateUpdate.agent;
    if (!updatedAgent?.id) {
      throw memoryRuntimeError({
        status: 502,
        code: "thread_memory_state_update_planner_invalid",
        message: "Rust thread-memory state planning did not return an agent record.",
        details: { thread_id: threadId, control_kind: controlKind },
      });
    }
    const operationKind = requiredThreadMemoryOperationKind(stateUpdate, threadId, controlKind);
    store.agents.set(updatedAgent.id, updatedAgent);
    store.writeAgent(updatedAgent, operationKind);
    return result;
  }

  function requiredThreadMemoryOperationKind(stateUpdate, threadId, controlKind) {
    const expectedOperationKind = `thread.${controlKind}`;
    const operationKind = optionalString(stateUpdate.operation_kind);
    if (!operationKind) {
      throw memoryRuntimeError({
        status: 502,
        code: "thread_memory_state_update_operation_kind_missing",
        message: "Rust thread-memory state planning did not return an operation kind.",
        details: {
          thread_id: threadId,
          control_kind: controlKind,
          operation_kind: expectedOperationKind,
        },
      });
    }
    if (operationKind !== expectedOperationKind) {
      throw memoryRuntimeError({
        status: 502,
        code: "thread_memory_state_update_operation_kind_mismatch",
        message: "Rust thread-memory state planning returned an unexpected operation kind.",
        details: {
          thread_id: threadId,
          control_kind: controlKind,
          expected_operation_kind: expectedOperationKind,
          operation_kind: operationKind,
        },
      });
    }
    return operationKind;
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
