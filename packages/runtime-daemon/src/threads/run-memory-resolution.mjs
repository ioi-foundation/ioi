export function createRunMemoryResolution({
  memoryListFilters,
  memoryOptionsForRequest,
  memoryPolicyOverrides,
  memoryWriteBlockReason,
  normalizeSubagentInheritanceMode,
  optionalString,
  runtimeMemoryCommandPlanner,
  shouldInheritSubagentMemory,
  subagentMemoryPolicy,
  subagentReceiverForRequest,
  threadIdForAgent,
} = {}) {
  function throwRunMemoryRustCoreRequired({ operation, threadId = null, agentId = null, memoryId = null } = {}) {
    const error = new Error(
      "Run memory resolution requires direct Rust daemon-core memory projection, admission, and persistence.",
    );
    error.status = 501;
    error.code = "runtime_run_memory_mutation_rust_core_required";
    error.details = {
      rust_core_boundary: "runtime.thread_memory_control",
      operation,
      operation_kind: "memory.run_resolution",
      thread_id: threadId,
      agent_id: agentId,
      ...(memoryId ? { memory_id: memoryId } : {}),
      evidence_refs: [
        "runtime_run_memory_projection_js_cache_retired",
        "runtime_run_memory_resolution_js_mutation_retired",
        "runtime_run_memory_command_store_core_fallback_retired",
        "runtime_memory_state_store_js_mutation_retired",
        "rust_daemon_core_thread_memory_control_required",
        "agentgres_thread_memory_state_truth_required",
      ],
    };
    throw error;
  }

  function runMemoryApi(store, { operation, threadId = null, agentId = null, memoryId = null } = {}) {
    if (
      store?.publicListMemoryForThread &&
      store?.publicMemoryPathForThread &&
      store?.publicMemoryPolicyForThread &&
      store?.rememberForAgent &&
      store?.updateMemoryForThread &&
      store?.deleteMemoryForThread &&
      store?.setMemoryPolicyForThread
    ) {
      return store;
    }
    throwRunMemoryRustCoreRequired({ operation, threadId, agentId, memoryId });
  }

  function resolveRunMemory(store, agent, request = {}, prompt = "") {
    const memoryOptions = memoryOptionsForRequest(request);
    const threadId = memoryOptions.thread_id ?? threadIdForAgent(agent.id);
    const command = planRunMemoryCommand(agent, threadId, prompt);
    const memoryApi = runMemoryApi(store, {
      operation: "memory_projection",
      threadId,
      agentId: agent?.id ?? null,
    });
    const paths = memoryApi.publicMemoryPathForThread(threadId, {});
    let policy = {
      ...objectRecord(memoryApi.publicMemoryPolicyForThread(threadId, {})),
      ...memoryPolicyOverrides(memoryOptions),
    };
    const policyUpdates = [];
    const mutations = [];
    if (command.kind === "disable" || command.kind === "enable") {
      const policyMutation = commitRunMemoryPolicy(memoryApi, agent, threadId, command);
      mutations.push(policyMutation);
      policyUpdates.push(policyMutation);
      policy = {
        ...policy,
        ...objectRecord(policyMutation.policy),
      };
    }
    const subagentMemoryInheritance =
      (request.mode ?? "send") === "handoff"
        ? store.resolveSubagentMemoryInheritance({ agent, threadId, request, parentPolicy: policy })
        : null;
    const effectivePolicy = subagentMemoryInheritance?.effective_policy ?? policy;
    const requestedRemember =
      memoryOptions.remember ??
      request.remember ??
      null;
    const requestedWrite =
      command.kind === "remember" ||
      command.kind === "edit" ||
      command.kind === "delete" ||
      Boolean(requestedRemember);
    const policyBlockReason = memoryWriteBlockReason(effectivePolicy, memoryOptions, requestedWrite);
    if (subagentMemoryInheritance) {
      subagentMemoryInheritance.write_block_reason = policyBlockReason;
      subagentMemoryInheritance.write_allowed = requestedWrite
        ? policyBlockReason === null
        : !effectivePolicy.disabled && !effectivePolicy.read_only && !effectivePolicy.write_requires_approval;
    }
    if (effectivePolicy.disabled || effectivePolicy.injection_enabled === false) {
      return {
        command: command.kind,
        records: [],
        writes: mutations.filter((mutation) => mutation.receipt?.kind === "memory_write"),
        mutations,
        policy: effectivePolicy,
        policyUpdates,
        paths,
        injected: false,
        disabled: Boolean(effectivePolicy.disabled),
        policyBlockReason,
        subagentMemoryInheritance,
      };
    }
    const writes = [];
    if (!policyBlockReason && command.kind === "remember") {
      const write = commitRunMemoryWrite(memoryApi, agent, threadId, command.text, memoryOptions);
      writes.push(write);
      mutations.push(write);
    } else if (!policyBlockReason && command.kind === "edit") {
      mutations.push(commitRunMemoryEdit(memoryApi, threadId, command, memoryOptions));
    } else if (!policyBlockReason && command.kind === "delete") {
      mutations.push(commitRunMemoryDelete(memoryApi, threadId, command, memoryOptions));
    } else if (!policyBlockReason && requestedRemember) {
      const write = commitRunMemoryWrite(memoryApi, agent, threadId, requestedRemember, memoryOptions);
      writes.push(write);
      mutations.push(write);
    }
    const records = subagentMemoryInheritance?.records ??
      recordsFromProjection(memoryApi.publicListMemoryForThread(threadId, memoryOptions));
    return {
      command: command.kind,
      records,
      writes,
      mutations,
      policy: effectivePolicy,
      policyUpdates,
      paths,
      injected: command.kind !== "remember" && records.length > 0,
      policyBlockReason,
      subagentMemoryInheritance,
    };
  }

  function resolveSubagentMemoryInheritance(store, { agent, threadId, request = {}, parentPolicy = {} } = {}) {
    const memoryOptions = memoryOptionsForRequest(request);
    const requestedMode =
      optionalString(memoryOptions.subagent_inheritance) ??
      parentPolicy.subagent_inheritance ??
      "explicit";
    const mode = normalizeSubagentInheritanceMode(requestedMode);
    const receiver = subagentReceiverForRequest(request);
    const filters = memoryListFilters(memoryOptions);
    const parentAllowsInjection = !parentPolicy.disabled && parentPolicy.injection_enabled !== false;
    const records = parentAllowsInjection && shouldInheritSubagentMemory(mode, memoryOptions)
      ? recordsFromProjection(runMemoryApi(store, {
          operation: "memory_projection",
          threadId,
          agentId: agent?.id ?? null,
        }).publicListMemoryForThread(threadId, {
          ...memoryOptions,
          redaction: memoryOptions.redaction ?? parentPolicy.redaction,
        }))
      : [];
    const effectivePolicy = subagentMemoryPolicy({ agent, threadId, parentPolicy, receiver, mode });
    return {
      schema_version: "ioi.agent-runtime.subagent-memory-inheritance.v1",
      object: "ioi.subagent_memory_inheritance",
      parent_agent_id: agent.id,
      subagent_name: receiver,
      thread_id: threadId,
      mode,
      requested_mode: requestedMode,
      parent_policy_id: parentPolicy.id ?? null,
      effective_policy_id: effectivePolicy.id,
      parent_policy: parentPolicy,
      effective_policy: effectivePolicy,
      filters,
      records,
      inherited_record_ids: records.map((record) => record.id),
      write_allowed: !effectivePolicy.disabled && !effectivePolicy.read_only && !effectivePolicy.write_requires_approval,
      write_block_reason: null,
      evidence_refs: [
        "subagent_memory_inheritance",
        "agent_memory_store",
        parentPolicy.id,
        effectivePolicy.id,
        ...records.map((record) => record.id),
      ].filter(Boolean),
    };
  }

  return {
    resolveRunMemory,
    resolveSubagentMemoryInheritance,
  };

  function planRunMemoryCommand(agent, threadId, prompt = "") {
    const plan = runtimeMemoryCommandPlanner?.planRuntimeMemoryCommand?.({
      operation: "runtime_memory_command_plan",
      operation_kind: "memory.run_command.plan",
      prompt,
      thread_id: threadId,
      agent_id: agent?.id ?? null,
      source: "runtime_run_memory_resolution",
    });
    const command = objectRecord(plan?.command);
    const kind = optionalString(plan?.command_kind ?? command?.kind);
    if (!command || !kind) {
      throwRunMemoryRustCoreRequired({
        operation: "memory_command_plan",
        threadId,
        agentId: agent?.id ?? null,
      });
    }
    return {
      ...command,
      kind,
    };
  }

  function commitRunMemoryWrite(memoryApi, agent, threadId, text, memoryOptions = {}) {
    return runMemoryMutationFromResult(
      "memory_write",
      memoryApi.rememberForAgent(agent, {
        text,
        threadId,
        scope: optionalString(memoryOptions.scope) ?? "thread",
        source: "runtime_run_memory_resolution",
        workflow: runMemoryControlRequest(memoryOptions),
      }),
    );
  }

  function commitRunMemoryEdit(memoryApi, threadId, command = {}, memoryOptions = {}) {
    return runMemoryMutationFromResult(
      "memory_edit",
      memoryApi.updateMemoryForThread(threadId, command.id, {
        ...runMemoryControlRequest(memoryOptions),
        text: command.text,
        source: "runtime_run_memory_resolution",
      }),
    );
  }

  function commitRunMemoryDelete(memoryApi, threadId, command = {}, memoryOptions = {}) {
    return runMemoryMutationFromResult(
      "memory_delete",
      memoryApi.deleteMemoryForThread(threadId, command.id, {
        ...runMemoryControlRequest(memoryOptions),
        source: "runtime_run_memory_resolution",
        reason: "runtime_run_memory_resolution_delete",
      }),
    );
  }

  function commitRunMemoryPolicy(memoryApi, agent, threadId, command = {}) {
    const disabled = command.kind === "disable";
    return runMemoryMutationFromResult(
      disabled ? "memory_disable" : "memory_enable",
      memoryApi.setMemoryPolicyForThread(threadId, {
        source: "runtime_run_memory_resolution",
        policy: {
          disabled,
          injection_enabled: !disabled,
        },
        reason: disabled
          ? "runtime_run_memory_resolution_disable"
          : "runtime_run_memory_resolution_enable",
        agent_id: agent?.id ?? null,
      }),
    );
  }

  function runMemoryControlRequest(memoryOptions = {}) {
    const request = {};
    for (const key of [
      "memory_key",
      "workflow_graph_id",
      "workflow_node_id",
      "turn_id",
      "idempotency_key",
    ]) {
      const value = optionalString(memoryOptions[key]);
      if (value) request[key] = value;
    }
    return request;
  }

  function runMemoryMutationFromResult(operation, result = {}) {
    const receiptRefs = stringArray(result.receipt_refs);
    const receipt = receiptRefs.length > 0
      ? {
          id: receiptRefs[0],
          receipt_ref: receiptRefs[0],
          receipt_refs: receiptRefs,
          kind: operation === "memory_disable" || operation === "memory_enable"
            ? "memory_policy"
            : operation,
          operation_kind: result.operation_kind ?? null,
          source: "rust_runtime_memory_control",
        }
      : null;
    return {
      operation,
      operation_kind: result.operation_kind ?? null,
      memory_state_kind: result.memory_state_kind ?? null,
      state_id: result.state_id ?? null,
      memory_id: result.memory_id ?? result.record?.id ?? null,
      record: objectRecord(result.record),
      policy: objectRecord(result.policy),
      receipt,
      result,
      commit: objectRecord(result.commit),
      receipt_refs: receiptRefs,
      evidence_refs: stringArray(result.evidence_refs),
    };
  }

  function recordsFromProjection(projection) {
    if (Array.isArray(projection)) return projection;
    return Array.isArray(projection?.records) ? projection.records : [];
  }

  function stringArray(values) {
    return Array.isArray(values) ? values.map((value) => String(value)).filter(Boolean) : [];
  }

  function objectRecord(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  }
}
