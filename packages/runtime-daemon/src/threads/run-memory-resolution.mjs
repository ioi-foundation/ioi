export function createRunMemoryResolution({
  memoryListFilters,
  memoryOptionsForRequest,
  memoryPolicyOverrides,
  memoryWriteBlockReason,
  normalizeSubagentInheritanceMode,
  optionalString,
  parseMemoryCommand,
  shouldInheritSubagentMemory,
  subagentMemoryPolicy,
  subagentReceiverForRequest,
  threadIdForAgent,
} = {}) {
  function throwRunMemoryRustCoreRequired({ operation, threadId = null, agentId = null, memoryId = null } = {}) {
    const error = new Error(
      "Run memory mutations require direct Rust daemon-core memory admission and persistence.",
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
        "runtime_run_memory_resolution_js_mutation_retired",
        "runtime_memory_state_store_js_mutation_retired",
        "rust_daemon_core_thread_memory_control_required",
        "agentgres_thread_memory_state_truth_required",
      ],
    };
    throw error;
  }

  function resolveRunMemory(store, agent, request = {}, prompt = "") {
    const memoryOptions = memoryOptionsForRequest(request);
    const threadId = memoryOptions.thread_id ?? threadIdForAgent(agent.id);
    const command = parseMemoryCommand(prompt);
    const paths = store.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
    let policy = store.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(memoryOptions),
    });
    const policyUpdates = [];
    const mutations = [];
    if (command.kind === "disable" || command.kind === "enable") {
      throwRunMemoryRustCoreRequired({
        operation: command.kind === "disable" ? "memory_disable" : "memory_enable",
        threadId,
        agentId: agent?.id ?? null,
      });
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
      throwRunMemoryRustCoreRequired({
        operation: "memory_write",
        threadId,
        agentId: agent?.id ?? null,
      });
    } else if (!policyBlockReason && command.kind === "edit") {
      throwRunMemoryRustCoreRequired({
        operation: "memory_edit",
        threadId,
        agentId: agent?.id ?? null,
        memoryId: command.id,
      });
    } else if (!policyBlockReason && command.kind === "delete") {
      throwRunMemoryRustCoreRequired({
        operation: "memory_delete",
        threadId,
        agentId: agent?.id ?? null,
        memoryId: command.id,
      });
    } else if (!policyBlockReason && requestedRemember) {
      throwRunMemoryRustCoreRequired({
        operation: "memory_write",
        threadId,
        agentId: agent?.id ?? null,
      });
    }
    const records = subagentMemoryInheritance?.records ??
      store.memory.list({ agent, threadId, workspace: agent.cwd, ...memoryListFilters(memoryOptions) });
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
      ? store.memory.list({
          agent,
          threadId,
          workspace: agent.cwd,
          ...memoryListFilters({
            ...memoryOptions,
            redaction: memoryOptions.redaction ?? parentPolicy.redaction,
          }),
        })
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
}
