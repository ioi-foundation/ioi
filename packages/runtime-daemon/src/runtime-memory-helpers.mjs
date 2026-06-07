export function createRuntimeMemoryHelpers({
  normalizeArray,
  optionalString,
  safeId,
} = {}) {
  function subagentMemoryPolicy({ agent, threadId, parentPolicy = {}, receiver, mode }) {
    const canonicalParentPolicy = withoutRetiredMemoryPolicyAliases(parentPolicy);
    const targetId = `${threadId}:${receiver ?? "subagent"}`;
    const id = `memory_policy_subagent_${safeId(targetId)}`;
    const disabled = Boolean(canonicalParentPolicy.disabled) || mode === "none";
    const injectionEnabled = canonicalParentPolicy.injection_enabled !== false && mode !== "none";
    const readOnly = disabled || Boolean(canonicalParentPolicy.read_only) || mode === "read_only";
    const writeRequiresApproval =
      mode === "explicit" ? true : Boolean(canonicalParentPolicy.write_requires_approval);
    return {
      ...canonicalParentPolicy,
      id,
      target_type: "subagent",
      target_id: targetId,
      agent_id: agent?.id ?? parentPolicy.agent_id ?? null,
      thread_id: threadId,
      workspace: agent?.cwd ?? parentPolicy.workspace ?? null,
      disabled,
      injection_enabled: injectionEnabled,
      read_only: readOnly,
      write_requires_approval: writeRequiresApproval,
      source: "daemon_subagent_memory_inheritance",
      updated_at: new Date().toISOString(),
      evidence_refs: [
        ...new Set([
          ...normalizeArray(canonicalParentPolicy.evidence_refs),
          "subagent_memory_inheritance",
          "memory.policy.effective.subagent",
        ]),
      ],
      effective: true,
      policy_refs: [canonicalParentPolicy.id].filter(Boolean),
    };
  }

  function memoryPolicyOverrides(options = {}) {
    const policy = {};
    for (const key of [
      "disabled",
      "injection_enabled",
      "read_only",
      "write_requires_approval",
      "retention",
      "redaction",
      "subagent_inheritance",
      "scope",
    ]) {
      if (options[key] !== undefined) policy[key] = options[key];
    }
    return policy;
  }

  function subagentReceiverForRequest(request = {}) {
    return optionalString(
      request.receiver ??
        request.options?.receiver ??
        request.subagent ??
        request.options?.subagent,
    ) ?? null;
  }

  function normalizeSubagentInheritanceMode(value) {
    const mode = optionalString(value) ?? "explicit";
    return ["none", "explicit", "read_only", "full"].includes(mode) ? mode : "explicit";
  }

  function shouldInheritSubagentMemory(mode, options = {}) {
    if (mode === "none") return false;
    if (mode === "explicit") return hasExplicitSubagentMemorySelector(options);
    return true;
  }

  function hasExplicitSubagentMemorySelector(options = {}) {
    return Boolean(
      optionalString(options.memory_key) ??
        optionalString(options.query) ??
        optionalString(options.scope),
    );
  }

  function memoryWriteBlockReason(policy = {}, options = {}, requestedWrite = false) {
    if (!requestedWrite) return null;
    if (policy.disabled) return "memory_disabled";
    if (policy.read_only) return "memory_read_only";
    if (policy.write_requires_approval && !memoryWriteApproved(options)) {
      return "memory_write_requires_approval";
    }
    return null;
  }

  function memoryWriteApproved(options = {}) {
    return Boolean(options.write_approved);
  }

  function withoutRetiredMemoryPolicyAliases(policy = {}) {
    const {
      targetType,
      targetId,
      agentId,
      threadId,
      injectionEnabled,
      readOnly,
      writeRequiresApproval,
      subagentInheritance,
      updatedAt,
      createdAt,
      evidenceRefs,
      policyRefs,
      ...canonicalPolicy
    } = policy;
    return canonicalPolicy;
  }

  function subagentMemoryInheritanceReceipt(runId, projection = {}) {
    return {
      id: `receipt_${runId}_subagent_memory_inheritance`,
      kind: "subagent_memory_inheritance",
      summary: `Subagent memory inheritance ${projection.mode} for ${projection.subagent_name ?? "handoff"} exposed ${normalizeArray(projection.records).length} record(s).`,
      redaction: projection.effective_policy?.redaction === "redacted" ? "redacted" : "none",
      evidenceRefs: normalizeArray(projection.evidence_refs),
    };
  }

  function memoryListFilters(options = {}) {
    return {
      scope: options.scope,
      memory_key: options.memory_key,
      query: options.query,
      limit: options.limit,
      redaction: options.redaction,
    };
  }

  function memoryEventKind(operation = "write") {
    switch (operation) {
      case "policy_update":
        return "MemoryPolicy";
      case "edit":
        return "MemoryEdit";
      case "delete":
        return "MemoryDelete";
      case "write":
      default:
        return "MemoryWrite";
    }
  }

  function memoryControlKind(operation = "write") {
    switch (operation) {
      case "policy_update":
        return "memory_policy";
      case "edit":
        return "memory_edit";
      case "delete":
        return "memory_delete";
      case "write":
      default:
        return "memory_write";
    }
  }

  function memoryOperatorControlKind(operation = "write") {
    switch (operation) {
      case "policy_update":
        return "OperatorControl.MemoryPolicy";
      case "edit":
        return "OperatorControl.MemoryEdit";
      case "delete":
        return "OperatorControl.MemoryDelete";
      case "write":
      default:
        return "OperatorControl.MemoryWrite";
    }
  }

  function memoryRuntimeEventKind(operation = "write") {
    switch (operation) {
      case "policy_update":
        return "memory.policy";
      case "edit":
        return "memory.edit";
      case "delete":
        return "memory.delete";
      case "write":
      default:
        return "memory.write";
    }
  }

  function memoryWorkflowNodeId(operation = "write") {
    switch (operation) {
      case "policy_update":
        return "runtime.memory-manager.policy";
      case "edit":
        return "runtime.memory.edit";
      case "delete":
        return "runtime.memory.delete";
      case "write":
      default:
        return "runtime.memory.write";
    }
  }

  function memoryMutationRowLabel(operation = "write") {
    switch (operation) {
      case "edit":
        return "Memory edit";
      case "delete":
        return "Memory delete";
      case "policy_update":
        return "Memory policy";
      case "write":
      default:
        return "Memory write";
    }
  }

  function memoryMutationRawInput(operation = "write") {
    switch (operation) {
      case "edit":
        return "/memory edit";
      case "delete":
        return "/memory delete";
      case "policy_update":
        return "/memory policy";
      case "write":
      default:
        return "/memory remember";
    }
  }

  function memoryMutationSummary(operation = "write", { record, policy } = {}) {
    switch (operation) {
      case "policy_update":
        return `Memory policy ${policy?.id ?? "thread"} updated.`;
      case "edit":
        return `Memory record ${record?.id ?? "unknown"} edited.`;
      case "delete":
        return `Memory record ${record?.id ?? "unknown"} deleted.`;
      case "write":
      default:
        return `Memory record ${record?.id ?? "unknown"} remembered.`;
    }
  }

  function memoryEventSummary(operation = "write") {
    switch (operation) {
      case "policy_update":
        return "Memory policy updated";
      case "edit":
        return "Memory record edited";
      case "delete":
        return "Memory record deleted";
      case "write":
      default:
        return "Memory write recorded";
    }
  }

  return {
    memoryControlKind,
    memoryEventKind,
    memoryEventSummary,
    hasExplicitSubagentMemorySelector,
    memoryListFilters,
    memoryMutationRawInput,
    memoryMutationRowLabel,
    memoryMutationSummary,
    memoryOperatorControlKind,
    memoryPolicyOverrides,
    memoryRuntimeEventKind,
    memoryWorkflowNodeId,
    memoryWriteApproved,
    memoryWriteBlockReason,
    normalizeSubagentInheritanceMode,
    shouldInheritSubagentMemory,
    subagentReceiverForRequest,
    subagentMemoryInheritanceReceipt,
    subagentMemoryPolicy,
  };
}
