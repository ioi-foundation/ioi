export function createRuntimeMemoryHelpers({
  normalizeArray,
  optionalString,
  safeId,
} = {}) {
  function subagentMemoryPolicy({ agent, threadId, parentPolicy = {}, receiver, mode }) {
    const targetId = `${threadId}:${receiver ?? "subagent"}`;
    const id = `memory_policy_subagent_${safeId(targetId)}`;
    const disabled = Boolean(parentPolicy.disabled) || mode === "none";
    const injectionEnabled = parentPolicy.injectionEnabled !== false && mode !== "none";
    const readOnly = disabled || Boolean(parentPolicy.readOnly) || mode === "read_only";
    const writeRequiresApproval =
      mode === "explicit" ? true : Boolean(parentPolicy.writeRequiresApproval);
    return {
      ...parentPolicy,
      id,
      targetType: "subagent",
      targetId,
      agentId: agent?.id ?? parentPolicy.agentId ?? null,
      threadId,
      workspace: agent?.cwd ?? parentPolicy.workspace ?? null,
      disabled,
      injectionEnabled,
      readOnly,
      writeRequiresApproval,
      source: "daemon_subagent_memory_inheritance",
      updatedAt: new Date().toISOString(),
      evidenceRefs: [
        ...new Set([
          ...normalizeArray(parentPolicy.evidenceRefs),
          "subagent_memory_inheritance",
          "memory.policy.effective.subagent",
        ]),
      ],
      effective: true,
      policyRefs: [parentPolicy.id].filter(Boolean),
    };
  }

  function memoryPolicyOverrides(options = {}) {
    const policy = {};
    for (const key of [
      "disabled",
      "injectionEnabled",
      "readOnly",
      "writeRequiresApproval",
      "retention",
      "redaction",
      "subagentInheritance",
      "scope",
    ]) {
      if (options[key] !== undefined) policy[key] = options[key];
    }
    if (options.injection_enabled !== undefined) policy.injectionEnabled = options.injection_enabled;
    if (options.read_only !== undefined) policy.readOnly = options.read_only;
    if (options.write_requires_approval !== undefined) policy.writeRequiresApproval = options.write_requires_approval;
    if (options.subagent_inheritance !== undefined) policy.subagentInheritance = options.subagent_inheritance;
    return policy;
  }

  function subagentReceiverForRequest(request = {}) {
    return optionalString(
      request.receiver ??
        request.options?.receiver ??
        request.subagent ??
        request.options?.subagent ??
        request.subagentName ??
        request.options?.subagentName,
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
      optionalString(options.memoryKey ?? options.memory_key) ??
        optionalString(options.query ?? options.q ?? options.memoryQuery ?? options.memory_query) ??
        optionalString(options.scope ?? options.memoryScope ?? options.memory_scope),
    );
  }

  function memoryWriteBlockReason(policy = {}, options = {}, requestedWrite = false) {
    if (!requestedWrite) return null;
    if (policy.disabled) return "memory_disabled";
    if (policy.readOnly) return "memory_read_only";
    if (policy.writeRequiresApproval && !memoryWriteApproved(options)) {
      return "memory_write_requires_approval";
    }
    return null;
  }

  function memoryWriteApproved(options = {}) {
    return Boolean(
      options.writeApproved ??
        options.write_approved ??
        options.approved ??
        options.approvalGranted ??
        options.approval_granted,
    );
  }

  function subagentMemoryInheritanceReceipt(runId, projection = {}) {
    return {
      id: `receipt_${runId}_subagent_memory_inheritance`,
      kind: "subagent_memory_inheritance",
      summary: `Subagent memory inheritance ${projection.mode} for ${projection.subagentName ?? "handoff"} exposed ${normalizeArray(projection.records).length} record(s).`,
      redaction: projection.effectivePolicy?.redaction === "redacted" ? "redacted" : "none",
      evidenceRefs: normalizeArray(projection.evidenceRefs),
    };
  }

  function memoryListFilters(options = {}) {
    return {
      scope: options.scope ?? options.memoryScope ?? options.memory_scope,
      memoryKey: options.memoryKey ?? options.memory_key,
      query: options.query ?? options.q ?? options.memoryQuery ?? options.memory_query,
      limit: options.limit ?? options.memoryLimit ?? options.memory_limit,
      redaction: options.redaction ?? options.memoryRedaction ?? options.memory_redaction,
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
