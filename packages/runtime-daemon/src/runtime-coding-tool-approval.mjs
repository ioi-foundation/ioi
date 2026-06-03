function defaultOptionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function defaultNormalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function camelCaseKey(key) {
  return String(key).replace(/_([a-z])/g, (_, char) => char.toUpperCase());
}

export function createCodingToolApprovalPolicy(deps = {}) {
  const approvalModeForThreadMode = deps.approvalModeForThreadMode || (() => "suggest");
  const codingToolInputSummary = deps.codingToolInputSummary || (() => ({}));
  const doctorHash = deps.doctorHash || ((value) => String(value ?? ""));
  const normalizeArray = deps.normalizeArray || defaultNormalizeArray;
  const normalizeThreadApprovalMode = deps.normalizeThreadApprovalMode || ((value, fallback) => value || fallback);
  const normalizeThreadInteractionMode = deps.normalizeThreadInteractionMode || ((value) => String(value || "agent"));
  const normalizedAgentRuntimeControls = deps.normalizedAgentRuntimeControls || ((agent = {}) => agent.runtimeControls || {});
  const optionalString = deps.optionalString || defaultOptionalString;
  const uniqueStrings = deps.uniqueStrings || ((values = []) => [...new Set(normalizeArray(values).filter(Boolean))]);

  function codingToolEffectRequiresApproval(effectClass) {
    const normalized = optionalString(effectClass)?.toLowerCase() ?? "unknown";
    return normalized !== "local_read";
  }

  function codingToolWorkflowApprovalPolicy(request = {}) {
    const codingPack =
      request.toolPack && typeof request.toolPack === "object" && !Array.isArray(request.toolPack)
        ? request.toolPack.coding && typeof request.toolPack.coding === "object" && !Array.isArray(request.toolPack.coding)
          ? request.toolPack.coding
          : request.toolPack
        : {};
    const nodeApprovalOverride =
      optionalString(
        request.node_approval_override ??
          request.nodeApprovalOverride ??
          request.approval_override ??
          request.approvalOverride ??
          codingPack.nodeApprovalOverride ??
          codingPack.node_approval_override,
      ) ?? "inherit";
    const approvalMode =
      optionalString(codingPack.approvalMode ?? codingPack.approval_mode) ??
      optionalString(request.approvalMode ?? request.approval_mode) ??
      null;
    const trustProfile =
      optionalString(
        request.trust_profile ??
          request.trustProfile ??
          codingPack.trustProfile ??
          codingPack.trust_profile,
      ) ?? "local_private";
    const explicitRequiresApproval =
      request.requires_approval ??
      request.requiresApproval ??
      codingPack.requires_approval ??
      codingPack.requiresApproval;
    const requestRequiresApproval = Boolean(explicitRequiresApproval);
    const nodeRequiresApproval = nodeApprovalOverride === "require_approval";
    const approvalModeRequiresApproval =
      approvalMode === "human_required" || approvalMode === "policy_required";
    const requiresApproval =
      requestRequiresApproval || nodeRequiresApproval || approvalModeRequiresApproval;
    const trustRequiresApproval = ["untrusted", "restricted", "review_required"].includes(
      trustProfile.toLowerCase(),
    );
    const reason = requestRequiresApproval || nodeRequiresApproval
      ? "workflow_node_requires_approval"
      : approvalModeRequiresApproval
        ? "workflow_approval_mode_requires_approval"
        : trustRequiresApproval
          ? "workflow_trust_profile_requires_approval"
          : "workflow_approval_mode_requires_approval";
    return {
      schema_version: "ioi.runtime.workflow-tool-approval-policy.v1",
      schemaVersion: "ioi.runtime.workflow-tool-approval-policy.v1",
      source: "react_flow",
      requires_approval: requiresApproval || trustRequiresApproval,
      requiresApproval: requiresApproval || trustRequiresApproval,
      node_approval_override: nodeApprovalOverride,
      nodeApprovalOverride,
      approval_mode: approvalMode,
      approvalMode,
      trust_profile: trustProfile,
      trustProfile,
      reason,
    };
  }

  function codingToolApprovalManifestForThread({
    agent,
    threadId,
    turnId,
    toolId,
    toolCallId,
    toolContract,
    input,
    request,
    workflowGraphId,
    workflowNodeId,
  }) {
    const effectClass = optionalString(toolContract?.effectClass) ?? "unknown";
    if (!codingToolEffectRequiresApproval(effectClass)) return null;
    const controls = normalizedAgentRuntimeControls(agent);
    const workflowPolicy = codingToolWorkflowApprovalPolicy(request);
    const threadMode = normalizeThreadInteractionMode(controls.mode ?? agent.mode ?? "agent");
    const approvalMode = normalizeThreadApprovalMode(controls.approvalMode, approvalModeForThreadMode(threadMode));
    const modeRequiresApproval = threadMode === "plan" || threadMode === "review";
    const approvalModeRequiresApproval = approvalMode === "human_required" || approvalMode === "policy_required";
    const requestedApprovalMode =
      optionalString(request.approval_mode ?? request.approvalMode ?? workflowPolicy.approvalMode) ?? null;
    const workflowApprovalModeRequiresApproval =
      requestedApprovalMode === "human_required" || requestedApprovalMode === "policy_required";
    if (
      !modeRequiresApproval &&
      !approvalModeRequiresApproval &&
      !workflowPolicy.requiresApproval &&
      !workflowApprovalModeRequiresApproval
    ) {
      return null;
    }
    const requestedMode = optionalString(request.mode ?? request.threadMode ?? request.thread_mode) ?? null;
    let normalizedRequestedMode = null;
    if (requestedMode) {
      try {
        normalizedRequestedMode = normalizeThreadInteractionMode(requestedMode);
      } catch {
        normalizedRequestedMode = requestedMode.toLowerCase().replace(/-/g, "_");
      }
    }
    const policyReason = modeRequiresApproval
      ? threadMode === "review"
        ? "thread_review_mode_requires_approval"
        : "thread_plan_mode_requires_approval"
      : approvalModeRequiresApproval
        ? `approval_mode_${approvalMode}_requires_approval`
        : workflowPolicy.reason;
    const scopeRequirements = uniqueStrings(
      normalizeArray(toolContract?.authorityScopeRequirements ?? toolContract?.authority_scope_requirements),
    );
    const inputHash = doctorHash(JSON.stringify(input ?? {}));
    return {
      schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
      schemaVersion: "ioi.runtime.coding-tool-approval-manifest.v1",
      object: "ioi.runtime_coding_tool_approval_manifest",
      action: "coding_tool.invoke",
      status: "approval_required",
      approval_required: true,
      approvalRequired: true,
      policy_reason: policyReason,
      policyReason,
      daemon_enforced: true,
      daemonEnforced: true,
      ui_override_ignored:
        Boolean(request.approval_granted ?? request.approvalGranted ?? request.approved) ||
        Boolean(requestedApprovalMode && requestedApprovalMode !== approvalMode) ||
        Boolean(normalizedRequestedMode && normalizedRequestedMode !== threadMode),
      workflow_policy: workflowPolicy,
      workflowPolicy,
      thread_id: threadId,
      threadId,
      turn_id: turnId || null,
      turnId: turnId || null,
      tool_id: toolId,
      toolId,
      tool_call_id: toolCallId,
      toolCallId,
      effect_class: effectClass,
      effectClass,
      risk_domain: optionalString(toolContract?.riskDomain ?? toolContract?.risk_domain) ?? "unknown",
      riskDomain: optionalString(toolContract?.riskDomain ?? toolContract?.risk_domain) ?? "unknown",
      authority_scope_requirements: scopeRequirements,
      authorityScopeRequirements: scopeRequirements,
      primitive_capabilities: normalizeArray(toolContract?.primitiveCapabilities ?? toolContract?.primitive_capabilities),
      primitiveCapabilities: normalizeArray(toolContract?.primitiveCapabilities ?? toolContract?.primitive_capabilities),
      thread_mode: threadMode,
      threadMode,
      approval_mode: approvalMode,
      approvalMode,
      trust_profile: "local_private",
      trustProfile: "local_private",
      workflow_trust_profile: workflowPolicy.trustProfile,
      workflowTrustProfile: workflowPolicy.trustProfile,
      node_requires_approval: workflowPolicy.requiresApproval,
      nodeRequiresApproval: workflowPolicy.requiresApproval,
      node_approval_override: workflowPolicy.nodeApprovalOverride,
      nodeApprovalOverride: workflowPolicy.nodeApprovalOverride,
      requested_mode: requestedMode,
      requestedMode,
      normalized_requested_mode: normalizedRequestedMode,
      normalizedRequestedMode,
      requested_approval_mode: requestedApprovalMode,
      requestedApprovalMode,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      input_summary: codingToolInputSummary(toolId, input),
      inputSummary: codingToolInputSummary(toolId, input),
      input_hash: inputHash,
      inputHash,
    };
  }

  function codingToolApprovalManifestsMatch(requestedManifest, retryManifest) {
    if (!requestedManifest || !retryManifest) return false;
    for (const key of ["thread_id", "tool_id", "tool_call_id", "effect_class", "input_hash"]) {
      const left = optionalString(requestedManifest[key] ?? requestedManifest[camelCaseKey(key)]);
      const right = optionalString(retryManifest[key] ?? retryManifest[camelCaseKey(key)]);
      if (left && right && left !== right) return false;
      if (!left || !right) return false;
    }
    const requestedNode = optionalString(requestedManifest.workflow_node_id ?? requestedManifest.workflowNodeId);
    const retryNode = optionalString(retryManifest.workflow_node_id ?? retryManifest.workflowNodeId);
    if (requestedNode && retryNode && requestedNode !== retryNode) return false;
    return true;
  }

  return {
    codingToolApprovalManifestForThread,
    codingToolApprovalManifestsMatch,
    codingToolEffectRequiresApproval,
    codingToolWorkflowApprovalPolicy,
  };
}
