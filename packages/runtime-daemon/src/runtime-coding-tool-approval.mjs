import {
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  createCodingToolApprovalRunnerFromEnv,
} from "./runtime-coding-tool-approval-runner.mjs";

function defaultOptionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function defaultNormalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

export function createCodingToolApprovalPolicy(deps = {}) {
  const approvalRunner = deps.approvalRunner ?? createCodingToolApprovalRunnerFromEnv(deps.env ?? process.env);
  const approvalModeForThreadMode = deps.approvalModeForThreadMode || (() => "suggest");
  const codingToolInputSummary = deps.codingToolInputSummary || (() => ({}));
  const normalizeArray = deps.normalizeArray || defaultNormalizeArray;
  const normalizeThreadApprovalMode = deps.normalizeThreadApprovalMode || ((value, fallback) => value || fallback);
  const normalizeThreadInteractionMode = deps.normalizeThreadInteractionMode || ((value) => String(value || "agent"));
  const normalizedAgentRuntimeControls = deps.normalizedAgentRuntimeControls || ((agent = {}) => agent.runtimeControls || {});
  const optionalString = deps.optionalString || defaultOptionalString;
  const uniqueStrings = deps.uniqueStrings || ((values = []) => [...new Set(normalizeArray(values).filter(Boolean))]);

  function codingToolWorkflowApprovalRequestForRust(request = {}) {
    const codingPack =
      request.tool_pack && typeof request.tool_pack === "object" && !Array.isArray(request.tool_pack)
        ? request.tool_pack.coding && typeof request.tool_pack.coding === "object" && !Array.isArray(request.tool_pack.coding)
          ? request.tool_pack.coding
          : request.tool_pack
        : {};
    const nodeApprovalOverride =
      optionalString(
        request.node_approval_override ??
          request.approval_override ??
          codingPack.node_approval_override,
      ) ?? "inherit";
    const approvalMode =
      optionalString(codingPack.approval_mode) ??
      optionalString(request.approval_mode) ??
      null;
    const trustProfile =
      optionalString(
        request.trust_profile ??
          codingPack.trust_profile,
      ) ?? "local_private";
    const explicitRequiresApproval =
      request.requires_approval ??
      codingPack.requires_approval;
    const approvalModeRequiresApproval =
      approvalMode === "human_required" || approvalMode === "policy_required";
    const trustRequiresApproval = ["untrusted", "restricted", "review_required"].includes(
      trustProfile.toLowerCase(),
    );
    return {
      node_approval_override: nodeApprovalOverride,
      approval_mode: approvalMode,
      trust_profile: trustProfile,
      requires_approval:
        Boolean(explicitRequiresApproval) ||
        nodeApprovalOverride === "require_approval" ||
        approvalModeRequiresApproval ||
        trustRequiresApproval,
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
    const effectClass = optionalString(toolContract?.effect_class ?? toolContract?.effectClass) ?? "unknown";
    const controls = normalizedAgentRuntimeControls(agent);
    const workflowPolicy = codingToolWorkflowApprovalRequestForRust(request);
    const threadMode = normalizeThreadInteractionMode(controls.mode ?? agent.mode ?? "agent");
    const approvalMode = normalizeThreadApprovalMode(controls.approvalMode, approvalModeForThreadMode(threadMode));
    const requestedApprovalMode =
      optionalString(request.approval_mode ?? workflowPolicy.approval_mode) ?? null;
    const requestedMode = optionalString(request.mode ?? request.thread_mode) ?? null;
    let normalizedRequestedMode = null;
    if (requestedMode) {
      try {
        normalizedRequestedMode = normalizeThreadInteractionMode(requestedMode);
      } catch {
        normalizedRequestedMode = requestedMode.toLowerCase().replace(/-/g, "_");
      }
    }
    const scopeRequirements = uniqueStrings(
      normalizeArray(toolContract?.authorityScopeRequirements ?? toolContract?.authority_scope_requirements),
    );
    const plan = approvalRunner.planApprovalManifest({
      schema_version: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
      thread_id: threadId,
      turn_id: turnId || null,
      tool_id: toolId,
      tool_call_id: toolCallId,
      effect_class: effectClass,
      risk_domain: optionalString(toolContract?.riskDomain ?? toolContract?.risk_domain) ?? "unknown",
      authority_scope_requirements: scopeRequirements,
      primitive_capabilities: normalizeArray(toolContract?.primitiveCapabilities ?? toolContract?.primitive_capabilities),
      thread_mode: threadMode,
      approval_mode: approvalMode,
      trust_profile: "local_private",
      requested_mode: requestedMode,
      normalized_requested_mode: normalizedRequestedMode,
      requested_approval_mode: requestedApprovalMode,
      ui_override_requested: Boolean(request.approval_granted),
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflow_policy: workflowPolicy,
      input_summary: codingToolInputSummary(toolId, input),
      input,
    });
    return plan.manifest ?? null;
  }

  function codingToolApprovalManifestsMatch(requestedManifest, retryManifest) {
    if (!requestedManifest || !retryManifest) return false;
    for (const key of ["thread_id", "tool_id", "tool_call_id", "effect_class", "input_hash"]) {
      const left = optionalString(requestedManifest[key]);
      const right = optionalString(retryManifest[key]);
      if (left && right && left !== right) return false;
      if (!left || !right) return false;
    }
    const requestedNode = optionalString(requestedManifest.workflow_node_id);
    const retryNode = optionalString(retryManifest.workflow_node_id);
    if (requestedNode && retryNode && requestedNode !== retryNode) return false;
    return true;
  }

  return {
    codingToolApprovalManifestForThread,
    codingToolApprovalManifestsMatch,
  };
}
