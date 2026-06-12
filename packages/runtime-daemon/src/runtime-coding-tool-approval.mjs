import {
  CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
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

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
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

  function codingToolApprovalSatisfactionForThread({
    store,
    threadId,
    approval_manifest: approvalManifest,
    request = {},
    toolId,
    toolCallId,
    workflowGraphId,
    workflowNodeId,
  }) {
    const approvalId = optionalString(request.approval_id);
    if (!approvalId) {
      return approvalRunner.planApprovalSatisfaction({
        schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
        thread_id: threadId,
        approval_id: null,
        approval_manifest: approvalManifest,
      });
    }
    const projectionContext = approvalProjectionContextForThread(store, threadId, request);
    const projection = approvalRunner.projectApprovalSatisfaction({
      schema_version: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
      thread_id: threadId,
      approval_id: approvalId,
      approval_manifest: approvalManifest,
      run: projectionContext.run,
      agent: projectionContext.agent,
      expected_head: optionalString(request.expected_head) ?? null,
      state_root_before: optionalString(request.state_root_before) ?? null,
      tool_id: toolId,
      tool_call_id: toolCallId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
    });
    return approvalRunner.planApprovalSatisfaction({
      schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
      thread_id: threadId,
      approval_id: approvalId,
      approval_manifest: approvalManifest,
      approval_request: projection?.approval_request ?? null,
      latest_decision: projection?.latest_decision ?? null,
      lease_state: projection?.lease_state ?? null,
      expected_head: projection?.expected_head ?? null,
      state_root_before: projection?.state_root_before ?? null,
    });
  }

  function approvalProjectionContextForThread(store, threadId, request = {}) {
    const explicitRunId = optionalString(request.run_id);
    let run = null;
    if (explicitRunId) {
      run = store?.getRun?.(explicitRunId) ?? store?.runs?.get?.(explicitRunId) ?? null;
    }
    const agent = objectRecord(request.agent) ?? store?.agentForThread?.(threadId) ?? null;
    if (!run && agent?.id && typeof store?.listRuns === "function") {
      const runs = store.listRuns(agent.id);
      run = Array.isArray(runs) ? runs.at(-1) ?? null : null;
    }
    return {
      agent,
      run,
    };
  }

  function codingToolApprovalBlockForThread({
    threadId,
    turnId,
    toolId,
    toolCallId,
    workspaceRoot,
    workflowGraphId,
    workflowNodeId,
    request = {},
    approval_manifest: approvalManifest,
    approval_gate: approvalGate,
    input,
    rollbackRefs = [],
    receiptRefs = [],
    policyDecisionRefs = [],
    artifactRefs = [],
    receiptId,
    idempotencyKey,
  }) {
    return approvalRunner.planApprovalBlock({
      schema_version: CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
      thread_id: threadId,
      turn_id: turnId || null,
      tool_id: toolId,
      tool_call_id: toolCallId,
      workspace_root: workspaceRoot || null,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      source: request.source ?? null,
      idempotency_key: idempotencyKey ?? null,
      receipt_id: receiptId ?? null,
      approval_manifest: approvalManifest,
      approval_gate: approvalGate,
      input_summary: codingToolInputSummary(toolId, input),
      rollback_refs: uniqueStrings(rollbackRefs),
      receipt_refs: uniqueStrings(receiptRefs),
      policy_decision_refs: uniqueStrings(policyDecisionRefs),
      artifact_refs: uniqueStrings(artifactRefs),
    });
  }

  return {
    codingToolApprovalManifestForThread,
    codingToolApprovalBlockForThread,
    codingToolApprovalSatisfactionForThread,
  };
}
