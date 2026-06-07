function defaultOptionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function defaultNormalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

export function createCodingToolBudgetRecovery(deps = {}) {
  const WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION =
    deps.WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION ||
    "ioi.workflow.coding-tool-budget-recovery-policy.v1";
  const WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION =
    deps.WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION ||
    "ioi.workflow.coding-tool-budget-recovery.v1";
  const WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON =
    deps.WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON ||
    "workflow_run_coding_tool_budget_preflight_blocked";
  const normalizeArray = deps.normalizeArray || defaultNormalizeArray;
  const optionalString = deps.optionalString || defaultOptionalString;
  const runtimeError = deps.runtimeError || ((payload) => {
    const error = new Error(payload?.message || "Runtime error");
    Object.assign(error, payload);
    return error;
  });
  const uniqueStrings = deps.uniqueStrings || ((values = []) => [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))]);

  function codingToolBudgetRecoveryAction(value) {
    const action = optionalString(value)?.toLowerCase().replace(/-/g, "_") ?? "request_approval";
    if (["request", "request_approval", "approval_request"].includes(action)) {
      return "request_approval";
    }
    if (["approve", "approved", "approve_override", "allow", "allowed"].includes(action)) {
      return "approve_override";
    }
    if (["reject", "rejected", "reject_override", "deny", "denied"].includes(action)) {
      return "reject_override";
    }
    if (["retry", "retry_approved", "approved_retry"].includes(action)) {
      return "retry_approved";
    }
    throw runtimeError({
      status: 400,
      code: "coding_tool_budget_recovery_action_invalid",
      message: "Coding-tool budget recovery accepts request_approval, approve_override, reject_override, or retry_approved.",
      details: { action: value ?? null },
    });
  }

  function codingToolBudgetRecoveryTargetNodeIds({ request = {}, blockedEvent = null, blockedPayload = {} }) {
    return uniqueStrings([
      ...normalizeArray(request.target_node_ids),
      ...normalizeArray(blockedPayload.target_node_ids),
      optionalString(request.workflow_node_id),
      optionalString(blockedEvent?.workflow_node_id),
      optionalString(blockedPayload.workflow_node_id),
    ]);
  }

  function codingToolBudgetRecoveryPolicyFromInputs({
    request = {},
    blockedPayload = {},
    targetNodeIds = [],
    source = "sdk_client",
  }) {
    const manifest =
      blockedPayload.approval_manifest ??
      {};
    const rawPolicy =
      request.recovery_policy ??
      blockedPayload.recovery_policy ??
      manifest.recovery_policy ??
      {};
    const policy = rawPolicy && typeof rawPolicy === "object" ? rawPolicy : {};
    const retryLimit = Number(policy.retry_limit ?? request.retry_limit ?? 1);
    const normalizedTargetNodeIds = uniqueStrings([
      ...normalizeArray(policy.target_node_ids),
      ...targetNodeIds,
    ]);
    return {
      schema_version:
        policy.schema_version ??
        WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
      requires_approval: policy.requires_approval ?? true,
      allow_override: policy.allow_override ?? true,
      retry_limit: Number.isFinite(retryLimit) && retryLimit > 0 ? Math.floor(retryLimit) : 1,
      approval_scope: policy.approval_scope ?? "target_nodes",
      operator_role: policy.operator_role ?? "budget_operator",
      target_node_ids: normalizedTargetNodeIds,
      source: policy.source ?? source,
    };
  }

  function recoveryPolicyRetryLimit(policy = {}) {
    const retryLimit = Number(policy.retry_limit ?? 1);
    return Number.isFinite(retryLimit) && retryLimit > 0 ? Math.floor(retryLimit) : 1;
  }

  function isCodingToolBudgetBlockedRuntimeEvent(event) {
    const payload = event?.payload_summary ?? event?.payload ?? {};
    const haystack = [
      event?.component_kind,
      event?.event_kind,
      event?.source_event_kind,
      event?.status,
      payload.event_kind,
      payload.reason,
      payload.block_reason,
      payload.budget_status,
      payload.context_budget_status,
      payload.result_summary?.reason,
      payload.error?.code,
      payload.error?.details?.reason,
    ]
      .map((value) => optionalString(value)?.toLowerCase())
      .filter(Boolean)
      .join(" ");
    return (
      haystack.includes("coding_tool") &&
      (haystack.includes("workflowruncodingtoolbudgetpreflightblocked") ||
        haystack.includes(WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON) ||
        haystack.includes("coding_tool_budget_exceeded") ||
        haystack.includes("exceeded") ||
        haystack.includes("blocked"))
    );
  }

  function codingToolBudgetRecoveryResult({
    action,
    status,
    reason = null,
    run,
    thread_id: threadId,
    turn_id: turnId,
    approval_id: approvalId,
    source_event_id: sourceEventId,
    target_node_ids: targetNodeIds,
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
    recovery_policy: recoveryPolicy,
    event = null,
    approval_event: approvalEvent = null,
    decision_event: decisionEvent = null,
    receipt_refs: receiptRefs = [],
    policy_decision_refs: policyDecisionRefs = [],
  }) {
    return {
      schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      status,
      action,
      recovery_action: action,
      reason,
      run_id: run.id,
      thread_id: threadId,
      turn_id: turnId,
      approval_id: approvalId,
      source_event_id: sourceEventId,
      target_node_ids: targetNodeIds,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      recovery_policy: recoveryPolicy,
      event_id: event?.event_id ?? null,
      seq: event?.seq ?? null,
      approval_event_id: approvalEvent?.event_id ?? null,
      approval_decision_event_id: decisionEvent?.event_id ?? null,
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      event,
      approval_event: approvalEvent,
      decision_event: decisionEvent,
    };
  }

  return {
    codingToolBudgetRecoveryAction,
    codingToolBudgetRecoveryPolicyFromInputs,
    codingToolBudgetRecoveryResult,
    codingToolBudgetRecoveryTargetNodeIds,
    isCodingToolBudgetBlockedRuntimeEvent,
    recoveryPolicyRetryLimit,
  };
}
