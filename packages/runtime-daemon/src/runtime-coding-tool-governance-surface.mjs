import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import {
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  codingToolInputSummary,
  codingToolSourceEventKind,
} from "./coding-tools.mjs";

function defaultApprovalReasonForDecisionEvent(event = {}) {
  const payload = event.payload_summary ?? event.payload ?? {};
  return optionalString(payload.reason ?? event.reason) ?? "approval_not_satisfied";
}

function defaultApprovalLeaseStateForDecision() {
  return { expired: false, leaseId: null, expiresAt: null };
}

function defaultCodingToolApprovalManifestsMatch(left, right) {
  return JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
}

export function createRuntimeCodingToolGovernanceSurface(deps = {}) {
  const {
    approvalLeaseStateForDecision = defaultApprovalLeaseStateForDecision,
    approvalReasonForDecisionEvent = defaultApprovalReasonForDecisionEvent,
    codingToolApprovalManifestsMatch = defaultCodingToolApprovalManifestsMatch,
  } = deps;

  function codingToolApprovalSatisfaction(store, { threadId, approval_manifest: approvalManifest, request }) {
    const approvalId = optionalString(request.approval_id);
    if (!approvalId) return { satisfied: false, reason: "approval_id_missing" };
    const approvalRequestEvent = store.latestApprovalRequestEvent(threadId, approvalId);
    if (!approvalRequestEvent) return { satisfied: false, approval_id: approvalId, reason: "approval_request_missing" };
    const requestedManifest =
      approvalRequestEvent.payload_summary?.approval_manifest ??
      null;
    if (!codingToolApprovalManifestsMatch(requestedManifest, approvalManifest)) {
      return { satisfied: false, approval_id: approvalId, reason: "approval_manifest_mismatch" };
    }
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const latestDecision = stream.events
      .filter(
        (event) =>
          event.approval_id === approvalId &&
          event.seq > approvalRequestEvent.seq &&
          (event.event_kind === "approval.approved" ||
            event.event_kind === "approval.rejected" ||
            event.event_kind === "approval.revoked"),
      )
      .at(-1);
    if (!latestDecision) return { satisfied: false, approval_id: approvalId, reason: "approval_decision_missing" };
    if (latestDecision.event_kind !== "approval.approved") {
      return {
        satisfied: false,
        approval_id: approvalId,
        decision_event_id: latestDecision.event_id,
        decision_seq: latestDecision.seq,
        reason: approvalReasonForDecisionEvent(latestDecision),
      };
    }
    const leaseState = approvalLeaseStateForDecision({
      threadId,
      approvalId,
      approvalRequestEvent,
      latestDecision,
    });
    if (leaseState.expired) {
      return {
        satisfied: false,
        approval_id: approvalId,
        decision_event_id: latestDecision.event_id,
        decision_seq: latestDecision.seq,
        reason: "approval_lease_expired",
        lease_id: leaseState.leaseId,
        expires_at: leaseState.expiresAt,
      };
    }
    return {
      satisfied: true,
      approval_id: approvalId,
      decision_event_id: latestDecision.event_id,
      decision_seq: latestDecision.seq,
      reason: approvalReasonForDecisionEvent(latestDecision),
      lease_id: leaseState.leaseId,
      expires_at: leaseState.expiresAt,
    };
  }

  function blockCodingToolForApproval(store, {
    agent,
    threadId,
    turnId,
    toolId,
    toolCallId,
    receiptId,
    input,
    request,
    workflowGraphId,
    workflowNodeId,
    requestRollbackRefs,
    diagnosticsRepairContext,
    approval_manifest: approvalManifest,
    toolContract,
  }) {
    const approvalId = `approval_coding_tool_${safeId(toolId)}_${doctorHash(
      `${threadId}:${turnId || "thread"}:${toolCallId}`,
    ).slice(0, 16)}`;
    const error = {
      code: "coding_tool_approval_required",
      message: `${toolId} requires approval before execution in ${approvalManifest.thread_mode} mode.`,
      details: {
        toolId,
        tool_call_id: toolCallId,
        thread_mode: approvalManifest.thread_mode,
        approval_mode: approvalManifest.approval_mode,
        policy_reason: approvalManifest.policy_reason,
      },
    };
    const approval = store.requestThreadApproval(threadId, {
      ...request,
      source: operatorControlSource(request.source),
      turn_id: turnId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      action: "coding_tool.invoke",
      actor: "runtime",
      reason: error.message,
      scope: "coding_tool",
      idempotency_key: `thread:${threadId}:approval.required:${approvalId}`,
      approval_id: approvalId,
      tool_id: toolId,
      effect_class: approvalManifest.effect_class,
      risk_domain: approvalManifest.risk_domain,
      authority_scope_requirements: approvalManifest.authority_scope_requirements,
      approval_manifest: approvalManifest,
      receipt_refs: [receiptId],
      policy_decision_refs: [`policy_coding_tool_${safeId(toolId)}_approval_required`],
    });
    const result = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      tool_name: toolId,
      status: "blocked",
      approval_required: true,
      approval_id: approval.approval_id,
      approval_manifest: approvalManifest,
      input_summary: codingToolInputSummary(toolId, input),
      error,
    };
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status: "blocked",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      approval_required: true,
      approval_id: approval.approval_id,
      approval_manifest: approvalManifest,
      receipt_refs: approval.receipt_refs,
      artifact_refs: [],
      rollback_refs: uniqueStrings(requestRollbackRefs),
      event: null,
      approval,
      approval_event_id: approval.event_id,
      workspace_snapshot: null,
      workspace_snapshot_event: null,
      auto_diagnostics: null,
      diagnostics_repair_context: diagnosticsRepairContext,
      tool_contract: toolContract ?? null,
      result,
      error,
    };
  }

  function blockCodingToolForBudget(store, {
    agent,
    threadId,
    turnId,
    toolId,
    toolCallId,
    receiptId,
    input,
    request,
    workflowGraphId,
    workflowNodeId,
    requestRollbackRefs,
    diagnosticsRepairContext,
    budgetPolicy,
    toolContract,
    codingToolIdempotencyKey,
  }) {
    const receiptRefs = uniqueStrings([
      receiptId,
      ...normalizeArray(budgetPolicy.receipt_refs ?? budgetPolicy.receiptRefs),
    ]);
    const policyDecisionRefs = uniqueStrings(
      budgetPolicy.policy_decision_refs ?? budgetPolicy.policyDecisionRefs,
    );
    const error = {
      code: "coding_tool_budget_exceeded",
      message: `${toolId} blocked because the workflow coding-tool budget was exceeded.`,
      details: {
        toolId,
        tool_call_id: toolCallId,
        reason: "coding_tool_budget_exceeded",
        budget_status: "exceeded",
        context_budget_status: budgetPolicy.status,
        context_budget: budgetPolicy,
        budget_usage_telemetry: budgetPolicy.usage_telemetry,
      },
    };
    const result = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      tool_name: toolId,
      status: "blocked",
      budget_status: "exceeded",
      context_budget_status: budgetPolicy.status,
      context_budget: budgetPolicy,
      input_summary: codingToolInputSummary(toolId, input),
      error,
    };
    const rollbackRefs = uniqueStrings(requestRollbackRefs);
    const payloadSummary = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      event_kind: "CodingToolBudgetBlocked",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      status: "blocked",
      summary: error.message,
      shell_fallback_used: false,
      input_summary: codingToolInputSummary(toolId, input),
      result_summary: { status: "blocked", reason: "coding_tool_budget_exceeded" },
      result,
      error,
      rollback_refs: rollbackRefs,
      diagnostics_repair_context: diagnosticsRepairContext,
      approval_required: false,
      budget_status: "exceeded",
      context_budget_status: budgetPolicy.status,
      context_budget: budgetPolicy,
      budget_usage_telemetry: budgetPolicy.usage_telemetry,
      policy_decision_refs: policyDecisionRefs,
      receipt_id: receiptId,
      receipt_count: receiptRefs.length,
      artifact_count: 0,
    };
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:coding-tool:${safeId(toolId)}:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key:
        codingToolIdempotencyKey ??
        `thread:${threadId}:coding-tool:${toolCallId}:budget-blocked`,
      source: operatorControlSource(request.source),
      source_event_kind: codingToolSourceEventKind(toolId),
      event_kind: "policy.blocked",
      status: "blocked",
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      tool_call_id: toolCallId,
      artifact_refs: [],
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status: "blocked",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      budget_status: "exceeded",
      context_budget: budgetPolicy,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
      artifact_refs: [],
      rollback_refs: rollbackRefs,
      event,
      workspace_snapshot: null,
      workspace_snapshot_event: null,
      auto_diagnostics: null,
      diagnostics_repair_context: diagnosticsRepairContext,
      tool_contract: toolContract ?? null,
      result,
      error,
    };
  }

  return {
    codingToolApprovalSatisfaction,
    blockCodingToolForApproval,
    blockCodingToolForBudget,
  };
}
