import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  optionalString,
} from "./runtime-value-helpers.mjs";

function defaultApprovalReasonForDecisionEvent(event = {}) {
  const payload = event.payload_summary ?? event.payload ?? {};
  return optionalString(payload.reason ?? event.reason) ?? "approval_not_satisfied";
}

function defaultApprovalLeaseStateForDecision() {
  return { expired: false, lease_id: null, expires_at: null };
}

function defaultCodingToolApprovalManifestsMatch(left, right) {
  return JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
}

export function createRuntimeCodingToolGovernanceSurface(deps = {}) {
  const {
    approvalLeaseStateForDecision = defaultApprovalLeaseStateForDecision,
    approvalReasonForDecisionEvent = defaultApprovalReasonForDecisionEvent,
    codingToolApprovalManifestsMatch = defaultCodingToolApprovalManifestsMatch,
    runtimeError = ({ status = 500, code = "runtime_error", message = code, details = {} } = {}) => {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
  } = deps;

  function throwGovernanceRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_coding_tool_governance_rust_core_required",
      message: "Runtime coding-tool governance control requires direct Rust daemon-core authority admission and persistence.",
      details: {
        rust_core_boundary: "runtime.coding_tool_governance",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

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
      thread_id: threadId,
      approval_id: approvalId,
      approval_request_event: approvalRequestEvent,
      latest_decision: latestDecision,
    });
    if (leaseState.expired) {
      return {
        satisfied: false,
        approval_id: approvalId,
        decision_event_id: latestDecision.event_id,
        decision_seq: latestDecision.seq,
        reason: "approval_lease_expired",
        lease_id: leaseState.lease_id,
        expires_at: leaseState.expires_at,
      };
    }
    return {
      satisfied: true,
      approval_id: approvalId,
      decision_event_id: latestDecision.event_id,
      decision_seq: latestDecision.seq,
      reason: approvalReasonForDecisionEvent(latestDecision),
      lease_id: leaseState.lease_id,
      expires_at: leaseState.expires_at,
    };
  }

  function blockCodingToolForApproval(store, {
    threadId,
    turnId,
    toolId,
    toolCallId,
    request = {},
    workflowGraphId,
    workflowNodeId,
    approval_manifest: approvalManifest,
  }) {
    throwGovernanceRustCoreRequired("coding_tool_approval_block", "coding_tool.approval.block", {
      thread_id: threadId,
      turn_id: turnId || null,
      tool_id: optionalString(toolId) ?? null,
      tool_call_id: optionalString(toolCallId) ?? null,
      workflow_graph_id: optionalString(workflowGraphId) ?? null,
      workflow_node_id: optionalString(workflowNodeId) ?? null,
      approval_mode: optionalString(approvalManifest?.approval_mode) ?? null,
      effect_class: optionalString(approvalManifest?.effect_class) ?? null,
      risk_domain: optionalString(approvalManifest?.risk_domain) ?? null,
      source: optionalString(request.source) ?? null,
      evidence_refs: [
        "coding_tool_approval_block_js_facade_retired",
        "rust_daemon_core_coding_tool_approval_block_required",
        "agentgres_coding_tool_approval_block_truth_required",
      ],
    });
  }

  function blockCodingToolForBudget(store, {
    threadId,
    turnId,
    toolId,
    toolCallId,
    request = {},
    workflowGraphId,
    workflowNodeId,
    budgetPolicy,
    codingToolIdempotencyKey,
  }) {
    throwGovernanceRustCoreRequired("coding_tool_budget_block", "policy.blocked", {
      thread_id: threadId,
      turn_id: turnId || null,
      tool_id: optionalString(toolId) ?? null,
      tool_call_id: optionalString(toolCallId) ?? null,
      workflow_graph_id: optionalString(workflowGraphId) ?? null,
      workflow_node_id: optionalString(workflowNodeId) ?? null,
      coding_tool_idempotency_key: optionalString(codingToolIdempotencyKey) ?? null,
      context_budget_status: optionalString(budgetPolicy?.status) ?? null,
      source: optionalString(request.source) ?? null,
      evidence_refs: [
        "coding_tool_budget_block_js_facade_retired",
        "rust_daemon_core_coding_tool_budget_block_required",
        "agentgres_coding_tool_budget_block_truth_required",
      ],
    });
  }

  return {
    codingToolApprovalSatisfaction,
    blockCodingToolForApproval,
    blockCodingToolForBudget,
  };
}
