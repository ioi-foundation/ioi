import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { optionalString } from "./runtime-value-helpers.mjs";

function approvalRequiredError(runtimeError, threadId) {
  return runtimeError({
    status: 400,
    code: "approval_id_required",
    message: "Approval decisions require an approval id.",
    details: { thread_id: threadId },
  });
}

function approvalRevokeRequiredError(runtimeError, threadId) {
  return runtimeError({
    status: 400,
    code: "approval_id_required",
    message: "Approval revocation requires an approval id.",
    details: { thread_id: threadId },
  });
}

export function createRuntimeApprovalSurface(deps = {}) {
  const {
    approvalDecisionForRequest,
    runtimeError,
  } = deps;

  function latestApprovalRequestEvent(store, threadId, approvalId) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            event.event_kind === "approval.required",
        )
        .at(-1) ?? null
    );
  }

  function latestApprovalDecisionEvent(store, threadId, approvalId) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            (event.event_kind === "approval.approved" ||
              event.event_kind === "approval.rejected" ||
              event.event_kind === "approval.revoked"),
        )
        .at(-1) ?? null
    );
  }

  function throwApprovalControlRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_approval_control_rust_core_required",
      message: "Runtime approval control requires direct Rust daemon-core authority admission and persistence.",
      details: {
        rust_core_boundary: "runtime.approval_control",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function requestThreadApproval(store, threadId, request = {}) {
    throwApprovalControlRustCoreRequired("approval_request", "approval.required", {
      thread_id: threadId,
      approval_id: optionalString(request.approval_id) ?? null,
      evidence_refs: [
        "approval_request_js_facade_retired",
        "rust_daemon_core_approval_request_required",
        "agentgres_approval_request_state_truth_required",
      ],
    });
  }

  function decideThreadApproval(store, threadId, approvalId, request = {}) {
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRequiredError(runtimeError, threadId);
      })();
    const decision = approvalDecisionForRequest(request.decision ?? request.action ?? request.status);
    throwApprovalControlRustCoreRequired("approval_decision", `approval.${decision}`, {
      thread_id: threadId,
      approval_id: normalizedApprovalId,
      decision,
      evidence_refs: [
        "approval_decision_js_facade_retired",
        "rust_daemon_core_approval_decision_required",
        "agentgres_approval_decision_state_truth_required",
      ],
    });
  }

  function revokeThreadApproval(store, threadId, approvalId, request = {}) {
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRevokeRequiredError(runtimeError, threadId);
      })();
    throwApprovalControlRustCoreRequired("approval_revoke", "approval.revoke", {
      thread_id: threadId,
      approval_id: normalizedApprovalId,
      evidence_refs: [
        "approval_revoke_js_facade_retired",
        "rust_daemon_core_approval_revoke_required",
        "agentgres_approval_revoke_state_truth_required",
      ],
    });
  }

  return {
    decideThreadApproval,
    latestApprovalDecisionEvent,
    latestApprovalRequestEvent,
    requestThreadApproval,
    revokeThreadApproval,
  };
}
