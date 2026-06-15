import {
  normalizeBooleanOption,
  normalizeArray,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

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
    approvalStateCore = null,
    nowIso = () => new Date().toISOString(),
    runtimeError,
  } = deps;

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
    const approvalId = requiredApprovalId(request.approval_id, threadId, "Approval requests");
    const target = approvalControlTargetFacts(request);
    const eventId = approvalEventId(request, approvalId, "request");
    const seq = approvalSeq(request);
    const createdAt = approvalCreatedAt(request);
    const source = approvalSource(request);
    const authority = requireApprovalStateCore(
      "authorizeApprovalRequest",
      "approval_request_authority",
      "approval.request.authority",
      threadId,
      approvalId,
    ).authorizeApprovalRequest(approvalRequestAuthorityRequest({
      threadId,
      approvalId,
      target,
      request,
      eventId,
      seq,
      createdAt,
      source,
    }));
    const approvalLease = rustApprovalLease(authority, runtimeError, "approval_request_authority");
    const leaseId = rustApprovalLeaseId(authority, approvalLease, runtimeError, "approval_request_authority");
    const leaseStatus = rustApprovalLeaseStatus(authority, runtimeError, "approval_request_authority");
    const record = requireApprovalStateCore(
      "planApprovalRequestStateUpdate",
      "approval_request",
      "approval.required",
      threadId,
      approvalId,
    ).planApprovalRequestStateUpdate({
      target_kind: target.target_kind,
      thread_id: threadId,
      run_id: target.run_id,
      state_dir: store?.stateDir ?? null,
      event_id: eventId,
      seq,
      created_at: createdAt,
      approval_id: approvalId,
      lease_id: leaseId,
      lease_status: leaseStatus,
      approval_lease: approvalLease,
      source,
      reason: optionalString(request.reason) ?? "operator requested approval",
      receipt_refs: normalizeArray(authority.authority_receipt_refs),
      policy_decision_refs: normalizeArray(authority.policy_decision_refs),
      authority_record: objectRecord(authority.authority) ?? objectRecord(authority) ?? null,
      authority_hash: optionalString(authority.authority_hash) ?? null,
      authority_grant_refs: [],
      authority_receipt_refs: normalizeArray(authority.authority_receipt_refs),
    });
    return applyRustApprovalStateUpdate(store, record);
  }

  function decideThreadApproval(store, threadId, approvalId, request = {}) {
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRequiredError(runtimeError, threadId);
      })();
    const target = approvalControlTargetFacts(request);
    const eventId = approvalEventId(request, normalizedApprovalId, "decision");
    const seq = approvalSeq(request);
    const createdAt = approvalCreatedAt(request);
    const source = approvalSource(request);
    const authority = requireApprovalStateCore(
      "authorizeApprovalDecision",
      "approval_decision_authority",
      "approval.decision.authority",
      threadId,
      normalizedApprovalId,
    ).authorizeApprovalDecision(approvalDecisionAuthorityRequest({
      threadId,
      approvalId: normalizedApprovalId,
      decision: request.decision,
      target,
      request,
      eventId,
      seq,
      createdAt,
      source,
    }));
    const decision = rustApprovalDecision(authority, runtimeError, "approval_decision_authority");
    const approvalLease = rustApprovalLease(authority, runtimeError, "approval_decision_authority");
    const leaseId = rustApprovalLeaseId(authority, approvalLease, runtimeError, "approval_decision_authority");
    const leaseStatus = rustApprovalLeaseStatus(authority, runtimeError, "approval_decision_authority");
    const record = requireApprovalStateCore(
      "planApprovalDecisionStateUpdate",
      "approval_decision",
      `approval.${decision}`,
      threadId,
      normalizedApprovalId,
    ).planApprovalDecisionStateUpdate({
      target_kind: target.target_kind,
      thread_id: threadId,
      run_id: target.run_id,
      state_dir: store?.stateDir ?? null,
      event_id: eventId,
      seq,
      created_at: createdAt,
      approval_id: normalizedApprovalId,
      lease_id: leaseId,
      lease_status: leaseStatus,
      approval_lease: approvalLease,
      decision,
      status: decision === "approve" ? "approved" : "rejected",
      source,
      reason: optionalString(request.reason) ?? null,
      receipt_refs: normalizeArray(authority.authority_receipt_refs),
      policy_decision_refs: normalizeArray(authority.policy_decision_refs),
      authority_record: objectRecord(authority.authority) ?? objectRecord(authority) ?? null,
      authority_hash: optionalString(authority.authority_hash) ?? null,
      authority_grant_refs: normalizeArray(authority.wallet_network_grant_refs),
      authority_receipt_refs: normalizeArray(authority.authority_receipt_refs),
    });
    return applyRustApprovalStateUpdate(store, record);
  }

  function revokeThreadApproval(store, threadId, approvalId, request = {}) {
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRevokeRequiredError(runtimeError, threadId);
      })();
    const target = approvalControlTargetFacts(request);
    const eventId = approvalEventId(request, normalizedApprovalId, "revoke");
    const seq = approvalSeq(request);
    const createdAt = approvalCreatedAt(request);
    const source = approvalSource(request);
    const authority = requireApprovalStateCore(
      "authorizeApprovalDecision",
      "approval_decision_authority",
      "approval.decision.authority",
      threadId,
      normalizedApprovalId,
    ).authorizeApprovalDecision(approvalDecisionAuthorityRequest({
      threadId,
      approvalId: normalizedApprovalId,
      decision: "revoke",
      target,
      request,
      eventId,
      seq,
      createdAt,
      source,
    }));
    const decision = rustApprovalDecision(authority, runtimeError, "approval_revoke_authority");
    const approvalLease = rustApprovalLease(authority, runtimeError, "approval_revoke_authority");
    const leaseId = rustApprovalLeaseId(authority, approvalLease, runtimeError, "approval_revoke_authority");
    const record = requireApprovalStateCore(
      "planApprovalRevokeStateUpdate",
      "approval_revoke",
      "approval.revoke",
      threadId,
      normalizedApprovalId,
    ).planApprovalRevokeStateUpdate({
      target_kind: target.target_kind,
      thread_id: threadId,
      run_id: target.run_id,
      state_dir: store?.stateDir ?? null,
      event_id: eventId,
      seq,
      created_at: createdAt,
      approval_id: normalizedApprovalId,
      lease_id: leaseId,
      approval_lease: approvalLease,
      source,
      reason: optionalString(request.reason) ?? null,
      receipt_refs: normalizeArray(authority.authority_receipt_refs),
      policy_decision_refs: normalizeArray(authority.policy_decision_refs),
      authority_record: objectRecord(authority.authority) ?? objectRecord(authority) ?? null,
      authority_hash: optionalString(authority.authority_hash) ?? null,
      authority_grant_refs: normalizeArray(authority.wallet_network_grant_refs),
      authority_receipt_refs: normalizeArray(authority.authority_receipt_refs),
    });
    return applyRustApprovalStateUpdate(store, record);
  }

  function listThreadApprovals(store, threadId, request = {}) {
    const record = requireApprovalStateCore(
      "projectApprovalQueue",
      "approval_queue_projection",
      "approval.queue_projection",
      threadId,
      null,
    ).projectApprovalQueue({
      thread_id: threadId,
      state_dir: store?.stateDir ?? null,
      include_resolved: normalizeBooleanOption(request.include_resolved, false),
      expected_head: optionalString(request.expected_head) ?? null,
      state_root_before: optionalString(request.state_root_before) ?? null,
    });
    return record;
  }

  return {
    decideThreadApproval,
    listThreadApprovals,
    requestThreadApproval,
    revokeThreadApproval,
  };

  function requireApprovalStateCore(method, operation, operationKind, threadId, approvalId) {
    if (approvalStateCore?.[method]) return approvalStateCore;
    throwApprovalControlRustCoreRequired(operation, operationKind, {
      thread_id: threadId,
      approval_id: approvalId,
      evidence_refs: approvalControlEvidenceRefs(operation),
    });
  }

  function approvalControlTargetFacts(request = {}) {
    const targetKind = optionalString(request.target_kind) === "agent" ? "agent" : "run";
    if (targetKind === "agent") {
      return {
        target_kind: "agent",
        run_id: null,
      };
    }
    return {
      target_kind: "run",
      run_id: optionalString(request.run_id) ?? null,
    };
  }

  function applyRustApprovalStateUpdate(store, value = {}) {
    const record = objectRecord(value.record) ?? objectRecord(value) ?? {};
    const targetKind = optionalString(record.target_kind) ?? "run";
    const operationKind = optionalString(record.operation_kind) ?? "approval.required";
    const commit = targetKind === "agent"
      ? persistRustApprovalAgentUpdate(store, record, operationKind)
      : persistRustApprovalRunUpdate(store, record, operationKind);
    return {
      ...record,
      commit,
    };
  }

  function persistRustApprovalRunUpdate(store, record, operationKind) {
    const run = objectRecord(record.run);
    if (!run) {
      throw runtimeError({
        status: 502,
        code: "approval_rust_run_update_missing",
        message: "Rust approval authority did not return a run state projection.",
        details: { operation_kind: operationKind },
      });
    }
    const commit = store.writeRun(run, operationKind);
    if (run.id) store.runs?.set?.(String(run.id), run);
    return commit;
  }

  function persistRustApprovalAgentUpdate(store, record, operationKind) {
    const agent = objectRecord(record.agent);
    if (!agent) {
      throw runtimeError({
        status: 502,
        code: "approval_rust_agent_update_missing",
        message: "Rust approval authority did not return an agent state projection.",
        details: { operation_kind: operationKind },
      });
    }
    return store.writeAgent(agent, operationKind);
  }

  function requiredApprovalId(value, threadId, label) {
    const approvalId = optionalString(value);
    if (approvalId) return approvalId;
    throw runtimeError({
      status: 400,
      code: "approval_id_required",
      message: `${label} require an approval id.`,
      details: { thread_id: threadId },
    });
  }

  function approvalEventId(request = {}, approvalId, operation) {
    return optionalString(request.event_id) ??
      `event_${safeId(approvalId)}_${safeId(operation)}`;
  }

  function approvalSeq(request = {}) {
    const seq = Number(request.seq);
    return Number.isSafeInteger(seq) && seq > 0 ? seq : 1;
  }

  function approvalCreatedAt(request = {}) {
    return optionalString(request.created_at) ?? nowIso();
  }

  function approvalSource(request = {}) {
    return optionalString(request.source) ?? "sdk_client";
  }
}

function approvalDecisionAuthorityRequest({
  threadId,
  approvalId,
  decision,
  target,
  request,
  eventId,
  seq,
  createdAt,
  source,
}) {
  return {
    thread_id: threadId,
    approval_id: approvalId,
    decision,
    target_kind: target.target_kind,
    run_id: target.run_id,
    actor_ref: optionalString(request.actor_ref) ?? source,
    source,
    idempotency_key:
      optionalString(request.idempotency_key) ??
      `approval:${safeId(threadId)}:${safeId(approvalId)}:${safeId(decision)}:${seq}`,
    lease_id: optionalString(request.lease_id) ?? null,
    lease_ttl_ms: optionalPositiveInteger(request.ttl_ms ?? request.lease_ttl_ms),
    expires_at: optionalString(request.expires_at) ?? null,
    approval_lease: objectRecord(request.approval_lease) ?? null,
    wallet_approval_grant: objectRecord(request.wallet_approval_grant) ?? null,
    authority_grant_refs: [],
    authority_receipt_refs: normalizeArray(request.authority_receipt_refs),
    policy_decision_refs: normalizeArray(request.policy_decision_refs),
    approval_manifest: objectRecord(request.approval_manifest) ?? null,
    approval_request: objectRecord(request.approval_request) ?? null,
    authority_context: {
      event_id: eventId,
      seq,
      created_at: createdAt,
      rust_core_boundary: "runtime.approval_decision_authority",
    },
  };
}

function approvalRequestAuthorityRequest({
  threadId,
  approvalId,
  target,
  request,
  eventId,
  seq,
  createdAt,
  source,
}) {
  return {
    thread_id: threadId,
    approval_id: approvalId,
    target_kind: target.target_kind,
    run_id: target.run_id,
    actor_ref: optionalString(request.actor_ref) ?? source,
    source,
    idempotency_key:
      optionalString(request.idempotency_key) ??
      `approval:${safeId(threadId)}:${safeId(approvalId)}:request:${seq}`,
    lease_id: optionalString(request.lease_id) ?? null,
    lease_ttl_ms: optionalPositiveInteger(request.ttl_ms ?? request.lease_ttl_ms),
    expires_at: optionalString(request.expires_at) ?? null,
    action: optionalString(request.action) ?? null,
    scope: optionalString(request.scope) ?? null,
    authority_scope_requirements: normalizeArray(request.authority_scope_requirements),
    receipt_refs: normalizeArray(request.receipt_refs),
    policy_decision_refs: normalizeArray(request.policy_decision_refs),
    approval_manifest: objectRecord(request.approval_manifest) ?? {},
    authority_context: {
      ...(objectRecord(request.authority_context) ?? {}),
      thread_id: threadId,
      approval_id: approvalId,
      target_kind: target.target_kind,
      run_id: target.run_id,
      event_id: eventId,
      seq,
      created_at: createdAt,
      source,
    },
  };
}

function approvalControlEvidenceRefs(operation) {
  if (operation === "approval_request_authority") {
    return [
      "approval_request_authority_rust_owned",
      "rust_daemon_core_approval_request_authority_required",
      "agentgres_approval_request_authority_truth_required",
    ];
  }
  if (operation === "approval_decision_authority") {
    return [
      "approval_decision_wallet_network_authority_required",
      "rust_daemon_core_approval_decision_authority_required",
      "agentgres_approval_decision_authority_truth_required",
    ];
  }
  if (operation === "approval_queue_projection") {
    return [
      "approval_queue_js_readback_retired",
      "rust_daemon_core_approval_queue_projection_required",
      "agentgres_approval_queue_projection_truth_required",
    ];
  }
  if (operation === "approval_decision") {
    return [
      "approval_decision_js_facade_retired",
      "rust_daemon_core_approval_decision_required",
      "agentgres_approval_decision_state_truth_required",
    ];
  }
  if (operation === "approval_revoke") {
    return [
      "approval_revoke_js_facade_retired",
      "rust_daemon_core_approval_revoke_required",
      "agentgres_approval_revoke_state_truth_required",
    ];
  }
  return [
    "approval_request_js_facade_retired",
    "rust_daemon_core_approval_request_required",
    "agentgres_approval_request_state_truth_required",
  ];
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function optionalPositiveInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function rustApprovalDecision(authority, runtimeError, operation) {
  const decision = optionalString(authority?.decision ?? authority?.authority?.decision);
  if (decision === "approve" || decision === "reject" || decision === "revoke") {
    return decision;
  }
  throw runtimeError({
    status: 502,
    code: "approval_rust_decision_authority_incomplete",
    message: "Rust approval authority did not return a canonical decision.",
    details: {
      operation,
      decision: decision ?? null,
      rust_core_boundary: "runtime.approval_control",
    },
  });
}

function rustApprovalLease(authority, runtimeError, operation) {
  const lease =
    objectRecord(authority?.approval_lease) ??
    objectRecord(authority?.authority?.approval_lease);
  if (lease) return lease;
  throw runtimeError({
    status: 502,
    code: "approval_rust_lease_authority_incomplete",
    message: "Rust approval authority did not return an approval lease record.",
    details: {
      operation,
      rust_core_boundary: "runtime.approval_control",
    },
  });
}

function rustApprovalLeaseId(authority, approvalLease, runtimeError, operation) {
  const leaseId =
    optionalString(authority?.lease_id ?? authority?.authority?.lease_id) ??
    optionalString(approvalLease?.lease_id);
  if (leaseId) return leaseId;
  throw runtimeError({
    status: 502,
    code: "approval_rust_lease_id_missing",
    message: "Rust approval authority did not bind a lease id.",
    details: {
      operation,
      rust_core_boundary: "runtime.approval_control",
    },
  });
}

function rustApprovalLeaseStatus(authority, runtimeError, operation) {
  const leaseStatus = optionalString(authority?.lease_status ?? authority?.authority?.lease_status);
  if (leaseStatus) return leaseStatus;
  throw runtimeError({
    status: 502,
    code: "approval_rust_lease_status_missing",
    message: "Rust approval authority did not bind a lease status.",
    details: {
      operation,
      rust_core_boundary: "runtime.approval_control",
    },
  });
}
