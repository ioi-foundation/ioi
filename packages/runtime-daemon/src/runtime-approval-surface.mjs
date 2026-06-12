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
    approvalDecisionForRequest,
    approvalStateRunner = null,
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
    const target = approvalTarget(store, threadId, request);
    const record = requireApprovalStateRunner(
      "planApprovalRequestStateUpdate",
      "approval_request",
      "approval.required",
      threadId,
      approvalId,
    ).planApprovalRequestStateUpdate({
      target_kind: target.target_kind,
      thread_id: threadId,
      run_id: target.run_id,
      run: target.run,
      agent: target.agent,
      event_id: approvalEventId(request, approvalId, "request"),
      seq: approvalSeq(request),
      created_at: approvalCreatedAt(request),
      approval_id: approvalId,
      source: approvalSource(request),
      reason: optionalString(request.reason) ?? "operator requested approval",
      receipt_refs: normalizeArray(request.receipt_refs),
      policy_decision_refs: normalizeArray(request.policy_decision_refs),
    });
    return applyRustApprovalStateUpdate(store, record);
  }

  function decideThreadApproval(store, threadId, approvalId, request = {}) {
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRequiredError(runtimeError, threadId);
      })();
    const decision = approvalDecisionForRequest(request.decision);
    const target = approvalTarget(store, threadId, request);
    const eventId = approvalEventId(request, normalizedApprovalId, decision);
    const seq = approvalSeq(request);
    const createdAt = approvalCreatedAt(request);
    const source = approvalSource(request);
    const authority = requireApprovalStateRunner(
      "authorizeApprovalDecision",
      "approval_decision_authority",
      "approval.decision.authority",
      threadId,
      normalizedApprovalId,
    ).authorizeApprovalDecision(approvalDecisionAuthorityRequest({
      threadId,
      approvalId: normalizedApprovalId,
      decision,
      target,
      request,
      eventId,
      seq,
      createdAt,
      source,
    }));
    const record = requireApprovalStateRunner(
      "planApprovalDecisionStateUpdate",
      "approval_decision",
      `approval.${decision}`,
      threadId,
      normalizedApprovalId,
    ).planApprovalDecisionStateUpdate({
      target_kind: target.target_kind,
      thread_id: threadId,
      run_id: target.run_id,
      run: target.run,
      agent: target.agent,
      event_id: eventId,
      seq,
      created_at: createdAt,
      approval_id: normalizedApprovalId,
      lease_id: optionalString(request.lease_id) ?? null,
      lease_status: optionalString(request.lease_status) ?? (decision === "approve" ? "active" : "denied"),
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
    const target = approvalTarget(store, threadId, request);
    const eventId = approvalEventId(request, normalizedApprovalId, "revoke");
    const seq = approvalSeq(request);
    const createdAt = approvalCreatedAt(request);
    const source = approvalSource(request);
    const authority = requireApprovalStateRunner(
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
    const record = requireApprovalStateRunner(
      "planApprovalRevokeStateUpdate",
      "approval_revoke",
      "approval.revoke",
      threadId,
      normalizedApprovalId,
    ).planApprovalRevokeStateUpdate({
      target_kind: target.target_kind,
      thread_id: threadId,
      run_id: target.run_id,
      run: target.run,
      agent: target.agent,
      event_id: eventId,
      seq,
      created_at: createdAt,
      approval_id: normalizedApprovalId,
      lease_id: optionalString(request.lease_id) ?? null,
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
    const target = approvalQueueTarget(store, threadId);
    const record = requireApprovalStateRunner(
      "projectApprovalQueue",
      "approval_queue_projection",
      "approval.queue_projection",
      threadId,
      null,
    ).projectApprovalQueue({
      thread_id: threadId,
      agent: target.agent,
      run: target.run,
      runs: target.runs,
      include_resolved: normalizeBooleanOption(request.include_resolved, false),
      expected_head: optionalString(request.expected_head) ?? null,
      state_root_before: optionalString(request.state_root_before) ?? null,
    });
    return {
      ...record,
      source: record.source ?? "rust_approval_queue_projection_command",
      backend: record.backend ?? "rust_authority",
    };
  }

  return {
    decideThreadApproval,
    listThreadApprovals,
    requestThreadApproval,
    revokeThreadApproval,
  };

  function requireApprovalStateRunner(method, operation, operationKind, threadId, approvalId) {
    if (approvalStateRunner?.[method]) return approvalStateRunner;
    throwApprovalControlRustCoreRequired(operation, operationKind, {
      thread_id: threadId,
      approval_id: approvalId,
      evidence_refs: approvalControlEvidenceRefs(operation),
    });
  }

  function approvalTarget(store, threadId, request = {}) {
    const targetKind = optionalString(request.target_kind) === "agent" ? "agent" : "run";
    if (targetKind === "agent") {
      const agent = objectRecord(request.agent) ?? store.agentForThread?.(threadId) ?? null;
      if (!agent) {
        throw runtimeError({
          status: 404,
          code: "approval_agent_not_found",
          message: "Approval control requires an agent for the requested thread.",
          details: { thread_id: threadId },
        });
      }
      return {
        target_kind: "agent",
        run_id: null,
        run: null,
        agent,
      };
    }
    const runId = optionalString(request.run_id ?? request.run?.id);
    const run = objectRecord(request.run) ??
      (runId ? runForId(store, runId) : latestRunForThread(store, threadId));
    if (!run) {
      throw runtimeError({
        status: 404,
        code: "approval_run_not_found",
        message: "Approval control requires a canonical run for Rust authority planning.",
        details: { thread_id: threadId, run_id: runId ?? null },
      });
    }
    return {
      target_kind: "run",
      run_id: optionalString(run.id) ?? runId ?? null,
      run,
      agent: null,
    };
  }

  function approvalQueueTarget(store, threadId) {
    const agent = store.agentForThread?.(threadId) ?? null;
    if (!agent) {
      throw runtimeError({
        status: 404,
        code: "approval_agent_not_found",
        message: "Approval queue projection requires an agent for the requested thread.",
        details: { thread_id: threadId },
      });
    }
    const runs = agent?.id ? normalizeArray(store.listRuns?.(agent.id)) : [];
    return {
      agent,
      run: runs.at(-1) ?? null,
      runs,
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
      source: value.source ?? record.source ?? "rust_approval_control_api",
      backend: value.backend ?? record.backend ?? "rust_authority",
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

  function runForId(store, runId) {
    if (!runId) return null;
    try {
      return store.getRun?.(runId) ?? store.runs?.get?.(runId) ?? null;
    } catch {
      return store.runs?.get?.(runId) ?? null;
    }
  }

  function latestRunForThread(store, threadId) {
    const agent = store.agentForThread?.(threadId) ?? null;
    if (!agent?.id) return null;
    const runs = store.listRuns?.(agent.id) ?? [];
    return runs.at(-1) ?? null;
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
    authority_grant_refs: normalizeArray(request.authority_grant_refs),
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

function approvalControlEvidenceRefs(operation) {
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
