function defaultOptionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function defaultNormalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function defaultSafeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

export function createRuntimeApprovalLease(deps = {}) {
  const doctorHash = deps.doctorHash || ((value) => String(value ?? ""));
  const normalizeArray = deps.normalizeArray || defaultNormalizeArray;
  const optionalPositiveInteger = deps.optionalPositiveInteger || ((value) => {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 ? number : null;
  });
  const optionalString = deps.optionalString || defaultOptionalString;
  const runtimeError = deps.runtimeError || ((payload) => {
    const error = new Error(payload?.message || "Runtime error");
    Object.assign(error, payload);
    return error;
  });
  const safeId = deps.safeId || defaultSafeId;
  const uniqueStrings = deps.uniqueStrings || ((values = []) => [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))]);

  function approvalLeaseMetadataForRequest({ request = {}, approvalId, action, scope, now, threadId } = {}) {
    const ttlMs = optionalPositiveInteger(
      request.ttl_ms ?? request.ttlMs ?? request.lease_ttl_ms ?? request.leaseTtlMs,
    );
    const expiresAt =
      optionalString(request.expires_at ?? request.expiresAt) ??
      (ttlMs ? new Date(Date.parse(now) + ttlMs).toISOString() : null);
    const expectedReceiptRefs = uniqueStrings(
      normalizeArray(request.expected_receipt_refs ?? request.expectedReceiptRefs),
    );
    const authorityScopeRequirements = uniqueStrings(
      normalizeArray(request.authority_scope_requirements ?? request.authorityScopeRequirements),
    );
    const leaseId =
      optionalString(request.lease_id ?? request.leaseId) ??
      `approval_lease_${safeId(approvalId)}`;
    const policyHash =
      optionalString(request.policy_hash ?? request.policyHash) ??
      doctorHash(
        JSON.stringify({
          approvalId,
          action,
          scope,
          threadId,
          authorityScopeRequirements,
          expectedReceiptRefs,
          ttlMs,
          expiresAt,
        }),
      );
    return {
      schema_version: "ioi.runtime.approval-lease.v1",
      schemaVersion: "ioi.runtime.approval-lease.v1",
      lease_id: leaseId,
      leaseId,
      approval_id: approvalId,
      approvalId,
      status: "pending",
      action,
      scope,
      policy_hash: policyHash,
      policyHash,
      ttl_ms: ttlMs,
      ttlMs,
      expires_at: expiresAt,
      expiresAt,
      expected_receipt_refs: expectedReceiptRefs,
      expectedReceiptRefs,
      authority_scope_requirements: authorityScopeRequirements,
      authorityScopeRequirements,
      revoke_endpoint: `/v1/threads/${threadId}/approvals/${encodeURIComponent(approvalId)}/revoke`,
      revokeEndpoint: `/v1/threads/${threadId}/approvals/${encodeURIComponent(approvalId)}/revoke`,
      created_at: now,
      createdAt: now,
    };
  }

  function approvalLeaseMetadataFromPayload(payload = {}, approvalId, threadId) {
    const lease =
      payload.approval_lease && typeof payload.approval_lease === "object"
        ? payload.approval_lease
        : payload.approvalLease && typeof payload.approvalLease === "object"
          ? payload.approvalLease
          : {};
    const leaseId =
      optionalString(lease.lease_id ?? lease.leaseId ?? payload.lease_id ?? payload.leaseId) ??
      `approval_lease_${safeId(approvalId)}`;
    const policyHash =
      optionalString(lease.policy_hash ?? lease.policyHash ?? payload.policy_hash ?? payload.policyHash) ??
      null;
    const ttlMs = optionalPositiveInteger(lease.ttl_ms ?? lease.ttlMs ?? payload.ttl_ms ?? payload.ttlMs);
    const expiresAt =
      optionalString(lease.expires_at ?? lease.expiresAt ?? payload.expires_at ?? payload.expiresAt) ??
      null;
    const expectedReceiptRefs = uniqueStrings(
      normalizeArray(
        lease.expected_receipt_refs ??
          lease.expectedReceiptRefs ??
          payload.expected_receipt_refs ??
          payload.expectedReceiptRefs,
      ),
    );
    const authorityScopeRequirements = uniqueStrings(
      normalizeArray(
        lease.authority_scope_requirements ??
          lease.authorityScopeRequirements ??
          payload.authority_scope_requirements ??
          payload.authorityScopeRequirements,
      ),
    );
    return {
      schema_version: "ioi.runtime.approval-lease.v1",
      schemaVersion: "ioi.runtime.approval-lease.v1",
      lease_id: leaseId,
      leaseId,
      approval_id: approvalId,
      approvalId,
      action: optionalString(lease.action ?? payload.action) ?? null,
      scope: optionalString(lease.scope ?? payload.scope) ?? "thread",
      policy_hash: policyHash,
      policyHash,
      ttl_ms: ttlMs,
      ttlMs,
      expires_at: expiresAt,
      expiresAt,
      expected_receipt_refs: expectedReceiptRefs,
      expectedReceiptRefs,
      authority_scope_requirements: authorityScopeRequirements,
      authorityScopeRequirements,
      revoke_endpoint: `/v1/threads/${threadId}/approvals/${encodeURIComponent(approvalId)}/revoke`,
      revokeEndpoint: `/v1/threads/${threadId}/approvals/${encodeURIComponent(approvalId)}/revoke`,
    };
  }

  function approvalLeaseStateForDecision({
    threadId,
    approvalId,
    approvalRequestEvent,
    latestDecision,
  }) {
    const decisionPayload = latestDecision?.payload_summary ?? latestDecision?.payload ?? {};
    const requestPayload = approvalRequestEvent?.payload_summary ?? approvalRequestEvent?.payload ?? {};
    const decisionLease = approvalLeaseMetadataFromPayload(decisionPayload, approvalId, threadId);
    const requestLease = approvalLeaseMetadataFromPayload(requestPayload, approvalId, threadId);
    const leaseId =
      optionalString(decisionLease.lease_id ?? decisionLease.leaseId) ??
      optionalString(requestLease.lease_id ?? requestLease.leaseId) ??
      null;
    const expiresAt =
      optionalString(decisionLease.expires_at ?? decisionLease.expiresAt) ??
      optionalString(requestLease.expires_at ?? requestLease.expiresAt) ??
      null;
    const expiresMs = expiresAt ? Date.parse(expiresAt) : Number.NaN;
    return {
      leaseId,
      expiresAt,
      expired: Number.isFinite(expiresMs) && expiresMs <= Date.now(),
    };
  }

  function approvalReasonForDecisionEvent(event) {
    if (event?.event_kind === "approval.approved") return "approval_approved";
    if (event?.event_kind === "approval.revoked") return "approval_revoked";
    return "approval_rejected";
  }

  function approvalDecisionForRequest(value) {
    const decision = optionalString(value)?.toLowerCase();
    if (["approve", "approved", "accept", "accepted", "allow", "allowed"].includes(decision)) {
      return "approve";
    }
    if (["reject", "rejected", "deny", "denied", "block", "blocked"].includes(decision)) {
      return "reject";
    }
    throw runtimeError({
      status: 400,
      code: "approval_decision_invalid",
      message: "Approval decisions must be approve or reject.",
      details: { decision: value ?? null },
    });
  }

  return {
    approvalDecisionForRequest,
    approvalLeaseMetadataForRequest,
    approvalLeaseMetadataFromPayload,
    approvalLeaseStateForDecision,
    approvalReasonForDecisionEvent,
  };
}
