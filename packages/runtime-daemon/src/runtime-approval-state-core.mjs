export const APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-request-state-update-request.v1";
export const APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-decision-state-update-request.v1";
export const APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-revoke-state-update-request.v1";
export const APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-queue-projection-request.v1";
export const APPROVAL_REQUEST_AUTHORITY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-request-authority-request.v1";
export const APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-decision-authority-request.v1";
export const RUNTIME_APPROVAL_STATE_BACKEND = "rust_authority";
export const APPROVAL_REQUEST_STATE_UPDATE_API_METHOD = "planApprovalRequestStateUpdate";
export const APPROVAL_DECISION_STATE_UPDATE_API_METHOD = "planApprovalDecisionStateUpdate";
export const APPROVAL_REVOKE_STATE_UPDATE_API_METHOD = "planApprovalRevokeStateUpdate";
export const APPROVAL_QUEUE_PROJECTION_API_METHOD = "projectApprovalQueue";
export const APPROVAL_REQUEST_AUTHORITY_API_METHOD = "authorizeApprovalRequest";
export const APPROVAL_DECISION_AUTHORITY_API_METHOD = "authorizeApprovalDecision";

const RETIRED_APPROVAL_STATE_CORE_REQUEST_ALIASES = [
  "request",
  "approvalRequest",
  "approval_request_wrapper",
  "approvalDecision",
  "approval_decision_wrapper",
  "approvalRevoke",
  "approval_revoke_wrapper",
  "queueProjection",
  "queue_projection_wrapper",
  "schemaVersion",
  "approvalId",
  "eventId",
  "createdAt",
  "receiptRefs",
  "policyDecisionRefs",
  "runId",
  "targetKind",
  "includeResolved",
  "expectedHead",
  "stateRootBefore",
  "leaseId",
  "leaseStatus",
  "authorityRecord",
  "authorityHash",
  "authorityGrantRefs",
  "authorityReceiptRefs",
  "walletNetworkGrantRefs",
  "directTruthWriteAllowed",
  "actorRef",
  "idempotencyKey",
  "threadId",
];

const RETIRED_APPROVAL_STATE_CORE_TRUTH_FIELDS = [
  "record",
  "commit",
  "approvals",
  "pending_count",
  "resolved_count",
  "operator_control",
  "direct_truth_write_allowed",
  "wallet_network_grant_refs",
];

export function createRuntimeApprovalStateCore(options = {}) {
  return new RuntimeApprovalStateCore(options);
}

export class RuntimeApprovalStateCore {
  constructor(options = {}) {
    assertNoRetiredApprovalStateCoreOption("command", options.command);
    assertNoRetiredApprovalStateCoreOption("args", options.args);
    assertNoRetiredApprovalStateCoreOption("daemonCoreInvoker", options.daemonCoreInvoker);
    assertNoRetiredApprovalStateCoreOption("daemonCoreApi", options.daemonCoreApi);
    this.daemonCoreApprovalApi = approvalApi(options.daemonCoreApprovalApi);
  }

  planApprovalRequestStateUpdate(request = {}) {
    assertCanonicalApprovalStateCoreRequest(request);
    return assertApprovalStateCoreOperationKind(this.invokeRustApprovalApi(
      APPROVAL_REQUEST_STATE_UPDATE_API_METHOD,
      {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      },
    ), "approval.required", "approval_request_state_update");
  }

  planApprovalDecisionStateUpdate(request = {}) {
    assertCanonicalApprovalStateCoreRequest(request);
    return assertApprovalStateCoreOperationKind(this.invokeRustApprovalApi(
      APPROVAL_DECISION_STATE_UPDATE_API_METHOD,
      {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      },
    ), ["approval.approve", "approval.reject"], "approval_decision_state_update");
  }

  planApprovalRevokeStateUpdate(request = {}) {
    assertCanonicalApprovalStateCoreRequest(request);
    return assertApprovalStateCoreOperationKind(this.invokeRustApprovalApi(
      APPROVAL_REVOKE_STATE_UPDATE_API_METHOD,
      {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      },
    ), "approval.revoke", "approval_revoke_state_update");
  }

  projectApprovalQueue(request = {}) {
    assertCanonicalApprovalStateCoreRequest(request);
    return assertApprovalStateCoreOperationKind(this.invokeRustApprovalApi(
      APPROVAL_QUEUE_PROJECTION_API_METHOD,
      {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    ), "approval.queue_projection", "approval_queue_projection");
  }

  authorizeApprovalRequest(request = {}) {
    assertCanonicalApprovalStateCoreRequest(request);
    return assertApprovalStateCoreOperationKind(this.invokeRustApprovalApi(
      APPROVAL_REQUEST_AUTHORITY_API_METHOD,
      {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_REQUEST_AUTHORITY_REQUEST_SCHEMA_VERSION,
      },
    ), "approval.request.authority", "approval_request_authority");
  }

  authorizeApprovalDecision(request = {}) {
    assertCanonicalApprovalStateCoreRequest(request);
    return assertApprovalStateCoreOperationKind(this.invokeRustApprovalApi(
      APPROVAL_DECISION_AUTHORITY_API_METHOD,
      {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION,
      },
    ), "approval.decision.authority", "approval_decision_authority");
  }

  invokeRustApprovalApi(method, request) {
    const invoke = this.daemonCoreApprovalApi?.[method];
    if (typeof invoke !== "function") {
      throw new RuntimeApprovalStateCoreError(
        `Approval state control requires daemonCoreApprovalApi.${method} for Rust daemon-core wallet.network authority, Agentgres state updates, and approval queue projection.`,
        "approval_state_core_direct_approval_api_unconfigured",
        { boundary: `daemonCoreApprovalApi.${method}`, backend: RUNTIME_APPROVAL_STATE_BACKEND },
      );
    }
    const response = invoke.call(this.daemonCoreApprovalApi, request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeApprovalStateCoreError(
        error.message ?? "Rust approval state core rejected the request.",
        error.code ?? "approval_state_core_direct_approval_api_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalApprovalStateCoreRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_APPROVAL_STATE_CORE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  const retiredTruthFields = RETIRED_APPROVAL_STATE_CORE_TRUTH_FIELDS.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0 && retiredTruthFields.length === 0) return;
  throw new RuntimeApprovalStateCoreError(
    "Approval state core request aliases and Rust-owned truth fields are retired; use canonical snake_case request facts and Rust-derived approval truth.",
    "approval_state_core_request_fields_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      retired_truth_fields: retiredTruthFields,
      canonical_fields: [
        "schema_version",
        "target_kind",
        "thread_id",
        "run_id",
        "agent",
        "run",
        "event_id",
        "seq",
        "created_at",
        "approval_id",
        "source",
        "reason",
        "receipt_refs",
        "policy_decision_refs",
        "lease_id",
        "lease_status",
        "lease_ttl_ms",
        "expires_at",
        "approval_lease",
        "wallet_approval_grant",
        "action",
        "scope",
        "authority_scope_requirements",
        "decision",
        "status",
        "authority_record",
        "authority_hash",
        "authority_grant_refs",
        "authority_receipt_refs",
        "state_dir",
        "include_resolved",
        "expected_head",
        "state_root_before",
      ],
      derived_by: RUNTIME_APPROVAL_STATE_BACKEND,
    },
  );
}

function assertApprovalStateCoreOperationKind(value = {}, expectedOperationKind, codePrefix) {
  const expectedOperationKinds = Array.isArray(expectedOperationKind)
    ? expectedOperationKind
    : [expectedOperationKind];
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? {};
  const authority = objectRecord(result.authority) ?? {};
  const operationKind = optionalString(
    result.operation_kind ?? record.operation_kind ?? authority.operation_kind,
  );
  if (!operationKind) {
    throw new RuntimeApprovalStateCoreError(
      "Rust approval state core result did not include an operation kind.",
      `${codePrefix}_operation_kind_missing`,
      { operationKind: expectedOperationKinds[0], expectedOperationKinds },
    );
  }
  if (!expectedOperationKinds.includes(operationKind)) {
    throw new RuntimeApprovalStateCoreError(
      "Rust approval state core result included an unexpected operation kind.",
      `${codePrefix}_operation_kind_mismatch`,
      { expectedOperationKind: expectedOperationKinds[0], expectedOperationKinds, operationKind },
    );
  }
  return value;
}

function assertNoRetiredApprovalStateCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeApprovalStateCoreError(
    "Approval state command compatibility options are retired; use daemonCoreApprovalApi for direct Rust daemon-core approval authority and projection.",
    "approval_state_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class RuntimeApprovalStateCoreError extends Error {
  constructor(message, code = "approval_state_core_error", details = {}) {
    super(message);
    this.name = "RuntimeApprovalStateCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function approvalApi(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
