import assert from "node:assert/strict";
import test from "node:test";

import {
  APPROVAL_DECISION_AUTHORITY_API_METHOD,
  APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION,
  APPROVAL_DECISION_STATE_UPDATE_API_METHOD,
  APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  APPROVAL_QUEUE_PROJECTION_API_METHOD,
  APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION,
  APPROVAL_REQUEST_AUTHORITY_API_METHOD,
  APPROVAL_REQUEST_AUTHORITY_REQUEST_SCHEMA_VERSION,
  APPROVAL_REQUEST_STATE_UPDATE_API_METHOD,
  APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  APPROVAL_REVOKE_STATE_UPDATE_API_METHOD,
  APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_APPROVAL_STATE_BACKEND,
  RuntimeApprovalStateCore,
  RuntimeApprovalStateCoreError,
  createRuntimeApprovalStateCore,
} from "./runtime-approval-state-core.mjs";

const WALLET_APPROVAL_GRANT_HASH = "sha256:wallet-approval-grant-alpha";
const WALLET_APPROVAL_GRANT_REF =
  "wallet.network://grant/approval/wallet-approval-grant-alpha";

function walletApprovalGrant() {
  return {
    schema_version: 1,
    authority_id: Array.from({ length: 32 }, (_, index) => index + 1),
    request_hash: Array.from({ length: 32 }, () => 1),
    policy_hash: Array.from({ length: 32 }, () => 2),
    audience: Array.from({ length: 32 }, () => 3),
    nonce: Array.from({ length: 32 }, () => 4),
    counter: 1,
    expires_at: 1850000000000,
    max_usages: 1,
    window_id: 9,
    approver_public_key: Array.from({ length: 32 }, () => 7),
    approver_sig: Array.from({ length: 64 }, () => 8),
    approver_suite: -8,
  };
}

function approvalRequest() {
  const authority = approvalRequestAuthorityResult(approvalRequestAuthorityRequest());
  return {
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run: { id: "run_alpha", status: "running", trace: {} },
    event_id: "event_approval",
    seq: 3,
    created_at: "2026-06-06T04:30:00.000Z",
    approval_id: "approval_alpha",
    source: "runtime_auto",
    reason: "Need permission",
    receipt_refs: authority.authority_receipt_refs,
    policy_decision_refs: authority.policy_decision_refs,
    authority_record: authority.authority,
    authority_hash: authority.authority_hash,
    authority_grant_refs: [],
    authority_receipt_refs: authority.authority_receipt_refs,
  };
}

function approvalRequestResult(request) {
  return {
    source: "rust_approval_request_state_update_protocol",
    backend: RUNTIME_APPROVAL_STATE_BACKEND,
    status: "planned",
    operation_kind: "approval.required",
    target_kind: "run",
    updated_at: request.created_at,
    operator_control: {
      control: "approval_request",
      approval_id: request.approval_id,
      event_id: request.event_id,
    },
    run: {
      ...request.run,
      status: "blocked",
      turnStatus: "waiting_for_approval",
      trace: {
        approvalRequests: [
          {
            approval_id: request.approval_id,
            event_id: request.event_id,
          },
        ],
      },
    },
  };
}

function approvalRequestAuthorityRequest() {
  return {
    thread_id: "thread_alpha",
    approval_id: "approval_alpha",
    target_kind: "run",
    run_id: "run_alpha",
    actor_ref: "operator://local/heath",
    idempotency_key: "approval:thread_alpha:approval_alpha:request",
    receipt_refs: ["receipt://authority/approval-request/approval_alpha"],
    policy_decision_refs: ["policy_approval"],
    approval_manifest: {
      approval_id: "approval_alpha",
      thread_id: "thread_alpha",
    },
    authority_context: {
      surface: "runtime.approval_control",
    },
  };
}

function approvalRequestAuthorityResult(request) {
  return {
    schema_version: "ioi.runtime.approval-request-authority.v1",
    object: "ioi.runtime_approval_request_authority",
    source: "rust_approval_request_authority_protocol",
    backend: RUNTIME_APPROVAL_STATE_BACKEND,
    status: "issued",
    operation_kind: "approval.request.authority",
    thread_id: request.thread_id,
    approval_id: request.approval_id,
    target_kind: request.target_kind,
    run_id: request.run_id,
    actor_ref: request.actor_ref,
    idempotency_key: request.idempotency_key,
    receipt_refs: request.receipt_refs,
    authority_receipt_refs: request.receipt_refs,
    policy_decision_refs: request.policy_decision_refs,
    direct_truth_write_allowed: false,
    authority_hash: "sha256:approval-request-authority",
    authority: {
      schema_version: "ioi.runtime.approval-request-authority.v1",
      object: "ioi.runtime_approval_request_authority",
      status: "issued",
      operation_kind: "approval.request.authority",
      thread_id: request.thread_id,
      approval_id: request.approval_id,
      authority_receipt_refs: request.receipt_refs,
      policy_decision_refs: request.policy_decision_refs,
      direct_truth_write_allowed: false,
      authority_hash: "sha256:approval-request-authority",
    },
  };
}

function approvalDecisionAuthorityRequest(decision = "approve") {
  return {
    thread_id: "thread_alpha",
    approval_id: "approval_alpha",
    decision,
    target_kind: "run",
    run_id: "run_alpha",
    actor_ref: "operator://local/heath",
    idempotency_key: `approval:thread_alpha:approval_alpha:${decision}`,
    wallet_approval_grant: walletApprovalGrant(),
    authority_grant_refs: [],
    authority_receipt_refs: ["receipt://wallet.network/approval/approval_alpha"],
    policy_decision_refs: ["policy_wallet_approval"],
    approval_request: {
      approval_id: "approval_alpha",
      thread_id: "thread_alpha",
      seq: 3,
      receipt_refs: ["receipt_approval"],
      policy_decision_refs: ["policy_approval"],
    },
    latest_decision: null,
  };
}

function approvalDecisionAuthorityResult(request) {
  const walletGrantRefs = [WALLET_APPROVAL_GRANT_REF];
  const walletGrantHash = WALLET_APPROVAL_GRANT_HASH;
  const walletGrantRef = WALLET_APPROVAL_GRANT_REF;
  return {
    schema_version: "ioi.runtime.approval-decision-authority.v1",
    object: "ioi.runtime_approval_decision_authority",
    source: "rust_approval_decision_authority_protocol",
    backend: RUNTIME_APPROVAL_STATE_BACKEND,
    status: "authorized",
    operation_kind: "approval.decision.authority",
    thread_id: request.thread_id,
    approval_id: request.approval_id,
    decision: request.decision,
    target_kind: request.target_kind,
    run_id: request.run_id,
    actor_ref: request.actor_ref,
    idempotency_key: request.idempotency_key,
    wallet_approval_grant_hash: walletGrantHash,
    wallet_approval_grant_ref: walletGrantRef,
    wallet_network_grant_refs: walletGrantRefs,
    authority_receipt_refs: request.authority_receipt_refs,
    policy_decision_refs: request.policy_decision_refs,
    direct_truth_write_allowed: false,
    authority_hash: "sha256:approval-authority",
    authority: {
      schema_version: "ioi.runtime.approval-decision-authority.v1",
      object: "ioi.runtime_approval_decision_authority",
      status: "authorized",
      operation_kind: "approval.decision.authority",
      thread_id: request.thread_id,
      approval_id: request.approval_id,
      decision: request.decision,
      wallet_approval_grant_hash: walletGrantHash,
      wallet_approval_grant_ref: walletGrantRef,
      wallet_network_grant_refs: walletGrantRefs,
      authority_receipt_refs: request.authority_receipt_refs,
      policy_decision_refs: request.policy_decision_refs,
      direct_truth_write_allowed: false,
      authority_hash: "sha256:approval-authority",
    },
  };
}

function approvalDecisionRequest() {
  const authority = approvalDecisionAuthorityResult(approvalDecisionAuthorityRequest());
  return {
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run: { id: "run_alpha", trace: {} },
    event_id: "event_decision",
    seq: 4,
    created_at: "2026-06-06T04:35:00.000Z",
    approval_id: "approval_alpha",
    lease_id: "lease_alpha",
    lease_status: "active",
    decision: "approve",
    status: "approved",
    source: "runtime_auto",
    reason: "Looks good",
    receipt_refs: authority.authority_receipt_refs,
    policy_decision_refs: authority.policy_decision_refs,
    authority_record: authority.authority,
    authority_hash: authority.authority_hash,
    authority_grant_refs: authority.wallet_network_grant_refs,
    authority_receipt_refs: authority.authority_receipt_refs,
  };
}

function approvalDecisionResult(request) {
  return {
    source: "rust_approval_decision_state_update_protocol",
    backend: RUNTIME_APPROVAL_STATE_BACKEND,
    status: "planned",
    operation_kind: "approval.approve",
    target_kind: "run",
    updated_at: request.created_at,
    operator_control: {
      control: "approval_decision",
      approval_id: request.approval_id,
      lease_id: request.lease_id,
      event_id: request.event_id,
      authority_hash: request.authority_hash,
    },
    run: {
      ...request.run,
      trace: {
        approvalDecisions: [
          {
            approval_id: request.approval_id,
            event_id: request.event_id,
          },
        ],
      },
    },
  };
}

function approvalRevokeRequest() {
  const authority = approvalDecisionAuthorityResult(approvalDecisionAuthorityRequest("revoke"));
  return {
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run: { id: "run_alpha", trace: {} },
    event_id: "event_revoke",
    seq: 5,
    created_at: "2026-06-06T04:40:00.000Z",
    approval_id: "approval_alpha",
    lease_id: "lease_alpha",
    source: "runtime_auto",
    reason: "Changed my mind",
    receipt_refs: authority.authority_receipt_refs,
    policy_decision_refs: authority.policy_decision_refs,
    authority_record: authority.authority,
    authority_hash: authority.authority_hash,
    authority_grant_refs: authority.wallet_network_grant_refs,
    authority_receipt_refs: authority.authority_receipt_refs,
  };
}

function approvalRevokeResult(request) {
  return {
    source: "rust_approval_revoke_state_update_protocol",
    backend: RUNTIME_APPROVAL_STATE_BACKEND,
    status: "planned",
    operation_kind: "approval.revoke",
    target_kind: "run",
    updated_at: request.created_at,
    operator_control: {
      control: "approval_revoke",
      approval_id: request.approval_id,
      lease_id: request.lease_id,
      lease_status: "revoked",
      event_id: request.event_id,
      authority_hash: request.authority_hash,
    },
    run: {
      ...request.run,
      turnStatus: "waiting_for_input",
      trace: {
        approvalRevocations: [
          {
            approval_id: request.approval_id,
            event_id: request.event_id,
          },
        ],
      },
    },
  };
}

function approvalQueueRequest() {
  return {
    thread_id: "thread_alpha",
    state_dir: "/runtime-state",
    include_resolved: false,
    expected_head: "agentgres://head/before",
    state_root_before: "state://root/before",
  };
}

function approvalQueueResult(request) {
  return {
    source: "rust_approval_queue_projection_protocol",
    backend: RUNTIME_APPROVAL_STATE_BACKEND,
    status: "projected",
    operation_kind: "approval.queue_projection",
    thread_id: request.thread_id,
    approvals: [
      {
        schema_version: "ioi.runtime.approval-queue-entry.v1",
        thread_id: request.thread_id,
        approval_id: "approval_alpha",
        status: "pending",
        decision: null,
        request_event_id: "event_approval",
      },
    ],
    pending_count: 1,
    resolved_count: 0,
    expected_head: request.expected_head,
    state_root_before: request.state_root_before,
  };
}

test("approval state core calls typed Rust daemon-core approval request API", () => {
  let captured = null;
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_REQUEST_STATE_UPDATE_API_METHOD](request) {
        captured = request;
        return approvalRequestResult(request);
      },
    },
  });

  const result = core.planApprovalRequestStateUpdate(approvalRequest());

  assert.equal(captured.schema_version, APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.approval_id, "approval_alpha");
  assert.equal(Object.hasOwn(captured, "approvalId"), false);
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.operation_kind, "approval.required");
  assert.equal(result.operator_control.approval_id, "approval_alpha");
});

test("approval state core calls typed Rust daemon-core approval request authority API", () => {
  let captured = null;
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_REQUEST_AUTHORITY_API_METHOD](request) {
        captured = request;
        return approvalRequestAuthorityResult(request);
      },
    },
  });

  const result = core.authorizeApprovalRequest(approvalRequestAuthorityRequest());

  assert.equal(captured.schema_version, APPROVAL_REQUEST_AUTHORITY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.approval_id, "approval_alpha");
  assert.deepEqual(captured.receipt_refs, [
    "receipt://authority/approval-request/approval_alpha",
  ]);
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.operation_kind, "approval.request.authority");
  assert.equal(result.authority_hash, "sha256:approval-request-authority");
});

test("approval state core calls typed Rust daemon-core wallet.network decision authority API", () => {
  let captured = null;
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_DECISION_AUTHORITY_API_METHOD](request) {
        captured = request;
        return approvalDecisionAuthorityResult(request);
      },
    },
  });

  const result = core.authorizeApprovalDecision(approvalDecisionAuthorityRequest());

  assert.equal(captured.schema_version, APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.approval_id, "approval_alpha");
  assert.deepEqual(captured.wallet_approval_grant, walletApprovalGrant());
  assert.deepEqual(captured.authority_grant_refs, []);
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.operation_kind, "approval.decision.authority");
  assert.equal(result.authority_hash, "sha256:approval-authority");
});

test("approval state core calls typed Rust daemon-core approval decision state API", () => {
  let captured = null;
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_DECISION_STATE_UPDATE_API_METHOD](request) {
        captured = request;
        return approvalDecisionResult(request);
      },
    },
  });

  const result = core.planApprovalDecisionStateUpdate(approvalDecisionRequest());

  assert.equal(captured.schema_version, APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.decision, "approve");
  assert.equal(captured.authority_hash, "sha256:approval-authority");
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.operation_kind, "approval.approve");
  assert.equal(result.operator_control.lease_id, "lease_alpha");
});

test("approval state core calls typed Rust daemon-core approval revoke state API", () => {
  let captured = null;
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_REVOKE_STATE_UPDATE_API_METHOD](request) {
        captured = request;
        return approvalRevokeResult(request);
      },
    },
  });

  const result = core.planApprovalRevokeStateUpdate(approvalRevokeRequest());

  assert.equal(captured.schema_version, APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.approval_id, "approval_alpha");
  assert.equal(captured.authority_hash, "sha256:approval-authority");
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.operation_kind, "approval.revoke");
  assert.equal(result.operator_control.lease_status, "revoked");
});

test("approval state core calls typed Rust daemon-core approval queue projection API", () => {
  let captured = null;
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_QUEUE_PROJECTION_API_METHOD](request) {
        captured = request;
        return approvalQueueResult(request);
      },
    },
  });

  const result = core.projectApprovalQueue(approvalQueueRequest());

  assert.equal(captured.schema_version, APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.thread_id, "thread_alpha");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "agent"), false);
  assert.equal(Object.hasOwn(captured, "run"), false);
  assert.equal(Object.hasOwn(captured, "runs"), false);
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.include_resolved, false);
  assert.equal(result.operation_kind, "approval.queue_projection");
  assert.equal(result.pending_count, 1);
});

test("approval state core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    record: {
      operation_kind: "approval.queue_projection",
      thread_id: "thread_alpha",
    },
  };
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_QUEUE_PROJECTION_API_METHOD]() {
        return rustEnvelope;
      },
    },
  });

  const result = core.projectApprovalQueue(approvalQueueRequest());

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "approvals"), false);
  assert.equal(Object.hasOwn(result, "pending_count"), false);
  assert.equal(Object.hasOwn(result, "resolved_count"), false);
});

test("approval state core rejects retired compatibility options", () => {
  assert.throws(
    () => new RuntimeApprovalStateCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeApprovalStateCoreError &&
      error.code === "approval_state_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeApprovalStateCore({ args: ["--approval-state"] }),
    (error) =>
      error instanceof RuntimeApprovalStateCoreError &&
      error.code === "approval_state_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeApprovalStateCore({ daemonCoreInvoker() {} }),
    (error) =>
      error instanceof RuntimeApprovalStateCoreError &&
      error.code === "approval_state_core_compatibility_option_retired",
  );
});

test("approval state core rejects retired request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_REQUEST_STATE_UPDATE_API_METHOD]() {
        calls.push("invoked");
        return {};
      },
    },
  });

  assert.throws(
    () =>
      core.planApprovalRequestStateUpdate({
        ...approvalRequest(),
        request: approvalRequest(),
        schemaVersion: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        approvalId: "approval_alias",
        eventId: "event_alias",
        receiptRefs: ["receipt_alias"],
        operator_control: {},
        record: {},
        pending_count: 1,
      }),
    (error) =>
      error.code === "approval_state_core_request_fields_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("request") &&
      error.details.retired_aliases.includes("schemaVersion") &&
      error.details.retired_aliases.includes("approvalId") &&
      error.details.retired_aliases.includes("eventId") &&
      error.details.retired_aliases.includes("receiptRefs") &&
      error.details.retired_truth_fields.includes("operator_control") &&
      error.details.retired_truth_fields.includes("record") &&
      error.details.retired_truth_fields.includes("pending_count"),
  );
  assert.deepEqual(calls, []);
});

test("approval state core fails closed without direct daemon-core API", () => {
  const core = createRuntimeApprovalStateCore({});

  assert.throws(
    () => core.planApprovalRequestStateUpdate(approvalRequest()),
    (error) =>
      error instanceof RuntimeApprovalStateCoreError &&
      error.code === "approval_state_core_direct_approval_api_unconfigured",
  );
});

test("approval state core fails closed without Rust-planned operation kinds", () => {
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_REQUEST_STATE_UPDATE_API_METHOD]() {
        return { status: "planned" };
      },
    },
  });

  assert.throws(
    () => core.planApprovalRequestStateUpdate(approvalRequest()),
    (error) => {
      assert.equal(error.code, "approval_request_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.required");
      return true;
    },
  );
});

test("approval state core fails closed on mismatched Rust operation kind", () => {
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_DECISION_STATE_UPDATE_API_METHOD]() {
        return { operation_kind: "approval.required" };
      },
    },
  });

  assert.throws(
    () => core.planApprovalDecisionStateUpdate(approvalDecisionRequest()),
    (error) => {
      assert.equal(error.code, "approval_decision_state_update_operation_kind_mismatch");
      assert.equal(error.details.expectedOperationKind, "approval.approve");
      assert.deepEqual(error.details.expectedOperationKinds, ["approval.approve", "approval.reject"]);
      assert.equal(error.details.operationKind, "approval.required");
      return true;
    },
  );
});

test("approval state core surfaces Rust wallet.network rejection", () => {
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_DECISION_AUTHORITY_API_METHOD]() {
        return {
          ok: false,
          error: {
            code: "approval_decision_authority_invalid",
            message: "MissingWalletNetworkAuthority",
          },
        };
      },
    },
  });

  assert.throws(
    () => core.authorizeApprovalDecision(approvalDecisionAuthorityRequest()),
    (error) =>
      error.code === "approval_decision_authority_invalid" &&
      error.message === "MissingWalletNetworkAuthority",
  );
});

test("approval state core surfaces Rust approval request authority rejection", () => {
  const core = createRuntimeApprovalStateCore({
    daemonCoreApprovalApi: {
      [APPROVAL_REQUEST_AUTHORITY_API_METHOD]() {
        return {
          ok: false,
          error: {
            code: "approval_request_authority_invalid",
            message: "MissingAuthorityReceipt",
          },
        };
      },
    },
  });

  assert.throws(
    () => core.authorizeApprovalRequest({ ...approvalRequestAuthorityRequest(), receipt_refs: [] }),
    (error) =>
      error.code === "approval_request_authority_invalid" &&
      error.message === "MissingAuthorityReceipt",
  );
});
