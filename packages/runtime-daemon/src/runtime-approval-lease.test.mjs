import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeApprovalLease } from "./runtime-approval-lease.mjs";

function createLease() {
  return createRuntimeApprovalLease({
    doctorHash: (value) => `hash_${Buffer.from(String(value)).toString("hex").slice(0, 12)}`,
    normalizeArray: (value) => Array.isArray(value) ? value.filter(Boolean) : [],
    optionalPositiveInteger: (value) => {
      const number = Number(value);
      return Number.isInteger(number) && number > 0 ? number : null;
    },
    optionalString: (value) => {
      if (value === undefined || value === null) return undefined;
      const text = String(value).trim();
      return text || undefined;
    },
    runtimeError: (payload) => {
      const error = new Error(payload.message);
      Object.assign(error, payload);
      return error;
    },
    safeId: (value) => String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_"),
    uniqueStrings: (values = []) => [...new Set((Array.isArray(values) ? values : []).map((value) => String(value)).filter(Boolean))],
  });
}

test("approval lease metadata for request uses canonical fields", () => {
  const lease = createLease();
  const metadata = lease.approvalLeaseMetadataForRequest({
    request: {
      ttl_ms: 1000,
      expected_receipt_refs: ["receipt_1", "receipt_1"],
      authority_scope_requirements: ["workspace.write"],
    },
    approval_id: "approval 1",
    action: "file.write",
    scope: "thread",
    now: "2026-06-03T12:00:00.000Z",
    thread_id: "thread_1",
  });

  assert.equal(metadata.schema_version, "ioi.runtime.approval-lease.v1");
  assert.equal(metadata.lease_id, "approval_lease_approval_1");
  assert.equal(metadata.expires_at, "2026-06-03T12:00:01.000Z");
  assert.equal(metadata.ttl_ms, 1000);
  assert.match(metadata.policy_hash, /^hash_/);
  assert.deepEqual(metadata.expected_receipt_refs, ["receipt_1"]);
  assert.deepEqual(metadata.authority_scope_requirements, ["workspace.write"]);
  assert.equal(metadata.revoke_endpoint, "/v1/threads/thread_1/approvals/approval%201/revoke");
  for (const alias of [
    "schemaVersion",
    "leaseId",
    "approvalId",
    "policyHash",
    "ttlMs",
    "expiresAt",
    "expectedReceiptRefs",
    "authorityScopeRequirements",
    "revokeEndpoint",
    "createdAt",
  ]) {
    assert.equal(Object.hasOwn(metadata, alias), false);
  }
});

test("approval lease metadata for request ignores retired request aliases", () => {
  const lease = createLease();
  const metadata = lease.approvalLeaseMetadataForRequest({
    request: {
      ttlMs: 1000,
      leaseTtlMs: 2000,
      expiresAt: "2026-06-03T12:00:05.000Z",
      expectedReceiptRefs: ["receipt_retired"],
      authorityScopeRequirements: ["scope_retired"],
      leaseId: "lease_retired",
      policyHash: "policy_retired",
    },
    approval_id: "approval 1",
    action: "file.write",
    scope: "thread",
    now: "2026-06-03T12:00:00.000Z",
    thread_id: "thread_1",
  });

  assert.equal(metadata.ttl_ms, null);
  assert.equal(metadata.expires_at, null);
  assert.deepEqual(metadata.expected_receipt_refs, []);
  assert.deepEqual(metadata.authority_scope_requirements, []);
  assert.equal(metadata.lease_id, "approval_lease_approval_1");
  assert.notEqual(metadata.policy_hash, "policy_retired");
});

test("approval lease metadata from payload uses canonical nested and top-level fields", () => {
  const lease = createLease();
  const metadata = lease.approvalLeaseMetadataFromPayload({
    approval_lease: {
      lease_id: "lease_1",
      policy_hash: "policy_hash_1",
      ttl_ms: 500,
      expires_at: "2026-06-03T12:00:05.000Z",
      expected_receipt_refs: ["receipt_nested"],
      authority_scope_requirements: ["scope_nested"],
      action: "shell.run",
      scope: "run",
    },
  }, "approval_1", "thread_1");

  assert.equal(metadata.lease_id, "lease_1");
  assert.equal(metadata.policy_hash, "policy_hash_1");
  assert.equal(metadata.ttl_ms, 500);
  assert.equal(metadata.scope, "run");
  assert.equal(metadata.action, "shell.run");
  assert.deepEqual(metadata.expected_receipt_refs, ["receipt_nested"]);
  assert.deepEqual(metadata.authority_scope_requirements, ["scope_nested"]);
  for (const alias of [
    "schemaVersion",
    "leaseId",
    "policyHash",
    "ttlMs",
    "expiresAt",
    "expectedReceiptRefs",
    "authorityScopeRequirements",
    "revokeEndpoint",
  ]) {
    assert.equal(Object.hasOwn(metadata, alias), false);
  }
});

test("approval lease metadata from payload ignores retired payload aliases", () => {
  const lease = createLease();
  const metadata = lease.approvalLeaseMetadataFromPayload({
    approvalLease: {
      leaseId: "lease_retired",
      policyHash: "policy_retired",
      ttlMs: 500,
      expiresAt: "2026-06-03T12:00:05.000Z",
      expectedReceiptRefs: ["receipt_retired"],
      authorityScopeRequirements: ["scope_retired"],
    },
    leaseId: "lease_payload_retired",
    policyHash: "policy_payload_retired",
  }, "approval_1", "thread_1");

  assert.equal(metadata.lease_id, "approval_lease_approval_1");
  assert.equal(metadata.policy_hash, null);
  assert.equal(metadata.ttl_ms, null);
  assert.equal(metadata.expires_at, null);
  assert.deepEqual(metadata.expected_receipt_refs, []);
  assert.deepEqual(metadata.authority_scope_requirements, []);
});

test("approval lease state for decision detects expiration and decision lease precedence", () => {
  const lease = createLease();
  const state = lease.approvalLeaseStateForDecision({
    thread_id: "thread_1",
    approval_id: "approval_1",
    approval_request_event: {
      payload_summary: {
        approval_lease: {
          lease_id: "request_lease",
          expires_at: "2999-01-01T00:00:00.000Z",
        },
      },
    },
    latest_decision: {
      payload_summary: {
        approval_lease: {
          lease_id: "decision_lease",
          expires_at: "2000-01-01T00:00:00.000Z",
        },
      },
    },
  });

  assert.equal(state.lease_id, "decision_lease");
  assert.equal(state.expires_at, "2000-01-01T00:00:00.000Z");
  assert.equal(Object.hasOwn(state, "leaseId"), false);
  assert.equal(Object.hasOwn(state, "expiresAt"), false);
  assert.equal(state.expired, true);
});

test("approval decision and reason helpers normalize aliases", () => {
  const lease = createLease();

  assert.equal(lease.approvalDecisionForRequest("allow"), "approve");
  assert.equal(lease.approvalDecisionForRequest("blocked"), "reject");
  assert.equal(lease.approvalReasonForDecisionEvent({ event_kind: "approval.approved" }), "approval_approved");
  assert.equal(lease.approvalReasonForDecisionEvent({ event_kind: "approval.revoked" }), "approval_revoked");
  assert.equal(lease.approvalReasonForDecisionEvent({ event_kind: "approval.rejected" }), "approval_rejected");
  assert.throws(
    () => lease.approvalDecisionForRequest("maybe"),
    /Approval decisions must be approve or reject/,
  );
});
