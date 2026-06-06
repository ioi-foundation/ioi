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
    approvalId: "approval 1",
    action: "file.write",
    scope: "thread",
    now: "2026-06-03T12:00:00.000Z",
    threadId: "thread_1",
  });

  assert.equal(metadata.schemaVersion, "ioi.runtime.approval-lease.v1");
  assert.equal(metadata.leaseId, "approval_lease_approval_1");
  assert.equal(metadata.expiresAt, "2026-06-03T12:00:01.000Z");
  assert.equal(metadata.ttl_ms, 1000);
  assert.match(metadata.policyHash, /^hash_/);
  assert.deepEqual(metadata.expectedReceiptRefs, ["receipt_1"]);
  assert.deepEqual(metadata.authority_scope_requirements, ["workspace.write"]);
  assert.equal(metadata.revokeEndpoint, "/v1/threads/thread_1/approvals/approval%201/revoke");
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
    approvalId: "approval 1",
    action: "file.write",
    scope: "thread",
    now: "2026-06-03T12:00:00.000Z",
    threadId: "thread_1",
  });

  assert.equal(metadata.ttl_ms, null);
  assert.equal(metadata.expires_at, null);
  assert.deepEqual(metadata.expected_receipt_refs, []);
  assert.deepEqual(metadata.authority_scope_requirements, []);
  assert.equal(metadata.lease_id, "approval_lease_approval_1");
  assert.notEqual(metadata.policy_hash, "policy_retired");
});

test("approval lease metadata from payload supports nested and top-level aliases", () => {
  const lease = createLease();
  const metadata = lease.approvalLeaseMetadataFromPayload({
    approvalLease: {
      leaseId: "lease_1",
      policyHash: "policy_hash_1",
      ttlMs: 500,
      expiresAt: "2026-06-03T12:00:05.000Z",
      expectedReceiptRefs: ["receipt_nested"],
      authorityScopeRequirements: ["scope_nested"],
      action: "shell.run",
      scope: "run",
    },
  }, "approval_1", "thread_1");

  assert.equal(metadata.lease_id, "lease_1");
  assert.equal(metadata.policy_hash, "policy_hash_1");
  assert.equal(metadata.ttlMs, 500);
  assert.equal(metadata.scope, "run");
  assert.equal(metadata.action, "shell.run");
  assert.deepEqual(metadata.expected_receipt_refs, ["receipt_nested"]);
  assert.deepEqual(metadata.authorityScopeRequirements, ["scope_nested"]);
});

test("approval lease state for decision detects expiration and decision lease precedence", () => {
  const lease = createLease();
  const state = lease.approvalLeaseStateForDecision({
    threadId: "thread_1",
    approvalId: "approval_1",
    approvalRequestEvent: {
      payload_summary: {
        approvalLease: {
          leaseId: "request_lease",
          expiresAt: "2999-01-01T00:00:00.000Z",
        },
      },
    },
    latestDecision: {
      payload_summary: {
        approvalLease: {
          leaseId: "decision_lease",
          expiresAt: "2000-01-01T00:00:00.000Z",
        },
      },
    },
  });

  assert.equal(state.leaseId, "decision_lease");
  assert.equal(state.expiresAt, "2000-01-01T00:00:00.000Z");
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
