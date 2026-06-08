import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolGovernanceSurface } from "./runtime-coding-tool-governance-surface.mjs";

function createSurface({ expired = false, manifestsMatch = true } = {}) {
  return createRuntimeCodingToolGovernanceSurface({
    approvalLeaseStateForDecision() {
      return {
        expired,
        lease_id: "lease-one",
        expires_at: "2026-06-04T12:00:00.000Z",
      };
    },
    approvalReasonForDecisionEvent(event) {
      return event?.payload_summary?.reason ?? "approval_not_satisfied";
    },
    codingToolApprovalManifestsMatch() {
      return manifestsMatch;
    },
    runtimeError({ status, code, message, details }) {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
  });
}

function createStore({ approvalEvent = null, decisionEvent = null } = {}) {
  const events = [approvalEvent, decisionEvent].filter(Boolean);
  return {
    events,
    approvalRequests: [],
    latestApprovalRequestEvent(threadId, approvalId) {
      return events
        .filter(
          (event) =>
            event.thread_id === threadId &&
            event.approval_id === approvalId &&
            event.event_kind === "approval.required",
        )
        .at(-1) ?? null;
    },
    runtimeEventStream() {
      return { events };
    },
    requestThreadApproval(threadId, request = {}) {
      this.approvalRequests.push({ threadId, request });
      throw new Error("requestThreadApproval must not be called by the retired JS governance facade");
    },
    appendRuntimeEvent(record) {
      throw new Error(`appendRuntimeEvent must not be called by the retired JS governance facade: ${record?.event_kind}`);
    },
  };
}

function approvalEvent(overrides = {}) {
  return {
    event_id: "event-approval-request",
    seq: 1,
    thread_id: "thread-one",
    approval_id: "approval-one",
    event_kind: "approval.required",
    payload_summary: {
      approval_manifest: { tool_id: "file.write" },
    },
    ...overrides,
  };
}

function decisionEvent(kind = "approval.approved", overrides = {}) {
  return {
    event_id: "event-decision",
    seq: 2,
    thread_id: "thread-one",
    approval_id: "approval-one",
    event_kind: kind,
    payload_summary: {
      reason: kind === "approval.approved" ? "approved" : "rejected_by_operator",
    },
    ...overrides,
  };
}

const baseAgent = {
  id: "agent-one",
  cwd: "/workspace/project",
};

function assertNoRetiredGovernanceDetailAliases(details) {
  for (const field of [
    "threadId",
    "turnId",
    "toolId",
    "toolCallId",
    "workflowGraphId",
    "workflowNodeId",
    "approvalMode",
    "effectClass",
    "riskDomain",
    "codingToolIdempotencyKey",
    "contextBudgetStatus",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details, field), false);
  }
}

test("coding-tool governance reports approval satisfaction states", () => {
  const approvedStore = createStore({
    approvalEvent: approvalEvent(),
    decisionEvent: decisionEvent(),
  });
  const approved = createSurface().codingToolApprovalSatisfaction(approvedStore, {
    threadId: "thread-one",
    approval_manifest: { tool_id: "file.write" },
    request: { approval_id: "approval-one" },
  });

  assert.deepEqual(approved, {
    satisfied: true,
    approval_id: "approval-one",
    decision_event_id: "event-decision",
    decision_seq: 2,
    reason: "approved",
    lease_id: "lease-one",
    expires_at: "2026-06-04T12:00:00.000Z",
  });
  for (const field of ["approvalId", "decisionEventId", "decisionSeq", "leaseId", "expiresAt"]) {
    assert.equal(Object.hasOwn(approved, field), false);
  }
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(approvedStore, {
      threadId: "thread-one",
      approval_manifest: {},
      request: {},
    }).reason,
    "approval_id_missing",
  );
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(createStore(), {
      threadId: "thread-one",
      approval_manifest: {},
      request: { approval_id: "missing" },
    }).reason,
    "approval_request_missing",
  );
  assert.equal(
    createSurface({ manifestsMatch: false }).codingToolApprovalSatisfaction(approvedStore, {
      threadId: "thread-one",
      approval_manifest: { tool_id: "file.write" },
      request: { approval_id: "approval-one" },
    }).reason,
    "approval_manifest_mismatch",
  );
  assert.equal(
    createSurface({ manifestsMatch: false }).codingToolApprovalSatisfaction(createStore({
      approvalEvent: approvalEvent({
        payload_summary: {
          approvalManifest: { tool_id: "file.write" },
        },
      }),
    }), {
      threadId: "thread-one",
      approval_manifest: { tool_id: "file.write" },
      request: { approval_id: "approval-one" },
    }).reason,
    "approval_manifest_mismatch",
  );
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(createStore({ approvalEvent: approvalEvent() }), {
      threadId: "thread-one",
      approval_manifest: { tool_id: "file.write" },
      request: { approval_id: "approval-one" },
    }).reason,
    "approval_decision_missing",
  );
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(approvedStore, {
      threadId: "thread-one",
      approval_manifest: { tool_id: "file.write" },
      request: { approvalId: "approval-one" },
    }).reason,
    "approval_id_missing",
  );
});

test("coding-tool governance rejects non-approved or expired decisions", () => {
  const rejected = createSurface().codingToolApprovalSatisfaction(
    createStore({
      approvalEvent: approvalEvent(),
      decisionEvent: decisionEvent("approval.rejected"),
    }),
    {
      threadId: "thread-one",
      approval_manifest: { tool_id: "file.write" },
      request: { approval_id: "approval-one" },
    },
  );
  const expired = createSurface({ expired: true }).codingToolApprovalSatisfaction(
    createStore({
      approvalEvent: approvalEvent(),
      decisionEvent: decisionEvent(),
    }),
    {
      threadId: "thread-one",
      approval_manifest: { tool_id: "file.write" },
      request: { approval_id: "approval-one" },
    },
  );

  assert.equal(rejected.satisfied, false);
  assert.equal(rejected.reason, "rejected_by_operator");
  assert.equal(rejected.decision_event_id, "event-decision");
  assert.equal(Object.hasOwn(rejected, "decisionEventId"), false);
  assert.equal(expired.satisfied, false);
  assert.equal(expired.reason, "approval_lease_expired");
  assert.equal(expired.lease_id, "lease-one");
  assert.equal(expired.expires_at, "2026-06-04T12:00:00.000Z");
  assert.equal(Object.hasOwn(expired, "leaseId"), false);
});

test("coding-tool governance approval block facade fails closed before JS approval persistence", () => {
  const store = createStore();

  assert.throws(
    () => createSurface().blockCodingToolForApproval(store, {
      agent: baseAgent,
      threadId: "thread-one",
      turnId: "turn-one",
      toolId: "file.write",
      toolCallId: "tool-call-one",
      receiptId: "receipt-tool",
      input: { path: "src/main.js", content: "hello" },
      request: { source: "agent_studio" },
      workflowGraphId: "graph-one",
      workflowNodeId: "node-one",
      requestRollbackRefs: ["rollback-one"],
      diagnosticsRepairContext: { mode: "compact" },
      approval_manifest: {
        thread_mode: "agent",
        approval_mode: "human_required",
        policy_reason: "writes_require_approval",
        effect_class: "workspace_write",
        risk_domain: "workspace",
        authority_scope_requirements: ["workspace.write"],
      },
      toolContract: { id: "file.write" },
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_governance_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_governance");
      assert.equal(error.details.operation, "coding_tool_approval_block");
      assert.equal(error.details.operation_kind, "coding_tool.approval.block");
      assert.equal(error.details.thread_id, "thread-one");
      assert.equal(error.details.turn_id, "turn-one");
      assert.equal(error.details.tool_id, "file.write");
      assert.equal(error.details.tool_call_id, "tool-call-one");
      assert.equal(error.details.workflow_graph_id, "graph-one");
      assert.equal(error.details.workflow_node_id, "node-one");
      assert.equal(error.details.approval_mode, "human_required");
      assert.equal(error.details.effect_class, "workspace_write");
      assert.equal(error.details.risk_domain, "workspace");
      assert.equal(error.details.source, "agent_studio");
      assert.deepEqual(error.details.evidence_refs, [
        "coding_tool_approval_block_js_facade_retired",
        "rust_daemon_core_coding_tool_approval_block_required",
        "agentgres_coding_tool_approval_block_truth_required",
      ]);
      assertNoRetiredGovernanceDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.approvalRequests, []);
});

test("coding-tool governance budget block facade fails closed before JS event append", () => {
  const store = createStore();
  const budgetPolicy = {
    status: "blocked",
    receipt_refs: ["receipt-budget"],
    receiptRefs: ["receipt-retired-budget"],
    policy_decision_refs: ["policy-budget"],
    policyDecisionRefs: ["policy-retired-budget"],
    usage_telemetry: { totalTokens: 100 },
    usageTelemetry: { totalTokens: 100 },
  };

  assert.throws(
    () => createSurface().blockCodingToolForBudget(store, {
      agent: baseAgent,
      threadId: "thread-one",
      turnId: "turn-one",
      toolId: "file.write",
      toolCallId: "tool-call-one",
      receiptId: "receipt-tool",
      input: { path: "src/main.js", content: "hello" },
      request: { source: "agent_studio" },
      workflowGraphId: "graph-one",
      workflowNodeId: "node-one",
      requestRollbackRefs: ["rollback-one"],
      diagnosticsRepairContext: { mode: "compact" },
      budgetPolicy,
      toolContract: { id: "file.write" },
      codingToolIdempotencyKey: "idempotent-budget-block",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_governance_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_governance");
      assert.equal(error.details.operation, "coding_tool_budget_block");
      assert.equal(error.details.operation_kind, "policy.blocked");
      assert.equal(error.details.thread_id, "thread-one");
      assert.equal(error.details.turn_id, "turn-one");
      assert.equal(error.details.tool_id, "file.write");
      assert.equal(error.details.tool_call_id, "tool-call-one");
      assert.equal(error.details.workflow_graph_id, "graph-one");
      assert.equal(error.details.workflow_node_id, "node-one");
      assert.equal(error.details.coding_tool_idempotency_key, "idempotent-budget-block");
      assert.equal(error.details.context_budget_status, "blocked");
      assert.equal(error.details.source, "agent_studio");
      assert.deepEqual(error.details.evidence_refs, [
        "coding_tool_budget_block_js_facade_retired",
        "rust_daemon_core_coding_tool_budget_block_required",
        "agentgres_coding_tool_budget_block_truth_required",
      ]);
      assertNoRetiredGovernanceDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.events, []);
});
