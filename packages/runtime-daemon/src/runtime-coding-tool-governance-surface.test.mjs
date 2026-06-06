import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolGovernanceSurface } from "./runtime-coding-tool-governance-surface.mjs";

function createSurface({ expired = false, manifestsMatch = true } = {}) {
  return createRuntimeCodingToolGovernanceSurface({
    approvalLeaseStateForDecision() {
      return {
        expired,
        leaseId: "lease-one",
        expiresAt: "2026-06-04T12:00:00.000Z",
      };
    },
    approvalReasonForDecisionEvent(event) {
      return event?.payload_summary?.reason ?? "approval_not_satisfied";
    },
    codingToolApprovalManifestsMatch() {
      return manifestsMatch;
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
      return {
        approval_id: request.approvalId,
        event_id: "event-approval-request",
        receipt_refs: ["receipt-approval"],
        policy_decision_refs: ["policy-approval"],
      };
    },
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `event-${events.length + 1}`,
        seq: events.length + 1,
      };
      events.push(event);
      return event;
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
      approval_manifest: { toolId: "file.write" },
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

const baseInput = {
  path: "src/main.js",
  content: "hello",
};

const baseAgent = {
  id: "agent-one",
  cwd: "/workspace/project",
};

test("coding-tool governance reports approval satisfaction states", () => {
  const approvedStore = createStore({
    approvalEvent: approvalEvent(),
    decisionEvent: decisionEvent(),
  });
  const approved = createSurface().codingToolApprovalSatisfaction(approvedStore, {
    threadId: "thread-one",
    approvalManifest: { toolId: "file.write" },
    request: { approvalId: "approval-one" },
  });

  assert.deepEqual(approved, {
    satisfied: true,
    approvalId: "approval-one",
    decisionEventId: "event-decision",
    decisionSeq: 2,
    reason: "approved",
    leaseId: "lease-one",
    expiresAt: "2026-06-04T12:00:00.000Z",
  });
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(approvedStore, {
      threadId: "thread-one",
      approvalManifest: {},
      request: {},
    }).reason,
    "approval_id_missing",
  );
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(createStore(), {
      threadId: "thread-one",
      approvalManifest: {},
      request: { approvalId: "missing" },
    }).reason,
    "approval_request_missing",
  );
  assert.equal(
    createSurface({ manifestsMatch: false }).codingToolApprovalSatisfaction(approvedStore, {
      threadId: "thread-one",
      approvalManifest: { toolId: "file.write" },
      request: { approvalId: "approval-one" },
    }).reason,
    "approval_manifest_mismatch",
  );
  assert.equal(
    createSurface().codingToolApprovalSatisfaction(createStore({ approvalEvent: approvalEvent() }), {
      threadId: "thread-one",
      approvalManifest: { toolId: "file.write" },
      request: { approvalId: "approval-one" },
    }).reason,
    "approval_decision_missing",
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
      approvalManifest: { toolId: "file.write" },
      request: { approvalId: "approval-one" },
    },
  );
  const expired = createSurface({ expired: true }).codingToolApprovalSatisfaction(
    createStore({
      approvalEvent: approvalEvent(),
      decisionEvent: decisionEvent(),
    }),
    {
      threadId: "thread-one",
      approvalManifest: { toolId: "file.write" },
      request: { approvalId: "approval-one" },
    },
  );

  assert.equal(rejected.satisfied, false);
  assert.equal(rejected.reason, "rejected_by_operator");
  assert.equal(expired.satisfied, false);
  assert.equal(expired.reason, "approval_lease_expired");
  assert.equal(expired.leaseId, "lease-one");
});

test("coding-tool governance blocks tools for approval with stable result envelope", () => {
  const store = createStore();
  const result = createSurface().blockCodingToolForApproval(store, {
    agent: baseAgent,
    threadId: "thread-one",
    turnId: "turn-one",
    toolId: "file.write",
    toolCallId: "tool-call-one",
    receiptId: "receipt-tool",
    input: baseInput,
    request: { source: "agent_studio" },
    workflowGraphId: "graph-one",
    workflowNodeId: "node-one",
    requestRollbackRefs: ["rollback-one"],
    diagnosticsRepairContext: { mode: "compact" },
    approvalManifest: {
      thread_mode: "agent",
      approval_mode: "human_required",
      policy_reason: "writes_require_approval",
      effect_class: "workspace_write",
      risk_domain: "workspace",
      authority_scope_requirements: ["workspace.write"],
    },
    toolContract: { id: "file.write" },
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.approval_required, true);
  assert.equal(result.event, null);
  assert.equal(result.approval_id, "approval_coding_tool_file.write_b26083c886c8d94e");
  assert.equal(result.approval_event_id, "event-approval-request");
  assert.deepEqual(result.receipt_refs, ["receipt-approval"]);
  assert.deepEqual(result.rollback_refs, ["rollback-one"]);
  assert.equal(result.error.code, "coding_tool_approval_required");
  assert.deepEqual(result.result.input_summary, {});
  for (const field of [
    "approvalRequired",
    "approvalId",
    "approvalManifest",
    "workspaceSnapshot",
    "workspaceSnapshotEvent",
    "autoDiagnostics",
    "diagnosticsRepairContext",
    "toolContract",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
  for (const field of [
    "schemaVersion",
    "toolName",
    "approvalRequired",
    "approvalId",
    "approvalManifest",
    "inputSummary",
  ]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.equal(store.approvalRequests[0].threadId, "thread-one");
  assert.equal(store.approvalRequests[0].request.action, "coding_tool.invoke");
  assert.equal(store.approvalRequests[0].request.idempotencyKey, `thread:thread-one:approval.required:${result.approval_id}`);
});

test("coding-tool governance blocks tools for budget with event envelope", () => {
  const store = createStore();
  const budgetPolicy = {
    status: "blocked",
    receipt_refs: ["receipt-budget"],
    policy_decision_refs: ["policy-budget"],
    usage_telemetry: { totalTokens: 100 },
    usageTelemetry: { totalTokens: 100 },
  };
  const result = createSurface().blockCodingToolForBudget(store, {
    agent: baseAgent,
    threadId: "thread-one",
    turnId: "turn-one",
    toolId: "file.write",
    toolCallId: "tool-call-one",
    receiptId: "receipt-tool",
    input: baseInput,
    request: { source: "agent_studio" },
    workflowGraphId: "graph-one",
    workflowNodeId: "node-one",
    requestRollbackRefs: ["rollback-one"],
    diagnosticsRepairContext: { mode: "compact" },
    budgetPolicy,
    toolContract: { id: "file.write" },
    codingToolIdempotencyKey: "idempotent-budget-block",
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.budget_status, "exceeded");
  assert.equal(result.event.event_kind, "policy.blocked");
  assert.equal(result.event.source_event_kind, "CodingTool.FileWrite");
  assert.equal(result.event.idempotency_key, "idempotent-budget-block");
  assert.equal(result.event.component_kind, "coding_tool");
  assert.deepEqual(result.receipt_refs, ["receipt-tool", "receipt-budget"]);
  assert.deepEqual(result.policy_decision_refs, ["policy-budget"]);
  assert.deepEqual(result.rollback_refs, ["rollback-one"]);
  assert.equal(result.result.error.code, "coding_tool_budget_exceeded");
  assert.equal(result.result.schema_version, "ioi.runtime.coding-tool-result.v1");
  assert.equal(result.result.tool_name, "file.write");
  assert.deepEqual(result.result.error.details.budget_usage_telemetry, {
    totalTokens: 100,
  });
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      result.result.error.details,
      "budgetUsageTelemetry",
    ),
    false,
  );
  for (const field of [
    "budgetStatus",
    "contextBudget",
    "receiptRefs",
    "policyDecisionRefs",
    "workspaceSnapshot",
    "workspaceSnapshotEvent",
    "autoDiagnostics",
    "diagnosticsRepairContext",
    "toolContract",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
  for (const field of [
    "schemaVersion",
    "toolName",
    "budgetStatus",
    "contextBudgetStatus",
    "contextBudget",
    "inputSummary",
  ]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.equal(result.event.payload_summary.result_summary.reason, "coding_tool_budget_exceeded");
  assert.deepEqual(result.event.payload_summary.budget_usage_telemetry, {
    totalTokens: 100,
  });
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      result.event.payload_summary,
      "budgetUsageTelemetry",
    ),
    false,
  );
  for (const field of [
    "approvalRequired",
    "budgetStatus",
    "contextBudgetStatus",
    "contextBudget",
    "policyDecisionRefs",
    "diagnosticsRepairContext",
  ]) {
    assert.equal(Object.hasOwn(result.event.payload_summary, field), false);
  }
  assert.equal(result.event.payload_summary.receipt_count, 2);
});
