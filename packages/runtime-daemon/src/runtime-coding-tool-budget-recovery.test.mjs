import assert from "node:assert/strict";
import test from "node:test";

import { createCodingToolBudgetRecovery } from "./runtime-coding-tool-budget-recovery.mjs";

function createRecovery() {
  return createCodingToolBudgetRecovery({
    WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION: "policy.v1",
    WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION: "recovery.v1",
    WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON: "workflow_run_coding_tool_budget_preflight_blocked",
    normalizeArray: (value) => Array.isArray(value) ? value.filter(Boolean) : [],
    optionalString: (value) => typeof value === "string" ? value.trim() || null : null,
    runtimeError: (payload) => {
      const error = new Error(payload.message);
      Object.assign(error, payload);
      return error;
    },
    uniqueStrings: (values = []) => [...new Set((Array.isArray(values) ? values : []).filter(Boolean).map((value) => String(value)))],
  });
}

test("budget recovery action normalizes accepted aliases and rejects invalid input", () => {
  const recovery = createRecovery();

  assert.equal(recovery.codingToolBudgetRecoveryAction(undefined), "request_approval");
  assert.equal(recovery.codingToolBudgetRecoveryAction("request"), "request_approval");
  assert.equal(recovery.codingToolBudgetRecoveryAction("approve"), "approve_override");
  assert.equal(recovery.codingToolBudgetRecoveryAction("deny"), "reject_override");
  assert.equal(recovery.codingToolBudgetRecoveryAction("retry-approved"), "retry_approved");
  assert.throws(
    () => recovery.codingToolBudgetRecoveryAction("launch"),
    /Coding-tool budget recovery accepts/,
  );
});

test("budget recovery target nodes merge request, blocked payload, and event ids", () => {
  const recovery = createRecovery();
  const ids = recovery.codingToolBudgetRecoveryTargetNodeIds({
    request: {
      target_node_ids: ["node_a", "node_b"],
      workflow_node_id: "node_request",
    },
    blockedEvent: {
      workflow_node_id: "node_event",
    },
    blockedPayload: {
      target_node_ids: ["node_b", "node_c"],
      workflow_node_id: "node_payload",
    },
  });

  assert.deepEqual(ids, ["node_a", "node_b", "node_c", "node_request", "node_event", "node_payload"]);
});

test("budget recovery policy applies defaults and bounded retry limit", () => {
  const recovery = createRecovery();
  const policy = recovery.codingToolBudgetRecoveryPolicyFromInputs({
    request: {
      retry_limit: 2.8,
    },
    blockedPayload: {
      approval_manifest: {
        recovery_policy: {
          requires_approval: false,
          allow_override: false,
          target_node_ids: ["node_policy"],
        },
      },
    },
    targetNodeIds: ["node_runtime", "node_policy"],
  });

  assert.equal(policy.schema_version, "policy.v1");
  assert.equal(policy.requires_approval, false);
  assert.equal(policy.allow_override, false);
  assert.equal(policy.retry_limit, 2);
  assert.equal(policy.approval_scope, "target_nodes");
  assert.equal(policy.operator_role, "budget_operator");
  assert.deepEqual(policy.target_node_ids, ["node_policy", "node_runtime"]);
  for (const alias of [
    "schemaVersion",
    "requiresApproval",
    "allowOverride",
    "retryLimit",
    "approvalScope",
    "operatorRole",
    "targetNodeIds",
  ]) {
    assert.equal(Object.hasOwn(policy, alias), false);
  }
});

test("budget recovery ignores retired blocked payload aliases", () => {
  const recovery = createRecovery();
  const ids = recovery.codingToolBudgetRecoveryTargetNodeIds({
    blockedPayload: {
      targetNodeIds: ["node_retired"],
      workflowNodeId: "node_retired_workflow",
    },
  });
  const policy = recovery.codingToolBudgetRecoveryPolicyFromInputs({
    blockedPayload: {
      approvalManifest: {
        recoveryPolicy: {
          retryLimit: 9,
          targetNodeIds: ["node_policy_retired"],
        },
      },
      recoveryPolicy: {
        retryLimit: 8,
      },
    },
  });

  assert.deepEqual(ids, []);
  assert.equal(policy.retry_limit, 1);
  assert.deepEqual(policy.target_node_ids, []);
});

test("budget recovery detects coding-tool budget blocked runtime events", () => {
  const recovery = createRecovery();

  assert.equal(recovery.isCodingToolBudgetBlockedRuntimeEvent({
    event_kind: "workflow.run.coding_tool",
    payload_summary: {
      reason: "workflow_run_coding_tool_budget_preflight_blocked",
    },
  }), true);
  assert.equal(recovery.isCodingToolBudgetBlockedRuntimeEvent({
    event_kind: "runtime.progress",
    payload_summary: { reason: "blocked" },
  }), false);
});

test("budget recovery ignores retired blocked-event detector aliases", () => {
  const recovery = createRecovery();

  assert.equal(recovery.isCodingToolBudgetBlockedRuntimeEvent({
    payload_summary: {
      eventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
      blockReason: "coding_tool_budget_exceeded",
      budgetStatus: "exceeded",
      contextBudgetStatus: "blocked",
      resultSummary: { reason: "coding_tool_budget_exceeded" },
    },
  }), false);
});

test("budget recovery retry limit and result envelope emit canonical fields only", () => {
  const recovery = createRecovery();

  assert.equal(recovery.recoveryPolicyRetryLimit({ retry_limit: 0 }), 1);
  assert.equal(recovery.recoveryPolicyRetryLimit({ retry_limit: 3.7 }), 3);

  const result = recovery.codingToolBudgetRecoveryResult({
    action: "retry_approved",
    status: "completed",
    reason: "approved",
    run: { id: "run_1" },
    thread_id: "thread_1",
    turn_id: "turn_1",
    approval_id: "approval_1",
    source_event_id: "event_1",
    target_node_ids: ["node_1"],
    workflow_graph_id: "graph_1",
    workflow_node_id: "node_1",
    recovery_policy: { retry_limit: 1 },
    event: { event_id: "event_result", seq: 5 },
    approval_event: { event_id: "event_approval" },
    decision_event: { event_id: "event_decision" },
    receipt_refs: ["receipt_1"],
    policy_decision_refs: ["policy_1"],
  });

  assert.equal(result.schema_version, "recovery.v1");
  assert.equal(result.recovery_action, "retry_approved");
  assert.equal(result.run_id, "run_1");
  assert.equal(result.approval_decision_event_id, "event_decision");
  assert.deepEqual(result.target_node_ids, ["node_1"]);
  assert.deepEqual(result.receipt_refs, ["receipt_1"]);
  assert.deepEqual(result.policy_decision_refs, ["policy_1"]);
  const retiredInputResult = recovery.codingToolBudgetRecoveryResult({
    action: "retry_approved",
    status: "completed",
    run: { id: "run_1" },
    threadId: "thread_retired",
    approvalId: "approval_retired",
    targetNodeIds: ["node_retired"],
    receiptRefs: ["receipt_retired"],
    policyDecisionRefs: ["policy_retired"],
  });
  assert.notEqual(retiredInputResult.thread_id, "thread_retired");
  assert.notEqual(retiredInputResult.approval_id, "approval_retired");
  assert.notDeepEqual(retiredInputResult.target_node_ids, ["node_retired"]);
  assert.notDeepEqual(retiredInputResult.receipt_refs, ["receipt_retired"]);
  assert.notDeepEqual(retiredInputResult.policy_decision_refs, ["policy_retired"]);
  for (const alias of [
    "schemaVersion",
    "recoveryAction",
    "runId",
    "threadId",
    "turnId",
    "approvalId",
    "sourceEventId",
    "targetNodeIds",
    "workflowGraphId",
    "workflowNodeId",
    "recoveryPolicy",
    "eventId",
    "approvalEventId",
    "approvalDecisionEventId",
    "receiptRefs",
    "policyDecisionRefs",
    "approvalEvent",
    "decisionEvent",
  ]) {
    assert.equal(Object.hasOwn(result, alias), false);
  }
});
