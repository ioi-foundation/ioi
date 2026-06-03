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
    uniqueStrings: (values = []) => [...new Set((Array.isArray(values) ? values : []).map((value) => String(value)).filter(Boolean))],
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
      targetNodeIds: ["node_a", "node_b"],
      workflowNodeId: "node_request",
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
      retryLimit: 2.8,
    },
    blockedPayload: {
      approvalManifest: {
        recoveryPolicy: {
          requiresApproval: false,
          allowOverride: false,
          targetNodeIds: ["node_policy"],
        },
      },
    },
    targetNodeIds: ["node_runtime", "node_policy"],
  });

  assert.equal(policy.schemaVersion, "policy.v1");
  assert.equal(policy.requires_approval, false);
  assert.equal(policy.allowOverride, false);
  assert.equal(policy.retryLimit, 2);
  assert.equal(policy.approvalScope, "target_nodes");
  assert.equal(policy.operatorRole, "budget_operator");
  assert.deepEqual(policy.targetNodeIds, ["node_policy", "node_runtime"]);
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

test("budget recovery retry limit and result envelope preserve aliases", () => {
  const recovery = createRecovery();

  assert.equal(recovery.recoveryPolicyRetryLimit({ retry_limit: 0 }), 1);
  assert.equal(recovery.recoveryPolicyRetryLimit({ retryLimit: 3.7 }), 3);

  const result = recovery.codingToolBudgetRecoveryResult({
    action: "retry_approved",
    status: "completed",
    reason: "approved",
    run: { id: "run_1" },
    threadId: "thread_1",
    turnId: "turn_1",
    approvalId: "approval_1",
    sourceEventId: "event_1",
    targetNodeIds: ["node_1"],
    workflowGraphId: "graph_1",
    workflowNodeId: "node_1",
    recoveryPolicy: { retryLimit: 1 },
    event: { event_id: "event_result", seq: 5 },
    approvalEvent: { event_id: "event_approval" },
    decisionEvent: { event_id: "event_decision" },
    receiptRefs: ["receipt_1"],
    policyDecisionRefs: ["policy_1"],
  });

  assert.equal(result.schemaVersion, "recovery.v1");
  assert.equal(result.recovery_action, "retry_approved");
  assert.equal(result.runId, "run_1");
  assert.equal(result.approvalDecisionEventId, "event_decision");
  assert.deepEqual(result.target_node_ids, ["node_1"]);
  assert.deepEqual(result.receiptRefs, ["receipt_1"]);
  assert.deepEqual(result.policy_decision_refs, ["policy_1"]);
});
