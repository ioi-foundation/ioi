import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolGovernanceSurface } from "./runtime-coding-tool-governance-surface.mjs";

function createSurface(overrides = {}) {
  return createRuntimeCodingToolGovernanceSurface({
    runtimeError({ status, code, message, details }) {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
    ...overrides,
  });
}

function createStore() {
  return {
    events: [],
    approvalRequests: [],
    latestApprovalRequestEvent(threadId, approvalId) {
      throw new Error(`approval satisfaction JS event lookup must be retired: ${threadId}:${approvalId}`);
    },
    runtimeEventStream() {
      throw new Error("approval satisfaction JS stream lookup must be retired");
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

test("coding-tool approval satisfaction JS gate is retired", () => {
  const surface = createSurface();
  assert.equal(Object.hasOwn(surface, "codingToolApprovalSatisfaction"), false);
  assert.equal(surface.codingToolApprovalSatisfaction, undefined);
});

test("coding-tool governance approval block facade is retired", () => {
  const surface = createSurface();
  assert.equal(Object.hasOwn(surface, "blockCodingToolForApproval"), false);
  assert.equal(surface.blockCodingToolForApproval, undefined);
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

test("coding-tool governance budget block ignores retired planner alias", () => {
  const store = createStore();
  const calls = [];
  const surface = createSurface({
    codingToolBudgetBlockPlanner: {
      planCodingToolBudgetBlock(request) {
        calls.push(request);
        return { status: "blocked" };
      },
    },
  });

  assert.throws(
    () => surface.blockCodingToolForBudget(store, {
      threadId: "thread-one",
      turnId: "turn-one",
      toolId: "file.write",
      toolCallId: "tool-call-one",
      budgetPolicy: { status: "blocked" },
      codingToolIdempotencyKey: "idempotent-budget-block",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_governance_rust_core_required");
      return true;
    },
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(store.events, []);
});

test("coding-tool governance budget block delegates to Rust planner without JS event append", () => {
  const store = createStore();
  const calls = [];
  const surface = createSurface({
    contextPolicyCore: {
      planCodingToolBudgetBlock(request) {
        calls.push(request);
        return {
          source: "rust_coding_tool_budget_block_command",
          backend: "rust_policy",
          status: "blocked",
          operation_kind: "coding_tool.budget.block",
          reason: "coding_tool_budget_exceeded",
          context_budget_status: "blocked",
          receipt_refs: ["receipt_budget"],
          policy_decision_refs: ["policy_budget"],
          event: {
            event_stream_id: "thread-one:events",
            event_kind: "tool.blocked",
            status: "blocked",
            receipt_refs: ["receipt_budget"],
            payload_summary: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              rust_budget_block: true,
              context_budget_status: "blocked",
              receipt_refs: ["receipt_budget"],
            },
          },
          result: {
            schema_version: "ioi.runtime.coding-tool-result.v1",
            status: "blocked",
            rust_budget_block: true,
          },
        };
      },
    },
  });

  const result = surface.blockCodingToolForBudget(store, {
    agent: baseAgent,
    threadId: "thread-one",
    turnId: "turn-one",
    toolId: "file.inspect",
    toolCallId: "tool-call-one",
    workspaceRoot: "/workspace/project",
    receiptId: "receipt-tool",
    inputSummary: { path: "README.md" },
    request: { source: "agent_studio" },
    workflowGraphId: "graph-one",
    workflowNodeId: "node-one",
    requestRollbackRefs: ["rollback-one"],
    budgetPolicy: {
      status: "blocked",
      usage_telemetry: { prompt_tokens: 10 },
      receipt_refs: ["receipt_budget_policy"],
      policy_decision_refs: ["policy_budget"],
      receiptRefs: ["receipt_retired"],
      policyDecisionRefs: ["policy_retired"],
    },
    artifactRefs: ["artifact-one"],
    codingToolIdempotencyKey: "idempotent-budget-block",
  });

  assert.equal(result.source, "rust_coding_tool_budget_block_command");
  assert.equal(result.operation_kind, "coding_tool.budget.block");
  assert.equal(result.event.payload_summary.rust_budget_block, true);
  assert.deepEqual(calls, [{
    thread_id: "thread-one",
    turn_id: "turn-one",
    tool_id: "file.inspect",
    tool_call_id: "tool-call-one",
    workspace_root: "/workspace/project",
    workflow_graph_id: "graph-one",
    workflow_node_id: "node-one",
    source: "agent_studio",
    idempotency_key: "idempotent-budget-block",
    receipt_id: "receipt-tool",
    input_summary: { path: "README.md" },
    budget_policy: {
      status: "blocked",
      usage_telemetry: { prompt_tokens: 10 },
      receipt_refs: ["receipt_budget_policy"],
      policy_decision_refs: ["policy_budget"],
    },
    rollback_refs: ["rollback-one"],
    receipt_refs: ["receipt_budget_policy"],
    policy_decision_refs: ["policy_budget"],
    artifact_refs: ["artifact-one"],
  }]);
  assert.equal(Object.hasOwn(calls[0], "threadId"), false);
  assert.equal(Object.hasOwn(calls[0].budget_policy, "receiptRefs"), false);
  assert.equal(Object.hasOwn(calls[0].budget_policy, "policyDecisionRefs"), false);
  assert.equal(Object.hasOwn(calls[0].budget_policy, "usageTelemetry"), false);
  assert.deepEqual(store.events, []);
});
