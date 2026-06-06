import assert from "node:assert/strict";
import test from "node:test";

import {
  codingToolBudgetPolicyForRequest,
  contextBudgetNumber,
  contextBudgetThresholds,
  contextBudgetUsageTelemetryFromRequest,
  evaluateCompactionPolicyDecision,
  evaluateContextBudgetPolicy,
} from "./context-budget-policy.mjs";

const retiredContextBudgetUsageInputAliasKeys = [
  "usageTelemetry",
  "runtimeUsageMeter",
  "runtime_usage_meter",
  "budgetUsageTelemetry",
  "runtimeTelemetrySummary",
  "runtime_telemetry_summary",
];

function budgetRunnerMock({ capture = null } = {}) {
  const resultForRequest = (request, { source, event_kind, component_kind }) => {
    capture?.(request);
    const limit = request.thresholds.max_total_tokens;
    const total = request.usage_telemetry.total_tokens ?? 0;
    const wouldBlock = typeof limit === "number" && total > limit;
    const wouldWarn =
      typeof limit === "number" &&
      total >= limit * (request.thresholds.warn_at_ratio ?? 0.8);
    const status = wouldBlock && request.mode === "block" ? "blocked" : wouldBlock || wouldWarn ? "warn" : "ok";
    const violations = wouldBlock
      ? [{ id: "total_tokens", label: "total tokens", actual: total, limit, ratio: total / limit, severity: "violation" }]
      : [];
    return {
      schema_version: "ioi.runtime.context-budget-policy.v1",
      object: "ioi.runtime_context_budget_policy",
      source,
      backend: "rust_policy",
      status,
      mode: request.mode,
      scope: request.scope,
      thread_id: request.thread_id,
      run_id: request.run_id,
      workflow_graph_id: request.workflow_graph_id,
      workflow_node_id: request.workflow_node_id,
      event_kind,
      component_kind,
      usage_telemetry: request.usage_telemetry,
      usage_summary: { total_tokens: total },
      policy_decision_id: "policy_context_budget_thread_mock",
      policy_decision: { status },
      receipt_refs: ["receipt_context_budget_thread_mock"],
      policy_decision_refs: ["policy_context_budget_thread_mock"],
      warnings: [],
      violations,
      would_block: wouldBlock,
      summary:
        status === "blocked"
          ? "Context budget blocked: total tokens exceeded."
          : status === "warn"
            ? "Context budget warning: total tokens near or over limit."
            : "Context budget is within policy.",
    };
  };
  return {
    evaluateContextBudgetPolicy(request) {
      return resultForRequest(request, {
        source: "rust_context_budget_policy_command",
        event_kind: "RuntimeContextBudget.Evaluate",
        component_kind: "context_budget",
      });
    },
    evaluateCodingToolBudgetPolicy(request) {
      return resultForRequest(request, {
        source: "rust_coding_tool_budget_policy_command",
        event_kind: "RuntimeCodingToolBudget.Evaluate",
        component_kind: "coding_tool",
      });
    },
    evaluateCompactionPolicy(request) {
      capture?.(request);
      const budgetStatus =
        request.context_budget_status ??
        request.context_budget?.status ??
        request.context_budget?.policy_decision?.status ??
        "ok";
      const normalizedBudgetStatus = budgetStatus === "warning" ? "warn" : budgetStatus;
      const selectedAction =
        normalizedBudgetStatus === "blocked"
          ? request.actions?.blocked_action ?? "compact"
          : normalizedBudgetStatus === "warn"
            ? request.actions?.warn_action ?? "warn"
            : request.actions?.ok_action ?? "noop";
      const approvalRequired =
        Boolean(request.approval?.approval_required) || selectedAction === "approval_required";
      const approvalGranted = Boolean(request.approval?.approval_granted);
      const action =
        selectedAction === "approval_required" && approvalGranted
          ? "compact"
          : selectedAction === "compact" && approvalRequired && !approvalGranted
            ? "approval_required"
            : selectedAction;
      const status =
        action === "approval_required"
          ? "waiting"
          : action === "compact" && request.compact?.execute_compaction
            ? "compacted"
            : action === "compact"
              ? "compact_pending"
              : "ok";
      return {
        schema_version: "ioi.runtime.compaction-policy.v1",
        object: "ioi.runtime_compaction_policy",
        source: "rust_compaction_policy_command",
        backend: "rust_policy",
        status,
        action,
        selected_action: selectedAction,
        budget_status: normalizedBudgetStatus,
        thread_id: request.thread_id,
        turn_id: request.turn_id,
        workflow_graph_id: request.workflow_graph_id,
        workflow_node_id: request.workflow_node_id,
        compact_workflow_node_id:
          request.compact?.compact_workflow_node_id ?? "runtime.context-compact",
        context_budget: request.context_budget,
        approval_required: approvalRequired,
        approval_granted: approvalGranted,
        approval_satisfied: !approvalRequired || approvalGranted,
        approval_id: action === "approval_required" ? "approval_compaction_thread_mock" : null,
        execute_compaction: Boolean(request.compact?.execute_compaction),
        compaction_requested: action === "compact",
        compaction_executed: false,
        compaction_event_id: null,
        compaction_seq: null,
        compact_reason:
          request.compact?.compact_reason ??
          "Compaction policy blocked: Context budget blocked.",
        compact_scope: request.compact?.compact_scope ?? "thread",
        continuation_allowed: action !== "stop",
        receipt_refs: ["receipt_compaction_policy_thread_mock"],
        policy_decision_refs: ["policy_compaction_thread_mock"],
        policy_decision_id: "policy_compaction_thread_mock",
        summary:
          action === "approval_required"
            ? "Compaction policy requires operator approval before compacting."
            : action === "compact"
              ? "Compaction policy executed context compaction."
              : "Compaction policy allowed continuation.",
      };
    },
  };
}

test("context budget telemetry and thresholds normalize canonical request fields", () => {
  const telemetry = { total_tokens: 12, estimated_cost_usd: 0.02, context_pressure: 0.3 };
  assert.equal(contextBudgetUsageTelemetryFromRequest({ usage_telemetry: telemetry }), telemetry);
  assert.equal(contextBudgetUsageTelemetryFromRequest({ usage: telemetry }), telemetry);

  assert.deepEqual(contextBudgetThresholds({
    thresholds: {
      maxTotalTokens: "100",
      maxCostUsd: "0.25",
      maxContextPressure: "0.9",
      warnAtRatio: "0.75",
    },
  }), {
    max_total_tokens: 100,
    maxTotalTokens: 100,
    max_cost_usd: 0.25,
    maxCostUsd: 0.25,
    max_context_pressure: 0.9,
    maxContextPressure: 0.9,
    warn_at_ratio: 0.75,
    warnAtRatio: 0.75,
  });

  assert.equal(contextBudgetNumber(undefined, "", -1, "42"), 42);
  assert.equal(contextBudgetNumber(undefined, "nope"), null);
});

test("context budget usage telemetry ignores retired request aliases", () => {
  const telemetry = { total_tokens: 99, estimated_cost_usd: 0.2, context_pressure: 0.7 };
  for (const key of retiredContextBudgetUsageInputAliasKeys) {
    assert.equal(contextBudgetUsageTelemetryFromRequest({ [key]: telemetry }), null);
    assert.equal(
      codingToolBudgetPolicyForRequest({
        request: {
          [key]: telemetry,
          max_total_tokens: 1,
        },
      }),
      null,
    );
  }
});

test("context budget policy warns in simulate mode and blocks in block mode", () => {
  let capturedRequest = null;
  const usageTelemetry = {
    total_tokens: 120,
    estimated_cost_usd: 0.6,
    context_pressure: 0.91,
    thread_id: "thread-1",
  };

  const simulated = evaluateContextBudgetPolicy({
    usageTelemetry,
    request: {
      mode: "simulate",
      thresholds: {
        max_total_tokens: 100,
        max_cost_usd: 1,
        max_context_pressure: 0.95,
        warn_at_ratio: 0.8,
      },
      workflowNodeId: "node-budget",
    },
    budgetRunner: budgetRunnerMock({
      capture: (request) => {
        capturedRequest = request;
      },
    }),
  });

  assert.equal(capturedRequest.schema_version, "ioi.runtime.context-budget-policy-request.v1");
  assert.equal(capturedRequest.workflow_node_id, "node-budget");
  assert.equal(simulated.status, "warn");
  assert.equal(simulated.would_block, true);
  assert.equal(simulated.thread_id, "thread-1");
  assert.equal(simulated.workflow_node_id, "node-budget");
  assert.equal(simulated.policy_decision.status, "warn");
  assert.equal(simulated.violations[0].id, "total_tokens");
  assert.equal(Object.hasOwn(simulated, "threadId"), false);

  const blocked = evaluateContextBudgetPolicy({
    usageTelemetry,
    request: {
      mode: "block",
      maxTotalTokens: 100,
    },
    budgetRunner: budgetRunnerMock(),
  });
  assert.equal(blocked.status, "blocked");
  assert.match(blocked.summary, /Context budget blocked/);
});

test("coding tool budget policy reads canonical tool pack fields and annotates runtime context", () => {
  let capturedRequest = null;
  const result = codingToolBudgetPolicyForRequest({
    request: {
      source: "react_flow",
      options: {
        toolPack: {
          coding: {
            budget_usage_telemetry: {
              total_tokens: 90,
              estimated_cost_usd: 0.03,
              context_pressure: 0.2,
            },
            max_total_tokens: 100,
            warn_at_ratio: 0.8,
            budget_mode: "warn",
          },
        },
      },
    },
    threadId: "thread-1",
    toolId: "CODING",
    toolCallId: "call-1",
    workflowGraphId: "graph-1",
    workflowNodeId: "node-1",
    budgetRunner: budgetRunnerMock({
      capture: (request) => {
        capturedRequest = request;
      },
    }),
  });

  assert.equal(capturedRequest.schema_version, "ioi.runtime.coding-tool-budget-policy-request.v1");
  assert.equal(capturedRequest.usage_telemetry.total_tokens, 90);
  assert.equal(capturedRequest.thresholds.max_total_tokens, 100);
  assert.equal(capturedRequest.thresholds.warn_at_ratio, 0.8);
  assert.equal(capturedRequest.mode, "warn");
  assert.equal(result.status, "warn");
  assert.equal(result.event_kind, "RuntimeCodingToolBudget.Evaluate");
  assert.equal(result.scope, "thread");
  assert.equal(result.thread_id, "thread-1");
  assert.equal(result.workflow_graph_id, "graph-1");
  assert.equal(result.workflow_node_id, "node-1");
});

test("coding tool budget policy returns null without telemetry or limits", () => {
  assert.equal(codingToolBudgetPolicyForRequest({ request: {} }), null);
  assert.equal(codingToolBudgetPolicyForRequest({
    request: {
      budget_usage_telemetry: { total_tokens: 10 },
    },
  }), null);
});

test("compaction policy maps budget status to approval and compact decisions", () => {
  let capturedRequest = null;
  const waiting = evaluateCompactionPolicyDecision({
    threadId: "thread-1",
    turnId: "turn-1",
    request: {
      context_budget_status: "blocked",
      policy: {
        blocked_action: "compact",
        approval_required: "yes",
      },
    },
    policyRunner: budgetRunnerMock({
      capture: (request) => {
        capturedRequest = request;
      },
    }),
  });

  assert.equal(capturedRequest.schema_version, "ioi.runtime.compaction-policy-request.v1");
  assert.equal(capturedRequest.thread_id, "thread-1");
  assert.equal(capturedRequest.actions.blocked_action, "compact");
  assert.equal(waiting.action, "approval_required");
  assert.equal(waiting.status, "waiting");
  assert.equal(waiting.approval_required, true);
  assert.equal(waiting.approval_satisfied, false);
  assert.equal(waiting.continuation_allowed, true);
  assert.match(waiting.approval_id, /^approval_compaction_thread/);
  assert.equal(Object.hasOwn(waiting, "approvalId"), false);

  const compact = evaluateCompactionPolicyDecision({
    threadId: "thread-1",
    request: {
      context_budget: { policy_decision: { status: "warning" } },
      policy: {
        warn_action: "compact",
        execute_compaction: "true",
      },
      approved: true,
    },
    policyRunner: budgetRunnerMock(),
  });

  assert.equal(compact.action, "compact");
  assert.equal(compact.status, "compacted");
  assert.equal(compact.execute_compaction, true);
  assert.equal(compact.compaction_requested, true);
});
