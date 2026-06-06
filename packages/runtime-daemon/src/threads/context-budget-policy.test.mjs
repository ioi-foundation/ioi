import assert from "node:assert/strict";
import test from "node:test";

import {
  codingToolBudgetPolicyForRequest,
  contextBudgetNumber,
  contextBudgetThresholds,
  contextBudgetUsageTelemetryFromRequest,
  contextBudgetUsageSummary,
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
  return {
    evaluateBudgetPolicy(request) {
      capture?.(request);
      return {
        schema_version: "ioi.runtime.context-budget-policy.v1",
        object: "ioi.runtime_context_budget_policy",
        source: "rust_coding_tool_budget_policy_command",
        backend: "rust_policy",
        status: request.usage_telemetry.total_tokens > request.thresholds.max_total_tokens ? "blocked" : "warn",
        mode: request.mode,
        scope: request.scope,
        thread_id: request.thread_id,
        workflow_graph_id: request.workflow_graph_id,
        workflow_node_id: request.workflow_node_id,
        event_kind: "RuntimeCodingToolBudget.Evaluate",
        component_kind: "coding_tool",
        usage_telemetry: request.usage_telemetry,
        usage_summary: { total_tokens: request.usage_telemetry.total_tokens },
        policy_decision_id: "policy_context_budget_thread_mock",
        policy_decision: { status: "warn" },
        receipt_refs: ["receipt_context_budget_thread_mock"],
        policy_decision_refs: ["policy_context_budget_thread_mock"],
        warnings: [],
        violations: [],
        would_block: false,
        summary: "Context budget warning: total tokens near or over limit.",
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
  });

  assert.equal(simulated.status, "warn");
  assert.equal(simulated.would_block, true);
  assert.equal(simulated.thread_id, "thread-1");
  assert.equal(simulated.workflow_node_id, "node-budget");
  assert.equal(simulated.policy_decision.status, "warn");
  assert.equal(simulated.violations[0].id, "total_tokens");

  const blocked = evaluateContextBudgetPolicy({
    usageTelemetry,
    request: {
      mode: "block",
      maxTotalTokens: 100,
    },
  });
  assert.equal(blocked.status, "blocked");
  assert.match(blocked.summary, /Context budget blocked/);
});

test("usage summary aggregates workflow usage rows", () => {
  const summary = contextBudgetUsageSummary({
    scope: "workflow",
    thread_id: "thread-1",
    usage: [
      { total_tokens: 10, estimated_cost_usd: 0.1, context_pressure: 0.2 },
      { total_tokens: 20, estimated_cost_usd: 0.05, context_pressure: 0.45 },
    ],
  });

  assert.equal(summary.total_tokens, 30);
  assert.equal(summary.estimated_cost_usd, 0.15);
  assert.equal(summary.context_pressure, 0.45);
  assert.equal(summary.scope, "workflow");
  assert.equal(summary.thread_id, "thread-1");
});

test("context budget usage summary ignores retired data aliases", () => {
  const summary = contextBudgetUsageSummary({
    scope: "workflow",
    threadId: "retired-thread",
    usage: [
      { totalTokens: 10, estimatedCostUsd: 0.1, contextPressure: 0.2 },
      { total_tokens: 20, estimated_cost_usd: 0.05, context_pressure: 0.45 },
    ],
  });

  assert.equal(summary.total_tokens, 20);
  assert.equal(summary.estimated_cost_usd, 0.05);
  assert.equal(summary.context_pressure, 0.45);
  assert.equal(summary.thread_id, null);

  const direct = contextBudgetUsageSummary({
    totalTokens: 99,
    estimatedCostUsd: 0.4,
    contextPressure: 0.8,
    threadId: "retired-thread",
  });
  assert.equal(direct.total_tokens, 0);
  assert.equal(direct.estimated_cost_usd, 0);
  assert.equal(direct.context_pressure, 0);
  assert.equal(direct.thread_id, null);
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
  const waiting = evaluateCompactionPolicyDecision({
    threadId: "thread-1",
    turnId: "turn-1",
    request: {
      contextBudgetStatus: "blocked",
      policy: {
        blockedAction: "compact",
        approvalRequired: "yes",
      },
    },
  });

  assert.equal(waiting.action, "approval_required");
  assert.equal(waiting.status, "waiting");
  assert.equal(waiting.approval_required, true);
  assert.equal(waiting.approval_satisfied, false);
  assert.equal(waiting.continuation_allowed, true);
  assert.match(waiting.approval_id, /^approval_compaction_thread-1_/);

  const compact = evaluateCompactionPolicyDecision({
    threadId: "thread-1",
    request: {
      contextBudget: { policyDecision: { status: "warning" } },
      policy: {
        warnAction: "compact",
        executeCompaction: "true",
      },
      approved: true,
    },
  });

  assert.equal(compact.action, "compact");
  assert.equal(compact.status, "compacted");
  assert.equal(compact.execute_compaction, true);
  assert.equal(compact.compaction_requested, true);
});
