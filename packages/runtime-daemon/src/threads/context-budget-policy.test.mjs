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

test("context budget telemetry and thresholds normalize request aliases", () => {
  const telemetry = { totalTokens: 12, estimatedCostUsd: 0.02, contextPressure: 0.3 };
  assert.equal(contextBudgetUsageTelemetryFromRequest({ runtime_usage_meter: telemetry }), telemetry);

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
    threadId: "thread-1",
    usage: [
      { totalTokens: 10, estimatedCostUsd: 0.1, contextPressure: 0.2 },
      { total_tokens: 20, estimated_cost_usd: 0.05, context_pressure: 0.45 },
    ],
  });

  assert.equal(summary.total_tokens, 30);
  assert.equal(summary.estimated_cost_usd, 0.15);
  assert.equal(summary.context_pressure, 0.45);
  assert.equal(summary.scope, "workflow");
  assert.equal(summary.thread_id, "thread-1");
});

test("coding tool budget policy reads tool pack aliases and annotates runtime context", () => {
  const result = codingToolBudgetPolicyForRequest({
    request: {
      source: "react_flow",
      options: {
        toolPack: {
          coding: {
            budgetUsageTelemetry: {
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
  });

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
      budgetUsageTelemetry: { total_tokens: 10 },
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
