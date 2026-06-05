import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeSubagentBudgetUsageTelemetry,
  subagentBudgetUsageTelemetryForRequest,
  subagentUsageTelemetryForRun,
} from "./subagent-manager.mjs";

const retiredSubagentBudgetUsageRequestAliasKeys = [
  "budgetUsageTelemetry",
  "runtime_telemetry_summary",
  "runtimeTelemetrySummary",
];

const retiredSubagentUsageDataAliasInput = {
  cumulativeInputTokens: 5,
  inputTokens: 1,
  cumulativeOutputTokens: 7,
  outputTokens: 2,
  cumulativeTotalTokens: 99,
  totalTokens: 8,
  cumulativeCostEstimateUsd: 1.25,
  costEstimateUsd: 0.5,
  estimatedCostUsd: 0.75,
  sourceCounts: { runs: 1 },
  sourceRefs: ["source-retired"],
  receiptRefs: ["receipt-retired"],
  policyDecisionRefs: ["policy-retired"],
  runtimeTelemetrySummarySchemaVersion: "retired.summary.v1",
};

test("subagent budget usage telemetry accepts canonical request fields", () => {
  const telemetry = {
    cumulative_input_tokens: 3,
    cumulative_output_tokens: 4,
    cumulative_total_tokens: 10,
    cumulative_cost_estimate_usd: 0.12,
    source_counts: { runs: 1 },
    source_refs: ["usage-source"],
    receipt_refs: ["receipt-usage"],
    policy_decision_refs: ["policy-usage"],
    runtime_telemetry_summary_schema_version: "summary.v1",
  };

  const direct = subagentBudgetUsageTelemetryForRequest({
    budget_usage_telemetry: telemetry,
  });
  const nested = subagentBudgetUsageTelemetryForRequest({
    options: { budget_usage_telemetry: telemetry },
  });

  assert.equal(direct.cumulative_total_tokens, 10);
  assert.equal(direct.cumulative_cost_estimate_usd, 0.12);
  assert.deepEqual(direct.source_counts, { runs: 1 });
  assert.deepEqual(direct.source_refs, ["usage-source"]);
  assert.deepEqual(direct.receipt_refs, ["receipt-usage"]);
  assert.deepEqual(direct.policy_decision_refs, ["policy-usage"]);
  assert.equal(direct.runtime_telemetry_summary_schema_version, "summary.v1");
  assert.equal(nested.cumulative_total_tokens, 10);
});

test("subagent budget usage telemetry ignores retired request aliases", () => {
  for (const key of retiredSubagentBudgetUsageRequestAliasKeys) {
    assert.equal(
      subagentBudgetUsageTelemetryForRequest({
        [key]: {
          total_tokens: 100,
          cumulative_total_tokens: 100,
        },
      }),
      null,
    );
  }

  assert.equal(
    subagentBudgetUsageTelemetryForRequest({
      options: {
        budgetUsageTelemetry: {
          total_tokens: 100,
          cumulative_total_tokens: 100,
        },
      },
    }),
    null,
  );
});

test("subagent budget usage telemetry ignores retired data aliases", () => {
  const normalized = normalizeSubagentBudgetUsageTelemetry(
    retiredSubagentUsageDataAliasInput,
  );

  assert.equal(normalized.cumulative_input_tokens, 0);
  assert.equal(normalized.cumulative_output_tokens, 0);
  assert.equal(normalized.cumulative_total_tokens, 0);
  assert.equal(normalized.cumulative_cost_estimate_usd, 0);
  assert.equal(normalized.source_counts, null);
  assert.deepEqual(normalized.source_refs, []);
  assert.deepEqual(normalized.receipt_refs, []);
  assert.deepEqual(normalized.policy_decision_refs, []);
  assert.equal(normalized.runtime_telemetry_summary_schema_version, null);
});

test("subagent usage telemetry ignores retired previous usage aliases", () => {
  const run = {
    id: "run-one",
    result: "short result",
    model_route_decision: {
      route_id: "route.canonical",
      cost_estimate_usd: 0.42,
    },
    modelRouteDecision: {
      routeId: "route.retired",
      costEstimateUsd: 9,
    },
  };
  const canonical = subagentUsageTelemetryForRun(run, "short prompt", {
    cumulative_total_tokens: 10,
    cumulative_cost_estimate_usd: 0.2,
  });
  const retiredOnly = subagentUsageTelemetryForRun(
    run,
    "short prompt",
    retiredSubagentUsageDataAliasInput,
  );

  assert.equal(
    canonical.cumulative_total_tokens,
    canonical.total_tokens + 10,
  );
  assert.ok(canonical.cumulative_cost_estimate_usd > canonical.cost_estimate_usd);
  assert.equal(canonical.model_route_id, "route.canonical");
  assert.equal(canonical.cost_estimate_usd, 0.42);
  assert.equal(retiredOnly.cumulative_total_tokens, retiredOnly.total_tokens);
  assert.equal(retiredOnly.model_route_id, "route.canonical");
  assert.equal(retiredOnly.cost_estimate_usd, 0.42);
});
