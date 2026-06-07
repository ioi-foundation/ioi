import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkflowContextLifecyclePanel } from "./workflow-context-lifecycle-panel";

test("context lifecycle panel reads canonical usage snapshot identity and evidence", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [],
    usageTelemetry: {
      thread_id: "thread-canonical",
      turn_id: "turn-canonical",
      workflow_graph_id: "workflow-canonical",
      workflow_node_id: "workflow.usage-canonical",
      usage_meter_scope: "thread",
      total_tokens: 2048,
      estimated_cost_usd: 0.42,
      context_pressure: 0.62,
      receipt_refs: ["receipt-canonical"],
      policy_decision_refs: ["policy-canonical"],
    },
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "usage_snapshot");
  assert.equal(panel.rows[0]?.threadId, "thread-canonical");
  assert.equal(panel.rows[0]?.turnId, "turn-canonical");
  assert.equal(panel.rows[0]?.workflowGraphId, "workflow-canonical");
  assert.equal(panel.rows[0]?.workflowNodeId, "workflow.usage-canonical");
  assert.equal(panel.rows[0]?.scope, "thread");
  assert.equal(panel.rows[0]?.totalTokens, 2048);
  assert.equal(panel.rows[0]?.estimatedCostUsd, 0.42);
  assert.equal(panel.rows[0]?.contextPressure, 0.62);
  assert.deepEqual(panel.rows[0]?.receiptRefs, ["receipt-canonical"]);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, ["policy-canonical"]);
  assert.deepEqual(panel.evidenceRefs, ["receipt-canonical"]);
});

test("context lifecycle panel ignores retired usage snapshot aliases", () => {
  const panel = buildWorkflowContextLifecyclePanel({
    events: [],
    usageTelemetry: {
      threadId: "thread-retired",
      turnId: "turn-retired",
      workflowGraphId: "workflow-retired",
      workflowNodeId: "workflow.usage-retired",
      usageMeterScope: "thread-retired",
      total_tokens: 4096,
      estimated_cost_usd: 0.84,
      context_pressure: 0.81,
      receiptRefs: ["receipt-retired"],
      policyDecisionRefs: ["policy-retired"],
    },
  });

  assert.equal(panel.rows.length, 1);
  assert.equal(panel.rows[0]?.rowKind, "usage_snapshot");
  assert.equal(panel.rows[0]?.threadId, null);
  assert.equal(panel.rows[0]?.turnId, null);
  assert.equal(panel.rows[0]?.workflowGraphId, null);
  assert.equal(panel.rows[0]?.workflowNodeId, "runtime.usage-meter");
  assert.equal(panel.rows[0]?.scope, null);
  assert.equal(panel.rows[0]?.totalTokens, 4096);
  assert.deepEqual(panel.rows[0]?.receiptRefs, []);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(panel.evidenceRefs, []);
});
