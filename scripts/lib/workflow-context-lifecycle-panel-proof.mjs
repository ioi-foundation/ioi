#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-context-lifecycle-panel-proof.mjs <output-path>");
}

const { buildWorkflowContextLifecyclePanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-context-lifecycle-panel.ts"
);

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const body = await response.json();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${JSON.stringify(body)}`);
  return body;
}

async function fetchSseEvents(url) {
  const response = await fetch(url);
  const text = await response.text();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${text}`);
  return text
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.replace(/^data:\s?/, ""))
        .join("\n");
      return JSON.parse(data);
    });
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage27-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage27-state-"));
const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.context-lifecycle";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove context pressure and compaction lifecycle visibility.",
      options: {
        local: { cwd },
        model: { id: "auto", routeId: "route.native-local" },
      },
    }),
  });

  const turnStarted = performance.now();
  const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      prompt: "Give a concise context lifecycle proof response.",
      mode: "send",
    }),
  });
  const turnLatencyMs = Math.round(performance.now() - turnStarted);
  assert.equal(turn.status, "completed");
  assert.ok(turnLatencyMs < 30_000, `simple native-local turn exceeded 30s: ${turnLatencyMs}ms`);

  const usageTelemetry = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/usage?workflow_graph_id=${encodeURIComponent(workflowGraphId)}&workflow_node_id=runtime.usage-meter&source=react_flow`,
  );
  assert.ok(usageTelemetry.total_tokens >= turn.usage.total_tokens);

  const budget = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/context-budget`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      actor: "workflow-author",
      scope: "thread",
      workflowGraphId,
      workflowNodeId: "runtime.context-budget",
      mode: "block",
      usageTelemetry,
      thresholds: {
        maxTotalTokens: 1,
        maxCostUsd: 0.000001,
        maxContextPressure: 0.000001,
      },
    }),
  });
  assert.equal(budget.status, "blocked");
  assert.equal(budget.would_block, true);
  assert.ok(budget.violations.length >= 1);
  assert.ok(budget.receipt_refs[0].startsWith("receipt_context_budget_thread_"));

  const compaction = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/compaction-policy`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      actor: "workflow-author",
      workflowGraphId,
      workflowNodeId: "runtime.compaction-policy",
      turnId: turn.turn_id,
      contextBudget: budget,
      contextBudgetStatus: budget.status,
      policy: {
        blockedAction: "compact",
        approvalRequired: true,
        approvalGranted: true,
        executeCompaction: true,
        compactReason: "Stage 27 approved compaction after context budget block.",
        compactScope: "thread",
        compactWorkflowNodeId: "runtime.context-compact",
      },
    }),
  });
  assert.equal(compaction.status, "compacted");
  assert.equal(compaction.action, "compact");
  assert.equal(compaction.approval_required, true);
  assert.equal(compaction.approval_satisfied, true);
  assert.equal(compaction.compaction_executed, true);
  assert.ok(compaction.compaction_event_id);

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const panel = buildWorkflowContextLifecyclePanel({ events, usageTelemetry });
  const budgetRow = panel.rows.find((row) => row.rowKind === "context_budget");
  const policyRow = panel.rows.find((row) => row.rowKind === "compaction_policy");
  const compactRow = panel.rows.find((row) => row.rowKind === "context_compaction");

  assert.ok(budgetRow);
  assert.ok(policyRow);
  assert.ok(compactRow);
  assert.equal(panel.status, "ready");
  assert.equal(panel.budgetStatus, "blocked");
  assert.equal(panel.compactionAction, "compact");
  assert.equal(panel.compactionExecuted, true);
  assert.equal(panel.blockedBudgetCount, 1);
  assert.equal(panel.compactedCount, 1);
  assert.equal(panel.missingReceiptCount, 0);
  assert.equal(budgetRow.status, "blocked");
  assert.ok(budgetRow.totalTokens >= turn.usage.total_tokens);
  assert.ok(budgetRow.violationIds.includes("total_tokens"));
  assert.equal(policyRow.approvalRequired, true);
  assert.equal(policyRow.approvalSatisfied, true);
  assert.equal(policyRow.executeCompaction, true);
  assert.equal(policyRow.compactionExecuted, true);
  assert.equal(policyRow.compactionEventId, compaction.compaction_event_id);
  assert.equal(compactRow.status, "completed");
  assert.equal(compactRow.compactReason, "Stage 27 approved compaction after context budget block.");
  assert.ok(panel.rows.every((row) => row.rowKind === "usage_snapshot" || row.receiptRefs.length > 0));

  const proof = {
    schemaVersion: "ioi.autopilot.stage27.context-lifecycle-panel-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    turnId: turn.turn_id,
    workflowGraphId,
    turnLatencyMs,
    budgetEventId: budget.event_id,
    compactionPolicyEventId: compaction.event_id,
    compactionEventId: compaction.compaction_event_id,
    checks: {
      simpleTurnUnderThirtySeconds: turnLatencyMs < 30_000,
      usageTelemetryIncludesTurn: usageTelemetry.total_tokens >= turn.usage.total_tokens,
      contextBudgetBlocked: budget.status === "blocked" && budget.would_block === true,
      budgetReceiptLinked: budget.receipt_refs[0]?.startsWith("receipt_context_budget_thread_") === true,
      approvedCompactionExecuted: compaction.status === "compacted" && compaction.compaction_executed === true,
      panelReady: panel.status === "ready",
      rowsAreReceipted: panel.rows.every((row) => row.rowKind === "usage_snapshot" || row.receiptRefs.length > 0),
      compactReasonVisible: compactRow.compactReason ===
        "Stage 27 approved compaction after context budget block.",
    },
    receipts: {
      budget: budget.receipt_refs,
      compactionPolicy: compaction.receipt_refs,
      contextCompaction: compactRow.receiptRefs,
    },
    panel,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
