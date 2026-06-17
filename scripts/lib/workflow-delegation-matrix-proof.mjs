#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-delegation-matrix-proof.mjs <output-path>");
}

const { buildWorkflowRuntimeDelegationMatrix } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-delegation-matrix.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage16-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage16-state-"));
const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.delegation-matrix";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove subagent delegation lanes expose lineage, memory scope, cancellation, and writeback policy.",
      options: {
        local: { cwd },
        model: { id: "auto", routeId: "route.native-local" },
        agents: { reviewer: { prompt: "Review delegated evidence." } },
      },
    }),
  });
  const targetedMemory = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      text: "Delegation matrix reviewer memory.",
      memoryKey: "delegation-matrix",
      scope: "thread",
    }),
  });
  assert.ok(targetedMemory.record.id);

  const readOnlyTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      prompt: "Delegate with read-only inherited memory and attempted write.",
      mode: "handoff",
      options: {
        receiver: "reviewer",
        memory: {
          subagentInheritance: "read_only",
          memoryKey: "delegation-matrix",
          remember: "This read-only write must be blocked.",
        },
      },
    }),
  });
  const readOnlyTrace = await fetchJson(
    `${daemon.endpoint}/v1/runs/run_${readOnlyTurn.turn_id.slice("turn_".length)}/trace`,
  );
  assert.equal(readOnlyTrace.subagentMemoryInheritance.mode, "read_only");
  assert.equal(readOnlyTrace.subagentMemoryInheritance.writeBlockReason, "memory_read_only");
  assert.equal(readOnlyTrace.memoryWrites.length, 0);

  const fullTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      prompt: "Delegate with full inherited memory and permitted write.",
      mode: "handoff",
      options: {
        receiver: "reviewer",
        memory: {
          subagentInheritance: "full",
          memoryKey: "delegation-matrix",
          remember: "This full-inheritance write is allowed.",
        },
      },
    }),
  });
  const fullTrace = await fetchJson(
    `${daemon.endpoint}/v1/runs/run_${fullTurn.turn_id.slice("turn_".length)}/trace`,
  );
  assert.equal(fullTrace.subagentMemoryInheritance.mode, "full");
  assert.equal(fullTrace.subagentMemoryInheritance.writeBlockReason, null);
  assert.equal(fullTrace.memoryWrites.length, 1);

  const explore = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      role: "explore",
      prompt: "Inspect delegated evidence and return receipts.",
      toolPack: "coding",
      mergePolicy: "evidence_only",
      cancellationInheritance: "propagate",
      outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
      workflowGraphId,
      workflowNodeId: "runtime.subagent.spawn.explore",
      receiptRefs: ["receipt_delegation_matrix_source"],
      policyDecisionRefs: ["policy_delegation_matrix_spawn"],
    }),
  });
  const implement = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      role: "implement",
      prompt: "Prepare writeback but require manual review.",
      toolPack: "coding",
      mergePolicy: "manual_review",
      cancellationInheritance: "isolate",
      outputContract: ["SUMMARY", "CHANGES", "EVIDENCE", "RECEIPTS"],
      workflowGraphId,
      workflowNodeId: "runtime.subagent.spawn.implement",
      receiptRefs: ["receipt_delegation_matrix_writeback_source"],
      policyDecisionRefs: ["policy_delegation_matrix_writeback_manual_review"],
    }),
  });
  assert.equal(explore.cancellation_inheritance, "propagate");
  assert.equal(implement.cancellation_inheritance, "isolate");
  assert.equal(implement.merge_policy, "manual_review");
  assert.ok(explore.child_thread_id);
  assert.ok(implement.child_thread_id);

  const propagation = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/cancel`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      reason: "parent_cancel_delegation_matrix",
      workflowGraphId,
      workflowNodeId: "runtime.subagent.cancel.propagated",
    }),
  });
  assert.equal(propagation.canceled_count, 1);
  assert.equal(propagation.skipped_count, 1);
  assert.equal(propagation.canceled_subagents[0]?.subagent_id, explore.subagent_id);
  assert.equal(propagation.skipped_subagents[0]?.subagent_id, implement.subagent_id);

  const listed = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`);
  assert.equal(listed.count, 2);
  const implementRecord = listed.subagents.find((row) => row.subagent_id === implement.subagent_id);
  assert.equal(implementRecord.merge_policy, "manual_review");
  assert.equal(implementRecord.cancellation_inheritance, "isolate");

  const events = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const matrix = buildWorkflowRuntimeDelegationMatrix(events, { threadId: thread.thread_id });
  assert.equal(matrix.status, "ready");
  assert.equal(matrix.subagentLaneCount, 2);
  assert.equal(matrix.childThreadCount, 2);
  assert.ok(matrix.manualReviewCount >= 1);
  assert.ok(matrix.cancellationIsolatedCount >= 1);
  assert.ok(matrix.cancellationPropagatedCount >= 1);
  assert.ok(matrix.writeBlockedCount >= 1);
  assert.ok(matrix.writeAllowedCount >= 1);
  assert.ok(matrix.rows.some((row) => row.rowKind === "memory_scope" && row.memoryMode === "read_only"));
  assert.ok(matrix.rows.some((row) => row.rowKind === "memory_scope" && row.memoryMode === "full"));
  assert.ok(matrix.rows.some((row) => row.subagentId === implement.subagent_id && row.mergePolicy === "manual_review"));

  const proof = {
    schemaVersion: "ioi.autopilot.stage16.delegation-matrix-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    subagents: {
      explore: {
        subagentId: explore.subagent_id,
        childThreadId: explore.child_thread_id,
        runId: explore.run_id,
        cancellationInheritance: explore.cancellation_inheritance,
        mergePolicy: explore.merge_policy,
      },
      implement: {
        subagentId: implement.subagent_id,
        childThreadId: implement.child_thread_id,
        runId: implement.run_id,
        cancellationInheritance: implement.cancellation_inheritance,
        mergePolicy: implement.merge_policy,
      },
    },
    checks: {
      readOnlyWriteBlocked: readOnlyTrace.subagentMemoryInheritance.writeBlockReason === "memory_read_only",
      fullWriteAllowed: fullTrace.memoryWrites.length === 1,
      parentChildLineageVisible: matrix.childThreadCount === 2,
      writebackManualReviewVisible: matrix.manualReviewCount >= 1,
      cancellationPropagationHonored: propagation.canceled_count === 1 && propagation.skipped_count === 1,
      isolatedSubagentSkipped: propagation.skipped_subagents[0]?.subagent_id === implement.subagent_id,
      receiptsPresent: matrix.receiptRefs.length > 0,
    },
    propagation,
    matrix,
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
