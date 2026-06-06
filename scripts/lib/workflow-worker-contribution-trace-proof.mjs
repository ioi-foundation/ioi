#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-worker-contribution-trace-proof.mjs <output-path>");
}

const { buildWorkflowWorkerContributionTrace } = await import(
  "../../packages/agent-ide/src/runtime/workflow-worker-contribution-trace.ts"
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

function safeId(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9._:-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage29-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage29-state-"));
const targetPath = path.join(cwd, "worker-target.txt");
fs.writeFileSync(targetPath, "worker = draft\n", "utf8");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.worker-contribution-trace";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove worker contribution trace links subagent lineage to a file hunk.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.worker-contribution",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });

  const implementer = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      role: "implement",
      prompt: "Draft the worker-target.txt hunk and return CHANGES/EVIDENCE/RECEIPTS.",
      toolPack: "coding",
      mergePolicy: "manual_review",
      cancellationInheritance: "isolate",
      outputContract: ["SUMMARY", "CHANGES", "EVIDENCE", "RECEIPTS"],
      workflowGraphId,
      workflowNodeId: "runtime.subagent.spawn.worker-contribution",
      receiptRefs: ["receipt_worker_contribution_parent_authorized"],
      policyDecisionRefs: ["policy_worker_contribution_manual_review"],
    }),
  });
  assert.equal(implementer.merge_policy, "manual_review");
  assert.ok(implementer.child_thread_id);

  const workerNodeId = `workflow.worker.${safeId(implementer.subagent_id)}.file.apply_patch`;
  const patch = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: workerNodeId,
      toolCallId: "coding_tool_worker_contribution_patch",
      toolPack: { coding: { diagnosticsMode: "skip" } },
      input: {
        path: "worker-target.txt",
        oldText: "worker = draft",
        newText: "worker = implemented",
      },
    }),
  });
  assert.equal(patch.status, "completed");
  assert.equal(patch.result.applied, true);
  assert.equal(fs.readFileSync(targetPath, "utf8"), "worker = implemented\n");
  assert.ok(patch.rollback_refs.includes(patch.workspace_snapshot.snapshot_id));

  const listed = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`);
  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const contributions = [
    {
      contributionId: "worker-target-hunk-0",
      subagentId: implementer.subagent_id,
      childThreadId: implementer.child_thread_id,
      toolCallId: patch.tool_call_id,
      eventId: patch.event.event_id,
      filePath: "worker-target.txt",
      hunkIndex: 0,
      hunkHeader: "@@ -1 +1 @@",
      editCount: patch.result.editCount,
      receiptRefs: patch.receipt_refs,
      policyDecisionRefs: ["policy_worker_contribution_manual_review"],
    },
  ];
  const trace = buildWorkflowWorkerContributionTrace({
    events,
    subagents: listed.subagents,
    contributions,
  });
  const row = trace.rows[0];

  assert.equal(trace.status, "ready");
  assert.equal(trace.contributionCount, 1);
  assert.equal(trace.readyCount, 1);
  assert.equal(trace.manualReviewCount, 1);
  assert.equal(trace.missingWorkerCount, 0);
  assert.equal(trace.missingEventCount, 0);
  assert.equal(trace.missingReceiptCount, 0);
  assert.equal(row.subagentId, implementer.subagent_id);
  assert.equal(row.childThreadId, implementer.child_thread_id);
  assert.equal(row.mergePolicy, "manual_review");
  assert.equal(row.toolCallId, patch.tool_call_id);
  assert.equal(row.eventId, patch.event.event_id);
  assert.equal(row.filePath, "worker-target.txt");
  assert.equal(row.hunkIndex, 0);
  assert.equal(row.editCount, 1);
  assert.equal(row.snapshotId, patch.workspace_snapshot.snapshot_id);
  assert.ok(row.receiptRefs.length >= patch.receipt_refs.length);
  assert.ok(row.rollbackRefs.includes(patch.workspace_snapshot.snapshot_id));

  const proof = {
    schemaVersion: "ioi.autopilot.stage29.worker-contribution-trace-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    subagentId: implementer.subagent_id,
    childThreadId: implementer.child_thread_id,
    patchEventId: patch.event.event_id,
    snapshotId: patch.workspace_snapshot.snapshot_id,
    checks: {
      subagentLineageVisible: row.subagentId === implementer.subagent_id &&
        row.childThreadId === implementer.child_thread_id,
      manualReviewMergePolicyVisible: row.mergePolicy === "manual_review",
      contributionEventLinked: row.eventId === patch.event.event_id,
      hunkFileAndIndexVisible: row.filePath === "worker-target.txt" && row.hunkIndex === 0,
      receiptsLinked: row.receiptRefs.length >= patch.receipt_refs.length,
      rollbackSnapshotLinked: row.rollbackRefs.includes(patch.workspace_snapshot.snapshot_id),
      traceReady: trace.status === "ready",
    },
    contribution: contributions[0],
    trace,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
