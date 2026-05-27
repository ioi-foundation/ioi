#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-file-apply-patch-atomicity-proof.mjs <output-path>");
}

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

function read(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-patch-atomicity-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-patch-atomicity-state-"));
const successPath = path.join(cwd, "success.txt");
const stalePath = path.join(cwd, "stale.txt");
const successBefore = "alpha = 1\nbeta = 1\ngamma = 1\n";
const successAfter = "alpha = 2\nbeta = 2\ngamma = 1\n";
const staleBefore = "first = old\nsecond = old\nthird = stable\n";

fs.writeFileSync(successPath, successBefore, "utf8");
fs.writeFileSync(stalePath, staleBefore, "utf8");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.file-apply-patch-atomicity";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove file.apply_patch multi-edit atomicity for all-green and stale-hunk transactions.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.atomicity",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });
  assert.equal(mode.mode, "yolo");
  assert.equal(mode.approval_mode, "never_prompt");

  const success = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "workflow.coding.file.apply_patch.atomicity.success",
        toolCallId: "coding_tool_atomic_patch_success",
        input: {
          path: "success.txt",
          edits: [
            { type: "replace", oldText: "alpha = 1", newText: "alpha = 2" },
            { type: "replace", oldText: "beta = 1", newText: "beta = 2" },
          ],
        },
      }),
    },
  );
  assert.equal(success.status, "completed");
  assert.equal(success.result.editCount, 2);
  assert.equal(success.result.applied, true);
  assert.equal(read(successPath), successAfter);

  const stale = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "workflow.coding.file.apply_patch.atomicity.stale",
        toolCallId: "coding_tool_atomic_patch_stale_hunk",
        input: {
          path: "stale.txt",
          edits: [
            { type: "replace", oldText: "first = old", newText: "first = new" },
            { type: "replace", oldText: "second = stale-elsewhere", newText: "second = new" },
          ],
        },
      }),
    },
  );
  assert.equal(stale.status, "failed");
  assert.equal(stale.error?.code, "file_apply_patch_old_text_missing");
  assert.equal(read(stalePath), staleBefore);
  assert.equal(stale.workspace_snapshot, null);
  assert.deepEqual(stale.rollback_refs, []);

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const successEvent = events.find((event) => event.tool_call_id === "coding_tool_atomic_patch_success");
  const staleEvent = events.find((event) => event.tool_call_id === "coding_tool_atomic_patch_stale_hunk");
  assert.equal(successEvent?.event_kind, "tool.completed");
  assert.equal(staleEvent?.event_kind, "tool.failed");
  assert.equal(staleEvent?.payload_summary?.error?.code, "file_apply_patch_old_text_missing");

  const checks = {
    modeAllowsRealRuntimeExecution: mode.mode === "yolo" && mode.approval_mode === "never_prompt",
    allGreenMultiHunkApplied: success.status === "completed" && success.result.editCount === 2 && read(successPath) === successAfter,
    allGreenSnapshotRecorded: Boolean(success.workspace_snapshot?.snapshotId),
    staleMultiHunkRejected: stale.status === "failed" && stale.error?.code === "file_apply_patch_old_text_missing",
    staleTransactionDidNotMutateDisk: read(stalePath) === staleBefore,
    staleFailureHasNoSnapshotBecauseNoCommitOccurred: stale.workspace_snapshot === null,
    timelineShowsCompletedAndFailedPatchEvents:
      successEvent?.event_kind === "tool.completed" && staleEvent?.event_kind === "tool.failed",
    staleFailureCarriesWorkflowIdentity:
      staleEvent?.workflow_graph_id === workflowGraphId &&
      staleEvent?.workflow_node_id === "workflow.coding.file.apply_patch.atomicity.stale",
  };

  const proof = {
    schemaVersion: "workflow.file-apply-patch.atomicity-proof.v1",
    scenario: "multi_hunk_file_apply_patch_atomicity",
    passed: Object.values(checks).every(Boolean),
    startedAt: new Date().toISOString(),
    workspaceRoot: cwd,
    stateDir,
    threadId: thread.thread_id,
    workflowGraphId,
    success: {
      status: success.status,
      toolCallId: success.tool_call_id,
      editCount: success.result.editCount,
      applied: success.result.applied,
      workspaceSnapshotId: success.workspace_snapshot?.snapshotId ?? null,
      receiptRefs: success.receipt_refs,
      rollbackRefs: success.rollback_refs,
      eventId: successEvent?.event_id ?? null,
    },
    stale: {
      status: stale.status,
      toolCallId: stale.tool_call_id,
      errorCode: stale.error?.code ?? null,
      diskContentPreserved: read(stalePath) === staleBefore,
      workspaceSnapshotId: stale.workspace_snapshot?.snapshotId ?? null,
      receiptRefs: stale.receipt_refs,
      rollbackRefs: stale.rollback_refs,
      eventId: staleEvent?.event_id ?? null,
      note: "The stale transaction writes nothing, so no rollback snapshot is needed.",
    },
    checks,
    sourceRefs: [
      "packages/runtime-daemon/src/coding-tools.mjs:fileApplyPatchTool",
      "packages/runtime-daemon/src/index.mjs:invokeCodingTool",
      "scripts/lib/workflow-file-apply-patch-atomicity-proof.mjs",
    ],
  };
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
} finally {
  await daemon.close();
}
