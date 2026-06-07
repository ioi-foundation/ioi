#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-signed-replay-notebook-proof.mjs <output-path>");
}

const { buildWorkflowSignedReplayNotebook } = await import(
  "../../packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts"
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

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage28-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage28-state-"));
const targetPath = path.join(cwd, "replay-target.txt");
const before = "version = 1\n";
const after = "version = 2\n";
fs.writeFileSync(targetPath, before, "utf8");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.signed-replay-notebook";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove signed replay notebook cells over workspace snapshots.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.signed-replay",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });

  const patch = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "workflow.signed-replay.file.apply_patch",
      toolCallId: "coding_tool_signed_replay_patch",
      toolPack: { coding: { diagnosticsMode: "skip" } },
      input: {
        path: "replay-target.txt",
        oldText: before.trim(),
        newText: after.trim(),
      },
    }),
  });
  assert.equal(patch.status, "completed");
  assert.equal(patch.result.applied, true);
  assert.equal(fs.readFileSync(targetPath, "utf8"), after);
  assert.ok(patch.workspace_snapshot?.snapshot_id);

  const snapshots = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots`);
  assert.ok(snapshots.snapshots.some((snapshot) => snapshot.snapshot_id === patch.workspace_snapshot.snapshot_id));

  const restorePreview = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots/${patch.workspace_snapshot.snapshot_id}/restore-preview`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "workflow.signed-replay.restore.preview",
      }),
    },
  );
  assert.equal(restorePreview.preview_status, "ready");
  assert.equal(restorePreview.operations[0]?.path, "replay-target.txt");
  assert.match(restorePreview.operations[0]?.diff, /version = 1/);
  assert.equal(fs.readFileSync(targetPath, "utf8"), after);

  const restoreApplyBlocked = await fetchJson(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots/${patch.workspace_snapshot.snapshot_id}/restore-apply`,
    {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "workflow.signed-replay.restore.apply.blocked",
      }),
    },
  );
  assert.equal(restoreApplyBlocked.apply_status, "blocked");
  assert.equal(restoreApplyBlocked.approval_required, true);
  assert.equal(restoreApplyBlocked.approval_satisfied, false);
  assert.equal(restoreApplyBlocked.operations[0]?.apply_reason, "workspace_restore_apply_requires_approval");
  assert.equal(fs.readFileSync(targetPath, "utf8"), after);

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const notebook = buildWorkflowSignedReplayNotebook({
    events,
    snapshots: snapshots.snapshots,
    restoreResults: [restorePreview, restoreApplyBlocked],
  });
  const snapshotCell = notebook.cells.find((cell) => cell.cell_kind === "snapshot");
  const previewCell = notebook.cells.find((cell) => cell.cell_kind === "restore_preview");
  const blockedApplyCell = notebook.cells.find(
    (cell) => cell.cell_kind === "restore_apply" && cell.status === "blocked",
  );

  assert.ok(snapshotCell);
  assert.ok(previewCell);
  assert.ok(blockedApplyCell);
  assert.equal(notebook.status, "ready");
  assert.equal(notebook.read_only_replay_mode, true);
  assert.equal(notebook.snapshot_count >= 1, true);
  assert.equal(notebook.restore_preview_count >= 1, true);
  assert.equal(notebook.restore_apply_blocked_count, 1);
  assert.equal(notebook.restore_apply_applied_count, 0);
  assert.ok(notebook.rollback_ref_count >= 1);
  assert.equal(previewCell.read_only_replay, true);
  assert.equal(blockedApplyCell.read_only_replay, true);
  assert.equal(blockedApplyCell.approval_required, true);
  assert.equal(blockedApplyCell.approval_satisfied, false);
  assert.ok(snapshotCell.receipt_refs.length > 0);
  assert.ok(snapshotCell.artifact_refs.length > 0);
  assert.ok(snapshotCell.rollback_refs.includes(patch.workspace_snapshot.snapshot_id));
  assert.ok(previewCell.restore_apply_endpoint?.includes("/restore-apply"));
  assert.equal(fs.readFileSync(targetPath, "utf8"), after);

  const proof = {
    schemaVersion: "ioi.autopilot.stage28.signed-replay-notebook-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    snapshotId: patch.workspace_snapshot.snapshot_id,
    patchEventId: patch.event.event_id,
    restorePreviewEventId: restorePreview.event.event_id,
    checks: {
      patchCreatedWorkspaceSnapshot: Boolean(patch.workspace_snapshot?.snapshot_id),
      snapshotListed: snapshots.snapshots.some((snapshot) => snapshot.snapshot_id === patch.workspace_snapshot.snapshot_id),
      previewReadyAndReadOnly: restorePreview.preview_status === "ready" && fs.readFileSync(targetPath, "utf8") === after,
      applyWithoutApprovalBlocked: restoreApplyBlocked.apply_status === "blocked" &&
        restoreApplyBlocked.approval_satisfied === false,
      readOnlyReplayModeVisible: notebook.read_only_replay_mode,
      notebookReady: notebook.status === "ready",
      snapshotCellReceipted: snapshotCell.receipt_refs.length > 0 && snapshotCell.artifact_refs.length > 0,
      rollbackRefsVisible: snapshotCell.rollback_refs.includes(patch.workspace_snapshot.snapshot_id),
    },
    receipts: {
      patch: patch.receipt_refs,
      snapshot: patch.workspace_snapshot.receipt_refs,
      restorePreview: restorePreview.receipt_refs,
      restoreApplyBlocked: restoreApplyBlocked.receipt_refs,
    },
    notebook,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
