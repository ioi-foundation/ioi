import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeWorkspaceSnapshotSurface } from "./runtime-workspace-snapshot-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

function hash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function createSurface() {
  const writes = [];
  const surface = createRuntimeWorkspaceSnapshotSurface({
    notFound,
    runtimeError,
    now: () => "2026-06-04T15:00:00.000Z",
    workspaceRestoreApplyAllowsConflicts: () => false,
    workspaceRestoreApplyApprovalForRequest: (request = {}) => ({
      required: true,
      satisfied: request.confirm === true,
      source: request.confirm === true ? "request_confirmed" : "approval_required",
    }),
    workspaceRestoreApplyBlockedReason: (_operation, options = {}) =>
      options.approvalSatisfied ? "workspace_restore_apply_blocked_by_policy" : "workspace_restore_apply_requires_approval",
    workspaceRestoreApplyPolicyDecisionRefs: ({ snapshotId, approval } = {}) => [
      `policy_workspace_restore_apply_${snapshotId}_${approval?.satisfied ? "approval_satisfied" : "approval_required"}`,
    ],
    workspaceRestoreApplyStatus: (counts = {}) => {
      if (counts.applyBlockedCount > 0) return "blocked";
      if (counts.failedCount > 0) return "failed";
      if (counts.appliedCount === 0 && counts.applyNoopCount === counts.fileCount) return "noop";
      return "applied";
    },
    workspaceRestoreApplySummary: ({ snapshotId, applyStatus }) =>
      `Restore apply ${applyStatus} for ${snapshotId}.`,
    writeJson(filePath, value) {
      writes.push({ filePath, value });
    },
  });
  return { surface, writes };
}

function createStore(cwd = "/workspace") {
  const events = [];
  return {
    codingArtifacts: new Map(),
    events,
    agentForThread(threadId) {
      assert.equal(threadId, "thread_alpha");
      return { id: "agent_alpha", cwd };
    },
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
      };
      events.push(event);
      return event;
    },
    runtimeEventStream() {
      return { events };
    },
    pathFor(...segments) {
      return path.join("/tmp/runtime-workspace-snapshots", ...segments);
    },
  };
}

test("workspace snapshot surface prepares snapshots and persists content artifact", () => {
  const { surface, writes } = createSurface();
  const store = createStore();

  const snapshot = surface.prepareWorkspaceSnapshotForPatch(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    workspaceRoot: "/workspace",
    toolCallId: "tool_call_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_alpha",
    result: {
      applied: true,
      changedFiles: [
        {
          path: "src/app.js",
          beforeHash: hash("old"),
          afterHash: hash("newer"),
          beforeExists: true,
          afterExists: true,
          beforeSizeBytes: 3,
          afterSizeBytes: 5,
        },
      ],
      workspaceSnapshotDrafts: [
        {
          path: "src/app.js",
          beforeContent: "old",
          afterContent: "newer",
        },
      ],
    },
  });

  assert.equal(snapshot.record.fileCount, 1);
  assert.equal(snapshot.record.changedFileCount, 1);
  assert.equal(snapshot.record.restore.previewSupported, true);
  assert.match(snapshot.record.snapshotId, /^workspace_snapshot_tool_call_alpha_/);
  assert.equal(snapshot.artifactRecord.channel, "workspace-snapshot");
  assert.equal(snapshot.artifactRecord.created_at, "2026-06-04T15:00:00.000Z");
  assert.equal(store.codingArtifacts.get(snapshot.artifactRecord.id), snapshot.artifactRecord);
  assert.equal(writes.length, 1);
  assert.match(writes[0].filePath, /workspace_snapshot_tool_call_alpha_.*_content\.json$/);
});

test("workspace snapshot surface appends and lists snapshot events", () => {
  const { surface } = createSurface();
  const store = createStore();
  const snapshot = {
    snapshotId: "workspace_snapshot_alpha",
    snapshotHash: "hash_alpha",
    snapshotKind: "pre_post_touched_files",
    fileCount: 1,
    changedFileCount: 1,
    createdFileCount: 0,
    deletedFileCount: 0,
    restore: { status: "content_captured", previewSupported: true, applySupported: true },
    trigger: { toolCallId: "tool_call_alpha", workflowGraphId: "graph_alpha", workflowNodeId: "node_alpha" },
    files: [{ path: "src/app.js" }],
    receiptRefs: ["receipt_alpha"],
    artifactRefs: ["artifact_alpha"],
    summary: "snapshot ready",
  };

  const event = surface.appendWorkspaceSnapshotEvent(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    workspaceRoot: "/workspace",
    snapshot,
  });

  assert.equal(event.event_kind, "workspace.snapshot.created");
  assert.equal(event.workflow_node_id, "runtime.workspace-snapshot");
  assert.deepEqual(event.rollback_refs, ["workspace_snapshot_alpha"]);
  const list = surface.listWorkspaceSnapshots(store, "thread_alpha");
  assert.equal(list.snapshotCount, 1);
  assert.equal(list.snapshots[0].snapshotId, "workspace_snapshot_alpha");
});

test("workspace snapshot surface reads content packages and fails closed when unavailable", () => {
  const { surface } = createSurface();
  const store = createStore();
  store.codingArtifacts.set("artifact_snapshot", {
    id: "artifact_snapshot",
    thread_id: "thread_alpha",
    channel: "workspace-snapshot",
    content: JSON.stringify({
      snapshot: {
        snapshotId: "workspace_snapshot_alpha",
        restore: { previewSupported: true },
      },
      files: [{ path: "src/app.js" }],
    }),
  });

  const pkg = surface.workspaceSnapshotContentPackage(store, "thread_alpha", "workspace_snapshot_alpha");
  assert.equal(pkg.artifactRecord.id, "artifact_snapshot");
  assert.deepEqual(pkg.files, [{ path: "src/app.js" }]);

  store.codingArtifacts.set("artifact_snapshot_blocked", {
    id: "artifact_snapshot_blocked",
    thread_id: "thread_alpha",
    channel: "workspace-snapshot",
    content: JSON.stringify({
      snapshot: {
        snapshotId: "workspace_snapshot_blocked",
        restore: { previewSupported: false, status: "partial_content" },
      },
      files: [],
    }),
  });
  assert.throws(
    () => surface.workspaceSnapshotContentPackage(store, "thread_alpha", "workspace_snapshot_blocked"),
    (error) => error.status === 409 && error.code === "workspace_restore_preview_unavailable",
  );
});

test("workspace snapshot surface materializes restore artifacts and appends restore events", () => {
  const { surface, writes } = createSurface();
  const store = createStore();
  const preview = {
    snapshotId: "workspace_snapshot_alpha",
    previewStatus: "ready",
    operations: [{ path: "src/app.js", status: "ready" }],
    artifactRefs: ["artifact_preview"],
    receiptRefs: ["receipt_preview"],
    rollbackRefs: ["workspace_snapshot_alpha"],
  };
  const apply = {
    snapshotId: "workspace_snapshot_alpha",
    applyStatus: "blocked",
    operations: [{ path: "src/app.js", applyStatus: "blocked" }],
    artifactRefs: ["artifact_apply"],
    receiptRefs: ["receipt_apply"],
    rollbackRefs: ["workspace_snapshot_alpha"],
    policyDecisionRefs: ["policy_apply"],
  };

  const previewArtifact = surface.materializeWorkspaceRestorePreviewArtifact(store, {
    threadId: "thread_alpha",
    workspaceRoot: "/workspace",
    snapshotId: "workspace_snapshot_alpha",
    artifactId: "artifact_preview",
    receiptId: "receipt_preview",
    preview,
  });
  const applyArtifact = surface.materializeWorkspaceRestoreApplyArtifact(store, {
    threadId: "thread_alpha",
    workspaceRoot: "/workspace",
    snapshotId: "workspace_snapshot_alpha",
    artifactId: "artifact_apply",
    receiptId: "receipt_apply",
    apply,
  });
  const previewEvent = surface.appendWorkspaceRestorePreviewEvent(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    workspaceRoot: "/workspace",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "restore_node",
    preview,
  });
  const applyEvent = surface.appendWorkspaceRestoreApplyEvent(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    workspaceRoot: "/workspace",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "restore_node",
    apply,
  });

  assert.equal(previewArtifact.channel, "restore-preview");
  assert.equal(applyArtifact.channel, "restore-apply");
  assert.equal(previewEvent.status, "completed");
  assert.equal(previewEvent.payload_schema_version, "ioi.runtime.workspace-restore-preview.v1");
  assert.equal(applyEvent.status, "blocked");
  assert.deepEqual(applyEvent.policy_decision_refs, ["policy_apply"]);
  assert.equal(writes.length, 2);
});

test("workspace snapshot surface previews and applies snapshot restores", () => {
  const { surface } = createSurface();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-workspace-restore-"));
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src", "app.js"), "new");
  const store = createStore(cwd);
  store.codingArtifacts.set("artifact_snapshot", {
    id: "artifact_snapshot",
    thread_id: "thread_alpha",
    channel: "workspace-snapshot",
    content: JSON.stringify({
      snapshot: {
        snapshotId: "workspace_snapshot_alpha",
        snapshotHash: "hash_alpha",
        turnId: "turn_alpha",
        restore: { previewSupported: true },
      },
      files: [
        {
          path: "src/app.js",
          before: {
            exists: true,
            content: "old",
            contentHash: hash("old"),
          },
          after: {
            exists: true,
            contentHash: hash("new"),
          },
        },
      ],
    }),
  });

  const preview = surface.previewWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_alpha", {
    workflowNodeId: "restore_node",
  });
  assert.equal(preview.previewStatus, "ready");
  assert.equal(preview.event.event_kind, "workspace.restore.previewed");
  assert.equal(preview.event.workflow_node_id, "restore_node");

  const blocked = surface.applyWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_alpha", {});
  assert.equal(blocked.applyStatus, "blocked");
  assert.equal(fs.readFileSync(path.join(cwd, "src", "app.js"), "utf8"), "new");

  const applied = surface.applyWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_alpha", {
    confirm: true,
  });
  assert.equal(applied.applyStatus, "applied");
  assert.equal(fs.readFileSync(path.join(cwd, "src", "app.js"), "utf8"), "old");
  assert.equal(applied.event.event_kind, "workspace.restore.applied");
});
