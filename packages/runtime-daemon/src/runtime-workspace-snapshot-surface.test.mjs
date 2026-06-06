import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeWorkspaceSnapshotSurface } from "./runtime-workspace-snapshot-surface.mjs";

const RETIRED_WORKSPACE_ARTIFACT_ALIASES = [
  "schemaVersion",
  "threadId",
  "toolName",
  "toolCallId",
  "workspaceRoot",
  "mediaType",
  "receiptId",
  "contentBytes",
  "contentHash",
  "createdAt",
];

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
  const workspaceRestoreRunner = {
    planApplyPolicy(request = {}) {
      const approval = {
        required: true,
        satisfied: request.confirm === true || request.confirm_restore_apply === true,
        source: request.confirm === true || request.confirm_restore_apply === true ? "request_confirmed" : "approval_required",
      };
      const counts = request.counts;
      const applyStatus = counts
        ? counts.apply_blocked_count > 0
          ? "blocked"
          : counts.failed_count > 0
            ? "failed"
            : counts.applied_count === 0 && counts.apply_noop_count === counts.file_count
              ? "noop"
              : "applied"
        : null;
      return {
        approval,
        allowConflicts: false,
        allow_conflicts: false,
        conflictPolicy: "clean_preview_only",
        conflict_policy: "clean_preview_only",
        hardBlocked: false,
        hard_blocked: false,
        conflictBlocked: false,
        conflict_blocked: false,
        applyStatus,
        apply_status: applyStatus,
        policyDecisionRefs: [
          `policy_workspace_restore_apply_${request.snapshot_id}_${approval.satisfied ? "approval_satisfied" : "approval_required"}`,
        ],
        policy_decision_refs: [
          `policy_workspace_restore_apply_${request.snapshot_id}_${approval.satisfied ? "approval_satisfied" : "approval_required"}`,
        ],
        operationPolicies: (request.operations ?? []).map((operation) => ({
          path: operation.path,
          applyReason: approval.satisfied
            ? "workspace_restore_apply_blocked_by_policy"
            : "workspace_restore_apply_requires_approval",
          apply_reason: approval.satisfied
            ? "workspace_restore_apply_blocked_by_policy"
            : "workspace_restore_apply_requires_approval",
        })),
        operation_policies: (request.operations ?? []).map((operation) => ({
          path: operation.path,
          apply_reason: approval.satisfied
            ? "workspace_restore_apply_blocked_by_policy"
            : "workspace_restore_apply_requires_approval",
        })),
        summary: counts ? `Restore apply ${applyStatus} for ${request.snapshot_id}.` : null,
      };
    },
    previewOperations(request = {}) {
      return (request.files ?? []).map((file) => previewOperation(request.workspace_root, file));
    },
    applyOperations(request = {}) {
      return (request.files ?? []).map((file) => {
        const preview = previewOperation(request.workspace_root, file);
        if (preview.status === "noop") {
          return {
            ...preview,
            applyStatus: "noop",
            apply_status: "noop",
            appliedExists: preview.currentExists,
            applied_exists: preview.currentExists,
            appliedHash: preview.currentHash,
            applied_hash: preview.currentHash,
            appliedBytes: preview.currentBytes,
            applied_bytes: preview.currentBytes,
            appliedMatchesTarget: true,
            applied_matches_target: true,
          };
        }
        fs.mkdirSync(path.dirname(path.join(request.workspace_root, file.path)), { recursive: true });
        fs.writeFileSync(path.join(request.workspace_root, file.path), file.before.content ?? "", "utf8");
        return {
          ...preview,
          applyStatus: "applied",
          apply_status: "applied",
          appliedExists: true,
          applied_exists: true,
          appliedHash: hash(file.before.content ?? ""),
          applied_hash: hash(file.before.content ?? ""),
          appliedBytes: Buffer.byteLength(file.before.content ?? "", "utf8"),
          applied_bytes: Buffer.byteLength(file.before.content ?? "", "utf8"),
          appliedMatchesTarget: true,
          applied_matches_target: true,
        };
      });
    },
    captureSnapshotFiles(request = {}) {
      const draftsByPath = new Map((request.content_drafts ?? []).map((draft) => [draft.path, draft]));
      const captures = (request.changed_files ?? [])
        .filter((entry) => entry.path)
        .map((entry) => snapshotCapture(entry, draftsByPath.get(entry.path) ?? {}));
      const capturedFileCount = captures.filter((capture) => capture.contentCaptured).length;
      return {
        files: captures.map((capture) => capture.publicFile),
        contentFiles: captures.map((capture) => capture.contentFile),
        capturedFileCount,
        omittedFileCount: captures.length - capturedFileCount,
        contentCaptured: capturedFileCount === captures.length,
      };
    },
  };
  const surface = createRuntimeWorkspaceSnapshotSurface({
    notFound,
    runtimeError,
    now: () => "2026-06-04T15:00:00.000Z",
    workspaceRestoreRunner,
    writeJson(filePath, value) {
      writes.push({ filePath, value });
    },
  });
  return { surface, writes };
}

function snapshotCapture(entry = {}, draft = {}) {
  const beforeExists = Boolean(entry.beforeExists ?? entry.before_exists);
  const afterExists = Object.hasOwn(entry, "afterExists") || Object.hasOwn(entry, "after_exists")
    ? Boolean(entry.afterExists ?? entry.after_exists)
    : true;
  const beforeHash = entry.beforeHash ?? entry.before_hash ?? null;
  const afterHash = entry.afterHash ?? entry.after_hash ?? null;
  const before = snapshotCaptureSide(beforeExists, beforeHash, draft.beforeContent ?? draft.before_content);
  const after = snapshotCaptureSide(afterExists, afterHash, draft.afterContent ?? draft.after_content);
  const publicFile = {
    path: entry.path,
    created: Boolean(entry.created),
    deleted: beforeExists && !afterExists,
    changed: beforeHash !== afterHash,
    before: before.publicSide,
    after: after.publicSide,
    receiptRefs: [],
    receipt_refs: [],
    artifactRefs: [],
    artifact_refs: [],
  };
  return {
    publicFile,
    contentFile: {
      ...publicFile,
      before: before.contentSide,
      after: after.contentSide,
      encoding: "utf8",
    },
    contentCaptured: before.captured && after.captured,
  };
}

function snapshotCaptureSide(exists, contentHash, content) {
  if (!exists) {
    const side = {
      exists: false,
      contentHash,
      content_hash: contentHash,
      sizeBytes: 0,
      size_bytes: 0,
      mtimeMs: null,
      mtime_ms: null,
      contentCaptured: true,
      content_captured: true,
      contentBytes: 0,
      content_bytes: 0,
      omittedReason: null,
      omitted_reason: null,
    };
    return { publicSide: side, contentSide: { ...side, content: null }, captured: true };
  }
  const captured = typeof content === "string" && (!contentHash || hash(content) === contentHash);
  const side = {
    exists: true,
    contentHash,
    content_hash: contentHash,
    sizeBytes: content ? Buffer.byteLength(content, "utf8") : 0,
    size_bytes: content ? Buffer.byteLength(content, "utf8") : 0,
    mtimeMs: null,
    mtime_ms: null,
    contentCaptured: captured,
    content_captured: captured,
    contentBytes: content ? Buffer.byteLength(content, "utf8") : 0,
    content_bytes: content ? Buffer.byteLength(content, "utf8") : 0,
    omittedReason: captured ? null : "snapshot_content_missing",
    omitted_reason: captured ? null : "snapshot_content_missing",
  };
  return { publicSide: side, contentSide: { ...side, content: captured ? content : null }, captured };
}

function previewOperation(workspaceRoot, file = {}) {
  const targetPath = path.join(workspaceRoot, file.path);
  const currentExists = fs.existsSync(targetPath);
  const currentContent = currentExists ? fs.readFileSync(targetPath, "utf8") : "";
  const currentHash = currentExists ? hash(currentContent) : null;
  const targetExists = Boolean(file.before?.exists);
  const targetHash = targetExists ? file.before?.contentHash ?? file.before?.content_hash ?? null : null;
  const snapshotAfterExists = Boolean(file.after?.exists);
  const snapshotAfterHash = snapshotAfterExists ? file.after?.contentHash ?? file.after?.content_hash ?? null : null;
  const currentMatchesSnapshotPost =
    currentExists === snapshotAfterExists && (!snapshotAfterExists || currentHash === snapshotAfterHash);
  const currentMatchesRestoreTarget =
    currentExists === targetExists && (!targetExists || currentHash === targetHash);
  const status = currentMatchesRestoreTarget ? "noop" : currentMatchesSnapshotPost ? "ready" : "conflict";
  return {
    path: file.path,
    operation: currentMatchesRestoreTarget ? "noop" : targetExists ? "replace" : "delete",
    status,
    currentExists,
    current_exists: currentExists,
    currentHash,
    current_hash: currentHash,
    currentBytes: Buffer.byteLength(currentContent, "utf8"),
    current_bytes: Buffer.byteLength(currentContent, "utf8"),
    targetExists,
    target_exists: targetExists,
    targetHash,
    target_hash: targetHash,
    snapshotAfterExists,
    snapshot_after_exists: snapshotAfterExists,
    snapshotAfterHash,
    snapshot_after_hash: snapshotAfterHash,
    currentMatchesSnapshotPost,
    current_matches_snapshot_post: currentMatchesSnapshotPost,
    currentMatchesRestoreTarget,
    current_matches_restore_target: currentMatchesRestoreTarget,
    blockedReason: null,
    blocked_reason: null,
    diff: status === "ready" ? "diff" : "",
    diffBytes: status === "ready" ? 4 : 0,
    diff_bytes: status === "ready" ? 4 : 0,
    diffHash: hash(status === "ready" ? "diff" : ""),
    diff_hash: hash(status === "ready" ? "diff" : ""),
    diffTruncated: false,
    diff_truncated: false,
  };
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

  assert.equal(snapshot.record.file_count, 1);
  assert.equal(snapshot.record.changed_file_count, 1);
  assert.equal(snapshot.record.restore.preview_supported, true);
  assert.match(snapshot.record.snapshot_id, /^workspace_snapshot_tool_call_alpha_/);
  for (const field of [
    "schemaVersion",
    "threadId",
    "turnId",
    "workspaceRoot",
    "snapshotKind",
    "snapshotId",
    "snapshotHash",
    "fileCount",
    "changedFileCount",
    "createdFileCount",
    "deletedFileCount",
    "receiptRefs",
    "artifactRefs",
    "contentArtifactRefs",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(snapshot.record, field), false);
  }
  for (const field of ["toolName", "toolCallId", "workflowGraphId", "workflowNodeId"]) {
    assert.equal(Object.hasOwn(snapshot.record.trigger, field), false);
  }
  for (const field of ["maxContentBytes", "capturedFileCount", "omittedFileCount"]) {
    assert.equal(Object.hasOwn(snapshot.record.capture, field), false);
  }
  for (const field of ["previewSupported", "applySupported"]) {
    assert.equal(Object.hasOwn(snapshot.record.restore, field), false);
  }
  for (const field of ["contentIncluded", "contentArtifactIncluded", "pathsIncluded"]) {
    assert.equal(Object.hasOwn(snapshot.record.redaction, field), false);
  }
  assert.equal(snapshot.artifactRecord.channel, "workspace-snapshot");
  assert.equal(snapshot.artifactRecord.created_at, "2026-06-04T15:00:00.000Z");
  assert.equal(snapshot.artifactRecord.schema_version, "ioi.runtime.coding-tool-artifact.v1");
  assert.equal(snapshot.artifactRecord.thread_id, "thread_alpha");
  assert.equal(snapshot.artifactRecord.tool_name, "file.apply_patch");
  assert.equal(snapshot.artifactRecord.tool_call_id, "tool_call_alpha");
  assert.equal(snapshot.artifactRecord.workspace_root, "/workspace");
  for (const field of RETIRED_WORKSPACE_ARTIFACT_ALIASES) {
    assert.equal(Object.hasOwn(snapshot.artifactRecord, field), false);
  }
  const contentPayload = JSON.parse(snapshot.artifactRecord.content);
  assert.equal(contentPayload.schema_version, "ioi.runtime.workspace-snapshot.v1");
  assert.equal(contentPayload.thread_id, "thread_alpha");
  assert.equal(contentPayload.turn_id, "turn_alpha");
  assert.equal(contentPayload.workspace_root, "/workspace");
  assert.equal(contentPayload.snapshot_id, snapshot.record.snapshot_id);
  for (const field of ["schemaVersion", "threadId", "turnId", "workspaceRoot", "snapshotId", "snapshotHash"]) {
    assert.equal(Object.hasOwn(contentPayload, field), false);
  }
  assert.equal(store.codingArtifacts.get(snapshot.artifactRecord.id), snapshot.artifactRecord);
  assert.equal(writes.length, 1);
  assert.match(writes[0].filePath, /workspace_snapshot_tool_call_alpha_.*_content\.json$/);
});

test("workspace snapshot surface appends and lists snapshot events", () => {
  const { surface } = createSurface();
  const store = createStore();
  const snapshot = {
    snapshot_id: "workspace_snapshot_alpha",
    snapshot_hash: "hash_alpha",
    snapshot_kind: "pre_post_touched_files",
    file_count: 1,
    changed_file_count: 1,
    created_file_count: 0,
    deleted_file_count: 0,
    restore: { status: "content_captured", preview_supported: true, apply_supported: true },
    trigger: { tool_call_id: "tool_call_alpha", workflow_graph_id: "graph_alpha", workflow_node_id: "node_alpha" },
    files: [{ path: "src/app.js" }],
    receipt_refs: ["receipt_alpha"],
    artifact_refs: ["artifact_alpha"],
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
  assert.deepEqual(event.receipt_refs, ["receipt_alpha"]);
  assert.equal(event.payload_summary.snapshot_id, "workspace_snapshot_alpha");
  assert.equal(event.payload_summary.restore_preview_supported, true);
  const list = surface.listWorkspaceSnapshots(store, "thread_alpha");
  assert.equal(list.schema_version, "ioi.runtime.workspace-snapshot.v1");
  assert.equal(list.thread_id, "thread_alpha");
  assert.equal(list.snapshot_count, 1);
  assert.equal(list.snapshots[0].snapshot_id, "workspace_snapshot_alpha");
  assert.equal(Object.hasOwn(list.snapshots[0], "snapshotId"), false);
  for (const field of ["schemaVersion", "threadId", "snapshotCount"]) {
    assert.equal(Object.hasOwn(list, field), false);
  }
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
        snapshot_id: "workspace_snapshot_alpha",
        restore: { preview_supported: true },
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
        snapshot_id: "workspace_snapshot_blocked",
        restore: { preview_supported: false, status: "partial_content" },
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
    snapshot_id: "workspace_snapshot_alpha",
    preview_status: "ready",
    operations: [{ path: "src/app.js", status: "ready" }],
    artifact_refs: ["artifact_preview"],
    receipt_refs: ["receipt_preview"],
    rollback_refs: ["workspace_snapshot_alpha"],
  };
  const apply = {
    snapshot_id: "workspace_snapshot_alpha",
    apply_status: "blocked",
    operations: [{ path: "src/app.js", apply_status: "blocked" }],
    artifact_refs: ["artifact_apply"],
    receipt_refs: ["receipt_apply"],
    rollback_refs: ["workspace_snapshot_alpha"],
    policy_decision_refs: ["policy_apply"],
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
  for (const artifactRecord of [previewArtifact, applyArtifact]) {
    assert.equal(artifactRecord.schema_version, "ioi.runtime.coding-tool-artifact.v1");
    assert.equal(artifactRecord.thread_id, "thread_alpha");
    assert.equal(artifactRecord.tool_call_id, "workspace_snapshot_alpha");
    assert.equal(artifactRecord.workspace_root, "/workspace");
    for (const field of RETIRED_WORKSPACE_ARTIFACT_ALIASES) {
      assert.equal(Object.hasOwn(artifactRecord, field), false);
    }
  }
  assert.equal(previewEvent.status, "completed");
  assert.equal(previewEvent.tool_call_id, "workspace_snapshot_alpha");
  assert.deepEqual(previewEvent.artifact_refs, ["artifact_preview"]);
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
        snapshot_id: "workspace_snapshot_alpha",
        snapshot_hash: "hash_alpha",
        turn_id: "turn_alpha",
        restore: { preview_supported: true },
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
    workflow_node_id: "restore_node",
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

test("workspace snapshot restore rejects retired request aliases before agent lookup", () => {
  const { surface } = createSurface();
  const store = {
    agentForThread() {
      assert.fail("agent lookup must not run for retired workspace restore request aliases");
    },
  };
  const retiredRequest = {
    workflowGraphId: "graph_alias",
    workflowNodeId: "node_alias",
    idempotencyKey: "idempotency_alias",
    approvalDecision: "approved",
    policyDecision: "allow",
    confirmRestoreApply: true,
    applyConfirmed: true,
    approvalGranted: true,
    allowConflicts: true,
    overrideConflicts: true,
    restoreConflictPolicy: "allow_override",
    conflictPolicy: "override_conflicts",
    restorePolicy: "apply_with_approval",
  };

  for (const operation of [
    () =>
      surface.previewWorkspaceSnapshotRestore(
        store,
        "thread_alpha",
        "workspace_snapshot_alpha",
        retiredRequest,
      ),
    () =>
      surface.applyWorkspaceSnapshotRestore(
        store,
        "thread_alpha",
        "workspace_snapshot_alpha",
        retiredRequest,
      ),
  ]) {
    assert.throws(
      operation,
      (error) => {
        assert.equal(error.status, 400);
        assert.equal(error.code, "workspace_restore_request_aliases_retired");
        assert.deepEqual(error.details.retired_aliases, [
          "workflowGraphId",
          "workflowNodeId",
          "idempotencyKey",
          "approvalDecision",
          "policyDecision",
          "confirmRestoreApply",
          "applyConfirmed",
          "approvalGranted",
          "allowConflicts",
          "overrideConflicts",
          "restoreConflictPolicy",
          "conflictPolicy",
          "restorePolicy",
        ]);
        assert.deepEqual(error.details.canonical_fields, [
          "workflow_graph_id",
          "workflow_node_id",
          "idempotency_key",
          "approval_decision",
          "policy_decision",
          "confirm_restore_apply",
          "apply_confirmed",
          "approval_granted",
          "allow_conflicts",
          "override_conflicts",
          "restore_conflict_policy",
          "conflict_policy",
          "restore_policy",
        ]);
        return true;
      },
    );
  }
});
