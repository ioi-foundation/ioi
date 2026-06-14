import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeWorkspaceSnapshotSurface } from "./runtime-workspace-snapshot-surface.mjs";

const RETIRED_WORKSPACE_RESTORE_ERROR_DETAIL_ALIASES = [
  "threadId",
  "snapshotId",
];

function assertNoRetiredWorkspaceRestoreErrorDetailAliases(details) {
  for (const key of RETIRED_WORKSPACE_RESTORE_ERROR_DETAIL_ALIASES) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

function assertWorkspaceSnapshotRustCoreRequired(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_workspace_snapshot_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.workspace_snapshot");
  assert.equal(error.details.operation_kind, operationKind);
  return true;
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function restoreArtifact(kind, snapshotId = "workspace_snapshot_alpha") {
  const artifactId = `artifact://runtime.workspace_restore/${kind}/${snapshotId}`;
  const receiptId = `receipt://runtime.workspace_restore/${kind}/${snapshotId}`;
  return {
    schema_version: "ioi.runtime.workspace_restore_artifact.v1",
    id: artifactId,
    artifact_id: artifactId,
    thread_id: "thread_alpha",
    tool_name: `workspace.restore_${kind}`,
    channel: `restore-${kind}`,
    name: `workspace-restore-${kind}.json`,
    media_type: "application/json",
    redaction: `workspace_restore_${kind}`,
    snapshot_id: snapshotId,
    receipt_id: receiptId,
    receipt_refs: [receiptId],
    artifact_refs: [artifactId],
    content_hash: `sha256:${kind}`,
  };
}

function restoreEvent(kind, snapshotId = "workspace_snapshot_alpha", status = kind === "apply" ? "applied" : "ready") {
  const artifact = restoreArtifact(kind, snapshotId);
  return {
    schema_version: "ioi.runtime.workspace_restore.event.v1",
    event_id: `event_workspace_restore_${kind}`,
    event_stream_id: "thread_alpha:events",
    thread_id: "thread_alpha",
    event_kind: `workspace_restore.${kind}`,
    status,
    idempotency_key: `restore_${kind}`,
    receipt_refs: artifact.receipt_refs,
    artifact_refs: artifact.artifact_refs,
    rollback_refs: [snapshotId],
    payload_schema_version:
      kind === "apply"
        ? "ioi.runtime.workspace_restore_apply.v1"
        : "ioi.runtime.workspace_restore_preview.v1",
    payload_summary: {
      snapshot_id: snapshotId,
      receipt_refs: artifact.receipt_refs,
      artifact_refs: artifact.artifact_refs,
    },
  };
}

function snapshotArtifact(snapshotId = "workspace_snapshot_alpha") {
  const artifactId = `artifact://runtime.workspace_snapshot/${snapshotId}`;
  const receiptId = `receipt://runtime.workspace_snapshot/${snapshotId}`;
  return {
    schema_version: "ioi.runtime.workspace_snapshot_artifact.v1",
    id: artifactId,
    artifact_id: artifactId,
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    tool_name: "workspace.snapshot_capture",
    tool_call_id: "tool_call_alpha",
    channel: "workspace-snapshot",
    name: `${snapshotId}.json`,
    media_type: "application/json",
    redaction: "workspace_snapshot",
    snapshot_id: snapshotId,
    receipt_id: receiptId,
    receipt_refs: [receiptId],
    artifact_refs: [artifactId],
    content_hash: "sha256:snapshot",
  };
}

function snapshotEvent(snapshotId = "workspace_snapshot_alpha") {
  const artifact = snapshotArtifact(snapshotId);
  return {
    schema_version: "ioi.runtime.workspace-snapshot.event.v1",
    event_id: "event_workspace_snapshot_captured",
    event_stream_id: "thread_alpha:events",
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    event_kind: "workspace_snapshot.captured",
    status: "completed",
    idempotency_key: `workspace_snapshot:capture:${snapshotId}`,
    receipt_refs: artifact.receipt_refs,
    artifact_refs: artifact.artifact_refs,
    payload_schema_version: "ioi.runtime.workspace-snapshot.v1",
    payload_summary: {
      snapshot_id: snapshotId,
      receipt_refs: artifact.receipt_refs,
      artifact_refs: artifact.artifact_refs,
    },
  };
}

function createSurface(options = {}) {
  const writes = [];
  const surface = createRuntimeWorkspaceSnapshotSurface({
    runtimeError,
    runtimeThreadEventAdmissionForThread: options.runtimeThreadEventAdmissionForThread,
    workspaceRestoreCore: options.workspaceRestoreCore,
    writeJson(filePath, value) {
      writes.push({ filePath, value });
    },
  });
  return { surface, writes };
}

function createStore(cwd = "/workspace") {
  const events = [];
  const artifactCommits = [];
  return {
    codingArtifacts: new Map(),
    events,
    artifactCommits,
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
    admitRuntimeThreadEventForThread(_store, request) {
      const event = {
        ...request.event,
        seq: events.length + 1,
        agentgres_operation_ref: `agentgres://runtime-events/thread_alpha/events/${request.event.event_id}`,
      };
      events.push(event);
      return event;
    },
    commitRuntimeArtifactState(request) {
      artifactCommits.push(request);
      return {
        source: "rust_agentgres_runtime_artifact_state_commit_command",
        artifact_id: request.artifact_id,
        operation_kind: request.operation_kind,
        object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}`,
        content_hash: request.artifact.content_hash,
        admission_hash: `sha256:admission-${artifactCommits.length}`,
        commit_hash: `sha256:commit-${artifactCommits.length}`,
        written_record: true,
        storage_record: {
          object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}`,
          content_hash: request.artifact.content_hash,
          admission: { admission_hash: `sha256:admission-${artifactCommits.length}` },
        },
      };
    },
    pathFor(...segments) {
      return path.join("/tmp/runtime-workspace-snapshots", ...segments);
    },
  };
}

test("workspace snapshot surface captures patch snapshot through Rust workspace restore core", () => {
  const coreCalls = [];
  const artifact = snapshotArtifact();
  const event = snapshotEvent();
  const { surface, writes } = createSurface({
    workspaceRestoreCore: {
      captureSnapshotFiles(request) {
        coreCalls.push(request);
        return {
          snapshot_record: {
            schema_version: "ioi.runtime.workspace-snapshot.v1",
            snapshot_id: "workspace_snapshot_alpha",
            snapshot_hash: "sha256:alpha",
            snapshot_kind: "pre_post_touched_files",
            file_count: 1,
            changed_file_count: 1,
            created_file_count: 0,
            deleted_file_count: 0,
            restore: { status: "content_captured", preview_supported: true, apply_supported: true },
            trigger: {
              thread_id: "thread_alpha",
              turn_id: "turn_alpha",
              workspace_root: "/workspace",
              tool_call_id: "tool_call_alpha",
              workflow_graph_id: "graph_alpha",
              workflow_node_id: "node_alpha",
            },
            files: [{ path: "src/app.js" }],
            content_files: [{ path: "src/app.js" }],
            receipt_refs: artifact.receipt_refs,
            artifact_refs: artifact.artifact_refs,
            summary: "captured",
          },
          snapshot_artifact: artifact,
          snapshot_event: event,
          captured_file_count: 1,
          omitted_file_count: 0,
          content_captured: true,
        };
      },
    },
  });
  const store = createStore();

  assert.equal(
    surface.prepareWorkspaceSnapshotForPatch(store, {
      threadId: "thread_alpha",
      result: { applied: false },
    }),
    null,
  );

  const snapshot = surface.prepareWorkspaceSnapshotForPatch(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    workspaceRoot: "/workspace",
    toolCallId: "tool_call_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_alpha",
    result: {
      applied: true,
      changed_files: [
        {
          path: "src/app.js",
          before_hash: "sha256-old",
          after_hash: "sha256-new",
          before_exists: true,
          after_exists: true,
          before_size_bytes: 3,
          after_size_bytes: 3,
        },
      ],
      workspace_snapshot_drafts: [
        {
          path: "src/app.js",
          before_content: "old",
          after_content: "new",
        },
      ],
    },
  });

  assert.equal(coreCalls.length, 1);
  assert.equal(coreCalls[0].thread_id, "thread_alpha");
  assert.equal(coreCalls[0].tool_call_id, "tool_call_alpha");
  assert.equal(coreCalls[0].changed_files[0].before_hash, "sha256-old");
  assert.equal(coreCalls[0].content_drafts[0].before_content, "old");
  assert.equal(snapshot.record.snapshot_id, "workspace_snapshot_alpha");
  assert.deepEqual(snapshot.record.receipt_refs, artifact.receipt_refs);
  assert.deepEqual(snapshot.record.artifact_refs, artifact.artifact_refs);
  assert.equal(snapshot.snapshot_artifact_commit.artifact_id, artifact.id);
  assert.equal(snapshot.event.event_id, event.event_id);
  assert.deepEqual(
    store.artifactCommits.map((request) => request.operation_kind),
    ["artifact.workspace_snapshot"],
  );
  assert.deepEqual(
    store.events.map((admittedEvent) => admittedEvent.event_id),
    [event.event_id],
  );
  assert.equal(store.codingArtifacts.size, 0);
  assert.equal(writes.length, 0);
});

test("workspace snapshot surface fails closed when Rust patch capture core is absent", () => {
  const { surface, writes } = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.prepareWorkspaceSnapshotForPatch(store, {
        threadId: "thread_alpha",
        turnId: "turn_alpha",
        workspaceRoot: "/workspace",
        toolCallId: "tool_call_alpha",
        workflowGraphId: "graph_alpha",
        workflowNodeId: "node_alpha",
        result: {
          applied: true,
          changed_files: [{ path: "src/app.js" }],
          workspace_snapshot_drafts: [{ path: "src/app.js" }],
        },
      }),
    (error) => {
      assertWorkspaceSnapshotRustCoreRequired(error, "workspace_snapshot.capture");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.tool_call_id, "tool_call_alpha");
      assert.equal(error.details.changed_file_count, 1);
      assert.equal(error.details.snapshot_draft_count, 1);
      assert.ok(error.details.evidence_refs.includes("workspace_snapshot_js_capture_facade_retired"));
      return true;
    },
  );
  assert.equal(writes.length, 0);
  assert.equal(store.artifactCommits.length, 0);
});

test("workspace snapshot surface calls Rust list projection and rejects missing Rust snapshot event", () => {
  const coreCalls = [];
  const { surface } = createSurface({
    workspaceRestoreCore: {
      projectWorkspaceSnapshotList(request) {
        coreCalls.push(request);
        return {
          source: "rust_workspace_snapshot_projection_protocol",
          backend: "rust_workspace_restore",
          projection_kind: "workspace_snapshot.list",
          projection: {
            schema_version: "ioi.runtime.workspace_snapshot.v1",
            object: "ioi.runtime_workspace_snapshot_list",
            thread_id: "thread_alpha",
            snapshot_count: 1,
            snapshots: [{ snapshot_id: "workspace_snapshot_alpha" }],
          },
        };
      },
    },
  });
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

  assert.throws(
    () =>
      surface.appendWorkspaceSnapshotEvent(store, {
        threadId: "thread_alpha",
        turnId: "turn_alpha",
        workspaceRoot: "/workspace",
        snapshot,
      }),
    (error) => {
      assertWorkspaceSnapshotRustCoreRequired(error, "workspace_snapshot.event");
      assert.equal(error.details.snapshot_id, "workspace_snapshot_alpha");
      assert.ok(error.details.evidence_refs.includes("workspace_snapshot_event_js_append_retired"));
      return true;
    },
  );
  assert.equal(store.events.length, 0);

  const list = surface.listWorkspaceSnapshots(store, "thread_alpha");
  assert.equal(list.object, "ioi.runtime_workspace_snapshot_list");
  assert.equal(list.snapshot_count, 1);
  assert.deepEqual(coreCalls, [{ thread_id: "thread_alpha" }]);
  assert.equal(store.events.length, 0);
});

test("workspace snapshot content package projection calls Rust core before JS artifact reads", () => {
  const calls = [];
  const { surface } = createSurface({
    workspaceRestoreCore: {
      projectWorkspaceSnapshotContentPackage(request) {
        calls.push({ name: "core.projectWorkspaceSnapshotContentPackage", request });
        return {
          source: "rust_workspace_snapshot_projection_protocol",
          backend: "rust_workspace_restore",
          projection_kind: "workspace_snapshot.content_package",
          projection: {
            schema_version: "ioi.runtime.workspace_snapshot_content_package.v1",
            object: "ioi.runtime_workspace_snapshot_content_package",
            thread_id: "thread_alpha",
            snapshot_id: "workspace_snapshot_alpha",
            content_files: [{ path: "src/app.js", before: { content: "old" }, after: { content: "new" } }],
          },
        };
      },
    },
  });
  const store = {
    codingArtifacts: {
      values() {
        calls.push("codingArtifacts.values");
        return [];
      },
    },
  };

  const contentPackage = surface.workspaceSnapshotContentPackage(store, "thread_alpha", "workspace_snapshot_alpha");
  assert.equal(contentPackage.object, "ioi.runtime_workspace_snapshot_content_package");
  assert.equal(contentPackage.content_files[0].before.content, "old");
  assert.deepEqual(calls, [
    {
      name: "core.projectWorkspaceSnapshotContentPackage",
      request: { thread_id: "thread_alpha", snapshot_id: "workspace_snapshot_alpha" },
    },
  ]);
});

test("workspace snapshot surface commits Rust restore artifacts and admits Rust restore events", () => {
  const { surface, writes } = createSurface();
  const store = createStore();
  const previewArtifact = restoreArtifact("preview");
  const applyArtifact = restoreArtifact("apply");
  const previewEvent = restoreEvent("preview");
  const applyEvent = restoreEvent("apply");
  const preview = {
    snapshot_id: "workspace_snapshot_alpha",
    preview_status: "ready",
    operations: [{ path: "src/app.js", status: "ready" }],
    artifact_refs: previewArtifact.artifact_refs,
    receipt_refs: previewArtifact.receipt_refs,
    rollback_refs: ["workspace_snapshot_alpha"],
    restore_preview_artifact: previewArtifact,
    restore_preview_event: previewEvent,
  };
  const apply = {
    snapshot_id: "workspace_snapshot_alpha",
    apply_status: "applied",
    operations: [{ path: "src/app.js", apply_status: "applied" }],
    artifact_refs: applyArtifact.artifact_refs,
    receipt_refs: applyArtifact.receipt_refs,
    rollback_refs: ["workspace_snapshot_alpha"],
    policy_decision_refs: ["policy_apply"],
    restore_apply_artifact: applyArtifact,
    restore_apply_event: applyEvent,
  };

  const previewCommit = surface.materializeWorkspaceRestorePreviewArtifact(store, {
    thread_id: "thread_alpha",
    workspace_root: "/workspace",
    snapshot_id: "workspace_snapshot_alpha",
    artifact_id: previewArtifact.id,
    receipt_id: previewArtifact.receipt_id,
    preview,
  });
  const applyCommit = surface.materializeWorkspaceRestoreApplyArtifact(store, {
    thread_id: "thread_alpha",
    workspace_root: "/workspace",
    snapshot_id: "workspace_snapshot_alpha",
    artifact_id: applyArtifact.id,
    receipt_id: applyArtifact.receipt_id,
    apply,
  });
  const admittedPreviewEvent = surface.appendWorkspaceRestorePreviewEvent(store, {
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    workspace_root: "/workspace",
    workflow_graph_id: "graph_alpha",
    workflow_node_id: "restore_node",
    preview,
  });
  const admittedApplyEvent = surface.appendWorkspaceRestoreApplyEvent(store, {
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    workspace_root: "/workspace",
    workflow_graph_id: "graph_alpha",
    workflow_node_id: "restore_node",
    apply,
  });

  assert.equal(previewCommit.artifact_id, previewArtifact.id);
  assert.equal(applyCommit.artifact_id, applyArtifact.id);
  assert.equal(admittedPreviewEvent.event_kind, "workspace_restore.preview");
  assert.equal(admittedApplyEvent.event_kind, "workspace_restore.apply");
  assert.deepEqual(
    store.artifactCommits.map((request) => request.operation_kind),
    ["artifact.workspace_restore_preview", "artifact.workspace_restore_apply"],
  );
  assert.deepEqual(
    store.events.map((event) => event.event_id),
    ["event_workspace_restore_preview", "event_workspace_restore_apply"],
  );
  assert.equal(writes.length, 0);
  assert.equal(store.codingArtifacts.size, 0);
});

test("workspace snapshot surface routes restore preview/apply through Rust core", () => {
  const coreCalls = [];
  const { surface } = createSurface({
    workspaceRestoreCore: {
      previewSnapshotRestore(request) {
        coreCalls.push({ name: "previewSnapshotRestore", request });
        const artifact = restoreArtifact("preview", request.snapshot_id);
        return {
          source: "rust_workspace_snapshot_restore_protocol",
          backend: "rust_workspace_restore",
          projection_kind: "workspace_restore.preview",
          restore_preview: {
            schema_version: "ioi.runtime.workspace_restore_preview.v1",
            object: "ioi.runtime_workspace_restore_preview",
            thread_id: request.thread_id,
            snapshot_id: request.snapshot_id,
            preview_status: "ready",
            operations: [{ path: "src/app.js", status: "ready" }],
            artifact_refs: artifact.artifact_refs,
            receipt_refs: artifact.receipt_refs,
            rollback_refs: [request.snapshot_id],
            restore_preview_artifact: artifact,
            restore_preview_event: restoreEvent("preview", request.snapshot_id),
          },
        };
      },
      applySnapshotRestore(request) {
        coreCalls.push({ name: "applySnapshotRestore", request });
        const artifact = restoreArtifact("apply", request.snapshot_id);
        return {
          source: "rust_workspace_snapshot_restore_protocol",
          backend: "rust_workspace_restore",
          projection_kind: "workspace_restore.apply",
          restore_apply: {
            schema_version: "ioi.runtime.workspace_restore_apply.v1",
            object: "ioi.runtime_workspace_restore_apply",
            thread_id: request.thread_id,
            snapshot_id: request.snapshot_id,
            preview_status: "ready",
            apply_status: "applied",
            operations: [{ path: "src/app.js", apply_status: "applied" }],
            artifact_refs: artifact.artifact_refs,
            receipt_refs: artifact.receipt_refs,
            rollback_refs: [request.snapshot_id],
            policy_decision_refs: ["policy_apply"],
            restore_apply_artifact: artifact,
            restore_apply_event: restoreEvent("apply", request.snapshot_id),
          },
        };
      },
    },
  });
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-workspace-restore-"));
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src", "app.js"), "new");
  const store = createStore(cwd);

  const preview = surface.previewWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_alpha", {
    workflow_graph_id: "graph_alpha",
    workflow_node_id: "restore_node",
    idempotency_key: "restore_preview_key",
  });
  const apply = surface.applyWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_alpha", {
    workflow_graph_id: "graph_alpha",
    workflow_node_id: "restore_node",
    idempotency_key: "restore_apply_key",
    approval_granted: true,
  });

  assert.equal(preview.preview_status, "ready");
  assert.equal(apply.apply_status, "applied");
  assert.equal(coreCalls[0].name, "previewSnapshotRestore");
  assert.equal(coreCalls[0].request.thread_id, "thread_alpha");
  assert.equal(coreCalls[0].request.snapshot_id, "workspace_snapshot_alpha");
  assert.equal(coreCalls[0].request.workspace_root, cwd);
  assert.equal(coreCalls[0].request.workflow_node_id, "restore_node");
  assert.equal(coreCalls[0].request.idempotency_key, "restore_preview_key");
  assert.equal(coreCalls[1].name, "applySnapshotRestore");
  assert.equal(coreCalls[1].request.approval_granted, true);
  assert.equal(Object.hasOwn(coreCalls[1].request, "approvalGranted"), false);
  assert.equal(fs.readFileSync(path.join(cwd, "src", "app.js"), "utf8"), "new");
});

test("workspace snapshot restore fail-closed details use canonical fields", () => {
  const { surface } = createSurface();
  const store = createStore();

  for (const operation of [
    () => surface.previewWorkspaceSnapshotRestore(store, "thread_alpha", "", {}),
    () => surface.applyWorkspaceSnapshotRestore(store, "thread_alpha", "", {}),
  ]) {
    assert.throws(
      operation,
      (error) => {
        assert.equal(error.status, 400);
        assert.equal(error.code, "workspace_snapshot_id_required");
        assert.deepEqual(error.details, { thread_id: "thread_alpha" });
        assert.equal(error.details.thread_id, "thread_alpha");
        assertNoRetiredWorkspaceRestoreErrorDetailAliases(error.details);
        return true;
      },
    );
  }

  for (const [operation, expectedCode] of [
    [
      () => surface.previewWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_empty", {}),
      "workspace_restore.preview",
    ],
    [
      () => surface.applyWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_empty", {}),
      "workspace_restore.apply",
    ],
  ]) {
    assert.throws(
      operation,
      (error) => {
        assertWorkspaceSnapshotRustCoreRequired(error, expectedCode);
        assert.equal(error.details.thread_id, "thread_alpha");
        assert.equal(error.details.snapshot_id, "workspace_snapshot_empty");
        assertNoRetiredWorkspaceRestoreErrorDetailAliases(error.details);
        return true;
      },
    );
  }
});

test("workspace restore public facade calls Rust public restore API instead of operation helpers", () => {
  const calls = [];
  const surface = createRuntimeWorkspaceSnapshotSurface({
    runtimeError,
    workspaceRestoreCore: {
      planApplyPolicy() {
        assert.fail("policy helper must not run in the public workspace restore facade");
      },
      previewOperations() {
        assert.fail("preview operation helper must not run in the public workspace restore facade");
      },
      applyOperations() {
        assert.fail("apply operation helper must not run in the public workspace restore facade");
      },
      applySnapshotRestore(request) {
        calls.push(request);
        const artifact = restoreArtifact("apply", request.snapshot_id);
        return {
          source: "rust_workspace_snapshot_restore_protocol",
          backend: "rust_workspace_restore",
          projection_kind: "workspace_restore.apply",
          restore_apply: {
            schema_version: "ioi.runtime.workspace_restore_apply.v1",
            object: "ioi.runtime_workspace_restore_apply",
            thread_id: request.thread_id,
            snapshot_id: request.snapshot_id,
            apply_status: "blocked",
            artifact_refs: artifact.artifact_refs,
            receipt_refs: artifact.receipt_refs,
            rollback_refs: [request.snapshot_id],
            restore_apply_artifact: artifact,
            restore_apply_event: restoreEvent("apply", request.snapshot_id, "blocked"),
          },
        };
      },
    },
  });
  const store = createStore();

  const apply = surface.applyWorkspaceSnapshotRestore(store, "thread_alpha", "workspace_snapshot_policy", {});
  assert.equal(apply.apply_status, "blocked");
  assert.equal(calls[0].snapshot_id, "workspace_snapshot_policy");
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
