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

function createSurface(options = {}) {
  const writes = [];
  const surface = createRuntimeWorkspaceSnapshotSurface({
    runtimeError,
    workspaceRestoreRunner: options.workspaceRestoreRunner,
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
    pathFor(...segments) {
      return path.join("/tmp/runtime-workspace-snapshots", ...segments);
    },
  };
}

test("workspace snapshot surface captures patch snapshot through Rust workspace restore runner", () => {
  const runnerCalls = [];
  const { surface, writes } = createSurface({
    workspaceRestoreRunner: {
      captureSnapshotFiles(request) {
        runnerCalls.push(request);
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
            receipt_refs: ["receipt_snapshot"],
            artifact_refs: ["artifact_snapshot"],
            summary: "captured",
          },
          snapshot_event: {
            schema_version: "ioi.runtime.workspace-snapshot.event.v1",
            event_id: "event_snapshot",
            event_kind: "workspace_snapshot.captured",
            receipt_refs: ["receipt_snapshot"],
            artifact_refs: ["artifact_snapshot"],
          },
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

  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].thread_id, "thread_alpha");
  assert.equal(runnerCalls[0].tool_call_id, "tool_call_alpha");
  assert.equal(runnerCalls[0].changed_files[0].before_hash, "sha256-old");
  assert.equal(runnerCalls[0].content_drafts[0].before_content, "old");
  assert.equal(snapshot.record.snapshot_id, "workspace_snapshot_alpha");
  assert.deepEqual(snapshot.record.receipt_refs, ["receipt_snapshot"]);
  assert.deepEqual(snapshot.record.artifact_refs, ["artifact_snapshot"]);
  assert.equal(snapshot.event.event_id, "event_snapshot");
  assert.equal(store.codingArtifacts.size, 0);
  assert.equal(writes.length, 0);
  assert.equal(store.artifactCommits.length, 0);
});

test("workspace snapshot surface fails closed when Rust patch capture runner is absent", () => {
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

test("workspace snapshot surface calls Rust list projection and fails closed before JS snapshot event append", () => {
  const runnerCalls = [];
  const { surface } = createSurface({
    workspaceRestoreRunner: {
      listSnapshots(request) {
        runnerCalls.push(request);
        return {
          schema_version: "ioi.runtime.workspace_snapshot.v1",
          object: "ioi.runtime_workspace_snapshot_list",
          thread_id: "thread_alpha",
          snapshot_count: 1,
          snapshots: [{ snapshot_id: "workspace_snapshot_alpha" }],
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
  assert.deepEqual(runnerCalls, [{ thread_id: "thread_alpha" }]);
  assert.equal(store.events.length, 0);
});

test("workspace snapshot content package projection calls Rust runner before JS artifact reads", () => {
  const calls = [];
  const { surface } = createSurface({
    workspaceRestoreRunner: {
      workspaceSnapshotContentPackage(request) {
        calls.push({ name: "runner.workspaceSnapshotContentPackage", request });
        return {
          schema_version: "ioi.runtime.workspace_snapshot_content_package.v1",
          object: "ioi.runtime_workspace_snapshot_content_package",
          thread_id: "thread_alpha",
          snapshot_id: "workspace_snapshot_alpha",
          content_files: [{ path: "src/app.js", before: { content: "old" }, after: { content: "new" } }],
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
      name: "runner.workspaceSnapshotContentPackage",
      request: { thread_id: "thread_alpha", snapshot_id: "workspace_snapshot_alpha" },
    },
  ]);
});

test("workspace snapshot surface fails closed before JS restore artifact and event mutation", () => {
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

  assert.throws(
    () =>
      surface.materializeWorkspaceRestorePreviewArtifact(store, {
        thread_id: "thread_alpha",
        workspace_root: "/workspace",
        snapshot_id: "workspace_snapshot_alpha",
        artifact_id: "artifact_preview",
        receipt_id: "receipt_preview",
        preview,
      }),
    (error) => {
      assertWorkspaceSnapshotRustCoreRequired(error, "artifact.restore-preview");
      assert.equal(error.details.artifact_id, "artifact_preview");
      assert.ok(error.details.evidence_refs.includes("workspace_restore_artifact_js_materializer_retired"));
      return true;
    },
  );
  assert.throws(
    () =>
      surface.materializeWorkspaceRestoreApplyArtifact(store, {
        thread_id: "thread_alpha",
        workspace_root: "/workspace",
        snapshot_id: "workspace_snapshot_alpha",
        artifact_id: "artifact_apply",
        receipt_id: "receipt_apply",
        apply,
      }),
    (error) => {
      assertWorkspaceSnapshotRustCoreRequired(error, "artifact.restore-apply");
      assert.equal(error.details.artifact_id, "artifact_apply");
      return true;
    },
  );
  assert.throws(
    () =>
      surface.appendWorkspaceRestorePreviewEvent(store, {
        thread_id: "thread_alpha",
        turn_id: "turn_alpha",
        workspace_root: "/workspace",
        workflow_graph_id: "graph_alpha",
        workflow_node_id: "restore_node",
        preview,
      }),
    (error) => {
      assertWorkspaceSnapshotRustCoreRequired(error, "workspace_restore.preview.event");
      assert.equal(error.details.snapshot_id, "workspace_snapshot_alpha");
      assert.ok(error.details.evidence_refs.includes("workspace_restore_preview_event_js_append_retired"));
      return true;
    },
  );
  assert.throws(
    () =>
      surface.appendWorkspaceRestoreApplyEvent(store, {
        thread_id: "thread_alpha",
        turn_id: "turn_alpha",
        workspace_root: "/workspace",
        workflow_graph_id: "graph_alpha",
        workflow_node_id: "restore_node",
        apply,
      }),
    (error) => {
      assertWorkspaceSnapshotRustCoreRequired(error, "workspace_restore.apply.event");
      assert.equal(error.details.snapshot_id, "workspace_snapshot_alpha");
      assert.ok(error.details.evidence_refs.includes("workspace_restore_apply_event_js_append_retired"));
      return true;
    },
  );
  assert.equal(writes.length, 0);
  assert.equal(store.artifactCommits.length, 0);
  assert.equal(store.codingArtifacts.size, 0);
  assert.equal(store.events.length, 0);
});

test("workspace snapshot surface routes restore preview/apply through Rust runner", () => {
  const runnerCalls = [];
  const { surface } = createSurface({
    workspaceRestoreRunner: {
      previewSnapshotRestore(request) {
        runnerCalls.push({ name: "previewSnapshotRestore", request });
        return {
          schema_version: "ioi.runtime.workspace_restore_preview.v1",
          object: "ioi.runtime_workspace_restore_preview",
          thread_id: request.thread_id,
          snapshot_id: request.snapshot_id,
          preview_status: "ready",
          operations: [{ path: "src/app.js", status: "ready" }],
        };
      },
      applySnapshotRestore(request) {
        runnerCalls.push({ name: "applySnapshotRestore", request });
        return {
          schema_version: "ioi.runtime.workspace_restore_apply.v1",
          object: "ioi.runtime_workspace_restore_apply",
          thread_id: request.thread_id,
          snapshot_id: request.snapshot_id,
          preview_status: "ready",
          apply_status: "applied",
          operations: [{ path: "src/app.js", apply_status: "applied" }],
        };
      },
    },
  });
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-workspace-restore-"));
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src", "app.js"), "new");
  const store = {
    agentForThread() {
      return { cwd };
    },
  };

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
  assert.equal(runnerCalls[0].name, "previewSnapshotRestore");
  assert.equal(runnerCalls[0].request.thread_id, "thread_alpha");
  assert.equal(runnerCalls[0].request.snapshot_id, "workspace_snapshot_alpha");
  assert.equal(runnerCalls[0].request.workspace_root, cwd);
  assert.equal(runnerCalls[0].request.workflow_node_id, "restore_node");
  assert.equal(runnerCalls[0].request.idempotency_key, "restore_preview_key");
  assert.equal(runnerCalls[1].name, "applySnapshotRestore");
  assert.equal(runnerCalls[1].request.approval_granted, true);
  assert.equal(Object.hasOwn(runnerCalls[1].request, "approvalGranted"), false);
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
    workspaceRestoreRunner: {
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
        return {
          schema_version: "ioi.runtime.workspace_restore_apply.v1",
          object: "ioi.runtime_workspace_restore_apply",
          thread_id: request.thread_id,
          snapshot_id: request.snapshot_id,
          apply_status: "blocked",
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
