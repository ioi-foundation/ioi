import assert from "node:assert/strict";
import test from "node:test";

import {
  RUST_WORKSPACE_RESTORE_BACKEND,
  RuntimeWorkspaceRestoreCore,
  RuntimeWorkspaceRestoreCoreError,
  WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_CORE_SCHEMA_VERSION,
  WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION,
  createRuntimeWorkspaceRestoreCore,
} from "./runtime-workspace-restore-core.mjs";

function operationsRequest() {
  return {
    workspace_root: "/workspace",
    max_diff_bytes: 4096,
    files: [
      {
        path: "src/app.js",
        before: {
          exists: true,
          content_hash: "sha256-old",
          content: "old",
        },
        after: {
          exists: true,
          content_hash: "sha256-new",
        },
      },
    ],
  };
}

test("workspace restore core calls direct Rust daemon-core workspace APIs", () => {
  const calls = [];
  const core = createRuntimeWorkspaceRestoreCore({
    daemonCoreInvoker(coreRequest) {
      calls.push(coreRequest);
      return {
        schema_version: "rust.envelope.v1",
        operation: coreRequest.operation,
      };
    },
  });

  core.planApplyPolicy({ snapshot_id: "workspace_snapshot_alpha" });
  core.previewOperations(operationsRequest());
  core.applyOperations({ ...operationsRequest(), allow_conflicts: false });
  core.captureSnapshotFiles({
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    workspace_root: "/workspace",
    tool_call_id: "tool_call_alpha",
    workflow_graph_id: "graph_alpha",
    workflow_node_id: "node_alpha",
    changed_files: [
      {
        path: "src/app.js",
        before_hash: "sha256-old",
        after_hash: "sha256-new",
        before_exists: true,
        after_exists: true,
      },
    ],
    content_drafts: [{ path: "src/app.js", before_content: "old", after_content: "new" }],
    max_content_bytes: 262144,
  });
  core.projectWorkspaceSnapshotList({ thread_id: "thread_alpha" });
  core.projectWorkspaceSnapshotContentPackage({
    thread_id: "thread_alpha",
    snapshot_id: "workspace_snapshot_alpha",
  });
  core.previewSnapshotRestore({
    thread_id: "thread_alpha",
    snapshot_id: "workspace_snapshot_alpha",
    workspace_root: "/workspace",
  });
  core.applySnapshotRestore({
    thread_id: "thread_alpha",
    snapshot_id: "workspace_snapshot_alpha",
    workspace_root: "/workspace",
  });

  assert.deepEqual(
    calls.map((call) => call.operation),
    [
      "plan_workspace_restore_apply_policy",
      "preview_workspace_restore_operations",
      "apply_workspace_restore_operations",
      "capture_workspace_snapshot_files",
      "project_workspace_snapshot_list",
      "project_workspace_snapshot_content_package",
      "preview_workspace_snapshot_restore",
      "apply_workspace_snapshot_restore",
    ],
  );
  for (const call of calls) {
    assert.equal(call.schema_version, WORKSPACE_RESTORE_CORE_SCHEMA_VERSION);
    assert.equal(call.backend, RUST_WORKSPACE_RESTORE_BACKEND);
  }
  assert.equal(calls[0].request.schema_version, WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[1].request.schema_version, WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[1].request.files[0].before.content_hash, "sha256-old");
  assert.equal(calls[2].request.schema_version, WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[3].request.schema_version, WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[3].thread_id, "thread_alpha");
  assert.equal(calls[3].request.changed_files[0].before_hash, "sha256-old");
  assert.equal(calls[3].request.content_drafts[0].before_content, "old");
  assert.equal(calls[4].request.schema_version, WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[5].request.schema_version, WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[6].request.schema_version, WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[7].request.schema_version, WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION);
});

test("workspace restore core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.workspace_restore_preview.v1",
    restore_preview: {
      snapshot_id: "workspace_snapshot_alpha",
    },
  };
  const core = createRuntimeWorkspaceRestoreCore({
    daemonCoreInvoker() {
      return rustEnvelope;
    },
  });

  const result = core.previewSnapshotRestore({
    thread_id: "thread_alpha",
    snapshot_id: "workspace_snapshot_alpha",
    workspace_root: "/workspace",
  });

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "preview_status"), false);
  assert.equal(Object.hasOwn(result, "restore_preview_artifact"), false);
});

test("workspace restore core rejects retired compatibility options", () => {
  for (const options of [
    { command: "ioi-runtime-daemon-core" },
    { args: ["--restore"] },
    { env: { IOI_WORKSPACE_RESTORE_COMMAND: "retired" } },
  ]) {
    assert.throws(
      () => new RuntimeWorkspaceRestoreCore(options),
      (error) =>
        error instanceof RuntimeWorkspaceRestoreCoreError &&
        error.code === "workspace_restore_core_compatibility_option_retired",
    );
  }
});

test("workspace restore core rejects retired request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeWorkspaceRestoreCore({
    daemonCoreInvoker() {
      calls.push("invoked");
      return {};
    },
  });

  assert.throws(
    () =>
      core.captureSnapshotFiles({
        changedFiles: [{ path: "src/app.js" }],
        contentDrafts: [{ path: "src/app.js" }],
        maxContentBytes: 1024,
      }),
    (error) =>
      error.code === "workspace_restore_core_request_aliases_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("changedFiles") &&
      error.details.retired_aliases.includes("contentDrafts") &&
      error.details.retired_aliases.includes("maxContentBytes"),
  );
  assert.throws(
    () =>
      core.applyOperations({
        workspace_root: "/workspace",
        files: [{ path: "src/app.js", before: { contentHash: "sha256-alias" } }],
      }),
    (error) =>
      error.code === "workspace_restore_core_request_aliases_retired" &&
      error.details.retired_aliases.includes("files.*.contentHash"),
  );
  assert.deepEqual(calls, []);
});

test("workspace restore core fails closed without direct daemon-core API", () => {
  const core = createRuntimeWorkspaceRestoreCore({});

  assert.throws(
    () => core.planApplyPolicy({ snapshot_id: "workspace_snapshot_alpha" }),
    (error) => error.code === "workspace_restore_core_direct_invoker_unconfigured",
  );
});

test("workspace restore core surfaces Rust rejection", () => {
  const core = createRuntimeWorkspaceRestoreCore({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "workspace_snapshot_restore_invalid",
          message: "MissingSnapshotId",
        },
      };
    },
  });

  assert.throws(
    () => core.applySnapshotRestore({ thread_id: "thread_alpha", workspace_root: "/workspace" }),
    (error) =>
      error.code === "workspace_snapshot_restore_invalid" &&
      /MissingSnapshotId/.test(error.message),
  );
});
