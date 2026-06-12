import assert from "node:assert/strict";
import test from "node:test";

import {
  RustWorkspaceRestoreRunner,
  WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
  WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
  WorkspaceRestoreRunnerError,
  createWorkspaceRestoreRunnerFromEnv,
} from "./runtime-workspace-restore-runner.mjs";

function policyRequest() {
  return {
    snapshot_id: "workspace_snapshot_alpha",
    confirm_restore_apply: true,
    operations: [
      {
        path: "src/app.js",
        status: "ready",
      },
    ],
    counts: {
      file_count: 1,
      ready_count: 1,
      applied_count: 1,
    },
  };
}

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

test("workspace restore runner sends apply policy through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker(bridgeRequest) {
      calls.push(bridgeRequest);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_workspace_restore",
        approval: {
          required: true,
          satisfied: true,
          source: "boolean_confirmation",
        },
        allow_conflicts: false,
        conflict_policy: "clean_preview_only",
        hard_blocked: false,
        conflict_blocked: false,
        policy_status: "allowed",
        apply_status: "applied",
        policy_decision_refs: ["policy_workspace_restore_apply_workspace_snapshot_alpha_approval_satisfied"],
        operation_policies: [
          {
            path: "src/app.js",
            apply_reason: "workspace_restore_apply_blocked_by_policy",
          },
        ],
        summary: "Restore apply restored 1 file(s) from workspace_snapshot_alpha.",
      };
    },
  });

  const result = runner.planApplyPolicy(policyRequest());

  assert.equal(calls[0].schema_version, WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].operation, "plan_workspace_restore_apply_policy");
  assert.equal(calls[0].backend, "rust_workspace_restore");
  assert.equal(
    calls[0].request.schema_version,
    WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.snapshot_id, "workspace_snapshot_alpha");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.approval.satisfied, true);
  assert.equal(result.apply_status, "applied");
  assert.deepEqual(result.policy_decision_refs, [
    "policy_workspace_restore_apply_workspace_snapshot_alpha_approval_satisfied",
  ]);
  assert.equal(result.operation_policies[0].apply_reason, "workspace_restore_apply_blocked_by_policy");
  for (const field of [
    "allowConflicts",
    "conflictPolicy",
    "hardBlocked",
    "conflictBlocked",
    "policyStatus",
    "applyStatus",
    "policyDecisionRefs",
    "operationPolicies",
    "operationPolicyByPath",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
});

test("workspace restore runner sends preview operations through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker(bridgeRequest) {
      calls.push(bridgeRequest);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_workspace_restore",
        operation: "preview_workspace_restore_operations",
        operations: [
          {
            path: "src/app.js",
            operation: "replace",
            status: "ready",
            current_exists: true,
            current_hash: "sha256-new",
            current_bytes: 3,
            target_exists: true,
            target_hash: "sha256-old",
            snapshot_after_exists: true,
            snapshot_after_hash: "sha256-new",
            current_matches_snapshot_post: true,
            current_matches_restore_target: false,
            diff: "diff",
            diff_bytes: 4,
            diff_hash: "sha256-diff",
            diff_truncated: false,
          },
        ],
      };
    },
  });

  const operations = runner.previewOperations(operationsRequest());

  assert.equal(calls[0].operation, "preview_workspace_restore_operations");
  assert.equal(calls[0].schema_version, WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION);
  assert.equal(
    calls[0].request.schema_version,
    WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(operations[0].status, "ready");
  assert.equal(operations[0].current_exists, true);
  assert.equal(operations[0].current_matches_snapshot_post, true);
  for (const field of [
    "currentExists",
    "currentHash",
    "currentBytes",
    "targetExists",
    "targetHash",
    "snapshotAfterExists",
    "snapshotAfterHash",
    "currentMatchesSnapshotPost",
    "currentMatchesRestoreTarget",
    "blockedReason",
    "diffBytes",
    "diffHash",
    "diffTruncated",
  ]) {
    assert.equal(Object.hasOwn(operations[0], field), false);
  }
});

test("workspace restore runner sends apply operations through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker(bridgeRequest) {
      calls.push(bridgeRequest);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_workspace_restore",
        operation: "apply_workspace_restore_operations",
        operations: [
          {
            path: "src/app.js",
            operation: "replace",
            status: "ready",
            current_exists: true,
            current_hash: "sha256-new",
            current_bytes: 3,
            target_exists: true,
            target_hash: "sha256-old",
            snapshot_after_exists: true,
            snapshot_after_hash: "sha256-new",
            current_matches_snapshot_post: true,
            current_matches_restore_target: false,
            diff: "diff",
            diff_bytes: 4,
            diff_hash: "sha256-diff",
            diff_truncated: false,
            apply_status: "applied",
            applied_exists: true,
            applied_hash: "sha256-old",
            applied_bytes: 3,
            applied_matches_target: true,
          },
        ],
      };
    },
  });

  const operations = runner.applyOperations({ ...operationsRequest(), allow_conflicts: false });

  assert.equal(calls[0].operation, "apply_workspace_restore_operations");
  assert.equal(calls[0].schema_version, WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION);
  assert.equal(
    calls[0].request.schema_version,
    WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(operations[0].apply_status, "applied");
  assert.equal(operations[0].applied_matches_target, true);
  for (const field of [
    "applyStatus",
    "applyReason",
    "appliedExists",
    "appliedHash",
    "appliedBytes",
    "appliedMatchesTarget",
    "errorMessage",
  ]) {
    assert.equal(Object.hasOwn(operations[0], field), false);
  }
});

test("workspace restore runner sends snapshot capture through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker(bridgeRequest) {
      calls.push(bridgeRequest);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_workspace_restore",
        captured_file_count: 1,
        omitted_file_count: 0,
        content_captured: true,
        files: [
          {
            path: "src/app.js",
            created: false,
            deleted: false,
            changed: true,
            before: {
              exists: true,
              content_hash: "sha256-old",
              size_bytes: 3,
              content_captured: true,
              content_bytes: 3,
            },
            after: {
              exists: true,
              content_hash: "sha256-new",
              size_bytes: 3,
              content_captured: true,
              content_bytes: 3,
            },
            receipt_refs: [],
            artifact_refs: [],
          },
        ],
        content_files: [
          {
            path: "src/app.js",
            created: false,
            deleted: false,
            changed: true,
            before: {
              exists: true,
              content_hash: "sha256-old",
              size_bytes: 3,
              content_captured: true,
              content_bytes: 3,
              content: "old",
            },
            after: {
              exists: true,
              content_hash: "sha256-new",
              size_bytes: 3,
              content_captured: true,
              content_bytes: 3,
              content: "new",
            },
            receipt_refs: [],
            artifact_refs: [],
            encoding: "utf8",
          },
        ],
      };
    },
  });

  const capture = runner.captureSnapshotFiles({
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
    content_drafts: [
      {
        path: "src/app.js",
        before_content: "old",
        after_content: "new",
      },
    ],
    max_content_bytes: 262144,
  });

  assert.equal(calls[0].operation, "capture_workspace_snapshot_files");
  assert.equal(calls[0].schema_version, WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION);
  assert.equal(
    calls[0].request.schema_version,
    WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.changed_files[0].before_hash, "sha256-old");
  assert.equal(calls[0].request.content_drafts[0].before_content, "old");
  assert.equal(capture.captured_file_count, 1);
  assert.equal(capture.files[0].before.content_hash, "sha256-old");
  assert.equal(capture.content_files[0].before.content, "old");
  for (const field of ["contentFiles", "capturedFileCount", "omittedFileCount", "contentCaptured"]) {
    assert.equal(Object.hasOwn(capture, field), false);
  }
  for (const field of ["receiptRefs", "artifactRefs"]) {
    assert.equal(Object.hasOwn(capture.files[0], field), false);
  }
  for (const field of [
    "contentHash",
    "sizeBytes",
    "mtimeMs",
    "contentCaptured",
    "contentBytes",
    "omittedReason",
  ]) {
    assert.equal(Object.hasOwn(capture.files[0].before, field), false);
  }
});

test("workspace restore runner does not synthesize Rust-owned snapshot capture refs", () => {
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker() {
      return {
        source: "rust_workspace_snapshot_capture_command",
        backend: "rust_workspace_restore",
        files: [
          {
            path: "src/app.js",
            before: {},
            after: {},
          },
        ],
        content_files: [
          {
            path: "src/app.js",
            before: {},
            after: {},
          },
        ],
      };
    },
  });

  const capture = runner.captureSnapshotFiles({
    changed_files: [{ path: "src/app.js" }],
  });

  assert.equal(capture.files[0].receipt_refs, null);
  assert.equal(capture.files[0].artifact_refs, null);
  assert.equal(capture.content_files[0].receipt_refs, null);
  assert.equal(capture.content_files[0].artifact_refs, null);
});

test("workspace restore runner ignores retired result reader aliases", () => {
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker(bridgeRequest) {
      if (bridgeRequest.operation === "capture_workspace_snapshot_files") {
        return {
          source: "rust_workspace_snapshot_capture_command",
          backend: "rust_workspace_restore",
          files: [
            {
              path: "src/app.js",
              before: {
                exists: true,
                contentHash: "sha256-alias",
                sizeBytes: 99,
                mtimeMs: 123,
                contentCaptured: true,
                contentBytes: 11,
                omittedReason: "alias-only",
              },
              after: {},
              receiptRefs: ["receipt_alias"],
              artifactRefs: ["artifact_alias"],
            },
          ],
        };
      }
      return {
        source: "rust_workspace_restore_operations_command",
        backend: "rust_workspace_restore",
        operations: [
          {
            path: "src/app.js",
            operation: "replace",
            status: "ready",
            currentExists: true,
            currentHash: "sha256-current-alias",
            currentBytes: 3,
            targetExists: true,
            targetHash: "sha256-target-alias",
            snapshotAfterExists: true,
            snapshotAfterHash: "sha256-snapshot-after-alias",
            currentMatchesSnapshotPost: true,
            currentMatchesRestoreTarget: true,
            blockedReason: "alias-only",
            diffBytes: 4,
            diffHash: "sha256-diff-alias",
            diffTruncated: true,
            applyStatus: "applied",
            applyReason: "alias-only",
            appliedExists: true,
            appliedHash: "sha256-applied-alias",
            appliedBytes: 5,
            appliedMatchesTarget: true,
            errorMessage: "alias-only",
          },
        ],
      };
    },
  });

  const operations = runner.applyOperations({ ...operationsRequest(), allow_conflicts: false });

  assert.equal(operations[0].current_exists, false);
  assert.equal(operations[0].current_hash, null);
  assert.equal(operations[0].current_bytes, 0);
  assert.equal(operations[0].target_exists, false);
  assert.equal(operations[0].target_hash, null);
  assert.equal(operations[0].snapshot_after_exists, false);
  assert.equal(operations[0].snapshot_after_hash, null);
  assert.equal(operations[0].current_matches_snapshot_post, false);
  assert.equal(operations[0].current_matches_restore_target, false);
  assert.equal(operations[0].blocked_reason, null);
  assert.equal(operations[0].diff_bytes, 0);
  assert.equal(operations[0].diff_hash, null);
  assert.equal(operations[0].diff_truncated, false);
  assert.equal(Object.hasOwn(operations[0], "apply_status"), false);
  assert.equal(Object.hasOwn(operations[0], "apply_reason"), false);
  assert.equal(Object.hasOwn(operations[0], "applied_exists"), false);
  assert.equal(Object.hasOwn(operations[0], "applied_hash"), false);
  assert.equal(Object.hasOwn(operations[0], "applied_bytes"), false);
  assert.equal(Object.hasOwn(operations[0], "applied_matches_target"), false);
  assert.equal(Object.hasOwn(operations[0], "error_message"), false);

  const capture = runner.captureSnapshotFiles({
    changed_files: [
      {
        path: "src/app.js",
        before_hash: "sha256-old",
        after_hash: "sha256-new",
      },
    ],
  });

  assert.equal(capture.files[0].before.content_hash, null);
  assert.equal(capture.files[0].before.size_bytes, 0);
  assert.equal(capture.files[0].before.mtime_ms, undefined);
  assert.equal(capture.files[0].before.content_captured, false);
  assert.equal(capture.files[0].before.content_bytes, 0);
  assert.equal(capture.files[0].before.omitted_reason, null);
  assert.equal(capture.files[0].receipt_refs, null);
  assert.equal(capture.files[0].artifact_refs, null);
});

test("workspace restore runner ignores retired request aliases", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker(bridgeRequest) {
      calls.push(bridgeRequest);
      return {
        source: "rust_workspace_snapshot_capture_command",
        backend: "rust_workspace_restore",
        files: [],
      };
    },
  });

  runner.captureSnapshotFiles({
    changedFiles: [
      {
        path: "src/app.js",
        beforeHash: "sha256-old",
        afterHash: "sha256-new",
        beforeExists: true,
        afterExists: true,
        beforeSizeBytes: 3,
        afterSizeBytes: 3,
      },
    ],
    workspaceSnapshotDrafts: [
      {
        path: "src/app.js",
        beforeContent: "old",
        afterContent: "new",
      },
    ],
    contentDrafts: [{ path: "src/other.js", beforeContent: "old", afterContent: "new" }],
    maxContentBytes: 262144,
  });

  assert.deepEqual(calls[0].request.changed_files, []);
  assert.deepEqual(calls[0].request.content_drafts, []);
  assert.equal(calls[0].request.max_content_bytes, undefined);

  runner.applyOperations({
    workspace_root: "/workspace",
    files: [
      {
        path: "src/app.js",
        before: {
          exists: true,
          contentHash: "sha256-old",
          content: "old",
        },
        after: {
          exists: true,
          contentHash: "sha256-new",
        },
      },
    ],
  });

  assert.equal(calls[1].request.files[0].before.content_hash, null);
  assert.equal(calls[1].request.files[0].after.content_hash, null);
});

test("workspace restore runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createWorkspaceRestoreRunnerFromEnv({
    IOI_WORKSPACE_RESTORE_COMMAND_ARGS: "--retired-restore",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  }, {
    daemonCoreInvoker(bridgeRequest) {
      calls.push(bridgeRequest);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_workspace_restore",
        operation: bridgeRequest.operation,
        operations: [],
      };
    },
  });

  const operations = runner.previewOperations(operationsRequest());

  assert.equal(calls[0].operation, "preview_workspace_restore_operations");
  assert.deepEqual(operations, []);
});

test("workspace restore runner rejects retired daemon-core command env", () => {
  assert.throws(
    () =>
      createWorkspaceRestoreRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof WorkspaceRestoreRunnerError &&
      error.code === "workspace_restore_command_selection_retired",
  );
});

test("workspace restore runner rejects retired workspace command env", () => {
  assert.throws(
    () =>
      createWorkspaceRestoreRunnerFromEnv({
        IOI_WORKSPACE_RESTORE_COMMAND: "retired-workspace-restore-bridge",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof WorkspaceRestoreRunnerError &&
      error.code === "workspace_restore_command_selection_retired",
  );
});

test("workspace restore runner command args env fails closed", () => {
  assert.throws(
    () =>
      createWorkspaceRestoreRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--restore",
      }),
    (error) =>
      error instanceof WorkspaceRestoreRunnerError &&
      error.code === "workspace_restore_command_args_retired",
  );
});

test("workspace restore runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkspaceRestoreRunner({ args: ["--restore"] }),
    (error) =>
      error instanceof WorkspaceRestoreRunnerError &&
      error.code === "workspace_restore_command_args_retired",
  );
});

test("workspace restore runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkspaceRestoreRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof WorkspaceRestoreRunnerError &&
      error.code === "workspace_restore_command_selection_retired",
  );
});

test("workspace restore runner fails closed without direct invoker", () => {
  const runner = createWorkspaceRestoreRunnerFromEnv({});

  assert.throws(
    () => runner.planApplyPolicy(policyRequest()),
    (error) => error.code === "workspace_restore_direct_invoker_unconfigured",
  );
});

test("workspace restore runner surfaces Rust policy rejection", () => {
  const runner = new RustWorkspaceRestoreRunner({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "workspace_restore_apply_policy_invalid",
          message: "MissingSnapshotId",
        },
      };
    },
  });

  assert.throws(
    () => runner.planApplyPolicy(policyRequest()),
    (error) =>
      error.code === "workspace_restore_apply_policy_invalid" &&
      /MissingSnapshotId/.test(error.message),
  );
});
