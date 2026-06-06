import assert from "node:assert/strict";
import test from "node:test";

import {
  RustWorkspaceRestoreRunner,
  WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_COMMAND_ENV,
  WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
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

test("workspace restore runner sends apply policy bridge request", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    command: "mock-workspace-restore-bridge",
    args: ["--restore"],
    spawnSyncImpl(command, args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ command, args, bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_workspace_restore_policy_command",
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
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planApplyPolicy(policyRequest());

  assert.equal(calls[0].command, "mock-workspace-restore-bridge");
  assert.deepEqual(calls[0].args, ["--restore"]);
  assert.equal(calls[0].bridgeRequest.operation, "plan_workspace_restore_apply_policy");
  assert.equal(calls[0].bridgeRequest.backend, "rust_workspace_restore");
  assert.equal(
    calls[0].bridgeRequest.request.schema_version,
    WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].bridgeRequest.request.snapshot_id, "workspace_snapshot_alpha");
  assert.equal(result.source, "rust_workspace_restore_policy_command");
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

test("workspace restore runner sends preview operations bridge request", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    command: "mock-workspace-restore-bridge",
    spawnSyncImpl(command, args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ command, args, bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_workspace_restore_operations_command",
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
          },
        }),
        stderr: "",
      };
    },
  });

  const operations = runner.previewOperations(operationsRequest());

  assert.equal(calls[0].bridgeRequest.operation, "preview_workspace_restore_operations");
  assert.equal(
    calls[0].bridgeRequest.request.schema_version,
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

test("workspace restore runner sends apply operations bridge request", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    command: "mock-workspace-restore-bridge",
    spawnSyncImpl(_command, _args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_workspace_restore_operations_command",
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
          },
        }),
        stderr: "",
      };
    },
  });

  const operations = runner.applyOperations({ ...operationsRequest(), allow_conflicts: false });

  assert.equal(calls[0].bridgeRequest.operation, "apply_workspace_restore_operations");
  assert.equal(
    calls[0].bridgeRequest.request.schema_version,
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

test("workspace restore runner sends snapshot capture bridge request", () => {
  const calls = [];
  const runner = new RustWorkspaceRestoreRunner({
    command: "mock-workspace-restore-bridge",
    spawnSyncImpl(_command, _args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_workspace_snapshot_capture_command",
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
          },
        }),
        stderr: "",
      };
    },
  });

  const capture = runner.captureSnapshotFiles({
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
    maxContentBytes: 262144,
  });

  assert.equal(calls[0].bridgeRequest.operation, "capture_workspace_snapshot_files");
  assert.equal(
    calls[0].bridgeRequest.request.schema_version,
    WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].bridgeRequest.request.changed_files[0].before_hash, "sha256-old");
  assert.equal(calls[0].bridgeRequest.request.content_drafts[0].before_content, "old");
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

test("workspace restore runner can be configured from env", () => {
  const runner = createWorkspaceRestoreRunnerFromEnv({
    [WORKSPACE_RESTORE_COMMAND_ENV]: "mock-workspace-restore-bridge",
  });

  assert.equal(runner.command, "mock-workspace-restore-bridge");
});

test("workspace restore runner fails closed without command", () => {
  const runner = createWorkspaceRestoreRunnerFromEnv({});

  assert.throws(
    () => runner.planApplyPolicy(policyRequest()),
    (error) => error.code === "workspace_restore_bridge_unconfigured",
  );
});

test("workspace restore runner surfaces Rust policy rejection", () => {
  const runner = new RustWorkspaceRestoreRunner({
    command: "mock-workspace-restore-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: false,
          error: {
            code: "workspace_restore_apply_policy_invalid",
            message: "MissingSnapshotId",
          },
        }),
        stderr: "",
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
