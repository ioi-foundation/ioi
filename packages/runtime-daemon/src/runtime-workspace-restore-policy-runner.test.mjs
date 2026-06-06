import assert from "node:assert/strict";
import test from "node:test";

import {
  RustWorkspaceRestorePolicyRunner,
  WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  WORKSPACE_RESTORE_POLICY_COMMAND_ENV,
  createWorkspaceRestorePolicyRunnerFromEnv,
} from "./runtime-workspace-restore-policy-runner.mjs";

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

test("workspace restore policy runner sends apply policy bridge request", () => {
  const calls = [];
  const runner = new RustWorkspaceRestorePolicyRunner({
    command: "mock-workspace-restore-policy-bridge",
    args: ["--restore-policy"],
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

  assert.equal(calls[0].command, "mock-workspace-restore-policy-bridge");
  assert.deepEqual(calls[0].args, ["--restore-policy"]);
  assert.equal(calls[0].bridgeRequest.operation, "plan_workspace_restore_apply_policy");
  assert.equal(calls[0].bridgeRequest.backend, "rust_workspace_restore");
  assert.equal(
    calls[0].bridgeRequest.request.schema_version,
    WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].bridgeRequest.request.snapshot_id, "workspace_snapshot_alpha");
  assert.equal(result.source, "rust_workspace_restore_policy_command");
  assert.equal(result.approval.satisfied, true);
  assert.equal(result.applyStatus, "applied");
  assert.deepEqual(result.policyDecisionRefs, [
    "policy_workspace_restore_apply_workspace_snapshot_alpha_approval_satisfied",
  ]);
  assert.equal(result.operationPolicyByPath.get("src/app.js"), "workspace_restore_apply_blocked_by_policy");
});

test("workspace restore policy runner can be configured from env", () => {
  const runner = createWorkspaceRestorePolicyRunnerFromEnv({
    [WORKSPACE_RESTORE_POLICY_COMMAND_ENV]: "mock-workspace-restore-policy-bridge",
  });

  assert.equal(runner.command, "mock-workspace-restore-policy-bridge");
});

test("workspace restore policy runner fails closed without command", () => {
  const runner = createWorkspaceRestorePolicyRunnerFromEnv({});

  assert.throws(
    () => runner.planApplyPolicy(policyRequest()),
    (error) => error.code === "workspace_restore_policy_bridge_unconfigured",
  );
});

test("workspace restore policy runner surfaces Rust policy rejection", () => {
  const runner = new RustWorkspaceRestorePolicyRunner({
    command: "mock-workspace-restore-policy-bridge",
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
