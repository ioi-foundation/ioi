import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkflowAuthorityBoundaryVisualizer } from "./workflow-authority-boundary-visualizer";

test("authority boundary visualizer reads canonical proof fields", () => {
  const visualizer = buildWorkflowAuthorityBoundaryVisualizer({
    sandboxProof: {
      workspace_root: "/workspace/project",
      outside_root: "/tmp/outside",
      checks: {
        absolute_path_escape_denied: true,
        symlink_read_escape_denied: true,
        symlink_write_escape_denied: true,
        disallowed_shell_network_command_denied: true,
        secret_env_filtered_from_subprocess: true,
        computer_use_act_requires_approval_before_execution: true,
      },
      results: {
        absolute_escape: { error_code: "policy" },
        symlink_read_escape: {
          error_code: "policy",
          resolved_path: "/tmp/outside/secret.txt",
        },
        symlink_write_escape: {
          error_code: "policy",
          outside_content_preserved: true,
        },
        disallowed_shell: { error_code: "test_run_command_not_allowed" },
        computer_use_act_lease: {
          authority_scope: "computer_use.native_browser.act",
          request_ref: "request-canonical",
        },
      },
    },
  });

  assert.equal(visualizer.status, "ready");
  assert.equal(visualizer.workspaceRoot, "/workspace/project");
  assert.equal(visualizer.outsideRoot, "/tmp/outside");
  assert.equal(visualizer.deniedZoneCount, 4);
  assert.equal(visualizer.approvalRequiredCount, 1);
  assert.equal(visualizer.scrubbedZoneCount, 1);
  assert.ok(visualizer.zones.some((zone) => zone.evidence.includes("outside_content_preserved")));
  assert.ok(
    visualizer.zones.some((zone) => zone.authorityScope === "computer_use.native_browser.act"),
  );
});

test("authority boundary visualizer ignores retired proof aliases", () => {
  const visualizer = buildWorkflowAuthorityBoundaryVisualizer({
    sandboxProof: {
      workspaceRoot: "/workspace/retired",
      outsideRoot: "/tmp/retired",
      checks: {
        absolutePathEscapeDenied: true,
        symlinkReadEscapeDenied: true,
        symlinkWriteEscapeDenied: true,
        disallowedShellNetworkCommandDenied: true,
        secretEnvFilteredFromSubprocess: true,
        computerUseActRequiresApprovalBeforeExecution: true,
      },
      results: {
        absoluteEscape: { errorCode: "policy" },
        symlinkReadEscape: {
          errorCode: "policy",
          resolvedPath: "/tmp/retired/secret.txt",
        },
        symlinkWriteEscape: {
          errorCode: "policy",
          outsideContentPreserved: true,
        },
        disallowedShell: { errorCode: "test_run_command_not_allowed" },
        computerUseActLease: {
          authorityScope: "computer_use.native_browser.act",
          requestRef: "request-retired",
        },
      },
    },
  });

  assert.equal(visualizer.status, "blocked");
  assert.equal(visualizer.workspaceRoot, null);
  assert.equal(visualizer.outsideRoot, null);
  assert.equal(visualizer.deniedZoneCount, 0);
  assert.equal(visualizer.approvalRequiredCount, 0);
  assert.equal(visualizer.scrubbedZoneCount, 0);
  assert.ok(!visualizer.zones.some((zone) => zone.evidence.includes("outside_content_preserved")));
  assert.ok(!visualizer.zones.some((zone) => zone.authorityScope === "computer_use.native_browser.act"));
});
