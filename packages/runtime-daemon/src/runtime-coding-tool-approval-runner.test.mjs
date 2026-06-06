import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  RustCodingToolApprovalRunner,
} from "./runtime-coding-tool-approval-runner.mjs";

test("coding tool approval runner sends Rust authority bridge request", () => {
  let captured = null;
  const runner = new RustCodingToolApprovalRunner({
    command: "ioi-step-module-bridge",
    spawnSyncImpl(command, args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_coding_tool_approval_command",
            backend: "rust_authority",
            approval_required: true,
            manifest: {
              schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
              thread_id: "thread_1",
              tool_id: "file.apply_patch",
              tool_call_id: "call_1",
              effect_class: "workspace_write",
              input_hash: "sha256:approval",
            },
            workflow_policy: {
              schema_version: "ioi.runtime.workflow-tool-approval-policy.v1",
              requires_approval: true,
            },
            input_hash: "sha256:approval",
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planApprovalManifest({
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
    input: { path: "src/app.js" },
  });

  assert.equal(captured.schema_version, CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_approval_manifest");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(captured.request.schema_version, CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.tool_id, "file.apply_patch");
  assert.equal(result.source, "rust_coding_tool_approval_command");
  assert.equal(result.approval_required, true);
  assert.equal(result.manifest.input_hash, "sha256:approval");
});

test("coding tool approval runner fails closed without bridge command", () => {
  const runner = new RustCodingToolApprovalRunner();

  assert.throws(
    () => runner.planApprovalManifest({ thread_id: "thread_1", tool_id: "file.apply_patch", tool_call_id: "call_1" }),
    /Coding-tool approval requires IOI_STEP_MODULE_COMMAND/,
  );
});
