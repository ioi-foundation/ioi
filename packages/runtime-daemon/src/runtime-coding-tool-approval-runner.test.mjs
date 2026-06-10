import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_APPROVAL_COMMAND_ENV,
  CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  CodingToolApprovalRunnerError,
  RustCodingToolApprovalRunner,
  createCodingToolApprovalRunnerFromEnv,
} from "./runtime-coding-tool-approval-runner.mjs";

test("coding tool approval runner env uses daemon-core command boundary", () => {
  const runner = createCodingToolApprovalRunnerFromEnv({
    [CODING_TOOL_APPROVAL_COMMAND_ENV]: "ioi-runtime-daemon-core",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
});

test("coding tool approval runner command args env fails closed", () => {
  assert.throws(
    () =>
      createCodingToolApprovalRunnerFromEnv({
        [CODING_TOOL_APPROVAL_COMMAND_ENV]: "ioi-runtime-daemon-core",
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof CodingToolApprovalRunnerError &&
      error.code === "coding_tool_approval_command_args_retired",
  );
});

test("coding tool approval runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustCodingToolApprovalRunner({ args: ["--json"] }),
    (error) =>
      error instanceof CodingToolApprovalRunnerError &&
      error.code === "coding_tool_approval_command_args_retired",
  );
});

test("coding tool approval runner sends Rust authority bridge request", () => {
  let captured = null;
  let capturedArgs = null;
  const runner = new RustCodingToolApprovalRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(command, args, options) {
      captured = JSON.parse(options.input);
      capturedArgs = args;
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

  assert.deepEqual(capturedArgs, []);
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
    /Coding-tool approval requires IOI_RUNTIME_DAEMON_CORE_COMMAND/,
  );
});
