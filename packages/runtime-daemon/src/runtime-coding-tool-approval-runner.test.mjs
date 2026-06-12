import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  CodingToolApprovalRunnerError,
  RustCodingToolApprovalRunner,
  createCodingToolApprovalRunnerFromEnv,
} from "./runtime-coding-tool-approval-runner.mjs";

test("coding tool approval runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createCodingToolApprovalRunnerFromEnv({
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired",
  }, {
    daemonCoreInvoker(request) {
      calls.push(request);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_authority",
        approval_required: true,
        manifest: {
          schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
          thread_id: request.request.thread_id,
          tool_id: request.request.tool_id,
          tool_call_id: request.request.tool_call_id,
          effect_class: request.request.effect_class,
          input_hash: "sha256:approval",
        },
      };
    },
  });

  const result = runner.planApprovalManifest({
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].operation, "plan_coding_tool_approval_manifest");
  assert.equal(result.manifest.tool_id, "file.apply_patch");
});

test("coding tool approval runner rejects retired daemon-core command env", () => {
  assert.throws(
    () =>
      createCodingToolApprovalRunnerFromEnv(
        {
          IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
        },
        {
          daemonCoreInvoker() {
            return {};
          },
        },
      ),
    (error) =>
      error instanceof CodingToolApprovalRunnerError &&
      error.code === "coding_tool_approval_command_selection_retired",
  );
});

test("coding tool approval runner command args env fails closed", () => {
  assert.throws(
    () =>
      createCodingToolApprovalRunnerFromEnv({
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

test("coding tool approval runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustCodingToolApprovalRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof CodingToolApprovalRunnerError &&
      error.code === "coding_tool_approval_command_selection_retired",
  );
});

test("coding tool approval runner sends Rust authority request through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustCodingToolApprovalRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "direct_daemon_core_api",
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
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.approval_required, true);
  assert.equal(result.manifest.input_hash, "sha256:approval");
});

test("coding tool approval runner unwraps direct invoker ok result", () => {
  const runner = new RustCodingToolApprovalRunner({
    daemonCoreInvoker(request) {
      return {
        ok: true,
        result: {
          source: "direct_daemon_core_api",
          backend: "rust_authority",
          approval_required: true,
          manifest: {
            schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
            thread_id: request.request.thread_id,
            tool_id: request.request.tool_id,
            tool_call_id: request.request.tool_call_id,
            effect_class: request.request.effect_class,
            input_hash: "sha256:approval",
          },
        },
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

  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.approval_required, true);
  assert.equal(result.manifest.input_hash, "sha256:approval");
});

test("coding tool approval runner fails closed without direct invoker", () => {
  const runner = new RustCodingToolApprovalRunner();

  assert.throws(
    () => runner.planApprovalManifest({ thread_id: "thread_1", tool_id: "file.apply_patch", tool_call_id: "call_1" }),
    (error) =>
      error instanceof CodingToolApprovalRunnerError &&
      error.code === "coding_tool_approval_direct_invoker_unconfigured",
  );
});
