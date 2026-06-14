import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
  RUST_CODING_TOOL_APPROVAL_BACKEND,
  RuntimeCodingToolApprovalCore,
  RuntimeCodingToolApprovalCoreError,
  createRuntimeCodingToolApprovalCore,
} from "./runtime-coding-tool-approval-core.mjs";

test("coding tool approval core calls direct Rust daemon-core approval APIs", () => {
  const calls = [];
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreInvoker(request) {
      calls.push(request);
      return {
        schema_version: "rust.approval.envelope.v1",
        operation: request.operation,
      };
    },
  });

  core.planApprovalManifest({
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
  });
  core.projectApprovalSatisfaction({
    thread_id: "thread_1",
    approval_id: "approval_alpha",
    state_dir: "/runtime-state",
  });
  core.planApprovalSatisfaction({
    thread_id: "thread_1",
    approval_id: "approval_alpha",
    approval_manifest: { tool_id: "file.apply_patch" },
  });
  core.planApprovalBlock({
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    approval_gate: { satisfied: false },
  });

  assert.deepEqual(
    calls.map((call) => call.operation),
    [
      "plan_coding_tool_approval_manifest",
      "project_coding_tool_approval_satisfaction",
      "plan_coding_tool_approval_satisfaction",
      "plan_coding_tool_approval_block",
    ],
  );
  for (const call of calls) {
    assert.equal(call.schema_version, CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION);
    assert.equal(call.backend, RUST_CODING_TOOL_APPROVAL_BACKEND);
  }
  assert.equal(calls[0].request.schema_version, CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION);
  assert.equal(
    calls[1].request.schema_version,
    CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[1].request.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(calls[1].request, "run"), false);
  assert.equal(Object.hasOwn(calls[1].request, "agent"), false);
  assert.equal(calls[2].request.schema_version, CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[3].request.schema_version, CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION);
});

test("coding tool approval core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.coding-tool-approval-result.v1",
    approval_required: true,
    manifest: {
      schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
      tool_id: "file.apply_patch",
    },
  };
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreInvoker() {
      return rustEnvelope;
    },
  });

  const result = core.planApprovalManifest({
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
  });

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "plan"), false);
  assert.equal(Object.hasOwn(result, "input_hash"), false);
});

test("coding tool approval core rejects retired compatibility options", () => {
  for (const options of [
    { command: "ioi-runtime-daemon-core" },
    { args: ["--approval"] },
    { env: { IOI_RUNTIME_DAEMON_CORE_COMMAND: "retired" } },
  ]) {
    assert.throws(
      () => new RuntimeCodingToolApprovalCore(options),
      (error) =>
        error instanceof RuntimeCodingToolApprovalCoreError &&
        error.code === "coding_tool_approval_core_compatibility_option_retired",
    );
  }
});

test("coding tool approval core rejects retired request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreInvoker() {
      calls.push("invoked");
      return {};
    },
  });

  assert.throws(
    () =>
      core.planApprovalManifest({
        threadId: "thread_1",
        toolId: "file.apply_patch",
        approvalGranted: true,
      }),
    (error) =>
      error.code === "coding_tool_approval_core_request_aliases_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("threadId") &&
      error.details.retired_aliases.includes("toolId") &&
      error.details.retired_aliases.includes("approvalGranted"),
  );
  assert.deepEqual(calls, []);
});

test("coding tool approval core fails closed without direct daemon-core API", () => {
  const core = createRuntimeCodingToolApprovalCore({});

  assert.throws(
    () => core.planApprovalManifest({ thread_id: "thread_1", tool_id: "file.apply_patch" }),
    (error) => error.code === "coding_tool_approval_core_direct_invoker_unconfigured",
  );
});

test("coding tool approval core surfaces Rust rejection", () => {
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "coding_tool_approval_manifest_invalid",
          message: "InvalidApprovalManifest",
        },
      };
    },
  });

  assert.throws(
    () => core.planApprovalManifest({ thread_id: "thread_1", tool_id: "file.apply_patch" }),
    (error) =>
      error.code === "coding_tool_approval_manifest_invalid" &&
      /InvalidApprovalManifest/.test(error.message),
  );
});
