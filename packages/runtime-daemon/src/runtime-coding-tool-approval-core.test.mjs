import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_APPROVAL_BLOCK_API_METHOD,
  CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_MANIFEST_API_METHOD,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD,
  CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD,
  CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
  RuntimeCodingToolApprovalCore,
  RuntimeCodingToolApprovalCoreError,
  createRuntimeCodingToolApprovalCore,
} from "./runtime-coding-tool-approval-core.mjs";

test("coding tool approval core calls typed Rust daemon-core approval APIs", () => {
  const calls = [];
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreApprovalApi: {
      [CODING_TOOL_APPROVAL_MANIFEST_API_METHOD](request) {
        calls.push({ method: CODING_TOOL_APPROVAL_MANIFEST_API_METHOD, request });
        return {
          schema_version: "rust.approval.envelope.v1",
          method: CODING_TOOL_APPROVAL_MANIFEST_API_METHOD,
        };
      },
      [CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD](request) {
        calls.push({ method: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD, request });
        return {
          schema_version: "rust.approval.envelope.v1",
          method: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD,
        };
      },
      [CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD](request) {
        calls.push({ method: CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD, request });
        return {
          schema_version: "rust.approval.envelope.v1",
          method: CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD,
        };
      },
      [CODING_TOOL_APPROVAL_BLOCK_API_METHOD](request) {
        calls.push({ method: CODING_TOOL_APPROVAL_BLOCK_API_METHOD, request });
        return {
          schema_version: "rust.approval.envelope.v1",
          method: CODING_TOOL_APPROVAL_BLOCK_API_METHOD,
        };
      },
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
    calls.map((call) => call.method),
    [
      CODING_TOOL_APPROVAL_MANIFEST_API_METHOD,
      CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD,
      CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD,
      CODING_TOOL_APPROVAL_BLOCK_API_METHOD,
    ],
  );
  for (const call of calls) {
    assert.equal(Object.hasOwn(call.request, "operation"), false);
    assert.equal(Object.hasOwn(call.request, "backend"), false);
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
    daemonCoreApprovalApi: {
      [CODING_TOOL_APPROVAL_MANIFEST_API_METHOD]() {
        return rustEnvelope;
      },
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
    { daemonCoreInvoker() {} },
    { daemonCoreApi: { [CODING_TOOL_APPROVAL_MANIFEST_API_METHOD]() {} } },
  ]) {
    assert.throws(
      () => new RuntimeCodingToolApprovalCore(options),
      (error) =>
        error instanceof RuntimeCodingToolApprovalCoreError &&
        error.code === "coding_tool_approval_core_compatibility_option_retired" &&
        (Object.hasOwn(options, "daemonCoreApi") ? error.details.retired_option === "daemonCoreApi" : true),
    );
  }
});

test("coding tool approval core rejects retired request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreApprovalApi: {
      [CODING_TOOL_APPROVAL_MANIFEST_API_METHOD]() {
        calls.push("invoked");
        return {};
      },
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
    (error) => error.code === "coding_tool_approval_core_direct_approval_api_unconfigured",
  );
});

test("coding tool approval core surfaces Rust rejection", () => {
  const core = createRuntimeCodingToolApprovalCore({
    daemonCoreApprovalApi: {
      [CODING_TOOL_APPROVAL_MANIFEST_API_METHOD]() {
        return {
          ok: false,
          error: {
            code: "coding_tool_approval_manifest_invalid",
            message: "InvalidApprovalManifest",
          },
        };
      },
    },
  });

  assert.throws(
    () => core.planApprovalManifest({ thread_id: "thread_1", tool_id: "file.apply_patch" }),
    (error) =>
      error.code === "coding_tool_approval_manifest_invalid" &&
      /InvalidApprovalManifest/.test(error.message),
  );
});
