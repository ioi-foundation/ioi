import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
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

test("coding tool approval runner sends Rust satisfaction request through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustCodingToolApprovalRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "direct_daemon_core_api",
        backend: "rust_authority",
        satisfied: true,
        approval_id: request.request.approval_id,
        decision_event_id: "event_decision",
        decision_seq: 4,
        lease_id: "lease_alpha",
        expires_at: "2026-06-06T04:45:00.000Z",
        reason: "approval_approved",
        receipt_refs: ["receipt_approval"],
        policy_decision_refs: ["policy_approval"],
        record: {
          schema_version: "ioi.runtime.coding-tool-approval-satisfaction-result.v1",
          status: "satisfied",
          operation_kind: "coding_tool.approval.satisfaction",
          satisfied: true,
        },
      };
    },
  });

  const result = runner.planApprovalSatisfaction({
    thread_id: "thread_1",
    approval_id: "approval_alpha",
    approval_manifest: { tool_id: "file.apply_patch" },
    approval_request: { approval_id: "approval_alpha" },
    latest_decision: { approval_id: "approval_alpha", event_kind: "approval.approved" },
    lease_state: { expired: false },
  });

  assert.equal(captured.schema_version, CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_approval_satisfaction");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(
    captured.request.schema_version,
    CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.approval_id, "approval_alpha");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.satisfied, true);
  assert.equal(result.approval_id, "approval_alpha");
  assert.equal(result.decision_event_id, "event_decision");
  assert.equal(result.decision_seq, 4);
  assert.deepEqual(result.receipt_refs, ["receipt_approval"]);
  assert.deepEqual(result.policy_decision_refs, ["policy_approval"]);
});

test("coding tool approval runner sends Rust satisfaction projection request through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustCodingToolApprovalRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "direct_daemon_core_api",
        backend: "rust_authority",
        status: "projected",
        operation_kind: "coding_tool.approval.satisfaction_projection",
        thread_id: request.request.thread_id,
        approval_id: request.request.approval_id,
        approval_request: {
          approval_id: request.request.approval_id,
          payload_summary: {
            approval_manifest: request.request.approval_manifest,
          },
        },
        latest_decision: {
          approval_id: request.request.approval_id,
          event_id: "event_decision",
          seq: 4,
          event_kind: "approval.approved",
        },
        lease_state: {
          expired: false,
          lease_id: "lease_alpha",
          status: "active",
        },
        expected_head: "agentgres://head/before",
        state_root_before: "state://root/before",
        record: {
          schema_version: "ioi.runtime.coding-tool-approval-satisfaction-projection.v1",
          status: "projected",
          operation_kind: "coding_tool.approval.satisfaction_projection",
        },
      };
    },
  });

  const result = runner.projectApprovalSatisfaction({
    thread_id: "thread_1",
    approval_id: "approval_alpha",
    approval_manifest: { tool_id: "file.apply_patch" },
    run: { id: "run_1" },
    agent: { id: "agent_1" },
  });

  assert.equal(captured.schema_version, CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_coding_tool_approval_satisfaction");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(
    captured.request.schema_version,
    CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.approval_id, "approval_alpha");
  assert.equal(captured.request.run.id, "run_1");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.status, "projected");
  assert.equal(result.approval_id, "approval_alpha");
  assert.equal(result.latest_decision.event_id, "event_decision");
  assert.equal(result.lease_state.lease_id, "lease_alpha");
  assert.equal(result.expected_head, "agentgres://head/before");
  assert.equal(result.state_root_before, "state://root/before");
});

test("coding tool approval runner sends Rust approval block request through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustCodingToolApprovalRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "direct_daemon_core_api",
        backend: "rust_authority",
        status: "blocked",
        operation_kind: "coding_tool.approval.block",
        approval_id: "approval_alpha",
        reason: "approval_required",
        receipt_refs: ["receipt_block"],
        policy_decision_refs: ["policy_block"],
        result: {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          status: "blocked",
          approval_required: true,
          approval_satisfied: false,
        },
        event: {
          event_kind: "tool.blocked",
          status: "blocked",
          receipt_refs: ["receipt_block"],
          artifact_refs: [],
          rollback_refs: [],
          payload_summary: {
            approval_required: true,
            approval_satisfied: false,
          },
        },
        record: {
          schema_version: "ioi.runtime.coding-tool-approval-block-result.v1",
          status: "blocked",
          operation_kind: "coding_tool.approval.block",
        },
      };
    },
  });

  const result = runner.planApprovalBlock({
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    approval_manifest: { tool_id: "file.apply_patch" },
    approval_gate: {
      satisfied: false,
      approval_id: "approval_alpha",
      reason: "approval_required",
    },
  });

  assert.equal(captured.schema_version, CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_approval_block");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(captured.request.schema_version, CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.tool_id, "file.apply_patch");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.status, "blocked");
  assert.equal(result.operation_kind, "coding_tool.approval.block");
  assert.equal(result.approval_id, "approval_alpha");
  assert.equal(result.event.event_kind, "tool.blocked");
  assert.equal(result.result.status, "blocked");
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
