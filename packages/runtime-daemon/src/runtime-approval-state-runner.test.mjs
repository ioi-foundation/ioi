import assert from "node:assert/strict";
import test from "node:test";

import {
  APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  APPROVAL_STATE_COMMAND_ARGS_ENV,
  APPROVAL_STATE_COMMAND_ENV,
  APPROVAL_STATE_COMMAND_SCHEMA_VERSION,
  RustRuntimeApprovalStateRunner,
  createRuntimeApprovalStateRunnerFromEnv,
  normalizeApprovalDecisionStateUpdateBridgeResult,
  normalizeApprovalRequestStateUpdateBridgeResult,
  normalizeApprovalRevokeStateUpdateBridgeResult,
} from "./runtime-approval-state-runner.mjs";

test("approval state runner env uses daemon-core command boundary", () => {
  const runner = createRuntimeApprovalStateRunnerFromEnv({
    [APPROVAL_STATE_COMMAND_ENV]: "ioi-runtime-daemon-core",
    [APPROVAL_STATE_COMMAND_ARGS_ENV]: "--json",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
  assert.deepEqual(runner.args, ["--json"]);
});

test("approval request state runner sends Rust authority bridge request", () => {
  let captured = null;
  const runner = new RustRuntimeApprovalStateRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_approval_request_state_update_command",
            backend: "rust_authority",
            status: "planned",
            operation_kind: "approval.required",
            target_kind: "run",
            updated_at: "2026-06-06T04:30:00.000Z",
            operator_control: {
              control: "approval_request",
              approval_id: "approval_alpha",
              event_id: "event_approval",
            },
            run: {
              id: "run_alpha",
              status: "blocked",
              turnStatus: "waiting_for_approval",
              trace: {
                approvalRequests: [
                  {
                    approval_id: "approval_alpha",
                    event_id: "event_approval",
                  },
                ],
              },
            },
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planApprovalRequestStateUpdate({
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run: { id: "run_alpha", status: "running", trace: {} },
    event_id: "event_approval",
    seq: 3,
    created_at: "2026-06-06T04:30:00.000Z",
    approval_id: "approval_alpha",
    source: "runtime_auto",
    reason: "Need permission",
    receipt_refs: ["receipt_approval"],
    policy_decision_refs: ["policy_approval"],
  });

  assert.equal(captured.schema_version, APPROVAL_STATE_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_approval_request_state_update");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(
    captured.request.schema_version,
    APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.approval_id, "approval_alpha");
  assert.equal(result.source, "rust_approval_request_state_update_command");
  assert.equal(result.operation_kind, "approval.required");
  assert.equal(result.target_kind, "run");
  assert.equal(result.operator_control.approval_id, "approval_alpha");
  for (const field of ["approvalId", "eventId", "receiptRefs", "policyDecisionRefs", "createdAt"]) {
    assert.equal(Object.hasOwn(result.operator_control, field), false);
  }
  assert.equal(result.run.trace.approvalRequests[0].event_id, "event_approval");
});

test("approval request state runner normalizes Rust agent target updates", () => {
  let captured = null;
  const runner = new RustRuntimeApprovalStateRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_approval_request_state_update_command",
            backend: "rust_authority",
            status: "planned",
            operation_kind: "approval.required",
            target_kind: "agent",
            updated_at: "2026-06-06T04:30:00.000Z",
            operator_control: {
              control: "approval_request",
              approval_id: "approval_alpha",
              event_id: "event_approval",
            },
            run: null,
            agent: {
              id: "agent_alpha",
              updatedAt: "2026-06-06T04:30:00.000Z",
            },
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planApprovalRequestStateUpdate({
    target_kind: "agent",
    thread_id: "thread_alpha",
    run_id: null,
    run: null,
    agent: { id: "agent_alpha" },
    event_id: "event_approval",
    seq: 3,
    created_at: "2026-06-06T04:30:00.000Z",
    approval_id: "approval_alpha",
    source: "runtime_auto",
    reason: "Need permission",
  });

  assert.equal(captured.request.target_kind, "agent");
  assert.equal(captured.request.agent.id, "agent_alpha");
  assert.equal(result.target_kind, "agent");
  assert.equal(result.run, null);
  assert.equal(result.agent.updatedAt, "2026-06-06T04:30:00.000Z");
});

test("approval request state runner fails closed without bridge command", () => {
  const runner = new RustRuntimeApprovalStateRunner();

  assert.throws(
    () => runner.planApprovalRequestStateUpdate({ run: {}, approval_id: "approval_alpha" }),
    /Runtime approval state updates require IOI_RUNTIME_DAEMON_CORE_COMMAND/,
  );
});

test("approval state runner fails closed without Rust-planned operation kinds", () => {
  assert.throws(
    () =>
      normalizeApprovalRequestStateUpdateBridgeResult({
        status: "planned",
        target_kind: "run",
        run: { id: "run_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "approval_request_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.required");
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeApprovalDecisionStateUpdateBridgeResult({
        status: "planned",
        operation_kind: "approval.required",
        target_kind: "run",
        run: { id: "run_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "approval_decision_state_update_operation_kind_mismatch");
      assert.equal(error.details.expectedOperationKind, "approval.approve");
      assert.deepEqual(error.details.expectedOperationKinds, ["approval.approve", "approval.reject"]);
      assert.equal(error.details.operationKind, "approval.required");
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeApprovalRevokeStateUpdateBridgeResult({
        status: "planned",
        target_kind: "run",
        run: { id: "run_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "approval_revoke_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.revoke");
      return true;
    },
  );
});

test("approval decision state runner sends Rust authority bridge request", () => {
  let captured = null;
  const runner = new RustRuntimeApprovalStateRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_approval_decision_state_update_command",
            backend: "rust_authority",
            status: "planned",
            operation_kind: "approval.approve",
            target_kind: "run",
            updated_at: "2026-06-06T04:35:00.000Z",
            operator_control: {
              control: "approval_decision",
              approval_id: "approval_alpha",
              lease_id: "lease_alpha",
              event_id: "event_decision",
            },
            run: {
              id: "run_alpha",
              trace: {
                approvalDecisions: [
                  {
                    approval_id: "approval_alpha",
                    event_id: "event_decision",
                  },
                ],
              },
            },
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planApprovalDecisionStateUpdate({
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run: { id: "run_alpha", trace: {} },
    event_id: "event_decision",
    seq: 4,
    created_at: "2026-06-06T04:35:00.000Z",
    approval_id: "approval_alpha",
    lease_id: "lease_alpha",
    lease_status: "active",
    decision: "approve",
    status: "approved",
    source: "runtime_auto",
    reason: "Looks good",
    receipt_refs: ["receipt_decision"],
    policy_decision_refs: ["policy_decision"],
  });

  assert.equal(captured.schema_version, APPROVAL_STATE_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_approval_decision_state_update");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(
    captured.request.schema_version,
    APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.decision, "approve");
  assert.equal(result.source, "rust_approval_decision_state_update_command");
  assert.equal(result.operation_kind, "approval.approve");
  assert.equal(result.target_kind, "run");
  assert.equal(result.operator_control.lease_id, "lease_alpha");
  for (const field of [
    "approvalId",
    "leaseId",
    "leaseStatus",
    "eventId",
    "receiptRefs",
    "policyDecisionRefs",
    "createdAt",
  ]) {
    assert.equal(Object.hasOwn(result.operator_control, field), false);
  }
  assert.equal(result.run.trace.approvalDecisions[0].event_id, "event_decision");
});

test("approval revoke state runner sends Rust authority bridge request", () => {
  let captured = null;
  const runner = new RustRuntimeApprovalStateRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_approval_revoke_state_update_command",
            backend: "rust_authority",
            status: "planned",
            operation_kind: "approval.revoke",
            target_kind: "run",
            updated_at: "2026-06-06T04:40:00.000Z",
            operator_control: {
              control: "approval_revoke",
              approval_id: "approval_alpha",
              lease_id: "lease_alpha",
              lease_status: "revoked",
              event_id: "event_revoke",
            },
            run: {
              id: "run_alpha",
              turnStatus: "waiting_for_input",
              trace: {
                approvalRevocations: [
                  {
                    approval_id: "approval_alpha",
                    event_id: "event_revoke",
                  },
                ],
              },
            },
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planApprovalRevokeStateUpdate({
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run: { id: "run_alpha", trace: {} },
    event_id: "event_revoke",
    seq: 5,
    created_at: "2026-06-06T04:40:00.000Z",
    approval_id: "approval_alpha",
    lease_id: "lease_alpha",
    source: "runtime_auto",
    reason: "Changed my mind",
    receipt_refs: ["receipt_revoke"],
    policy_decision_refs: ["policy_revoke"],
  });

  assert.equal(captured.schema_version, APPROVAL_STATE_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_approval_revoke_state_update");
  assert.equal(captured.backend, "rust_authority");
  assert.equal(
    captured.request.schema_version,
    APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.approval_id, "approval_alpha");
  assert.equal(result.source, "rust_approval_revoke_state_update_command");
  assert.equal(result.operation_kind, "approval.revoke");
  assert.equal(result.target_kind, "run");
  assert.equal(result.operator_control.lease_status, "revoked");
  for (const field of [
    "approvalId",
    "leaseId",
    "leaseStatus",
    "eventId",
    "receiptRefs",
    "policyDecisionRefs",
    "createdAt",
  ]) {
    assert.equal(Object.hasOwn(result.operator_control, field), false);
  }
  assert.equal(result.run.trace.approvalRevocations[0].event_id, "event_revoke");
});
