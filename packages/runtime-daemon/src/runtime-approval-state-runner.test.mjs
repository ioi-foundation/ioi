import assert from "node:assert/strict";
import test from "node:test";

import {
  APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  APPROVAL_STATE_COMMAND_SCHEMA_VERSION,
  RustRuntimeApprovalStateRunner,
} from "./runtime-approval-state-runner.mjs";

test("approval request state runner sends Rust authority bridge request", () => {
  let captured = null;
  const runner = new RustRuntimeApprovalStateRunner({
    command: "ioi-step-module-bridge",
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
            updated_at: "2026-06-06T04:30:00.000Z",
            operator_control: {
              control: "approval_request",
              approvalId: "approval_alpha",
              eventId: "event_approval",
            },
            run: {
              id: "run_alpha",
              status: "blocked",
              turnStatus: "waiting_for_approval",
              trace: {
                approvalRequests: [
                  {
                    approvalId: "approval_alpha",
                    eventId: "event_approval",
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
  assert.equal(result.operator_control.approvalId, "approval_alpha");
  assert.equal(result.run.trace.approvalRequests[0].eventId, "event_approval");
});

test("approval request state runner fails closed without bridge command", () => {
  const runner = new RustRuntimeApprovalStateRunner();

  assert.throws(
    () => runner.planApprovalRequestStateUpdate({ run: {}, approval_id: "approval_alpha" }),
    /Runtime approval state updates require IOI_STEP_MODULE_COMMAND/,
  );
});
