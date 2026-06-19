import assert from "node:assert/strict";
import test from "node:test";

import {
  admitHypervisorApprovedOperation,
} from "./runtime-hypervisor-approved-operation-admission.mjs";
import {
  HYPERVISOR_APPROVED_OPERATION_DISPATCH_SCHEMA_VERSION,
  dispatchHypervisorApprovedOperationPlan,
} from "./runtime-hypervisor-approved-operation-dispatch.mjs";

const approvedSessionRequest = {
  operation_family: "session",
  proposal_ref: "session-operation:daemon/restore",
  proposal_schema_version: "ioi.hypervisor.session_operation_proposal.v1",
  proposal_source: "daemon-session-operation-proposal",
  project_ref: "project:ioi",
  session_ref: "session:ioi",
  environment_ref: "environment:ioi",
  provider_candidate_ref: "provider:local-workstation",
  operation_kind: "restore_session",
  target_ref: "agentgres://restore/ioi/latest",
  wallet_approval_ref: "approval://wallet/session/restore",
  wallet_lease_ref: "lease:wallet/session/restore",
  required_scope_refs: ["scope:restore.apply"],
  authority_receipt_refs: ["receipt://wallet/session/restore"],
  agentgres_operation_ref: "agentgres://operation/session/ioi/restore",
  receipt_ref: "receipt://session/ioi/restore",
  state_root_ref: "agentgres://state-root/session/ioi",
  archive_ref: "artifact://agentgres/archive/ioi/latest",
  restore_ref: "agentgres://restore/ioi/latest",
};

function admittedPlan() {
  return admitHypervisorApprovedOperation(approvedSessionRequest, {
    nowIso: () => "2026-06-18T00:00:00.000Z",
  }).execution_plan;
}

test("dispatches an admitted execution plan through a mounted executor", async () => {
  const plan = admittedPlan();
  const calls = [];
  const result = await dispatchHypervisorApprovedOperationPlan(
    {
      execution_plan: plan,
      execution_plan_ref: plan.execution_plan_ref,
      dispatch_ref: plan.dispatch_ref,
      executor_kind: plan.executor_kind,
      executor_ref: "executor://hypervisor/session/local-workstation",
    },
    {
      nowIso: () => "2026-06-18T00:01:00.000Z",
      executeApprovedOperationPlan(receivedPlan, context) {
        calls.push({ receivedPlan, context });
        return {
          execution_status: "completed",
          execution_receipt_ref: "receipt://session/ioi/restore/executed",
          agentgres_operation_refs: [
            "agentgres://operation/session/ioi/restore/executed",
          ],
          artifact_refs: ["artifact://session/ioi/restore/log"],
          trace_refs: ["trace://session/ioi/restore"],
          next_state_root_ref: "agentgres://state-root/session/ioi/restored",
          execution_result_ref: "result://session/ioi/restore",
        };
      },
    },
  );

  assert.equal(
    result.schema_version,
    HYPERVISOR_APPROVED_OPERATION_DISPATCH_SCHEMA_VERSION,
  );
  assert.equal(result.dispatch_status, "executed");
  assert.equal(result.execution_status, "completed");
  assert.equal(result.executor_kind, "session_lifecycle_adapter");
  assert.equal(
    result.executor_ref,
    "executor://hypervisor/session/local-workstation",
  );
  assert.equal(result.operation_family, "session");
  assert.equal(result.wallet_lease_ref, plan.wallet_lease_ref);
  assert.deepEqual(result.required_scope_refs, ["scope:restore.apply"]);
  assert.deepEqual(result.receipt_refs, [
    "receipt://session/ioi/restore",
    "receipt://session/ioi/restore/executed",
  ]);
  assert.deepEqual(result.agentgres_operation_refs, [
    "agentgres://operation/session/ioi/restore",
    "agentgres://operation/session/ioi/restore/executed",
  ]);
  assert.deepEqual(result.artifact_refs, ["artifact://session/ioi/restore/log"]);
  assert.deepEqual(result.trace_refs, ["trace://session/ioi/restore"]);
  assert.equal(result.previous_state_root_ref, "agentgres://state-root/session/ioi");
  assert.equal(
    result.next_state_root_ref,
    "agentgres://state-root/session/ioi/restored",
  );
  assert.equal(result.execution_result_ref, "result://session/ioi/restore");
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].receivedPlan, plan);
  assert.equal(
    calls[0].context.executor_ref,
    "executor://hypervisor/session/local-workstation",
  );
  assert.match(
    calls[0].context.execution_attempt_ref,
    /^execution-attempt:\/\/hypervisor\//,
  );
});

test("rejects dispatch when no concrete executor is mounted", async () => {
  await assert.rejects(
    () =>
      dispatchHypervisorApprovedOperationPlan({
        execution_plan: admittedPlan(),
        executor_ref: "executor://hypervisor/session/local-workstation",
      }),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_approved_operation_executor_required",
      );
      assert.equal(error.status, 501);
      return true;
    },
  );
});

test("rejects dispatch input that does not match the admitted plan", async () => {
  const plan = admittedPlan();
  await assert.rejects(
    () =>
      dispatchHypervisorApprovedOperationPlan(
        {
          execution_plan: plan,
          dispatch_ref: "dispatch://hypervisor/session/tampered",
          executor_ref: "executor://hypervisor/session/local-workstation",
        },
        {
          executeApprovedOperationPlan() {
            return { execution_receipt_ref: "receipt://session/ioi/restore" };
          },
        },
      ),
    /must match the daemon-owned execution plan/,
  );
});

test("rejects non-daemon plans and executor results without execution receipts", async () => {
  await assert.rejects(
    () =>
      dispatchHypervisorApprovedOperationPlan(
        {
          execution_plan: {
            ...admittedPlan(),
            runtimeTruthSource: "client",
          },
          executor_ref: "executor://hypervisor/session/local-workstation",
        },
        {
          executeApprovedOperationPlan() {
            return { execution_receipt_ref: "receipt://session/ioi/restore" };
          },
        },
      ),
    /daemon-runtime plans/,
  );

  await assert.rejects(
    () =>
      dispatchHypervisorApprovedOperationPlan(
        {
          execution_plan: admittedPlan(),
          executor_ref: "executor://hypervisor/session/local-workstation",
        },
        {
          executeApprovedOperationPlan() {
            return {
              execution_status: "completed",
              agentgres_operation_refs: [
                "agentgres://operation/session/ioi/restore/executed",
              ],
            };
          },
        },
      ),
    /requires receipt_refs/,
  );
});

test("rejects retired camelCase aliases", async () => {
  await assert.rejects(
    () =>
      dispatchHypervisorApprovedOperationPlan(
        {
          executionPlan: admittedPlan(),
          executor_ref: "executor://hypervisor/session/local-workstation",
        },
        {
          executeApprovedOperationPlan() {
            return { execution_receipt_ref: "receipt://session/ioi/restore" };
          },
        },
      ),
    /snake_case/,
  );
});
