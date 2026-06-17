import assert from "node:assert/strict";
import test from "node:test";

import {
  MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION,
  admitManagedWorkerInstanceLifecycleTransition,
} from "./runtime-managed-worker-instance-lifecycle-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    lifecycle_id: "lifecycle:agent_123",
    worker_instance_id: "agent://agent_123",
    worker_package_ref: "package://worker/researcher@1",
    owner_ref: "wallet://user_123",
    from_state: "active",
    to_state: "idle",
    persistence_profile: "persistent",
    payment_status: "current",
    transition_reason: "operator_request",
    authority_scope_refs: ["scope:worker.lifecycle"],
    authority_grant_refs: ["grant://wallet/worker-lifecycle"],
    policy_refs: ["policy://worker-lifecycle"],
    latest_state_root: "state_root:worker:123",
    archive_refs: [],
    artifact_refs: [],
    receipt_refs: ["receipt://worker-lifecycle/idle"],
    agentgres_operation_refs: ["agentgres://operation/worker-lifecycle/idle"],
    required_controls: [],
    ...overrides,
  };
}

test("admits ordinary managed worker lifecycle transitions through daemon runtime truth", () => {
  const admission = admitManagedWorkerInstanceLifecycleTransition(baseRequest(), {
    nowIso: () => "2026-06-17T16:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.transition_id, "managed-worker-lifecycle:lifecycle_agent_123:active-idle");
  assert.equal(admission.worker_instance_id, "agent://agent_123");
  assert.equal(admission.state, "idle");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.equal(admission.freezes_new_billable_work, false);
  assert.equal(admission.pauses_high_risk_standing_orders, false);
});

test("payment lapse freezes billable work and cannot silently delete context", () => {
  const lapse = admitManagedWorkerInstanceLifecycleTransition(
    baseRequest({
      from_state: "active",
      to_state: "payment_past_due",
      payment_status: "past_due",
      transition_reason: "payment_lapse",
      new_billable_work_blocked: true,
      high_risk_orders_paused: true,
      required_controls: [
        "freeze_new_billable_work",
        "pause_high_risk_standing_orders",
      ],
      receipt_refs: ["receipt://worker-lifecycle/payment-past-due"],
      agentgres_operation_refs: [
        "agentgres://operation/worker-lifecycle/payment-past-due",
      ],
    }),
  );

  assert.equal(lapse.to_state, "payment_past_due");
  assert.equal(lapse.freezes_new_billable_work, true);
  assert.equal(lapse.pauses_high_risk_standing_orders, true);

  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition(
        baseRequest({
          from_state: "payment_past_due",
          to_state: "deleted",
          payment_status: "past_due",
          transition_reason: "payment_lapse",
          wallet_approval_ref: "approval://wallet/delete",
          authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.delete"],
          deletion_policy: {
            delete_runtime_state: true,
            delete_archives: false,
            forget_semantic_memory: false,
          },
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "managed_worker_lifecycle_lapse_delete_blocked");
      return true;
    },
  );

  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition(
        baseRequest({
          from_state: "idle",
          to_state: "payment_past_due",
          payment_status: "past_due",
          transition_reason: "payment_lapse",
          new_billable_work_blocked: false,
          high_risk_orders_paused: false,
          required_controls: [
            "freeze_new_billable_work",
            "pause_high_risk_standing_orders",
          ],
        }),
      ),
    (error) => {
      assert.equal(error.code, "managed_worker_lifecycle_lapse_freeze_required");
      return true;
    },
  );
});

test("archive and restore transitions require Agentgres refs, archive refs, state roots, receipts, and authority", () => {
  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition(
        baseRequest({
          from_state: "zero_to_idle",
          to_state: "archived",
          archive_refs: [],
          artifact_refs: ["artifact://worker/archive"],
          archive_policy: {
            archive_after: "PT1H",
            retain_for: "P90D",
            storage_policy_ref: "policy://storage/encrypted",
          },
          required_controls: ["agentgres_archive_ref"],
        }),
      ),
    (error) => {
      assert.equal(error.code, "managed_worker_lifecycle_archive_ref_required");
      return true;
    },
  );

  const archive = admitManagedWorkerInstanceLifecycleTransition(
    baseRequest({
      from_state: "zero_to_idle",
      to_state: "archived",
      archive_refs: ["archive://worker/agent-123"],
      artifact_refs: ["artifact://worker/archive"],
      receipt_refs: ["receipt://worker-lifecycle/archive"],
      agentgres_operation_refs: ["agentgres://operation/worker-lifecycle/archive"],
      archive_policy: {
        archive_after: "PT1H",
        retain_for: "P90D",
        storage_policy_ref: "policy://storage/encrypted",
      },
      required_controls: ["agentgres_archive_ref"],
    }),
  );

  assert.equal(archive.to_state, "archived");
  assert.deepEqual(archive.archive_refs, ["archive://worker/agent-123"]);

  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition(
        baseRequest({
          from_state: "archived",
          to_state: "restoring",
          archive_refs: ["archive://worker/agent-123"],
          authority_scope_refs: ["scope:worker.lifecycle"],
          wallet_approval_ref: "approval://wallet/restore",
          restore_policy: { restore_receipt_required: true },
        }),
      ),
    (error) => {
      assert.equal(error.code, "managed_worker_lifecycle_required_scope_missing");
      return true;
    },
  );

  const restore = admitManagedWorkerInstanceLifecycleTransition(
    baseRequest({
      from_state: "archived",
      to_state: "restoring",
      archive_refs: ["archive://worker/agent-123"],
      receipt_refs: ["receipt://worker-lifecycle/restore"],
      agentgres_operation_refs: ["agentgres://operation/worker-lifecycle/restore"],
      authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.restore"],
      wallet_approval_ref: "approval://wallet/restore",
      restore_import_ref: "restore://worker/agent-123",
      restore_policy: {
        restore_requires: "wallet_step_up",
        restore_receipt_required: true,
      },
    }),
  );

  assert.equal(restore.to_state, "restoring");
  assert.equal(restore.restore_import_ref, "restore://worker/agent-123");
});

test("export, delete, and forget transitions require explicit wallet authority", () => {
  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition(
        baseRequest({
          from_state: "archived",
          to_state: "exported",
          archive_refs: ["archive://worker/agent-123"],
          authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.export"],
          export_policy: { export_requires: "wallet_step_up" },
        }),
      ),
    (error) => {
      assert.equal(error.code, "managed_worker_lifecycle_wallet_approval_required");
      return true;
    },
  );

  const exported = admitManagedWorkerInstanceLifecycleTransition(
    baseRequest({
      from_state: "archived",
      to_state: "exported",
      archive_refs: ["archive://worker/agent-123"],
      authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.export"],
      wallet_approval_ref: "approval://wallet/export",
      export_policy: { export_requires: "wallet_step_up" },
    }),
  );
  assert.equal(exported.to_state, "exported");

  const deleted = admitManagedWorkerInstanceLifecycleTransition(
    baseRequest({
      from_state: "exported",
      to_state: "deleted",
      authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.delete"],
      wallet_approval_ref: "approval://wallet/delete",
      deletion_policy: {
        delete_runtime_state: true,
        delete_archives: false,
        forget_semantic_memory: false,
      },
    }),
  );
  assert.equal(deleted.to_state, "deleted");

  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition(
        baseRequest({
          from_state: "deleted",
          to_state: "forgotten",
          authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.forget"],
          wallet_approval_ref: "approval://wallet/forget",
          deletion_policy: {
            delete_runtime_state: true,
            delete_archives: true,
            forget_semantic_memory: false,
          },
        }),
      ),
    (error) => {
      assert.equal(error.code, "managed_worker_lifecycle_forget_policy_required");
      return true;
    },
  );
});

test("managed worker lifecycle admission rejects retired camelCase aliases", () => {
  assert.throws(
    () =>
      admitManagedWorkerInstanceLifecycleTransition({
        ...baseRequest(),
        lifecycleId: "legacy",
        workerInstanceId: "legacy",
        archiveRefs: [],
        receiptRefs: [],
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "managed_worker_lifecycle_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "lifecycleId",
        "workerInstanceId",
        "archiveRefs",
        "receiptRefs",
      ]);
      return true;
    },
  );
});
