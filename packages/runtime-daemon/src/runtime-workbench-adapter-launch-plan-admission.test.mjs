import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
  admitWorkbenchAdapterLaunchPlan,
} from "./runtime-workbench-adapter-launch-plan-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    launch_plan_ref: "workbench-adapter:external_editor/launch-plan",
    adapter_ref: "workbench-adapter:external_editor",
    target_ref: "adapter-target:external-editor",
    launch_mode: "external",
    connection_kind: "desktop_bridge",
    connection_contract_ref: "connection-contract:workbench-adapter/desktop-bridge",
    executor_lane: "desktop_bridge",
    control_action: "request_desktop_bridge",
    control_channel_ref: "control-channel:workbench-adapter/desktop-bridge",
    required_access_lease_refs: ["lease:workbench-adapter/desktop-bridge"],
    required_authority_scope_refs: [
      "scope:workspace.read",
      "scope:workspace.patch",
      "scope:receipt.write",
    ],
    required_receipt_refs: ["receipt-policy:workbench-adapter/desktop-bridge"],
    custody_posture: "redacted_projection",
    secret_release_policy: "no_durable_secret_release",
    restore_archive_policy: "not_required",
    provider_posture_required: false,
    agentgres_operation_refs: ["agentgres://operation/workbench-adapter/admit"],
    receipt_refs: ["receipt://workbench-adapter/admit"],
    ...overrides,
  };
}

test("admits external editor adapter launch plans as daemon-gated leases", () => {
  const admission = admitWorkbenchAdapterLaunchPlan(baseRequest(), {
    nowIso: () => "2026-06-17T18:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.connection_kind, "desktop_bridge");
  assert.equal(admission.executor_lane, "desktop_bridge");
  assert.equal(admission.control_action, "request_desktop_bridge");
  assert.equal(
    admission.control_channel_ref,
    "control-channel:workbench-adapter/desktop-bridge",
  );
  assert.deepEqual(admission.required_access_lease_refs, [
    "lease:workbench-adapter/desktop-bridge",
  ]);
  assert.deepEqual(admission.required_authority_scope_refs, [
    "scope:workspace.read",
    "scope:workspace.patch",
    "scope:receipt.write",
  ]);
  assert.equal(admission.secret_release_policy, "no_durable_secret_release");
  assert.equal(admission.requiresDaemonGate, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
});

test("persistent remote adapter sessions require provider posture and restore refs", () => {
  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan(
        baseRequest({
          launch_plan_ref: "workbench-adapter:remote_vm/launch-plan",
          adapter_ref: "workbench-adapter:remote_vm",
          target_ref: "adapter-target:remote-vm-workspace",
          launch_mode: "remote_url",
          connection_kind: "provider_workspace",
          connection_contract_ref:
            "connection-contract:workbench-adapter/provider-workspace",
          executor_lane: "provider_environment",
          control_action: "attach_provider_workspace",
          control_channel_ref:
            "control-channel:workbench-adapter/provider-workspace",
          required_access_lease_refs: ["lease:provider/workspace-access"],
          required_authority_scope_refs: ["scope:provider.workspace.attach"],
          required_receipt_refs: ["receipt-policy:workbench-adapter/provider"],
          custody_posture: "provider_session",
          restore_archive_policy: "required_for_remote_persistence",
          provider_posture_required: true,
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "workbench_adapter_provider_posture_ref_required");
      return true;
    },
  );

  const admission = admitWorkbenchAdapterLaunchPlan(
    baseRequest({
      launch_plan_ref: "workbench-adapter:remote_vm/launch-plan",
      adapter_ref: "workbench-adapter:remote_vm",
      target_ref: "adapter-target:remote-vm-workspace",
      launch_mode: "remote_url",
      connection_kind: "provider_workspace",
      connection_contract_ref:
        "connection-contract:workbench-adapter/provider-workspace",
      executor_lane: "provider_environment",
      control_action: "attach_provider_workspace",
      control_channel_ref:
        "control-channel:workbench-adapter/provider-workspace",
      required_access_lease_refs: [
        "lease:provider/workspace-access",
        "lease:provider/ports-read",
        "lease:workspace/logs-read",
      ],
      required_authority_scope_refs: [
        "scope:provider.workspace.attach",
        "scope:ports.expose",
        "scope:receipt.write",
      ],
      required_receipt_refs: ["receipt-policy:workbench-adapter/provider"],
      custody_posture: "provider_session",
      restore_archive_policy: "required_for_remote_persistence",
      provider_posture_required: true,
      provider_posture_ref: "provider-posture://akash/gpu-node-7",
      archive_ref: "artifact://workspace/archive/7",
      restore_ref: "agentgres://restore/workspace/7",
    }),
  );

  assert.equal(admission.connection_kind, "provider_workspace");
  assert.equal(admission.executor_lane, "provider_environment");
  assert.equal(admission.control_action, "attach_provider_workspace");
  assert.equal(admission.provider_posture_required, true);
  assert.equal(admission.archive_ref, "artifact://workspace/archive/7");
  assert.equal(admission.restore_ref, "agentgres://restore/workspace/7");
});

test("blocks durable secrets, runtime-truth claims, and prim-scope masquerades", () => {
  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan(
        baseRequest({ secret_release_policy: "release_durable_secret" }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "workbench_adapter_launch_durable_secret_release_blocked",
      );
      return true;
    },
  );

  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan(
        baseRequest({ control_action: "attach_provider_workspace" }),
      ),
    (error) => {
      assert.equal(error.code, "workbench_adapter_control_contract_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan(
        baseRequest({ adapter_runtime_truth_claimed: true }),
      ),
    (error) => {
      assert.equal(error.code, "workbench_adapter_runtime_truth_claim_blocked");
      return true;
    },
  );

  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan(
        baseRequest({
          required_authority_scope_refs: ["prim:shell.exec"],
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "workbench_adapter_launch_required_authority_scope_refs_prefix_invalid",
      );
      return true;
    },
  );
});

test("workbench adapter launch admission rejects retired camelCase aliases", () => {
  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan({
        ...baseRequest(),
        launchPlanRef: "legacy",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "workbench_adapter_launch_request_aliases_retired");
      return true;
    },
  );
});
