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
    connection_kind: "desktop_editor",
    connection_contract_ref: "connection-contract:workbench-adapter/desktop-bridge",
    executor_lane: "desktop_editor",
    control_action: "open_desktop_editor",
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
  assert.equal(admission.connection_kind, "desktop_editor");
  assert.equal(admission.executor_lane, "desktop_editor");
  assert.equal(admission.control_action, "open_desktop_editor");
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

test("admits browser code editor adapters without provider-session fields", () => {
  const admission = admitWorkbenchAdapterLaunchPlan(
    baseRequest({
      launch_plan_ref: "workbench-adapter:vscode_browser/launch-plan",
      adapter_ref: "workbench-adapter:vscode_browser",
      target_ref: "adapter-target:vscode-browser",
      launch_mode: "remote_url",
      connection_kind: "browser_editor_url",
      connection_contract_ref:
        "connection-contract:workbench-adapter/browser-editor",
      executor_lane: "browser_code_editor",
      control_action: "open_browser_editor",
      control_channel_ref: "control-channel:workbench-adapter/browser-editor",
      required_access_lease_refs: ["lease:workbench-adapter/browser-editor"],
      required_authority_scope_refs: [
        "scope:workspace.read",
        "scope:workspace.patch",
        "scope:receipt.write",
      ],
      required_receipt_refs: ["receipt-policy:workbench-adapter/browser-editor"],
    }),
  );

  assert.equal(admission.connection_kind, "browser_editor_url");
  assert.equal(admission.executor_lane, "browser_code_editor");
  assert.equal(admission.control_action, "open_browser_editor");
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
        baseRequest({ control_action: "open_browser_editor" }),
      ),
    (error) => {
      assert.equal(error.code, "workbench_adapter_control_contract_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      admitWorkbenchAdapterLaunchPlan(
        baseRequest({ connection_kind: "provider_workspace" }),
      ),
    (error) => {
      assert.equal(error.code, "workbench_adapter_launch_connection_kind_invalid");
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
