import assert from "node:assert/strict";
import test from "node:test";

import {
  CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
  admitCodeEditorAdapterLaunchPlan,
} from "./runtime-code-editor-adapter-launch-plan-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    launch_plan_ref: "code-editor-adapter:external_editor/launch-plan",
    adapter_ref: "code-editor-adapter:external_editor",
    target_ref: "adapter-target:external-editor",
    launch_mode: "external",
    connection_kind: "desktop_editor",
    connection_contract_ref: "connection-contract:code-editor-adapter/desktop-bridge",
    executor_lane: "desktop_editor",
    control_action: "open_desktop_editor",
    control_channel_ref: "control-channel:code-editor-adapter/desktop-bridge",
    required_access_lease_refs: ["lease:code-editor-adapter/desktop-bridge"],
    required_authority_scope_refs: [
      "scope:workspace.read",
      "scope:workspace.patch",
      "scope:receipt.write",
    ],
    required_receipt_refs: ["receipt-policy:code-editor-adapter/desktop-bridge"],
    custody_posture: "redacted_projection",
    secret_release_policy: "no_durable_secret_release",
    agentgres_operation_refs: ["agentgres://operation/code-editor-adapter/admit"],
    receipt_refs: ["receipt://code-editor-adapter/admit"],
    ...overrides,
  };
}

test("admits external editor adapter launch plans as daemon-gated leases", () => {
  const admission = admitCodeEditorAdapterLaunchPlan(baseRequest(), {
    nowIso: () => "2026-06-17T18:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.connection_kind, "desktop_editor");
  assert.equal(admission.executor_lane, "desktop_editor");
  assert.equal(admission.control_action, "open_desktop_editor");
  assert.equal(
    admission.control_channel_ref,
    "control-channel:code-editor-adapter/desktop-bridge",
  );
  assert.deepEqual(admission.required_access_lease_refs, [
    "lease:code-editor-adapter/desktop-bridge",
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
  const admission = admitCodeEditorAdapterLaunchPlan(
    baseRequest({
      launch_plan_ref: "code-editor-adapter:vscode_browser/launch-plan",
      adapter_ref: "code-editor-adapter:vscode_browser",
      target_ref: "adapter-target:vscode-browser",
      launch_mode: "remote_url",
      connection_kind: "browser_editor_url",
      connection_contract_ref:
        "connection-contract:code-editor-adapter/browser-editor",
      executor_lane: "browser_code_editor",
      control_action: "open_browser_editor",
      control_channel_ref: "control-channel:code-editor-adapter/browser-editor",
      required_access_lease_refs: ["lease:code-editor-adapter/browser-editor"],
      required_authority_scope_refs: [
        "scope:workspace.read",
        "scope:workspace.patch",
        "scope:receipt.write",
      ],
      required_receipt_refs: ["receipt-policy:code-editor-adapter/browser-editor"],
    }),
  );

  assert.equal(admission.connection_kind, "browser_editor_url");
  assert.equal(admission.executor_lane, "browser_code_editor");
  assert.equal(admission.control_action, "open_browser_editor");
});

test("blocks durable secrets, runtime-truth claims, and prim-scope masquerades", () => {
  assert.throws(
    () =>
      admitCodeEditorAdapterLaunchPlan(
        baseRequest({ secret_release_policy: "release_durable_secret" }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "code_editor_adapter_launch_durable_secret_release_blocked",
      );
      return true;
    },
  );

  assert.throws(
    () =>
      admitCodeEditorAdapterLaunchPlan(
        baseRequest({ control_action: "open_browser_editor" }),
      ),
    (error) => {
      assert.equal(error.code, "code_editor_adapter_control_contract_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      admitCodeEditorAdapterLaunchPlan(
        baseRequest({ connection_kind: "provider_workspace" }),
      ),
    (error) => {
      assert.equal(error.code, "code_editor_adapter_launch_connection_kind_invalid");
      return true;
    },
  );

  assert.throws(
    () =>
      admitCodeEditorAdapterLaunchPlan(
        baseRequest({ adapter_runtime_truth_claimed: true }),
      ),
    (error) => {
      assert.equal(error.code, "code_editor_adapter_runtime_truth_claim_blocked");
      return true;
    },
  );

  assert.throws(
    () =>
      admitCodeEditorAdapterLaunchPlan(
        baseRequest({
          required_authority_scope_refs: ["prim:shell.exec"],
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "code_editor_adapter_launch_required_authority_scope_refs_prefix_invalid",
      );
      return true;
    },
  );
});

test("code editor adapter launch admission rejects retired camelCase aliases", () => {
  assert.throws(
    () =>
      admitCodeEditorAdapterLaunchPlan({
        ...baseRequest(),
        launchPlanRef: "legacy",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "code_editor_adapter_launch_request_aliases_retired");
      return true;
    },
  );
});
