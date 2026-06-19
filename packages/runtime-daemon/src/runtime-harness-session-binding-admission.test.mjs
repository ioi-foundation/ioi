import assert from "node:assert/strict";
import test from "node:test";

import {
  HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION,
  admitHarnessSessionBinding,
} from "./runtime-harness-session-binding-admission.mjs";

function baseBinding(overrides = {}) {
  return {
    schema_version: "ioi.hypervisor.harness_session_binding.v1",
    session_binding_ref:
      "harness-session-binding:session-route-sessions-mission-default-project-ioi:harness-profile-default_harness_profile:model-config-local-codex-oss-qwen",
    session_route_ref: "session-route:sessions/mission.default/project:ioi",
    harness_selection_ref: "harness-profile:default_harness_profile",
    harness_selection_kind: "harness_profile",
    harness_label: "Default Harness Profile",
    harness_truth_boundary: "daemon-owned",
    harness_launch_route_ref: "harness-route:default-harness-profile/local-model",
    harness_profile_ref: "default_harness_profile",
    model_configuration_ref: "model-config:local/codex-oss-qwen",
    model_configuration_label: "Local Codex OSS / Qwen route",
    model_route_ref: "model-route:hypervisor/default-local",
    model_route_policy: "hypervisor_model_mount",
    model_route_availability_state: "daemon_verified",
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    model_route_loaded_instance_refs: ["model-instance:hypervisor/default-local"],
    workspace_mount_policy: "ctee_private_workspace",
    privacy_posture_ref: "privacy:ctee-private-workspace",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_policy_ref: "receipt-policy:harness-profile/default",
    receipt_preview_ref: "receipt-preview:new-session/admitted",
    expected_receipt_refs: [
      "receipt-preview:new-session/admitted",
      "receipt-policy:harness-profile/default",
    ],
    example_root_ref: null,
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
    agentgres_operation_refs: [
      "agentgres://operation/harness-session-binding/admit",
    ],
    receipt_refs: ["receipt://harness-session-binding/admit"],
    state_root: "agentgres://state-root/harness-session-binding/admit",
    ...overrides,
  };
}

test("admits Default Harness Profile local model session bindings", () => {
  const admission = admitHarnessSessionBinding(baseBinding(), {
    nowIso: () => "2026-06-18T12:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.admission_state, "admitted_for_harness_launch");
  assert.equal(
    admission.session_binding_ref,
    baseBinding().session_binding_ref,
  );
  assert.equal(admission.model_configuration_ref, "model-config:local/codex-oss-qwen");
  assert.deepEqual(admission.model_route_endpoint_refs, [
    "model-endpoint:hypervisor/default-local",
  ]);
  assert.deepEqual(admission.model_route_loaded_instance_refs, [
    "model-instance:hypervisor/default-local",
  ]);
  assert.equal(admission.requiresDaemonGate, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.equal(admission.harness_runtime_truth_claimed, false);
});

test("admits proposal-source Codex OSS bindings over local model mount", () => {
  const admission = admitHarnessSessionBinding(
    baseBinding({
      session_binding_ref:
        "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen",
      harness_selection_ref: "agent-harness-adapter:codex_cli",
      harness_selection_kind: "agent_harness_adapter",
      harness_truth_boundary: "proposal_source_only",
      harness_launch_route_ref: "harness-route:codex-cli/local-model",
      agent_harness_adapter_id: "codex_cli",
      harness_profile_ref: undefined,
      workspace_mount_policy: "redacted_projection",
      privacy_posture_ref: "privacy:redacted-projection",
      receipt_policy_ref: "receipt-policy:harness-adapter/default",
      expected_receipt_refs: [
        "receipt-preview:new-session/admitted",
        "receipt-policy:harness-adapter/default",
      ],
    }),
  );

  assert.equal(admission.harness_selection_ref, "agent-harness-adapter:codex_cli");
  assert.equal(admission.harness_truth_boundary, "proposal_source_only");
  assert.equal(admission.agent_harness_adapter_id, "codex_cli");
  assert.equal(admission.model_route_policy, "hypervisor_model_mount");
});

test("blocks external harness cTEE custody and provider-trust shortcuts", () => {
  assert.throws(
    () =>
      admitHarnessSessionBinding(
        baseBinding({
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen",
          harness_selection_ref: "agent-harness-adapter:codex_cli",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          agent_harness_adapter_id: "codex_cli",
          harness_profile_ref: undefined,
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_binding_external_ctee_custody_blocked",
      );
      return true;
    },
  );

  assert.throws(
    () =>
      admitHarnessSessionBinding(
        baseBinding({
          model_route_policy: "provider_trust",
          model_configuration_ref: "model-config:adapter-native/provider-trust",
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_binding_provider_trust_requires_future_lease",
      );
      return true;
    },
  );
});

test("blocks unavailable local model mounts and runtime-truth claims", () => {
  assert.throws(
    () =>
      admitHarnessSessionBinding(
        baseBinding({
          model_route_availability_state: "missing",
          model_route_endpoint_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.code, "harness_session_binding_model_route_unavailable");
      return true;
    },
  );

  assert.throws(
    () =>
      admitHarnessSessionBinding(
        baseBinding({ harness_runtime_truth_claimed: true }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_binding_runtime_truth_claim_blocked",
      );
      return true;
    },
  );
});

test("rejects retired camelCase aliases and prim-scope masquerades", () => {
  assert.throws(
    () =>
      admitHarnessSessionBinding({
        ...baseBinding(),
        sessionBindingRef: "legacy",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "harness_session_binding_request_aliases_retired");
      return true;
    },
  );

  assert.throws(
    () =>
      admitHarnessSessionBinding(
        baseBinding({ authority_scope_refs: ["prim:shell.exec"] }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "harness_session_binding_authority_scope_refs_prefix_invalid",
      );
      return true;
    },
  );
});
