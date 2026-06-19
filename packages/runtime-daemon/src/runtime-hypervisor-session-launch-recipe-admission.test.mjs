import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION,
  admitHypervisorSessionLaunchRecipe,
} from "./runtime-hypervisor-session-launch-recipe-admission.mjs";

function recipe(overrides = {}) {
  return {
    schema_version: "ioi.hypervisor.session_launch_recipe.v1",
    recipe_id: "workbench.default",
    label: "Workbench",
    description:
      "Governed code/systems session that opens the selected code editor adapter.",
    kind: "workbench",
    surface_id: "workbench",
    required_inputs: [
      "project",
      "adapter_preference",
      "harness",
      "model_route",
      "privacy_posture",
    ],
    model_mount_policy: "inherit",
    harness_profile_policy: "select",
    authority_scope_templates: ["scope:workspace.read", "scope:workspace.patch"],
    privacy_posture_templates: ["public_trunk", "redacted_projection"],
    ...overrides,
  };
}

function targetBinding(overrides = {}) {
  return {
    schema_version: "ioi.hypervisor.new_session_target_binding.v1",
    target_binding_ref: "target-binding:new-session/workbench-default/ioi",
    recipe_ref: "workbench.default",
    target_kind: "workbench",
    surface_id: "workbench",
    project_ref: "project:ioi",
    operator_intent_ref:
      "target-binding:new-session/workbench.default/ioi/operator-intent",
    session_route_ref: "session-route:workbench/workbench-default/ioi",
    code_editor_adapter_target_ref: "code-editor-target:vscode",
    automation_recipe_ref: null,
    agent_template_ref: null,
    foundry_job_ref: null,
    provider_candidate_ref: null,
    environment_ref: null,
    private_workspace_ref: null,
    runtimeTruthSource: "daemon-runtime",
    ...overrides,
  };
}

function request(overrides = {}) {
  return {
    schema_version:
      "ioi.hypervisor.session_launch_recipe_admission_request.v1",
    recipe: recipe(),
    target_binding: targetBinding(),
    model_route_ref: "model-route:hypervisor/default-local",
    privacy_posture_ref: "privacy:redacted-projection",
    authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
    receipt_preview_ref: "receipt-preview:new-session/workbench",
    expected_receipt_refs: [
      "receipt-preview:new-session/workbench",
      "receipt-policy:harness-adapter/default",
    ],
    agentgres_operation_refs: [
      "agentgres://operation/hypervisor/session-launch-recipe/workbench",
    ],
    receipt_refs: ["receipt://hypervisor/session-launch-recipe/workbench"],
    state_root:
      "agentgres://state-root/hypervisor/session-launch-recipe/workbench",
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
    ...overrides,
  };
}

test("admits Hypervisor session launch recipes before harness binding", () => {
  const admission = admitHypervisorSessionLaunchRecipe(request(), {
    nowIso: () => "2026-06-19T12:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.admission_state, "admitted_for_session_binding");
  assert.equal(admission.recipe_ref, "workbench.default");
  assert.equal(admission.target_binding_ref, targetBinding().target_binding_ref);
  assert.equal(admission.session_route_ref, targetBinding().session_route_ref);
  assert.equal(admission.model_route_ref, "model-route:hypervisor/default-local");
  assert.deepEqual(admission.authority_scope_refs, [
    "scope:workspace.read",
    "scope:workspace.patch",
  ]);
  assert.equal(admission.requiresDaemonGate, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
});

test("blocks target bindings that do not match the selected recipe", () => {
  assert.throws(
    () =>
      admitHypervisorSessionLaunchRecipe(
        request({
          target_binding: targetBinding({
            recipe_ref: "agent.default",
            target_kind: "agent",
            surface_id: "agents",
          }),
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_session_launch_recipe_target_mismatch",
      );
      return true;
    },
  );
});

test("blocks workbench launch recipes without code editor adapter targets", () => {
  assert.throws(
    () =>
      admitHypervisorSessionLaunchRecipe(
        request({
          target_binding: targetBinding({
            code_editor_adapter_target_ref: null,
          }),
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_session_launch_recipe_workbench_adapter_required",
      );
      return true;
    },
  );
});

test("rejects retired camelCase aliases and authority primitive masquerades", () => {
  assert.throws(
    () => admitHypervisorSessionLaunchRecipe(request({ recipeRef: "legacy" })),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_session_launch_recipe_retired_aliases",
      );
      return true;
    },
  );

  assert.throws(
    () =>
      admitHypervisorSessionLaunchRecipe(
        request({ authority_scope_refs: ["prim:shell.exec"] }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_session_launch_recipe_ref_prefix_invalid",
      );
      return true;
    },
  );
});
