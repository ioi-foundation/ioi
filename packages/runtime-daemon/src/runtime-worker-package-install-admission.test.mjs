import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION,
  admitWorkerPackageInstall,
} from "./runtime-worker-package-install-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    install_id: "install://aiagent/carwash-prep/heath/default",
    worker_package_ref: "package://aiagent/robotics.carwash_prep@1",
    worker_manifest_ref: "manifest://aiagent/robotics.carwash_prep@1",
    owner_ref: "wallet://user/heath",
    install_mode: "managed_instance_initialization",
    base_ontology_ref: "ontology:aiagent.base.v1",
    vertical_pack_refs: ["vertical_pack:robotics.carwash_prep.v1"],
    integration_surface_refs: [
      "integration_surface:robotics_physical",
      "integration_surface:embodied_humanoid",
    ],
    primitive_capability_requirements: [
      "prim:physical.actuate",
      "prim:sensor.stream",
    ],
    authority_scope_requirements: [
      "scope:physical.actuate",
      "scope:worker.lifecycle",
    ],
    risk_classes: ["physical_action"],
    policy_profile_refs: [
      "policy://aiagent/worker-install",
      "policy://ctee/private-workspace",
    ],
    receipt_policy_ref: "receipt_policy://aiagent/worker-install",
    evidence_requirement_refs: [
      "evidence_requirement:physical.preflight.v1",
    ],
    benchmark_profile_refs: ["benchmark://aiagent/robotics.carwash_prep.v1"],
    runtime_profile: "private_workspace_ctee",
    persistence_profile: "zero_to_idle",
    memory_policy_ref: "policy://memory/worker-instance",
    archive_policy_ref: "policy://archive/worker-instance",
    package_artifact_refs: ["artifact://package/robotics.carwash-prep/v1"],
    wallet_approval_ref: "approval://wallet/worker-install/carwash",
    install_right_ref: "license://aiagent/install/carwash-prep",
    managed_instance_ref: "agent://carwash-prep/heath/default",
    physical_action_policy_refs: ["policy://physical/carwash-prep"],
    safety_envelope_refs: ["safety://carwash/bay-3"],
    emergency_stop_authority_refs: ["estop://carwash/bay-3"],
    agentgres_operation_refs: [
      "agentgres://operation/worker-install/carwash-prep",
    ],
    receipt_refs: ["receipt://worker-install/carwash-prep"],
    state_root: "state_root:worker-install:carwash-prep",
    ...overrides,
  };
}

test("admits ontology-bound worker package installs through daemon runtime truth", () => {
  const admission = admitWorkerPackageInstall(baseRequest(), {
    nowIso: () => "2026-06-17T19:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(
    admission.admission_id,
    "worker-package-install:install_aiagent_carwash-prep_heath_default:managed_instance_initialization",
  );
  assert.equal(admission.worker_package_ref, "package://aiagent/robotics.carwash_prep@1");
  assert.equal(admission.base_ontology_ref, "ontology:aiagent.base.v1");
  assert.equal(admission.runtime_profile, "private_workspace_ctee");
  assert.equal(admission.persistence_profile, "zero_to_idle");
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.requiresDaemonGate, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(admission.authority_scope_requirements, [
    "scope:physical.actuate",
    "scope:worker.lifecycle",
  ]);
});

test("requires ontology, integration surfaces, and package artifact refs", () => {
  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          base_ontology_ref: null,
        }),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "worker_package_install_base_ontology_ref_required");
      return true;
    },
  );

  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          integration_surface_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "worker_package_install_integration_surface_refs_required");
      return true;
    },
  );
});

test("blocks prim capabilities masquerading as authority scopes", () => {
  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          authority_scope_requirements: [
            "scope:worker.lifecycle",
            "prim:physical.actuate",
          ],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(
        error.code,
        "worker_package_install_primitive_scope_masquerade_blocked",
      );
      return true;
    },
  );
});

test("physical-action worker packages require safety policy refs", () => {
  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          physical_action_policy_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "worker_package_install_physical_action_policy_refs_required");
      return true;
    },
  );

  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          safety_envelope_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "worker_package_install_safety_envelope_refs_required");
      return true;
    },
  );
});

test("private workspace cTEE installs require explicit cTEE policy profile", () => {
  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          policy_profile_refs: ["policy://aiagent/worker-install"],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "worker_package_install_ctee_policy_required");
      return true;
    },
  );
});

test("blocks vertical packs from becoming bespoke runtime forks", () => {
  assert.throws(
    () =>
      admitWorkerPackageInstall(
        baseRequest({
          hardcoded_vertical_runtime: true,
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "worker_package_install_vertical_runtime_fork_blocked");
      return true;
    },
  );
});
