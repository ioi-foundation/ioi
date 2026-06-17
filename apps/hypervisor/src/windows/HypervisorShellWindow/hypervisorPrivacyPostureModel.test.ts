import assert from "node:assert/strict";
import test from "node:test";

import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "./hypervisorPrivacyPostureModel.ts";

test("privacy posture projection separates workspace custody from model-weight custody", () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.execution_privacy_posture_projection.v1",
  );
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.invariant, /Model-weight custody is a separate admission lane/);
  assert.equal(
    projection.selected_privacy_ref,
    "privacy:ctee-private-workspace",
  );
  assert.equal(
    projection.default_model_route_ref,
    "model-route:hypervisor/default-local",
  );

  assert.ok(
    projection.workspace_segments.some(
      (segment) =>
        segment.custody_class === "encrypted_blob_ref" &&
        segment.node_plaintext_allowed === false &&
        segment.owner === "agentgres",
    ),
  );
  assert.ok(
    projection.workspace_segments.some(
      (segment) =>
        segment.custody_class === "capability_exit" &&
        segment.owner === "wallet_network",
    ),
  );

  const remoteApiLane = projection.model_weight_policies.find(
    (policy) => policy.lane === "remote_api_capability",
  );
  assert.equal(remoteApiLane?.protects_model_weights_from_provider_root, true);
  assert.equal(remoteApiLane?.protects_workspace_state, false);

  const forbiddenMountLane = projection.model_weight_policies.find(
    (policy) => policy.lane === "forbidden_plaintext_mount",
  );
  assert.equal(forbiddenMountLane?.protects_workspace_state, true);
  assert.equal(
    forbiddenMountLane?.protects_model_weights_from_provider_root,
    false,
  );
  assert.match(
    forbiddenMountLane?.admission_summary ?? "",
    /must not receive protected workspace plaintext or proprietary weights/,
  );
});

test("privacy posture projection covers rented-node, storage, TEE, and API postures", () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const postures = new Set(
    projection.provider_candidates.map((candidate) => candidate.posture),
  );
  const lanes = new Set(
    projection.provider_candidates.map((candidate) => candidate.model_weight_lane),
  );

  assert.ok(postures.has("ctee_split"));
  assert.ok(postures.has("encrypted_storage_only"));
  assert.ok(postures.has("confidential_compute"));
  assert.ok(postures.has("private_native"));
  assert.ok(lanes.has("forbidden_plaintext_mount"));
  assert.ok(lanes.has("tee_or_customer_cloud_mount"));
  assert.ok(lanes.has("open_or_local_weights"));

  const akashCandidate = projection.provider_candidates.find(
    (candidate) => candidate.candidate_ref === "provider-candidate:akash-gpu",
  );
  assert.equal(akashCandidate?.posture, "ctee_split");
  assert.equal(akashCandidate?.model_weight_lane, "forbidden_plaintext_mount");
  assert.equal(akashCandidate?.provider_root_plaintext_risk, "bounded");

  const controls = new Set(
    projection.admission_controls.map((control) => control.owner),
  );
  assert.ok(controls.has("wallet_network"));
  assert.ok(controls.has("hypervisor_daemon"));
  assert.ok(controls.has("agentgres"));
  assert.ok(
    projection.admission_controls.every(
      (control) => control.blocks_unsafe_plaintext && control.receipt_ref,
    ),
  );
  assert.match(projection.unsafe_mount_receipt_ref, /unsafe-mount-blocked/);
});
