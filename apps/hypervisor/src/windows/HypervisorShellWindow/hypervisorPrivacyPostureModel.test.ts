import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_PATH,
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE,
  loadHypervisorPrivacyPostureProjection,
  normalizeHypervisorPrivacyPostureProjection,
} from "./hypervisorPrivacyPostureModel.ts";

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

test("privacy posture projection normalizes daemon projection source and refs", () => {
  const projection = normalizeHypervisorPrivacyPostureProjection({
    projection_id: "privacy-posture:daemon/test",
    project_ref: "project:ioi",
    selected_session_ref: "session:ioi",
    selected_privacy_ref: "privacy:ctee-private-workspace",
    default_model_route_ref: "model-route:hypervisor/default-local",
    invariant:
      "Daemon privacy posture separates workspace custody and model-weight custody.",
    workspace_segments: [
      {
        segment_ref: "workspace-segment:daemon/encrypted",
        label: "Daemon encrypted state",
        custody_class: "encrypted_blob_ref",
        node_plaintext_allowed: false,
        owner: "agentgres",
        evidence_refs: ["artifact://daemon/encrypted"],
      },
    ],
    model_weight_policies: [
      {
        lane: "forbidden_plaintext_mount",
        label: "No provider-readable weights",
        protects_workspace_state: true,
        protects_model_weights_from_provider_root: false,
        allowed_postures: ["ctee_split"],
        admission_summary: "Remote nodes receive no protected plaintext.",
        authority_scope_refs: ["scope:privacy.enforce_no_plaintext_custody"],
      },
    ],
    provider_candidates: [
      {
        candidate_ref: "provider-candidate:akash-gpu",
        label: "Akash GPU provider",
        posture: "ctee_split",
        model_weight_lane: "forbidden_plaintext_mount",
        provider_root_plaintext_risk: "bounded",
        admission_summary: "Public/redacted only.",
        receipt_ref: "receipt://privacy/akash",
      },
    ],
    admission_controls: [
      {
        control_ref: "privacy-control:daemon",
        label: "Daemon admission",
        owner: "hypervisor_daemon",
        blocks_unsafe_plaintext: true,
        receipt_ref: "receipt://privacy/daemon",
      },
    ],
    unsafe_mount_receipt_ref: "receipt://privacy/unsafe-mount-blocked/daemon",
  });

  assert.equal(projection.source, "daemon-privacy-posture-projection");
  assert.equal(projection.projection_id, "privacy-posture:daemon/test");
  assert.equal(projection.project_ref, "project:ioi");
  assert.equal(projection.selected_session_ref, "session:ioi");
  assert.equal(projection.workspace_segments[0]?.owner, "agentgres");
  assert.equal(projection.provider_candidates[0]?.posture, "ctee_split");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
});

test("privacy posture loader calls the daemon projection route", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorPrivacyPostureProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    sessionRef: "session:ioi",
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "privacy-posture:daemon/loaded",
            project_ref: "project:ioi",
            selected_session_ref: "session:ioi",
            workspace_segments: [],
            model_weight_policies: [],
            provider_candidates: [],
            admission_controls: [],
          });
        },
      };
    },
  });

  assert.equal(projection.projection_id, "privacy-posture:daemon/loaded");
  assert.equal(projection.source, "daemon-privacy-posture-projection");
  assert.equal(calls.length, 1);
  const url = new URL(calls[0]!.input);
  assert.equal(url.pathname, HYPERVISOR_PRIVACY_POSTURE_PROJECTION_PATH);
  assert.equal(url.searchParams.get("project_id"), "project:ioi");
  assert.equal(url.searchParams.get("session_ref"), "session:ioi");
  assert.equal(calls[0]!.method, "GET");
});
