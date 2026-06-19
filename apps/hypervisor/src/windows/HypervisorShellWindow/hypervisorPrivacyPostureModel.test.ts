import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHypervisorPrivateWorkspaceMountAdmissionRequest,
  buildHypervisorModelWeightCustodyAdmissionRequest,
  HYPERVISOR_MODEL_WEIGHT_CUSTODY_ADMISSION_PATH,
  HYPERVISOR_PRIVATE_WORKSPACE_MOUNT_ADMISSION_PATH,
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_PATH,
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE,
  loadHypervisorPrivacyPostureProjection,
  modelWeightCustodyAdmissionAction,
  normalizeHypervisorPrivateWorkspaceMountAdmission,
  normalizeHypervisorPrivacyPostureProjection,
  requestHypervisorModelWeightCustodyAdmission,
  requestHypervisorPrivateWorkspaceMountAdmission,
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

test("model-weight custody admission builder maps safe lanes to daemon requests", () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const remoteApi = projection.model_weight_policies.find(
    (policy) => policy.lane === "remote_api_capability",
  )!;
  const local = projection.model_weight_policies.find(
    (policy) => policy.lane === "open_or_local_weights",
  )!;

  assert.equal(modelWeightCustodyAdmissionAction(remoteApi).state, "daemon_admissible");
  assert.equal(modelWeightCustodyAdmissionAction(local).state, "daemon_admissible");

  const remoteRequest = buildHypervisorModelWeightCustodyAdmissionRequest(
    projection,
    remoteApi,
  );
  assert.equal(remoteRequest.weight_class, "remote_api_private_weight");
  assert.equal(remoteRequest.mount_target, "provider_api");
  assert.equal(remoteRequest.execution_privacy_posture, "remote_api_provider_trust");
  assert.equal(remoteRequest.remote_provider_can_read_weights, false);
  assert.deepEqual(remoteRequest.required_controls, [
    "wallet_authorized_api_capability",
  ]);
  assert.deepEqual(remoteRequest.authority_scope_refs, [
    "scope:model.invoke_remote",
  ]);

  const localRequest = buildHypervisorModelWeightCustodyAdmissionRequest(
    projection,
    local,
  );
  assert.equal(localRequest.weight_class, "user_local_private_weight");
  assert.equal(localRequest.mount_target, "local_device");
  assert.equal(localRequest.execution_privacy_posture, "private_native");
  assert.deepEqual(localRequest.required_controls, ["local_only"]);
});

test("model-weight custody admission action blocks unsafe lanes in the client", async () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const providerTrust = projection.model_weight_policies.find(
    (policy) => policy.lane === "provider_trust_mount",
  )!;
  const tee = projection.model_weight_policies.find(
    (policy) => policy.lane === "tee_or_customer_cloud_mount",
  )!;
  const forbidden = projection.model_weight_policies.find(
    (policy) => policy.lane === "forbidden_plaintext_mount",
  )!;

  assert.equal(
    modelWeightCustodyAdmissionAction(providerTrust).state,
    "wallet_step_up_required",
  );
  assert.equal(modelWeightCustodyAdmissionAction(tee).state, "attestation_required");
  assert.equal(modelWeightCustodyAdmissionAction(forbidden).state, "blocked");

  await assert.rejects(
    () =>
      requestHypervisorModelWeightCustodyAdmission(projection, providerTrust, {
        endpoint: "http://daemon.test",
        fetchImpl: async () => {
          throw new Error("fetch should not be called");
        },
      }),
    /Provider-trust mounts require wallet disclosure/,
  );
});

test("model-weight custody admission client posts canonical request to daemon", async () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const remoteApi = projection.model_weight_policies.find(
    (policy) => policy.lane === "remote_api_capability",
  )!;
  const calls: Array<{ input: string; method?: string; body?: unknown }> = [];

  const admission = await requestHypervisorModelWeightCustodyAdmission(
    projection,
    remoteApi,
    {
      endpoint: "http://daemon.test/",
      fetchImpl: async (input, init) => {
        calls.push({
          input,
          method: init?.method,
          body: init?.body ? JSON.parse(init.body) : null,
        });
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              schema_version: "ioi.runtime.model_weight_custody_admission.v1",
              admission_id: "model-weight-custody-admission:remote-api",
              route_ref: "model-route:hypervisor/default-local",
              model_ref: "model:hypervisor/default-local",
              provider_ref: "provider:remote-api",
              decision: "admitted",
              weight_class: "remote_api_private_weight",
              mount_target: "provider_api",
              execution_privacy_posture: "remote_api_provider_trust",
              remote_provider_can_read_weights: false,
              protects_model_weights_from_provider_root: true,
              protects_workspace_state: false,
              required_controls: ["wallet_authorized_api_capability"],
              authority_scope_refs: ["scope:model.invoke_remote"],
              agentgres_operation_refs: ["agentgres://operation/privacy-posture/test"],
              artifact_refs: ["artifact://privacy-posture/test"],
              receipt_ref: "receipt://model-weight-custody/remote-api",
              admitted_at: "2026-06-19T00:00:00.000Z",
              runtimeTruthSource: "daemon-runtime",
            });
          },
        };
      },
    },
  );

  assert.equal(admission.admission_id, "model-weight-custody-admission:remote-api");
  assert.equal(admission.weight_class, "remote_api_private_weight");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.equal(calls.length, 1);
  const url = new URL(calls[0]!.input);
  assert.equal(url.pathname, HYPERVISOR_MODEL_WEIGHT_CUSTODY_ADMISSION_PATH);
  assert.equal(calls[0]!.method, "POST");
  assert.deepEqual(calls[0]!.body, {
    route_ref: "model-route:hypervisor/default-local",
    model_ref: "model:hypervisor/default-local",
    provider_ref: "provider:remote-api",
    weight_class: "remote_api_private_weight",
    mount_target: "provider_api",
    execution_privacy_posture: "remote_api_provider_trust",
    remote_provider_can_read_weights: false,
    required_controls: ["wallet_authorized_api_capability"],
    authority_scope_refs: ["scope:model.invoke_remote"],
    agentgres_operation_refs: [
      "agentgres://operation/privacy-posture/privacy-posture_hypervisor-core_default",
    ],
    artifact_refs: [
      "artifact://privacy-posture/privacy-posture_hypervisor-core_default",
    ],
  });
});

test("private workspace mount admission builder maps custody segments to daemon requests", () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const publicTrunk = projection.workspace_segments.find(
    (segment) => segment.custody_class === "public_trunk",
  )!;
  const encryptedRefs = projection.workspace_segments.find(
    (segment) => segment.custody_class === "encrypted_blob_ref",
  )!;
  const privateHead = projection.workspace_segments.find(
    (segment) => segment.custody_class === "private_head",
  )!;
  const capabilityExit = projection.workspace_segments.find(
    (segment) => segment.custody_class === "capability_exit",
  )!;

  const publicRequest = buildHypervisorPrivateWorkspaceMountAdmissionRequest(
    projection,
    publicTrunk,
  );
  assert.equal(publicRequest.custody_class, "public_trunk");
  assert.equal(publicRequest.provider_root_can_read_plaintext, true);
  assert.equal(publicRequest.protected_plaintext_requested, false);

  const encryptedRequest = buildHypervisorPrivateWorkspaceMountAdmissionRequest(
    projection,
    encryptedRefs,
  );
  assert.equal(encryptedRequest.custody_class, "encrypted_blob_ref");
  assert.equal(encryptedRequest.provider_root_can_read_plaintext, false);
  assert.deepEqual(encryptedRequest.required_controls, [
    "encrypted_blob_refs_only",
  ]);

  const privateHeadRequest = buildHypervisorPrivateWorkspaceMountAdmissionRequest(
    projection,
    privateHead,
  );
  assert.equal(privateHeadRequest.custody_class, "private_head");
  assert.equal(privateHeadRequest.mount_target, "rented_gpu");
  assert.equal(privateHeadRequest.execution_privacy_posture, "ctee_split");
  assert.equal(privateHeadRequest.provider_root_can_read_plaintext, false);
  assert.deepEqual(privateHeadRequest.required_controls, [
    "ctee_private_head_handle",
  ]);
  assert.deepEqual(privateHeadRequest.authority_scope_refs, [
    "scope:ctee.private-head.evaluate",
  ]);

  const teeRequest = buildHypervisorPrivateWorkspaceMountAdmissionRequest(
    projection,
    privateHead,
    {
      teeAttestationRef: "attestation://confidential-gpu/session",
    },
  );
  assert.equal(teeRequest.mount_target, "tee_session");
  assert.equal(teeRequest.execution_privacy_posture, "confidential_compute");
  assert.equal(teeRequest.protected_plaintext_requested, true);
  assert.deepEqual(teeRequest.required_controls, ["tee_attestation"]);

  const capabilityRequest = buildHypervisorPrivateWorkspaceMountAdmissionRequest(
    projection,
    capabilityExit,
  );
  assert.equal(capabilityRequest.custody_class, "capability_exit");
  assert.deepEqual(capabilityRequest.required_controls, ["capability_exit_only"]);
  assert.deepEqual(capabilityRequest.authority_scope_refs, [
    "scope:capability.use",
  ]);
});

test("private workspace mount admission client posts canonical request to daemon", async () => {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const privateHead = projection.workspace_segments.find(
    (segment) => segment.custody_class === "private_head",
  )!;
  const calls: Array<{ input: string; method?: string; body?: unknown }> = [];

  const admission = await requestHypervisorPrivateWorkspaceMountAdmission(
    projection,
    privateHead,
    {
      endpoint: "http://daemon.test/",
      fetchImpl: async (input, init) => {
        calls.push({
          input,
          method: init?.method,
          body: init?.body ? JSON.parse(init.body) : null,
        });
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              schema_version: "ioi.runtime.private_workspace_mount_admission.v1",
              admission_id: "private-workspace-mount-admission:ctee-head",
              decision: "admitted_declassification",
              workspace_ref: "workspace://ioi",
              mount_ref: "mount://workspace-segment_private-head",
              segment_ref: "workspace-segment:private-head",
              provider_ref: "provider:rented-gpu",
              custody_class: "private_head",
              mount_target: "rented_gpu",
              execution_privacy_posture: "ctee_split",
              provider_root_can_read_plaintext: false,
              protected_plaintext_requested: false,
              protected_plaintext_exposed_to_provider_root: false,
              protects_workspace_plaintext_from_provider_root: true,
              required_controls: ["ctee_private_head_handle"],
              authority_scope_refs: ["scope:ctee.private-head.evaluate"],
              agentgres_operation_refs: [
                "agentgres://operation/privacy-mount/test",
              ],
              artifact_refs: ["artifact://workspace/private-head-commitment"],
              state_root_ref: "agentgres://state-root/project_ioi",
              receipt_ref: "receipt://private-workspace-mount/ctee-head",
              admitted_at: "2026-06-19T00:00:00.000Z",
              runtimeTruthSource: "daemon-runtime",
            });
          },
        };
      },
    },
  );

  assert.equal(admission.admission_id, "private-workspace-mount-admission:ctee-head");
  assert.equal(admission.decision, "admitted_declassification");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.equal(calls.length, 1);
  const url = new URL(calls[0]!.input);
  assert.equal(url.pathname, HYPERVISOR_PRIVATE_WORKSPACE_MOUNT_ADMISSION_PATH);
  assert.equal(calls[0]!.method, "POST");
  assert.deepEqual(calls[0]!.body, {
    workspace_ref: "workspace://ioi",
    mount_ref: "mount://workspace-segment_private-head",
    segment_ref: "workspace-segment:private-head",
    provider_ref: "provider:rented-gpu",
    custody_class: "private_head",
    mount_target: "rented_gpu",
    execution_privacy_posture: "ctee_split",
    provider_root_can_read_plaintext: false,
    protected_plaintext_requested: false,
    required_controls: ["ctee_private_head_handle"],
    authority_scope_refs: ["scope:ctee.private-head.evaluate"],
    agentgres_operation_refs: [
      "agentgres://operation/privacy-mount/privacy-posture_hypervisor-core_default",
    ],
    artifact_refs: ["artifact://privacy-mount/workspace-segment_private-head"],
    state_root_ref: "agentgres://state-root/project_ioi",
  });
});

test("private workspace mount admission normalizer preserves unsafe exception receipts", () => {
  const admission = normalizeHypervisorPrivateWorkspaceMountAdmission({
    schema_version: "ioi.runtime.private_workspace_mount_admission.v1",
    admission_id: "private-workspace-mount-admission:unsafe",
    decision: "admitted_unsafe_exception",
    workspace_ref: "workspace://ioi",
    mount_ref: "mount://unsafe",
    segment_ref: "workspace-segment:private-head",
    provider_ref: "provider:rented-gpu",
    custody_class: "unsafe_plaintext_mount",
    mount_target: "rented_gpu",
    execution_privacy_posture: "unsafe_plaintext_mount",
    provider_root_can_read_plaintext: true,
    protected_plaintext_requested: true,
    protected_plaintext_exposed_to_provider_root: true,
    protects_workspace_plaintext_from_provider_root: false,
    required_controls: ["explicit_unsafe_plaintext_acceptance"],
    authority_scope_refs: ["scope:privacy.unsafe_plaintext_mount"],
    wallet_approval_ref: "approval://wallet/privacy/unsafe-mount",
    wallet_lease_ref: "lease:wallet/privacy/unsafe-mount",
    user_disclosure_ref: "disclosure://privacy/unsafe-mount",
    provider_trust_acceptance_ref: "approval://provider-trust/unsafe-mount",
    declassification_receipt_refs: [
      "receipt://privacy/declassification/unsafe-mount",
    ],
    agentgres_operation_refs: ["agentgres://operation/privacy-mount/unsafe"],
    artifact_refs: ["artifact://workspace/private-head-unsafe"],
    state_root_ref: "agentgres://state-root/workspace/ioi",
    receipt_ref: "receipt://private-workspace-mount/unsafe",
    admitted_at: "2026-06-19T00:00:00.000Z",
    runtimeTruthSource: "daemon-runtime",
  });

  assert.equal(admission.decision, "admitted_unsafe_exception");
  assert.equal(admission.protected_plaintext_exposed_to_provider_root, true);
  assert.equal(admission.protects_workspace_plaintext_from_provider_root, false);
  assert.deepEqual(admission.declassification_receipt_refs, [
    "receipt://privacy/declassification/unsafe-mount",
  ]);
});
