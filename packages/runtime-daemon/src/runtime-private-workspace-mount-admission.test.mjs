import assert from "node:assert/strict";
import test from "node:test";

import {
  PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION,
  admitPrivateWorkspaceMount,
} from "./runtime-private-workspace-mount-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    workspace_ref: "workspace://ioi",
    mount_ref: "mount://workspace/public-trunk",
    segment_ref: "workspace-segment:public-trunk",
    provider_ref: "provider:akash/gpu-market",
    custody_class: "public_trunk",
    mount_target: "rented_gpu",
    execution_privacy_posture: "ctee_split",
    provider_root_can_read_plaintext: true,
    protected_plaintext_requested: false,
    required_controls: [],
    authority_scope_refs: [],
    agentgres_operation_refs: ["agentgres://operation/privacy/mount"],
    artifact_refs: ["artifact://workspace/public-trunk"],
    state_root_ref: "agentgres://state-root/workspace/ioi",
    ...overrides,
  };
}

test("admits public trunk mounts without treating provider-readable public bytes as private custody", () => {
  const admission = admitPrivateWorkspaceMount(baseRequest(), {
    nowIso: () => "2026-06-18T12:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.custody_class, "public_trunk");
  assert.equal(admission.provider_root_can_read_plaintext, true);
  assert.equal(admission.protected_plaintext_requested, false);
  assert.equal(admission.protected_plaintext_exposed_to_provider_root, false);
  assert.equal(admission.protects_workspace_plaintext_from_provider_root, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.equal(admission.admitted_at, "2026-06-18T12:00:00.000Z");
});

test("admits redacted projections and encrypted blob refs only with matching controls", () => {
  const redacted = admitPrivateWorkspaceMount(
    baseRequest({
      mount_ref: "mount://workspace/redacted",
      segment_ref: "workspace-segment:redacted-projection",
      custody_class: "redacted_projection",
      required_controls: ["redaction_verified"],
      artifact_refs: ["artifact://workspace/redacted-projection"],
    }),
  );

  assert.equal(redacted.custody_class, "redacted_projection");
  assert.equal(redacted.decision, "admitted");

  const encrypted = admitPrivateWorkspaceMount(
    baseRequest({
      mount_ref: "mount://workspace/encrypted",
      segment_ref: "workspace-segment:encrypted-agentgres-refs",
      custody_class: "encrypted_blob_ref",
      provider_root_can_read_plaintext: false,
      execution_privacy_posture: "encrypted_storage_only",
      required_controls: ["encrypted_blob_refs_only"],
      artifact_refs: ["artifact://agentgres/encrypted-workspace-blob"],
    }),
  );

  assert.equal(encrypted.custody_class, "encrypted_blob_ref");
  assert.equal(encrypted.protected_plaintext_exposed_to_provider_root, false);

  assert.throws(
    () =>
      admitPrivateWorkspaceMount(
        baseRequest({
          custody_class: "redacted_projection",
          required_controls: [],
        }),
      ),
    /required control/,
  );
});

test("admits cTEE private-head handles on rented GPUs without provider plaintext", () => {
  const admission = admitPrivateWorkspaceMount(
    baseRequest({
      mount_ref: "mount://workspace/private-head-handle",
      segment_ref: "workspace-segment:private-head",
      custody_class: "private_head",
      mount_target: "rented_gpu",
      execution_privacy_posture: "ctee_split",
      provider_root_can_read_plaintext: false,
      protected_plaintext_requested: false,
      required_controls: ["ctee_private_head_handle"],
      authority_scope_refs: ["scope:ctee.private-head.evaluate"],
      artifact_refs: ["artifact://workspace/private-head-commitment"],
    }),
  );

  assert.equal(admission.decision, "admitted_declassification");
  assert.equal(admission.custody_class, "private_head");
  assert.equal(admission.provider_root_can_read_plaintext, false);
  assert.equal(admission.protects_workspace_plaintext_from_provider_root, true);
});

test("admits local private-head mounts only through wallet decryption leases", () => {
  const admission = admitPrivateWorkspaceMount(
    baseRequest({
      mount_ref: "mount://workspace/private-head-local",
      segment_ref: "workspace-segment:private-head",
      provider_ref: "provider:local-device",
      custody_class: "private_head",
      mount_target: "local_device",
      execution_privacy_posture: "private_native",
      provider_root_can_read_plaintext: false,
      protected_plaintext_requested: true,
      required_controls: ["wallet_decryption_lease"],
      authority_scope_refs: ["scope:artifact.decrypt"],
      wallet_lease_ref: "lease:wallet/private-head/decrypt",
      artifact_refs: ["artifact://workspace/private-head-local"],
    }),
  );

  assert.equal(admission.decision, "admitted_declassification");
  assert.equal(admission.protected_plaintext_requested, true);
  assert.equal(admission.protected_plaintext_exposed_to_provider_root, false);

  assert.throws(
    () =>
      admitPrivateWorkspaceMount(
        baseRequest({
          custody_class: "private_head",
          mount_target: "local_device",
          provider_root_can_read_plaintext: false,
          protected_plaintext_requested: true,
          required_controls: [],
          authority_scope_refs: [],
        }),
      ),
    /wallet_decryption_lease/,
  );
});

test("TEE and customer-cloud private-head mounts require attestation or customer boundary", () => {
  assert.throws(
    () =>
      admitPrivateWorkspaceMount(
        baseRequest({
          custody_class: "private_head",
          mount_target: "tee_session",
          execution_privacy_posture: "confidential_compute",
          provider_root_can_read_plaintext: false,
          protected_plaintext_requested: true,
          required_controls: ["tee_attestation"],
        }),
      ),
    /attestation or a customer-boundary ref/,
  );

  const admitted = admitPrivateWorkspaceMount(
    baseRequest({
      custody_class: "private_head",
      mount_target: "tee_session",
      execution_privacy_posture: "confidential_compute",
      provider_root_can_read_plaintext: false,
      protected_plaintext_requested: true,
      required_controls: ["tee_attestation"],
      tee_attestation_ref: "attestation://confidential-gpu/session",
    }),
  );

  assert.equal(admitted.decision, "admitted_declassification");
  assert.equal(admitted.tee_attestation_ref, "attestation://confidential-gpu/session");
});

test("capability exits expose handles rather than private workspace plaintext", () => {
  const admission = admitPrivateWorkspaceMount(
    baseRequest({
      mount_ref: "mount://workspace/capability-exit",
      segment_ref: "workspace-segment:capability-exit",
      custody_class: "capability_exit",
      mount_target: "rented_gpu",
      execution_privacy_posture: "ctee_split",
      provider_root_can_read_plaintext: false,
      protected_plaintext_requested: false,
      required_controls: ["capability_exit_only"],
      authority_scope_refs: ["scope:capability.use"],
      artifact_refs: [],
    }),
  );

  assert.equal(admission.decision, "admitted");
  assert.equal(admission.custody_class, "capability_exit");
});

test("unsafe plaintext mounts require wallet approval and declassification receipts", () => {
  assert.throws(
    () =>
      admitPrivateWorkspaceMount(
        baseRequest({
          custody_class: "unsafe_plaintext_mount",
          mount_target: "rented_gpu",
          execution_privacy_posture: "unsafe_plaintext_mount",
          provider_root_can_read_plaintext: true,
          protected_plaintext_requested: true,
          required_controls: ["explicit_unsafe_plaintext_acceptance"],
          authority_scope_refs: ["scope:privacy.unsafe_plaintext_mount"],
          user_disclosure_ref: "disclosure://privacy/unsafe-mount",
          provider_trust_acceptance_ref: "approval://provider-trust/unsafe-mount",
        }),
      ),
    /wallet_approval_ref/,
  );

  const admitted = admitPrivateWorkspaceMount(
    baseRequest({
      custody_class: "unsafe_plaintext_mount",
      mount_target: "rented_gpu",
      execution_privacy_posture: "unsafe_plaintext_mount",
      provider_root_can_read_plaintext: true,
      protected_plaintext_requested: true,
      required_controls: ["explicit_unsafe_plaintext_acceptance"],
      authority_scope_refs: ["scope:privacy.unsafe_plaintext_mount"],
      wallet_approval_ref: "approval://wallet/privacy/unsafe-mount",
      wallet_lease_ref: "lease:wallet/privacy/unsafe-mount",
      user_disclosure_ref: "disclosure://privacy/unsafe-mount",
      provider_trust_acceptance_ref: "approval://provider-trust/unsafe-mount",
      declassification_receipt_refs: [
        "receipt://privacy/declassification/unsafe-mount",
      ],
      artifact_refs: ["artifact://workspace/private-head-unsafe"],
    }),
  );

  assert.equal(admitted.decision, "admitted_unsafe_exception");
  assert.equal(admitted.protected_plaintext_exposed_to_provider_root, true);
  assert.equal(admitted.protects_workspace_plaintext_from_provider_root, false);
  assert.equal(
    admitted.wallet_approval_ref,
    "approval://wallet/privacy/unsafe-mount",
  );
  assert.deepEqual(admitted.declassification_receipt_refs, [
    "receipt://privacy/declassification/unsafe-mount",
  ]);
});

test("rejects retired camelCase request aliases", () => {
  assert.throws(
    () =>
      admitPrivateWorkspaceMount({
        ...baseRequest(),
        workspaceMountProfile: "legacy",
        providerRootCanReadPlaintext: true,
        protectedPlaintextRequested: true,
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "private_workspace_mount_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "workspaceMountProfile",
        "providerRootCanReadPlaintext",
        "protectedPlaintextRequested",
      ]);
      return true;
    },
  );
});
