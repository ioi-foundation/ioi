import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_WEIGHT_CUSTODY_ADMISSION_SCHEMA_VERSION,
  admitModelWeightCustodyRoute,
} from "./runtime-model-weight-custody-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    route_ref: "model-route:hypervisor/default-local",
    model_ref: "model:local/qwen",
    provider_ref: "provider:local",
    weight_class: "public_open_weight",
    mount_target: "rented_gpu",
    execution_privacy_posture: "ctee_split",
    remote_provider_can_read_weights: false,
    required_controls: ["no_remote_plaintext_mount"],
    authority_scope_refs: ["scope:model.invoke"],
    agentgres_operation_refs: ["agentgres://operation/model-weight/admission"],
    artifact_refs: ["artifact://model-weight/admission"],
    ...overrides,
  };
}

test("admits public open weights on rented GPU without treating the provider as authority", () => {
  const admission = admitModelWeightCustodyRoute(baseRequest(), {
    nowIso: () => "2026-06-17T14:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    MODEL_WEIGHT_CUSTODY_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.weight_class, "public_open_weight");
  assert.equal(admission.mount_target, "rented_gpu");
  assert.equal(admission.execution_privacy_posture, "ctee_split");
  assert.equal(admission.protects_model_weights_from_provider_root, true);
  assert.equal(admission.protects_workspace_state, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.equal(
    admission.receipt_ref,
    "receipt://model-weight-custody/model-route_hypervisor_default-local/public_open_weight",
  );
});

test("blocks private weights readable by remote root unless provider trust is explicit", () => {
  assert.throws(
    () =>
      admitModelWeightCustodyRoute(
        baseRequest({
          weight_class: "user_local_private_weight",
          mount_target: "rented_gpu",
          execution_privacy_posture: "ctee_split",
          remote_provider_can_read_weights: true,
          required_controls: ["local_only"],
          authority_scope_refs: ["scope:model.local_mount"],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "model_weight_custody_plaintext_private_weight_blocked");
      return true;
    },
  );

  assert.throws(
    () =>
      admitModelWeightCustodyRoute(
        baseRequest({
          weight_class: "forbidden_plaintext_mount",
          mount_target: "rented_gpu",
          execution_privacy_posture: "unsafe_plaintext_mount",
          remote_provider_can_read_weights: true,
        }),
      ),
    (error) => {
      assert.equal(error.code, "model_weight_custody_forbidden_plaintext_mount_blocked");
      return true;
    },
  );
});

test("remote API private-weight route protects weights but not private prompts by itself", () => {
  const admission = admitModelWeightCustodyRoute(
    baseRequest({
      route_ref: "model-route:provider/api",
      model_ref: "model:provider/private",
      provider_ref: "provider:foundation-api",
      weight_class: "remote_api_private_weight",
      mount_target: "provider_api",
      execution_privacy_posture: "remote_api_provider_trust",
      remote_provider_can_read_weights: false,
      required_controls: ["wallet_authorized_api_capability"],
      authority_scope_refs: ["scope:model.invoke_remote"],
    }),
  );

  assert.equal(admission.decision, "admitted");
  assert.equal(admission.protects_model_weights_from_provider_root, true);
  assert.equal(admission.protects_workspace_state, false);
  assert.equal(admission.mount_target, "provider_api");
});

test("TEE or customer-cloud model-weight mounts require attestation or customer boundary", () => {
  assert.throws(
    () =>
      admitModelWeightCustodyRoute(
        baseRequest({
          weight_class: "tee_or_customer_cloud_mount",
          mount_target: "tee_session",
          execution_privacy_posture: "confidential_compute",
          required_controls: ["tee_attestation"],
          authority_scope_refs: ["scope:cloud.deploy", "scope:secret.release"],
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "model_weight_custody_attestation_or_customer_boundary_required",
      );
      return true;
    },
  );

  const admitted = admitModelWeightCustodyRoute(
    baseRequest({
      route_ref: "model-route:confidential/h100",
      model_ref: "model:org/private",
      provider_ref: "provider:customer-cloud",
      weight_class: "tee_or_customer_cloud_mount",
      mount_target: "tee_session",
      execution_privacy_posture: "confidential_compute",
      remote_provider_can_read_weights: false,
      required_controls: ["tee_attestation"],
      authority_scope_refs: ["scope:cloud.deploy", "scope:secret.release"],
      tee_attestation_ref: "attestation://confidential-gpu/session",
    }),
  );

  assert.equal(admitted.weight_class, "tee_or_customer_cloud_mount");
  assert.equal(admitted.protects_model_weights_from_provider_root, true);
  assert.equal(admitted.protects_workspace_state, true);
});

test("provider-trust mounts require disclosure, acceptance, and cannot claim private-native", () => {
  assert.throws(
    () =>
      admitModelWeightCustodyRoute(
        baseRequest({
          weight_class: "provider_trust_remote_mount",
          mount_target: "rented_gpu",
          execution_privacy_posture: "private_native",
          remote_provider_can_read_weights: true,
          required_controls: ["explicit_provider_trust_acceptance"],
          authority_scope_refs: ["scope:provider.trust_override"],
          user_disclosure_ref: "disclosure://provider-trust/private-weights",
          provider_trust_acceptance_ref: "approval://provider-trust/private-weights",
        }),
      ),
    (error) => {
      assert.equal(error.code, "model_weight_custody_private_native_claim_invalid");
      return true;
    },
  );

  assert.throws(
    () =>
      admitModelWeightCustodyRoute(
        baseRequest({
          weight_class: "provider_trust_remote_mount",
          mount_target: "rented_gpu",
          execution_privacy_posture: "unsafe_plaintext_mount",
          remote_provider_can_read_weights: true,
          required_controls: ["explicit_provider_trust_acceptance"],
          authority_scope_refs: ["scope:provider.trust_override"],
        }),
      ),
    (error) => {
      assert.equal(
        error.code,
        "model_weight_custody_provider_trust_acceptance_required",
      );
      return true;
    },
  );

  const admitted = admitModelWeightCustodyRoute(
    baseRequest({
      route_ref: "model-route:provider-trust/private-weight",
      model_ref: "model:org/private",
      provider_ref: "provider:rented-gpu",
      weight_class: "provider_trust_remote_mount",
      mount_target: "rented_gpu",
      execution_privacy_posture: "unsafe_plaintext_mount",
      remote_provider_can_read_weights: true,
      required_controls: ["explicit_provider_trust_acceptance"],
      authority_scope_refs: ["scope:provider.trust_override"],
      user_disclosure_ref: "disclosure://provider-trust/private-weights",
      provider_trust_acceptance_ref: "approval://provider-trust/private-weights",
    }),
  );

  assert.equal(admitted.decision, "admitted_provider_trust");
  assert.equal(admitted.protects_model_weights_from_provider_root, false);
  assert.equal(admitted.protects_workspace_state, false);
});

test("model-weight custody admission rejects retired camelCase request aliases", () => {
  assert.throws(
    () =>
      admitModelWeightCustodyRoute({
        ...baseRequest(),
        modelWeightCustodyProfile: "legacy",
        remoteProviderCanReadWeights: true,
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_weight_custody_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "modelWeightCustodyProfile",
        "remoteProviderCanReadWeights",
      ]);
      return true;
    },
  );
});
