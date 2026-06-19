import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_ROUTE_MUTATION_ADMISSION_SCHEMA_VERSION,
  admitModelRouteMutation,
} from "./runtime-model-route-mutation-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    mutation_kind: "bind_session_route",
    route_ref: "model-route:local/default",
    project_ref: "project:ioi",
    session_ref: "session:ioi",
    provider_ref: "provider:local",
    provider_kind: "local",
    endpoint_refs: ["model-endpoint:local/default"],
    loaded_instance_refs: ["model-instance:local/default"],
    credential_posture: "no_credentials_required",
    provider_root_receives_prompt_plaintext: false,
    provider_root_receives_credential_plaintext: false,
    authority_scope_refs: ["scope:model.route.mutate"],
    credential_scope_refs: [],
    wallet_approval_ref: "approval://wallet/model-route/local",
    wallet_lease_ref: "lease:wallet/model-route/local",
    model_weight_custody_admission_ref:
      "model-weight-custody-admission:model-route_local_default",
    privacy_posture_ref: "privacy-posture:private-native",
    agentgres_operation_refs: [
      "agentgres://operation/model-route/local/bind-session",
    ],
    receipt_refs: ["receipt://model-route/local/bind-session"],
    state_root_ref: "agentgres://state-root/model-route/local",
    ...overrides,
  };
}

test("admits local model route binding after wallet and Agentgres refs are bound", () => {
  const admission = admitModelRouteMutation(baseRequest(), {
    nowIso: () => "2026-06-18T00:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    MODEL_ROUTE_MUTATION_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.admission_state, "admitted_for_model_router");
  assert.equal(admission.mutation_kind, "bind_session_route");
  assert.equal(admission.route_ref, "model-route:local/default");
  assert.equal(admission.provider_kind, "local");
  assert.equal(admission.credential_posture, "no_credentials_required");
  assert.deepEqual(admission.authority_scope_refs, [
    "scope:model.route.mutate",
  ]);
  assert.ok(
    admission.receipt_refs.includes(
      "receipt://model-route-mutation/model-route_local_default/bind_session_route",
    ),
  );
  assert.equal(admission.admitted_at, "2026-06-18T00:00:00.000Z");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
});

test("credentialed hosted API route requires secret scope and provider credential lease", () => {
  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          route_ref: "model-route:hosted/default",
          provider_ref: "provider:hosted-api",
          provider_kind: "hosted_api",
          endpoint_refs: ["model-endpoint:hosted/default"],
          credential_posture: "wallet_credential_lease",
          credential_scope_refs: [],
          provider_credential_lease_ref: null,
        }),
      ),
    /scope:secret.use/,
  );

  const admission = admitModelRouteMutation(
    baseRequest({
      route_ref: "model-route:hosted/default",
      provider_ref: "provider:hosted-api",
      provider_kind: "hosted_api",
      endpoint_refs: ["model-endpoint:hosted/default"],
      credential_posture: "wallet_credential_lease",
      credential_scope_refs: ["scope:secret.use"],
      provider_credential_lease_ref: "lease:wallet/provider/openai",
    }),
  );

  assert.equal(
    admission.provider_credential_lease_ref,
    "lease:wallet/provider/openai",
  );
  assert.deepEqual(admission.credential_scope_refs, ["scope:secret.use"]);
});

test("TEE, customer, and provider-trust routes require their matching boundary refs", () => {
  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          provider_ref: "provider:tee",
          provider_kind: "tee",
          endpoint_refs: ["model-endpoint:tee/default"],
        }),
      ),
    /attestation/,
  );

  assert.equal(
    admitModelRouteMutation(
      baseRequest({
        provider_ref: "provider:tee",
        provider_kind: "tee",
        endpoint_refs: ["model-endpoint:tee/default"],
        tee_attestation_ref: "attestation://tee/model-route",
      }),
    ).tee_attestation_ref,
    "attestation://tee/model-route",
  );

  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          provider_ref: "provider:customer-cloud",
          provider_kind: "customer",
          endpoint_refs: ["model-endpoint:customer/default"],
          credential_posture: "customer_boundary",
        }),
      ),
    /customer boundary/,
  );

  assert.equal(
    admitModelRouteMutation(
      baseRequest({
        provider_ref: "provider:customer-cloud",
        provider_kind: "customer",
        endpoint_refs: ["model-endpoint:customer/default"],
        credential_posture: "customer_boundary",
        credential_scope_refs: ["scope:secret.use"],
        customer_boundary_ref: "customer-boundary://org/model-route",
      }),
    ).customer_boundary_ref,
    "customer-boundary://org/model-route",
  );

  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          provider_ref: "provider:trust-me",
          provider_kind: "provider_trust",
          endpoint_refs: ["model-endpoint:trust/default"],
        }),
      ),
    /provider-trust acceptance/,
  );

  assert.equal(
    admitModelRouteMutation(
      baseRequest({
        provider_ref: "provider:trust-me",
        provider_kind: "provider_trust",
        endpoint_refs: ["model-endpoint:trust/default"],
        provider_trust_acceptance_ref: "approval://provider-trust/model-route",
      }),
    ).provider_trust_acceptance_ref,
    "approval://provider-trust/model-route",
  );
});

test("enabling or binding routes requires custody admission and privacy posture", () => {
  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({ model_weight_custody_admission_ref: null }),
      ),
    /model-weight custody admission/,
  );
  assert.throws(
    () =>
      admitModelRouteMutation(baseRequest({ privacy_posture_ref: null })),
    /privacy posture/,
  );

  const disabled = admitModelRouteMutation(
    baseRequest({
      mutation_kind: "disable_route",
      endpoint_refs: [],
      model_weight_custody_admission_ref: null,
      privacy_posture_ref: null,
    }),
  );
  assert.equal(disabled.mutation_kind, "disable_route");
  assert.deepEqual(disabled.endpoint_refs, []);
});

test("unsafe plaintext secret routes require explicit export scope and disclosure receipts", () => {
  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          credential_posture: "unsafe_plaintext_secret",
          provider_root_receives_credential_plaintext: true,
          credential_scope_refs: ["scope:secret.use"],
        }),
      ),
    /scope:secret.export/,
  );
  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          credential_posture: "unsafe_plaintext_secret",
          provider_root_receives_credential_plaintext: true,
          credential_scope_refs: ["scope:secret.export"],
          provider_trust_acceptance_ref: "approval://provider-trust/model-route",
        }),
      ),
    /secret disclosure receipts/,
  );
  assert.throws(
    () =>
      admitModelRouteMutation(
        baseRequest({
          credential_posture: "unsafe_plaintext_secret",
          provider_root_receives_credential_plaintext: true,
          credential_scope_refs: ["scope:secret.export"],
          secret_disclosure_receipt_refs: [
            "receipt://wallet/secret-disclosure/model-route",
          ],
        }),
      ),
    /provider-trust acceptance/,
  );

  const admission = admitModelRouteMutation(
    baseRequest({
      credential_posture: "unsafe_plaintext_secret",
      provider_root_receives_credential_plaintext: true,
      credential_scope_refs: ["scope:secret.export"],
      secret_disclosure_receipt_refs: [
        "receipt://wallet/secret-disclosure/model-route",
      ],
      provider_trust_acceptance_ref: "approval://provider-trust/model-route",
    }),
  );
  assert.equal(admission.provider_root_receives_credential_plaintext, true);
});

test("model route mutation admission rejects retired camelCase aliases", () => {
  assert.throws(
    () =>
      admitModelRouteMutation({
        ...baseRequest(),
        routeRef: "model-route:retired",
      }),
    /snake_case/,
  );
});
