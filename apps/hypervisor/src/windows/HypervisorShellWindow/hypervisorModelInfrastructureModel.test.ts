import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHypervisorModelRouteMutationAdmissionRequest,
  buildHypervisorModelInfrastructureProjectionFromInventory,
  HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE,
  HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH,
  HYPERVISOR_MODEL_ROUTE_MUTATION_ADMISSION_PATH,
  loadHypervisorModelInfrastructureProjection,
  normalizeHypervisorModelRouteMutationAdmission,
  normalizeHypervisorModelInfrastructureProjection,
  requestHypervisorModelRouteMutationAdmission,
} from "./hypervisorModelInfrastructureModel.ts";

test("model infrastructure projection binds routes, providers, custody, and receipts", () => {
  const projection = HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.model_infrastructure_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.infrastructure_boundary_invariant, /Models is an infrastructure projection/);
  assert.match(projection.infrastructure_boundary_invariant, /Hypervisor Core admits execution/);
  assert.match(projection.infrastructure_boundary_invariant, /Agentgres records model-route truth/);
  assert.equal(projection.inventory_source, "fixture");
  assert.ok(projection.model_route_refs.length >= 1);
  assert.ok(projection.endpoint_refs.length >= 1);
  assert.ok(projection.loaded_instance_refs.length >= 1);
  assert.ok(projection.provider_refs.length >= 1);
  assert.ok(projection.model_weight_custody_policy_refs.length >= 1);
  assert.ok(projection.latest_receipt_refs.length >= 1);
});

test("model infrastructure builds from model mount inventory without treating UI as truth", () => {
  const projection = buildHypervisorModelInfrastructureProjectionFromInventory(
    {
      schema_version: "ioi.hypervisor.model_mount_inventory_snapshot.v1",
      source: "daemon-model-mount-inventory",
      checked_at: "2026-06-17T00:00:00.000Z",
      routes: [
        {
          id: "model-route:custom/default",
          role: "default",
          status: "active",
          privacy: "local",
        },
      ],
      endpoints: [
        {
          id: "model-endpoint:custom/default",
          providerId: "provider:custom-local",
          modelId: "model:custom",
          status: "mounted",
          privacyClass: "local",
        },
      ],
      loadedInstances: [
        {
          id: "model-instance:custom/default",
          endpointId: "model-endpoint:custom/default",
          providerId: "provider:custom-local",
          modelId: "model:custom",
          status: "loaded",
        },
      ],
    },
    {
      selectedProjectId: "project:ioi",
      selectedSessionRef: "session:ioi",
      source: "daemon-model-infrastructure-projection",
    },
  );

  assert.equal(projection.source, "daemon-model-infrastructure-projection");
  assert.equal(projection.inventory_source, "daemon-model-mount-inventory");
  assert.equal(projection.selected_project_id, "project:ioi");
  assert.equal(projection.selected_session_ref, "session:ioi");
  assert.equal(projection.routes[0]?.route_ref, "model-route:custom/default");
  assert.equal(projection.routes[0]?.provider_ref, "provider:custom-local");
  assert.equal(
    projection.routes[0]?.model_weight_custody_lane,
    "local_or_open_weight",
  );
  assert.equal(
    projection.session_bindings[0]?.selected_model_route_ref,
    "model-route:custom/default",
  );
  assert.equal(
    projection.session_bindings[0]?.selected_endpoint_ref,
    "model-endpoint:custom/default",
  );
});

test("model infrastructure normalization preserves daemon projection fields", () => {
  const projection = normalizeHypervisorModelInfrastructureProjection(
    {
      projection_id: "model-infrastructure:daemon/normalized",
      selected_project_id: "project:daemon",
      selected_session_ref: "session:daemon",
      infrastructure_boundary_invariant:
        "Core projection; Models only renders evidence.",
      inventory_source: "daemon-model-mount-inventory",
      checked_at: "2026-06-17T00:00:00.000Z",
      model_route_refs: ["model-route:daemon"],
      endpoint_refs: ["endpoint:daemon"],
      loaded_instance_refs: ["instance:daemon"],
      provider_refs: ["provider:daemon"],
      routes: [
        {
          route_ref: "model-route:daemon",
          role: "default",
          status: "active",
          privacy_posture: "local",
          provider_ref: "provider:daemon",
          endpoint_refs: ["endpoint:daemon"],
          loaded_instance_refs: ["instance:daemon"],
          model_weight_custody_lane: "local_or_open_weight",
          authority_scope_refs: ["scope:model.invoke"],
          receipt_refs: ["receipt://model/daemon"],
        },
      ],
      providers: [
        {
          provider_ref: "provider:daemon",
          label: "Core provider",
          provider_kind: "local",
          privacy_posture: "local",
          credential_scope_refs: ["scope:secret.use"],
          receipt_ref: "receipt://provider/daemon",
        },
      ],
      session_bindings: [
        {
          session_ref: "session:daemon",
          selected_model_route_ref: "model-route:daemon",
          selected_endpoint_ref: "endpoint:daemon",
          selected_instance_ref: "instance:daemon",
          custody_profile_ref: "custody-profile:model/local",
          policy_ref: "policy:model-route/daemon",
          receipt_ref: "receipt://model/daemon",
        },
      ],
      model_weight_custody_policy_refs: [
        "model-weight-custody:local_or_open_weight",
      ],
      latest_receipt_refs: ["receipt://model/daemon"],
    },
    { source: "daemon-model-infrastructure-projection" },
  );

  assert.equal(projection.source, "daemon-model-infrastructure-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "model-infrastructure:daemon/normalized");
  assert.equal(projection.selected_session_ref, "session:daemon");
  assert.equal(projection.routes[0]?.route_ref, "model-route:daemon");
  assert.equal(projection.providers[0]?.provider_kind, "local");
  assert.doesNotMatch(
    JSON.stringify(projection.providers.map((provider) => provider.label)),
    /Daemon provider|runtime truth/i,
  );
  assert.equal(
    projection.session_bindings[0]?.custody_profile_ref,
    "custody-profile:model/local",
  );
  assert.deepEqual(projection.latest_receipt_refs, ["receipt://model/daemon"]);
});

test("model infrastructure loader calls daemon projection route with project and session", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorModelInfrastructureProjection({
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
            projection_id: "model-infrastructure:daemon/loaded",
            selected_project_id: "project:ioi",
            selected_session_ref: "session:ioi",
            model_route_refs: ["model-route:loaded"],
            endpoint_refs: ["endpoint:loaded"],
            loaded_instance_refs: ["instance:loaded"],
            provider_refs: ["provider:loaded"],
          });
        },
      };
    },
  });

  assert.deepEqual(calls, [
    {
      input:
        `http://daemon.test${HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH}?project_id=project%3Aioi&session_ref=session%3Aioi`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-model-infrastructure-projection");
  assert.equal(projection.projection_id, "model-infrastructure:daemon/loaded");
  assert.equal(projection.selected_project_id, "project:ioi");
  assert.equal(projection.selected_session_ref, "session:ioi");
  assert.deepEqual(projection.model_route_refs, ["model-route:loaded"]);
});

test("model route mutation builder maps selected route to daemon admission request", () => {
  const projection = HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE;
  const route = projection.routes[0]!;
  const request = buildHypervisorModelRouteMutationAdmissionRequest(
    projection,
    route,
  );

  assert.equal(request.mutation_kind, "bind_session_route");
  assert.equal(request.route_ref, route.route_ref);
  assert.equal(request.project_ref, projection.selected_project_id);
  assert.equal(request.session_ref, projection.selected_session_ref);
  assert.equal(request.provider_ref, route.provider_ref);
  assert.ok(request.authority_scope_refs.includes("scope:model.route.mutate"));
  assert.match(
    request.model_weight_custody_admission_ref ?? "",
    /^model-weight-custody-admission:/,
  );
  assert.match(request.privacy_posture_ref ?? "", /^privacy-posture:/);
  assert.ok(request.agentgres_operation_refs[0]?.startsWith("agentgres://operation/model-route/"));
  assert.ok(request.receipt_refs[0]?.startsWith("receipt://model-route/"));
  assert.ok(request.state_root_ref.startsWith("agentgres://state-root/model-route/"));
});

test("model route mutation builder marks hosted/provider-trust routes as credential leased", () => {
  const projection = buildHypervisorModelInfrastructureProjectionFromInventory(
    {
      schema_version: "ioi.hypervisor.model_mount_inventory_snapshot.v1",
      source: "daemon-model-mount-inventory",
      checked_at: "2026-06-18T00:00:00.000Z",
      routes: [
        {
          id: "model-route:hosted/default",
          role: "default",
          status: "active",
          privacy: "provider_trust",
        },
      ],
      endpoints: [
        {
          id: "model-endpoint:hosted/default",
          providerId: "provider:hosted-api",
          modelId: "model:hosted",
          status: "mounted",
          privacyClass: "provider_trust",
        },
      ],
      loadedInstances: [],
    },
    { selectedProjectId: "project:ioi", selectedSessionRef: "session:ioi" },
  );
  const route = projection.routes[0]!;
  const provider = {
    provider_ref: route.provider_ref,
    label: "Hosted API",
    provider_kind: "provider_trust" as const,
    privacy_posture: "provider_trust",
    credential_scope_refs: ["scope:secret.use"],
    receipt_ref: "receipt://provider/hosted",
  };
  const request = buildHypervisorModelRouteMutationAdmissionRequest(
    projection,
    route,
    { provider },
  );

  assert.equal(request.credential_posture, "wallet_credential_lease");
  assert.equal(
    request.provider_credential_lease_ref,
    "lease:wallet/provider-credential/provider_hosted-api",
  );
  assert.deepEqual(request.credential_scope_refs, ["scope:secret.use"]);
  assert.equal(request.provider_root_receives_prompt_plaintext, true);
  assert.match(
    request.provider_trust_acceptance_ref ?? "",
    /^approval:\/\/provider-trust\/model-route\//,
  );
});

test("model route mutation admission client posts canonical request to daemon", async () => {
  const projection = HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE;
  const route = projection.routes[0]!;
  const calls: Array<{ input: string; body: unknown; method?: string }> = [];
  const admission = await requestHypervisorModelRouteMutationAdmission(
    projection,
    route,
    {
      endpoint: "http://daemon.test/",
      fetchImpl: async (input, init) => {
        calls.push({
          input,
          method: init?.method,
          body: JSON.parse(init?.body ?? "{}"),
        });
        return {
          ok: true,
          status: 202,
          async text() {
            return JSON.stringify({
              admission_id: "model-route-mutation-admission:test",
              mutation_kind: "bind_session_route",
              route_ref: route.route_ref,
              project_ref: projection.selected_project_id,
              session_ref: projection.selected_session_ref,
              provider_ref: route.provider_ref,
              provider_kind: "local",
              endpoint_refs: route.endpoint_refs,
              loaded_instance_refs: route.loaded_instance_refs,
              credential_posture: "no_credentials_required",
              authority_scope_refs: ["scope:model.route.mutate"],
              credential_scope_refs: [],
              wallet_approval_ref: "approval://wallet/model-route/test",
              wallet_lease_ref: "lease:wallet/model-route/test",
              agentgres_operation_refs: [
                "agentgres://operation/model-route/test",
              ],
              receipt_refs: ["receipt://model-route/test"],
              state_root_ref: "agentgres://state-root/model-route/test",
              admitted_at: "2026-06-18T00:00:00.000Z",
            });
          },
        };
      },
    },
  );

  assert.deepEqual(calls.map((call) => call.input), [
    `http://daemon.test${HYPERVISOR_MODEL_ROUTE_MUTATION_ADMISSION_PATH}`,
  ]);
  assert.equal(calls[0]?.method, "POST");
  assert.equal(
    (calls[0]?.body as { route_ref?: string }).route_ref,
    route.route_ref,
  );
  assert.equal(
    admission.schema_version,
    "ioi.runtime.model_route_mutation_admission.v1",
  );
  assert.equal(admission.admission_state, "admitted_for_model_router");
  assert.equal(admission.route_ref, route.route_ref);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
});

test("model route mutation admission normalizer preserves provider-trust refs", () => {
  const admission = normalizeHypervisorModelRouteMutationAdmission({
    admission_id: "model-route-mutation-admission:provider",
    route_ref: "model-route:provider/default",
    provider_ref: "provider:remote",
    provider_kind: "provider_trust",
    credential_posture: "wallet_credential_lease",
    provider_root_receives_prompt_plaintext: true,
    provider_credential_lease_ref: "lease:wallet/provider/remote",
    provider_trust_acceptance_ref:
      "approval://provider-trust/model-route/provider",
    agentgres_operation_refs: ["agentgres://operation/model-route/provider"],
    receipt_refs: ["receipt://model-route/provider"],
    state_root_ref: "agentgres://state-root/model-route/provider",
  });

  assert.equal(admission.provider_kind, "provider_trust");
  assert.equal(admission.provider_root_receives_prompt_plaintext, true);
  assert.equal(
    admission.provider_trust_acceptance_ref,
    "approval://provider-trust/model-route/provider",
  );
});
