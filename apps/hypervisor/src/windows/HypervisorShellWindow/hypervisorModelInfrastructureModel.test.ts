import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHypervisorModelInfrastructureProjectionFromInventory,
  HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE,
  HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH,
  loadHypervisorModelInfrastructureProjection,
  normalizeHypervisorModelInfrastructureProjection,
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
