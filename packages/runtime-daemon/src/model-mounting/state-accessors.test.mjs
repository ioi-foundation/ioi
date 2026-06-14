import assert from "node:assert/strict";
import test from "node:test";

import {
  endpoint,
  ensureLoaded,
  getModel,
  instance,
  modelForProviderMount,
  provider,
  resolveEndpoint,
  route,
} from "./state-accessors.mjs";

function fakeState() {
  return {
    endpoints: new Map([
      ["endpoint.active", { id: "endpoint.active", modelId: "llama-test", status: "mounted", load_policy: { mode: "on_demand" } }],
      ["endpoint.unmounted", { id: "endpoint.unmounted", modelId: "gone", status: "unmounted" }],
    ]),
    artifacts: new Map([
      ["artifact.local", { id: "artifact.local", modelId: "model.local", providerId: "provider.local" }],
    ]),
    instances: new Map(),
    providers: new Map([["provider.local", { id: "provider.local", kind: "openai", capabilities: ["chat"], privacyClass: "hosted_metered" }]]),
    routes: new Map([["route.local-first", { id: "route.local-first" }]]),
    artifactProjectionRows: [
      {
        id: "artifact.local",
        artifact_id: "artifact.local",
        model_id: "model.local",
        provider_id: "provider.local",
        artifact_endpoint_projection_boundary: "model_mount.artifact_endpoint_projection",
      },
    ],
    endpointProjectionRows: [
      {
        id: "endpoint.active",
        endpoint_id: "endpoint.active",
        model_id: "llama-test",
        status: "mounted",
        load_policy: { mode: "on_demand" },
        artifact_endpoint_projection_boundary: "model_mount.artifact_endpoint_projection",
      },
      {
        id: "endpoint.unmounted",
        endpoint_id: "endpoint.unmounted",
        model_id: "gone",
        status: "unmounted",
        artifact_endpoint_projection_boundary: "model_mount.artifact_endpoint_projection",
      },
    ],
    instanceProjectionRows: [],
    routeProjectionRows: [
      {
        id: "route.local-first",
        route_id: "route.local-first",
        route_projection_boundary: "model_mount.route_control_projection",
      },
    ],
    evictions: 0,
    artifactProjectionReads: 0,
    endpointProjectionReads: 0,
    instanceProjectionReads: 0,
    providerProjectionReads: 0,
    routeProjectionReads: 0,
    loadedLookups: [],
    loadCalls: [],
    mounted: [],
    now: "2026-06-04T04:00:00.000Z",
    recordStateCommits: [],
    writes: [],
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
        admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
      };
    },
    endpoint(endpointId) {
      return endpoint(this, endpointId, { notFound: deps.notFound });
    },
    evictExpiredInstances() {
      this.evictions += 1;
    },
    loadedInstanceForEndpoint(endpointId, failIfMissing) {
      this.loadedLookups.push([endpointId, failIfMissing]);
      return this.listInstances().find(
        (candidate) => (candidate.endpointId ?? candidate.endpoint_id) === endpointId && candidate.status === "loaded",
      ) ?? null;
    },
    loadModel(body) {
      this.loadCalls.push(body);
      return { id: "instance.loaded.new", endpointId: body.endpoint_id, status: "loaded" };
    },
    listArtifacts() {
      this.artifactProjectionReads += 1;
      return this.artifactProjectionRows.map((record) => ({ ...record }));
    },
    listEndpoints() {
      this.endpointProjectionReads += 1;
      return this.endpointProjectionRows.map((record) => ({ ...record }));
    },
    listInstances() {
      this.instanceProjectionReads += 1;
      return this.instanceProjectionRows.map((record) => ({ ...record }));
    },
    listProviders() {
      this.providerProjectionReads += 1;
      return [{
        id: "provider.local",
        provider_id: "provider.local",
        provider_ref: "provider://local",
        kind: "openai",
        capabilities: ["chat"],
        privacy_class: "hosted_metered",
        provider_projection_boundary: "model_mount.provider_control_projection",
        evidence_refs: [
          "rust_daemon_core_provider_control_projection",
          "agentgres_provider_control_truth_required",
          "model_mount_provider_map_lookup_js_retired",
        ],
      }];
    },
    listRoutes() {
      this.routeProjectionReads += 1;
      return this.routeProjectionRows.map((record) => ({ ...record }));
    },
    mountEndpoint(body) {
      const record = { id: `endpoint.mounted.${body.model_id}`, modelId: body.model_id, status: "mounted" };
      this.mounted.push(body);
      this.endpoints.set(record.id, record);
      return record;
    },
    nowIso() {
      return this.now;
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
  };
}

const deps = {
  expiresAt(now, loadPolicy) {
    return loadPolicy?.mode === "resident" ? null : "2026-06-04T04:05:00.000Z";
  },
  notFound(message, details) {
    const error = new Error(message);
    error.status = 404;
    error.details = details;
    return error;
  },
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  normalizeScopes(scopes, fallback) {
    return scopes ?? fallback;
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, ".").toLowerCase();
  },
};

function hasCanonicalNotFoundDetail(error, key, value, retiredKey) {
  assert.equal(error.status, 404);
  assert.equal(error.details[key], value);
  assert.equal(Object.hasOwn(error.details, retiredKey), false);
  return true;
}

test("state lookup accessors return records and fail closed", () => {
  const state = fakeState();

  assert.equal(provider(state, "provider.local", deps).id, "provider.local");
  assert.equal(provider(state, "provider://local", deps).provider_id, "provider.local");
  assert.equal(state.providerProjectionReads, 2);
  assert.equal(endpoint(state, "endpoint.active", deps).id, "endpoint.active");
  assert.equal(route(state, "route.local-first", deps).id, "route.local-first");

  state.instanceProjectionRows.push({ id: "instance.1", status: "loaded" });
  assert.equal(instance(state, "instance.1", deps).id, "instance.1");

  assert.throws(
    () => provider(state, "missing", deps),
    (error) => hasCanonicalNotFoundDetail(error, "provider_id", "missing", "providerId"),
  );
  assert.equal(state.providerProjectionReads, 3);
  assert.throws(
    () => endpoint(state, "endpoint.unmounted", deps),
    (error) => hasCanonicalNotFoundDetail(error, "endpoint_id", "endpoint.unmounted", "endpointId"),
  );
  assert.throws(
    () => instance(state, "missing", deps),
    (error) => hasCanonicalNotFoundDetail(error, "instance_id", "missing", "instanceId"),
  );
  assert.throws(
    () => route(state, "missing", deps),
    (error) => hasCanonicalNotFoundDetail(error, "route_id", "missing", "routeId"),
  );
});

test("provider accessor uses Rust provider projection rather than JS provider map", () => {
  const state = fakeState();
  state.providers.set("provider.map-only", {
    id: "provider.map-only",
    kind: "custom_http",
  });

  assert.equal(provider(state, "provider.local", deps).provider_projection_boundary, "model_mount.provider_control_projection");
  assert.throws(
    () => provider(state, "provider.map-only", deps),
    (error) => hasCanonicalNotFoundDetail(error, "provider_id", "provider.map-only", "providerId"),
  );
});

test("topology accessors use Rust read projections rather than JS topology maps", () => {
  const state = fakeState();
  state.endpoints.set("endpoint.map-only", {
    id: "endpoint.map-only",
    modelId: "map-only",
    status: "mounted",
  });
  state.routes.set("route.map-only", { id: "route.map-only" });
  state.instances.set("instance.map-only", { id: "instance.map-only", status: "loaded" });
  state.artifacts.set("artifact.map-only", { id: "artifact.map-only", modelId: "map-only" });

  assert.equal(endpoint(state, "endpoint.active", deps).artifact_endpoint_projection_boundary, "model_mount.artifact_endpoint_projection");
  assert.equal(route(state, "route.local-first", deps).route_projection_boundary, "model_mount.route_control_projection");
  assert.equal(getModel(state, "artifact.local", deps).artifact_endpoint_projection_boundary, "model_mount.artifact_endpoint_projection");
  assert.throws(
    () => endpoint(state, "endpoint.map-only", deps),
    (error) => hasCanonicalNotFoundDetail(error, "endpoint_id", "endpoint.map-only", "endpointId"),
  );
  assert.throws(
    () => route(state, "route.map-only", deps),
    (error) => hasCanonicalNotFoundDetail(error, "route_id", "route.map-only", "routeId"),
  );
  assert.throws(
    () => instance(state, "instance.map-only", deps),
    (error) => hasCanonicalNotFoundDetail(error, "instance_id", "instance.map-only", "instanceId"),
  );
  assert.throws(
    () => getModel(state, "artifact.map-only", deps),
    (error) => hasCanonicalNotFoundDetail(error, "model_id", "artifact.map-only", "modelId"),
  );
});

test("resolveEndpoint prefers explicit endpoint, existing model endpoint, mount fallback, and unavailable error", () => {
  const state = fakeState();

  assert.equal(resolveEndpoint(state, "endpoint.active", null, deps).id, "endpoint.active");
  assert.equal(resolveEndpoint(state, null, "llama-test", deps).id, "endpoint.active");

  const mounted = resolveEndpoint(state, null, "new-model", deps);
  assert.equal(mounted.id, "endpoint.mounted.new-model");
  assert.deepEqual(state.mounted, [{ model_id: "new-model" }]);

  assert.throws(
    () => resolveEndpoint(state, null, null, deps),
    (error) => error.status === 424 && error.code === "product_model_unavailable",
  );
});

test("model accessors find artifacts and fail closed before provider-direct artifact mutation", () => {
  const state = fakeState();
  const providerRecord = provider(state, "provider.local", deps);

  assert.equal(getModel(state, "artifact.local", deps).id, "artifact.local");
  assert.equal(getModel(state, "model.local", deps).id, "artifact.local");
  assert.throws(
    () => getModel(state, "missing", deps),
    (error) => hasCanonicalNotFoundDetail(error, "model_id", "missing", "modelId"),
  );

  assert.equal(modelForProviderMount(state, "model.local", providerRecord, {}, state.now, deps).id, "artifact.local");
  state.artifactProjectionRows.push({
    artifact_id: "artifact.provider-ref-only",
    model_id: "model.provider-ref-only",
    provider_ref: "provider://local",
    artifact_endpoint_projection_boundary: "model_mount.artifact_endpoint_projection",
  });
  assert.equal(
    modelForProviderMount(state, "model.provider-ref-only", providerRecord, {}, state.now, deps).artifact_id,
    "artifact.provider-ref-only",
  );

  assert.throws(
    () =>
      modelForProviderMount(
        state,
        "remote-model",
        providerRecord,
        {
          display_name: "Remote Model",
          size_bytes: "123",
          context_window: "4096",
          capabilities: ["chat", "vision"],
          privacy_class: "hosted_private",
        },
        state.now,
        deps,
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_state_accessor_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.projection");
      assert.equal(error.details.operation_kind, "model_mount.artifact.provider_direct_mount");
      assert.equal(error.details.artifact_id, "provider.local.remote.model");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(error.details.provider_kind, "openai");
      assert.equal(error.details.model_id, "remote-model");
      assert.equal(Object.hasOwn(error.details, "artifactId"), false);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "modelId"), false);
      return true;
    },
  );

  assert.equal(state.artifacts.has("provider.local.remote.model"), false);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
});

test("ensureLoaded reuses existing instance without JS touch mutation", async () => {
  const state = fakeState();
  delete state.endpointProjectionRows[0].id;
  state.instanceProjectionRows.push({
    id: "instance.loaded",
    endpoint_id: "endpoint.active",
    status: "loaded",
    load_policy: { mode: "on_demand" },
    lastUsedAt: "old",
  });

  const updated = await ensureLoaded(state, endpoint(state, "endpoint.active", deps), deps);

  assert.equal(state.evictions, 0);
  assert.equal(updated.id, "instance.loaded");
  assert.equal(updated.lastUsedAt, "old");
  assert.equal(updated.expiresAt, undefined);
  assert.equal(state.instances.has("instance.loaded"), false);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.loadedLookups, [["endpoint.active", false]]);
});

test("ensureLoaded existing instance reuse does not require JS record-state commit", async () => {
  const state = fakeState();
  delete state.endpointProjectionRows[0].id;
  state.instanceProjectionRows.push({
    id: "instance.loaded",
    endpoint_id: "endpoint.active",
    status: "loaded",
    load_policy: { mode: "on_demand" },
    lastUsedAt: "old",
  });
  delete state.commitRuntimeModelMountRecordState;

  const loaded = await ensureLoaded(state, endpoint(state, "endpoint.active", deps), deps);

  assert.equal(loaded.id, "instance.loaded");
  assert.equal(state.instances.has("instance.loaded"), false);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
});

test("ensureLoaded calls loadModel when no active instance exists", async () => {
  const state = fakeState();

  const loaded = await ensureLoaded(state, endpoint(state, "endpoint.active", deps), deps);

  assert.equal(loaded.id, "instance.loaded.new");
  assert.deepEqual(state.loadCalls, [{ endpoint_id: "endpoint.active", load_policy: { mode: "on_demand" } }]);
});
