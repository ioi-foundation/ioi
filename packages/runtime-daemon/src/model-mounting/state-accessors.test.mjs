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
    evictions: 0,
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
      return [...this.instances.values()].find((candidate) => candidate.endpointId === endpointId && candidate.status === "loaded") ?? null;
    },
    loadModel(body) {
      this.loadCalls.push(body);
      return { id: "instance.loaded.new", endpointId: body.endpoint_id, status: "loaded" };
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
  assert.equal(endpoint(state, "endpoint.active", deps).id, "endpoint.active");
  assert.equal(route(state, "route.local-first", deps).id, "route.local-first");

  state.instances.set("instance.1", { id: "instance.1" });
  assert.equal(instance(state, "instance.1", deps).id, "instance.1");

  assert.throws(
    () => provider(state, "missing", deps),
    (error) => hasCanonicalNotFoundDetail(error, "provider_id", "missing", "providerId"),
  );
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
  const providerRecord = state.providers.get("provider.local");

  assert.equal(getModel(state, "artifact.local", deps).id, "artifact.local");
  assert.equal(getModel(state, "model.local", deps).id, "artifact.local");
  assert.throws(
    () => getModel(state, "missing", deps),
    (error) => hasCanonicalNotFoundDetail(error, "model_id", "missing", "modelId"),
  );

  assert.equal(modelForProviderMount(state, "model.local", providerRecord, {}, state.now, deps).id, "artifact.local");

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
  state.instances.set("instance.loaded", {
    id: "instance.loaded",
    endpointId: "endpoint.active",
    status: "loaded",
    load_policy: { mode: "on_demand" },
    lastUsedAt: "old",
  });

  const updated = await ensureLoaded(state, state.endpoints.get("endpoint.active"), deps);

  assert.equal(state.evictions, 0);
  assert.equal(updated.id, "instance.loaded");
  assert.equal(updated.lastUsedAt, "old");
  assert.equal(updated.expiresAt, undefined);
  assert.equal(state.instances.get("instance.loaded"), updated);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.loadedLookups, [["endpoint.active", false]]);
});

test("ensureLoaded existing instance reuse does not require JS record-state commit", async () => {
  const state = fakeState();
  state.instances.set("instance.loaded", {
    id: "instance.loaded",
    endpointId: "endpoint.active",
    status: "loaded",
    load_policy: { mode: "on_demand" },
    lastUsedAt: "old",
  });
  delete state.commitRuntimeModelMountRecordState;

  const loaded = await ensureLoaded(state, state.endpoints.get("endpoint.active"), deps);

  assert.equal(loaded.id, "instance.loaded");
  assert.equal(state.instances.get("instance.loaded").lastUsedAt, "old");
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
});

test("ensureLoaded calls loadModel when no active instance exists", async () => {
  const state = fakeState();

  const loaded = await ensureLoaded(state, state.endpoints.get("endpoint.active"), deps);

  assert.equal(loaded.id, "instance.loaded.new");
  assert.deepEqual(state.loadCalls, [{ endpoint_id: "endpoint.active", load_policy: { mode: "on_demand" } }]);
});
