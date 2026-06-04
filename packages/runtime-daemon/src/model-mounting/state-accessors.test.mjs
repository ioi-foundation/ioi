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
      ["endpoint.active", { id: "endpoint.active", modelId: "llama-test", status: "mounted", loadPolicy: { mode: "on_demand" } }],
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
    writes: [],
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
  driverNameForProvider(providerRecord) {
    return providerRecord.driver ?? "openai_compatible";
  },
  normalizeScopes(scopes, fallback) {
    return scopes ?? fallback;
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, ".").toLowerCase();
  },
};

test("state lookup accessors return records and fail closed", () => {
  const state = fakeState();

  assert.equal(provider(state, "provider.local", deps).id, "provider.local");
  assert.equal(endpoint(state, "endpoint.active", deps).id, "endpoint.active");
  assert.equal(route(state, "route.local-first", deps).id, "route.local-first");

  state.instances.set("instance.1", { id: "instance.1" });
  assert.equal(instance(state, "instance.1", deps).id, "instance.1");

  assert.throws(() => provider(state, "missing", deps), (error) => error.status === 404 && error.details.providerId === "missing");
  assert.throws(() => endpoint(state, "endpoint.unmounted", deps), (error) => error.status === 404 && error.details.endpointId === "endpoint.unmounted");
  assert.throws(() => instance(state, "missing", deps), (error) => error.status === 404 && error.details.instanceId === "missing");
  assert.throws(() => route(state, "missing", deps), (error) => error.status === 404 && error.details.routeId === "missing");
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

test("model accessors find artifacts and persist provider-direct mount artifacts", () => {
  const state = fakeState();
  const providerRecord = state.providers.get("provider.local");

  assert.equal(getModel(state, "artifact.local", deps).id, "artifact.local");
  assert.equal(getModel(state, "model.local", deps).id, "artifact.local");
  assert.throws(() => getModel(state, "missing", deps), (error) => error.status === 404 && error.details.modelId === "missing");

  assert.equal(modelForProviderMount(state, "model.local", providerRecord, {}, state.now, deps).id, "artifact.local");
  const mounted = modelForProviderMount(
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
  );

  assert.equal(mounted.id, "provider.local.remote.model");
  assert.equal(mounted.source, "openai_compatible_provider_direct_mount");
  assert.equal(mounted.sizeBytes, 123);
  assert.equal(mounted.contextWindow, 4096);
  assert.deepEqual(mounted.capabilities, ["chat", "vision"]);
  assert.equal(mounted.privacyClass, "hosted_private");
  assert.equal(state.artifacts.get(mounted.id), mounted);
  assert.equal(state.writes.at(-1)[0], "model-artifacts");
});

test("ensureLoaded refreshes existing instance and writes it back", async () => {
  const state = fakeState();
  state.instances.set("instance.loaded", {
    id: "instance.loaded",
    endpointId: "endpoint.active",
    status: "loaded",
    loadPolicy: { mode: "on_demand" },
    lastUsedAt: "old",
  });

  const updated = await ensureLoaded(state, state.endpoints.get("endpoint.active"), deps);

  assert.equal(state.evictions, 1);
  assert.equal(updated.id, "instance.loaded");
  assert.equal(updated.lastUsedAt, state.now);
  assert.equal(updated.expiresAt, "2026-06-04T04:05:00.000Z");
  assert.equal(state.instances.get("instance.loaded"), updated);
  assert.equal(state.writes.at(-1)[0], "model-instances");
  assert.deepEqual(state.loadedLookups, [["endpoint.active", false]]);
});

test("ensureLoaded calls loadModel when no active instance exists", async () => {
  const state = fakeState();

  const loaded = await ensureLoaded(state, state.endpoints.get("endpoint.active"), deps);

  assert.equal(loaded.id, "instance.loaded.new");
  assert.deepEqual(state.loadCalls, [{ endpoint_id: "endpoint.active", load_policy: { mode: "on_demand" } }]);
});
