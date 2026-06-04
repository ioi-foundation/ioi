import assert from "node:assert/strict";
import test from "node:test";

import {
  coalesceLoadedInstances,
  evictExpiredInstances,
  loadedInstanceForEndpoint,
  supersedeLoadedInstances,
} from "./loaded-instances.mjs";

function fakeState({ now = "2026-06-03T12:00:00.000Z", instances = [] } = {}) {
  return {
    instances: new Map(instances.map((instance) => [instance.id, { ...instance }])),
    endpoints: new Map([
      ["endpoint_a", { id: "endpoint_a", modelId: "model_a", backendId: "backend.native" }],
      ["endpoint_b", { id: "endpoint_b", modelId: "model_b", backendId: "backend.native" }],
    ]),
    providers: new Map(),
    receipts: [],
    transitionRequests: [],
    writes: [],
    endpoint(endpointId) {
      const endpoint = this.endpoints.get(endpointId);
      if (!endpoint) throw new Error(`missing endpoint ${endpointId}`);
      return endpoint;
    },
    lifecycleReceipt(kind, details) {
      this.receipts.push([kind, details]);
    },
    now() {
      return new Date(now);
    },
    nowIso() {
      return now;
    },
    writeMap(dir, map) {
      this.writes.push([dir, [...map.values()].map((instance) => ({ ...instance }))]);
    },
    planModelMountInstanceLifecycle(request) {
      this.transitionRequests.push(request);
      return {
        action: request.action,
        status: request.target_status,
        backendId: request.backend_ref,
        driver: request.driver,
        executionBackend: request.execution_backend,
        providerLifecycleHash: request.provider_lifecycle_hash,
        instance_lifecycle_hash: `sha256:${request.action}:${request.instance_ref}`,
        evidence_refs: [
          "rust_model_mount_instance_lifecycle",
          "rust_model_mount_provider_lifecycle_bound",
          ...request.evidence_refs,
        ],
      };
    },
  };
}

function notFound(message, details) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

test("loaded instance lookup preserves fail and nullable modes", () => {
  const state = fakeState({
    instances: [
      { id: "instance_a", endpointId: "endpoint_a", status: "loaded" },
      { id: "instance_b", endpointId: "endpoint_b", status: "evicted" },
    ],
  });

  assert.equal(loadedInstanceForEndpoint(state, "endpoint_a", true, { notFound }).id, "instance_a");
  assert.equal(loadedInstanceForEndpoint(state, "endpoint_b", false, { notFound }), null);
  assert.throws(
    () => loadedInstanceForEndpoint(state, "endpoint_missing", true, { notFound }),
    (error) => error.status === 404 && error.details.endpointId === "endpoint_missing",
  );
});

test("idle TTL eviction writes changed instances and emits lifecycle receipts", () => {
  const state = fakeState({
    instances: [
      {
        id: "instance_old",
        endpointId: "endpoint_a",
        modelId: "model_a",
        providerId: "provider_a",
        status: "loaded",
        expiresAt: "2026-06-03T11:59:59.000Z",
      },
      {
        id: "instance_fresh",
        endpointId: "endpoint_b",
        status: "loaded",
        expiresAt: "2026-06-03T12:00:01.000Z",
      },
    ],
  });

  evictExpiredInstances(state);

  assert.equal(state.instances.get("instance_old").status, "evicted");
  assert.equal(state.instances.get("instance_old").evictionReason, "idle_ttl");
  assert.equal(state.instances.get("instance_fresh").status, "loaded");
  assert.deepEqual(state.receipts, [
    ["model_idle_evict", {
      instanceId: "instance_old",
      endpointId: "endpoint_a",
      modelId: "model_a",
      providerId: "provider_a",
    }],
  ]);
  assert.equal(state.writes.length, 1);
  assert.equal(state.writes[0][0], "model-instances");
});

test("idle TTL eviction plans Rust lifecycle for migrated local providers", () => {
  const state = fakeState({
    instances: [
      {
        id: "instance_old",
        endpointId: "endpoint_a",
        modelId: "model_a",
        providerId: "provider.local",
        backendId: "backend.native",
        driver: "native_local",
        status: "loaded",
        expiresAt: "2026-06-03T11:59:59.000Z",
        providerLifecycleHash: "sha256:provider-load",
        providerEvidenceRefs: ["driver.load"],
        modelMountInstanceLifecycleEvidenceRefs: ["rust_model_mount_instance_lifecycle"],
      },
    ],
  });
  state.providers.set("provider.local", { id: "provider.local", kind: "ioi_native_local", driver: "native_local" });

  evictExpiredInstances(state);

  const evicted = state.instances.get("instance_old");
  assert.equal(evicted.status, "evicted");
  assert.equal(evicted.modelMountInstanceLifecycleAction, "evict");
  assert.equal(evicted.modelMountInstanceLifecycleStatus, "evicted");
  assert.equal(evicted.modelMountInstanceLifecycleHash, "sha256:evict:instance_old");
  assert.equal(state.transitionRequests.at(-1).action, "evict");
  assert.equal(state.transitionRequests.at(-1).target_status, "evicted");
  assert.equal(state.receipts.at(-1)[1].providerKind, "ioi_native_local");
  assert.equal(state.receipts.at(-1)[1].modelMountInstanceLifecycleAction, "evict");
});

test("idle TTL eviction skips writes when no loaded instances expire", () => {
  const state = fakeState({
    instances: [
      { id: "instance_a", endpointId: "endpoint_a", status: "loaded", expiresAt: "2026-06-03T12:00:01.000Z" },
      { id: "instance_b", endpointId: "endpoint_b", status: "evicted", expiresAt: "2026-06-03T11:00:00.000Z" },
    ],
  });

  evictExpiredInstances(state);

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
});

test("coalescing keeps newest loaded instance per endpoint", () => {
  const state = fakeState({
    instances: [
      { id: "instance_old", endpointId: "endpoint_a", status: "loaded", loadedAt: "2026-06-03T11:00:00.000Z" },
      { id: "instance_new", endpointId: "endpoint_a", status: "loaded", loadedAt: "2026-06-03T11:30:00.000Z" },
      { id: "instance_other", endpointId: "endpoint_b", status: "loaded", loadedAt: "2026-06-03T11:15:00.000Z" },
    ],
  });

  coalesceLoadedInstances(state);

  assert.equal(state.instances.get("instance_old").status, "superseded");
  assert.equal(state.instances.get("instance_old").supersededBy, "instance_new");
  assert.equal(state.instances.get("instance_new").status, "loaded");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.equal(state.writes.length, 1);
});

test("explicit supersede returns whether state changed", () => {
  const state = fakeState({
    instances: [
      { id: "instance_keep", endpointId: "endpoint_a", status: "loaded" },
      { id: "instance_old", endpointId: "endpoint_a", status: "loaded" },
      { id: "instance_other", endpointId: "endpoint_b", status: "loaded" },
    ],
  });

  assert.equal(supersedeLoadedInstances(state, "endpoint_a", "instance_keep"), true);
  assert.equal(state.instances.get("instance_old").status, "superseded");
  assert.equal(state.instances.get("instance_old").supersededBy, "instance_keep");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.equal(supersedeLoadedInstances(state, "endpoint_missing", "none"), false);
});

test("explicit supersede plans Rust lifecycle for migrated local providers", () => {
  const state = fakeState({
    instances: [
      {
        id: "instance_keep",
        endpointId: "endpoint_a",
        modelId: "model_a",
        providerId: "provider.local",
        status: "loaded",
        backendId: "backend.native",
      },
      {
        id: "instance_old",
        endpointId: "endpoint_a",
        modelId: "model_a",
        providerId: "provider.local",
        status: "loaded",
        backendId: "backend.native",
        driver: "native_local",
        providerLifecycleHash: "sha256:provider-load",
        providerEvidenceRefs: ["driver.load"],
        modelMountInstanceLifecycleEvidenceRefs: ["rust_model_mount_instance_lifecycle"],
      },
    ],
  });
  state.providers.set("provider.local", { id: "provider.local", kind: "local_folder", driver: "native_local" });

  assert.equal(supersedeLoadedInstances(state, "endpoint_a", "instance_keep"), true);

  const superseded = state.instances.get("instance_old");
  assert.equal(superseded.status, "superseded");
  assert.equal(superseded.modelMountInstanceLifecycleAction, "supersede");
  assert.equal(superseded.modelMountInstanceLifecycleStatus, "superseded");
  assert.equal(superseded.modelMountInstanceLifecycleHash, "sha256:supersede:instance_old");
  assert.equal(state.transitionRequests.at(-1).action, "supersede");
  assert.equal(state.transitionRequests.at(-1).target_status, "superseded");
  assert.equal(state.receipts.at(-1)[0], "model_supersede");
  assert.equal(state.receipts.at(-1)[1].providerKind, "local_folder");
});
