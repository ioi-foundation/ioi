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
    receipts: [],
    writes: [],
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
