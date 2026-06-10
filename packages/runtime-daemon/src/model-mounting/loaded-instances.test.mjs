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
    recordStateCommits: [],
    receipts: [],
    transitionRequests: [],
    writes: [],
    endpoint(endpointId) {
      const endpoint = this.endpoints.get(endpointId);
      if (!endpoint) throw new Error(`missing endpoint ${endpointId}`);
      return endpoint;
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push([kind, details]);
      return receipt;
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
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
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
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.endpoint_id, "endpoint_missing");
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      return true;
    },
  );
});

test("idle TTL eviction fails closed before JS lifecycle receipt or instance write", () => {
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

  assert.throws(
    () => evictExpiredInstances(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.instance_lifecycle");
      assert.equal(error.details.operation, "model_idle_evict");
      assert.equal(error.details.operation_kind, "model_mount.instance.evict");
      assert.equal(error.details.reason, "idle_ttl");
      assert.equal(error.details.instance_id, "instance_old");
      assert.equal(error.details.endpoint_id, "endpoint_a");
      assert.equal(error.details.model_id, "model_a");
      assert.equal(error.details.provider_id, "provider_a");
      assert.equal(Object.hasOwn(error.details, "instanceId"), false);
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.equal(state.instances.get("instance_fresh").status, "loaded");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("idle TTL eviction for migrated local providers still requires direct Rust core transition ownership", () => {
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
        model_mount_provider_lifecycle_hash: "sha256:provider-load",
        providerEvidenceRefs: ["driver.load"],
        model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
      },
    ],
  });
  state.providers.set("provider.local", { id: "provider.local", kind: "ioi_native_local", driver: "native_local" });

  assert.throws(
    () => evictExpiredInstances(state),
    (error) => {
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.operation, "model_idle_evict");
      assert.equal(error.details.instance_id, "instance_old");
      return true;
    },
  );

  const instance = state.instances.get("instance_old");
  assert.equal(instance.status, "loaded");
  assert.equal(instance.receiptId, undefined);
  assert.deepEqual(state.transitionRequests, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("idle TTL eviction skips writes when no loaded instances expire", () => {
  const state = fakeState({
    instances: [
      { id: "instance_a", endpointId: "endpoint_a", status: "loaded", expiresAt: "2026-06-03T12:00:01.000Z" },
      { id: "instance_b", endpointId: "endpoint_b", status: "evicted", expiresAt: "2026-06-03T11:00:00.000Z" },
    ],
  });

  assert.equal(evictExpiredInstances(state), false);

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("coalescing duplicate loaded instances fails closed before JS supersede mutation", () => {
  const state = fakeState({
    instances: [
      { id: "instance_old", endpointId: "endpoint_a", status: "loaded", loadedAt: "2026-06-03T11:00:00.000Z" },
      { id: "instance_new", endpointId: "endpoint_a", status: "loaded", loadedAt: "2026-06-03T11:30:00.000Z" },
      { id: "instance_other", endpointId: "endpoint_b", status: "loaded", loadedAt: "2026-06-03T11:15:00.000Z" },
    ],
  });

  assert.throws(
    () => coalesceLoadedInstances(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.operation, "model_supersede");
      assert.equal(error.details.operation_kind, "model_mount.instance.supersede");
      assert.equal(error.details.superseded_by, "instance_new");
      assert.equal(error.details.reason, "endpoint_reload");
      assert.equal(error.details.instance_id, "instance_old");
      assert.equal(Object.hasOwn(error.details, "supersededBy"), false);
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.equal(state.instances.get("instance_new").status, "loaded");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("explicit supersede fails closed before JS supersede mutation when state would change", () => {
  const state = fakeState({
    instances: [
      { id: "instance_keep", endpointId: "endpoint_a", status: "loaded" },
      { id: "instance_old", endpointId: "endpoint_a", status: "loaded" },
      { id: "instance_other", endpointId: "endpoint_b", status: "loaded" },
    ],
  });

  assert.throws(
    () => supersedeLoadedInstances(state, "endpoint_a", "instance_keep"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.operation, "model_supersede");
      assert.equal(error.details.operation_kind, "model_mount.instance.supersede");
      assert.equal(error.details.superseded_by, "instance_keep");
      assert.equal(error.details.instance_id, "instance_old");
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(supersedeLoadedInstances(state, "endpoint_missing", "none"), false);
});

test("explicit supersede for migrated local providers still requires direct Rust core transition ownership", () => {
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
        model_mount_provider_lifecycle_hash: "sha256:provider-load",
        providerEvidenceRefs: ["driver.load"],
        model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
      },
    ],
  });
  state.providers.set("provider.local", { id: "provider.local", kind: "local_folder", driver: "native_local" });

  assert.throws(
    () => supersedeLoadedInstances(state, "endpoint_a", "instance_keep"),
    (error) => {
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.operation, "model_supersede");
      assert.equal(error.details.superseded_by, "instance_keep");
      assert.equal(error.details.instance_id, "instance_old");
      return true;
    },
  );

  const instance = state.instances.get("instance_old");
  assert.equal(instance.status, "loaded");
  assert.equal(instance.receiptId, undefined);
  assert.deepEqual(state.transitionRequests, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("instance lifecycle maintenance does not depend on retired JS Agentgres commit shim", () => {
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
    ],
  });
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => evictExpiredInstances(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.instance_id, "instance_old");
      assert.equal(error.details.endpoint_id, "endpoint_a");
      assert.equal(error.details.model_id, "model_a");
      assert.equal(error.details.provider_id, "provider_a");
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
});
