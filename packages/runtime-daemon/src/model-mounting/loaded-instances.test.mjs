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
    planModelMountInstanceLifecycle(request) {
      this.transitionRequests.push(request);
      return {
        action: request.action,
        status: request.target_status,
        backendId: request.backend_ref,
        driver: request.driver,
        executionBackend: request.execution_backend,
        provider_lifecycle_hash: request.provider_lifecycle_hash,
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
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.endpoint_id, "endpoint_missing");
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      return true;
    },
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

  assert.equal(evictExpiredInstances(state), true);

  assert.equal(state.instances.get("instance_old").status, "evicted");
  assert.equal(state.instances.get("instance_old").evictionReason, "idle_ttl");
  assert.equal(state.instances.get("instance_old").receiptId, "receipt.model_idle_evict.1");
  assert.equal(state.instances.get("instance_fresh").status, "loaded");
  assert.deepEqual(state.receipts, [
    ["model_idle_evict", {
      instance_id: "instance_old",
      endpoint_id: "endpoint_a",
      model_id: "model_a",
      provider_id: "provider_a",
    }],
  ]);
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[0].record_id, "instance_old");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.evict");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.model_idle_evict.1"]);
  assert.equal(state.recordStateCommits[0].record.receiptId, "receipt.model_idle_evict.1");
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
        model_mount_provider_lifecycle_hash: "sha256:provider-load",
        providerEvidenceRefs: ["driver.load"],
        model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
      },
    ],
  });
  state.providers.set("provider.local", { id: "provider.local", kind: "ioi_native_local", driver: "native_local" });

  evictExpiredInstances(state);

  const evicted = state.instances.get("instance_old");
  assert.equal(evicted.status, "evicted");
  assert.equal(evicted.receiptId, "receipt.model_idle_evict.1");
  assert.equal(evicted.model_mount_instance_lifecycle_action, "evict");
  assert.equal(evicted.model_mount_instance_lifecycle_status, "evicted");
  assert.equal(evicted.model_mount_instance_lifecycle_hash, "sha256:evict:instance_old");
  assert.equal(state.transitionRequests.at(-1).action, "evict");
  assert.equal(state.transitionRequests.at(-1).target_status, "evicted");
  assert.equal(state.receipts.at(-1)[1].provider_kind, "ioi_native_local");
  assert.equal(state.receipts.at(-1)[1].model_mount_instance_lifecycle_action, "evict");
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "providerKind"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "instanceId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "endpointId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "modelId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "providerId"), false);
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

test("coalescing keeps newest loaded instance per endpoint", () => {
  const state = fakeState({
    instances: [
      { id: "instance_old", endpointId: "endpoint_a", status: "loaded", loadedAt: "2026-06-03T11:00:00.000Z" },
      { id: "instance_new", endpointId: "endpoint_a", status: "loaded", loadedAt: "2026-06-03T11:30:00.000Z" },
      { id: "instance_other", endpointId: "endpoint_b", status: "loaded", loadedAt: "2026-06-03T11:15:00.000Z" },
    ],
  });

  assert.equal(coalesceLoadedInstances(state), true);

  assert.equal(state.instances.get("instance_old").status, "superseded");
  assert.equal(state.instances.get("instance_old").supersededBy, "instance_new");
  assert.equal(state.instances.get("instance_old").receiptId, "receipt.model_supersede.1");
  assert.equal(state.instances.get("instance_new").status, "loaded");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[0].record_id, "instance_old");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.supersede");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.model_supersede.1"]);
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
  assert.equal(state.instances.get("instance_old").receiptId, "receipt.model_supersede.1");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[0].record_id, "instance_old");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.supersede");
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
        model_mount_provider_lifecycle_hash: "sha256:provider-load",
        providerEvidenceRefs: ["driver.load"],
        model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
      },
    ],
  });
  state.providers.set("provider.local", { id: "provider.local", kind: "local_folder", driver: "native_local" });

  assert.equal(supersedeLoadedInstances(state, "endpoint_a", "instance_keep"), true);

  const superseded = state.instances.get("instance_old");
  assert.equal(superseded.status, "superseded");
  assert.equal(superseded.receiptId, "receipt.model_supersede.1");
  assert.equal(superseded.model_mount_instance_lifecycle_action, "supersede");
  assert.equal(superseded.model_mount_instance_lifecycle_status, "superseded");
  assert.equal(superseded.model_mount_instance_lifecycle_hash, "sha256:supersede:instance_old");
  assert.equal(state.transitionRequests.at(-1).action, "supersede");
  assert.equal(state.transitionRequests.at(-1).target_status, "superseded");
  assert.equal(state.receipts.at(-1)[0], "model_supersede");
  assert.equal(state.receipts.at(-1)[1].provider_kind, "local_folder");
  assert.equal(state.receipts.at(-1)[1].superseded_by, "instance_keep");
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "providerKind"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1)[1], "supersededBy"), false);
  assert.equal(state.recordStateCommits.at(-1).operation_kind, "model_mount.instance.supersede");
});

test("instance lifecycle maintenance fails closed without Rust Agentgres record-state commit", () => {
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
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_instance_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-instances");
      assert.equal(error.details.record_id, "instance_old");
      assert.equal(error.details.instance_id, "instance_old");
      assert.equal(error.details.endpoint_id, "endpoint_a");
      assert.equal(error.details.model_id, "model_a");
      assert.equal(error.details.provider_id, "provider_a");
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.deepEqual(state.writes, []);
});
