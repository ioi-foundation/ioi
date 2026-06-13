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
      ["endpoint_a", { id: "endpoint_a", modelId: "model_a", backendId: "backend.native", providerId: "provider_a" }],
      ["endpoint_b", { id: "endpoint_b", modelId: "model_b", backendId: "backend.native", providerId: "provider_b" }],
    ]),
    providers: new Map([
      ["provider_a", { id: "provider_a", kind: "ioi_native_local", driver: "native_local" }],
      ["provider_b", { id: "provider_b", kind: "ioi_native_local", driver: "native_local" }],
    ]),
    recordStateCommits: [],
    receipts: [],
    transitionRequests: [],
    writes: [],
    now() {
      return new Date(now);
    },
    nowIso() {
      return now;
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push([kind, details]);
      return receipt;
    },
    writeMap(dir, map) {
      this.writes.push([dir, [...map.values()].map((instance) => ({ ...instance }))]);
    },
    planModelMountInstanceLifecycle(request) {
      this.transitionRequests.push(JSON.parse(JSON.stringify(request)));
      const record = {
        schema_version: request.schema_version,
        id: request.instance_ref,
        endpoint_id: request.endpoint_ref,
        model_id: request.model_ref,
        provider_id: request.provider_ref,
        instance_ref: request.instance_ref,
        endpoint_ref: request.endpoint_ref,
        model_ref: request.model_ref,
        provider_ref: request.provider_ref,
        action: request.action,
        status: request.target_status,
        backend_id: request.backend_ref,
        driver: request.driver,
        execution_backend: request.execution_backend,
        provider_lifecycle_hash: request.provider_lifecycle_hash,
        ...(request.reason ? { reason: request.reason } : {}),
        ...(request.superseded_by ? { superseded_by: request.superseded_by } : {}),
        evidence_refs: [
          "rust_model_mount_instance_lifecycle",
          "rust_model_mount_provider_lifecycle_bound",
          ...request.evidence_refs,
        ],
        instance_lifecycle_hash: `sha256:instance:${request.instance_ref}:${request.action}:${request.superseded_by ?? ""}`,
      };
      return {
        source: "rust_model_mount_instance_lifecycle_command",
        backend: "rust_model_mount_instance_lifecycle",
        result: record,
        action: request.action,
        status: record.status,
        backendId: record.backend_id,
        driver: record.driver,
        executionBackend: record.execution_backend,
        provider_lifecycle_hash: record.provider_lifecycle_hash,
        instance_lifecycle_hash: record.instance_lifecycle_hash,
        evidence_refs: record.evidence_refs,
        backendEvidenceRefs: record.evidence_refs,
      };
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

function loadedFixtureInstance(id, overrides = {}) {
  return {
    id,
    endpointId: "endpoint_a",
    modelId: "model_a",
    providerId: "provider_a",
    backendId: "backend.native",
    driver: "native_local",
    status: "loaded",
    provider_lifecycle_hash: "sha256:provider-load",
    ...overrides,
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

test("idle TTL eviction commits Rust-planned instance lifecycle before mutating instance truth", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_old", { expiresAt: "2026-06-03T11:59:59.000Z" }),
      loadedFixtureInstance("instance_fresh", {
        endpointId: "endpoint_b",
        modelId: "model_b",
        providerId: "provider_b",
        expiresAt: "2026-06-03T12:00:01.000Z",
      }),
    ],
  });

  assert.equal(evictExpiredInstances(state), true);

  const evicted = state.instances.get("instance_old");
  assert.equal(evicted.status, "evicted");
  assert.equal(evicted.action, "evict");
  assert.equal(evicted.reason, "idle_ttl");
  assert.equal(evicted.instance_lifecycle_hash, "sha256:instance:instance_old:evict:");
  assert.equal(state.instances.get("instance_fresh").status, "loaded");
  assert.equal(state.transitionRequests.length, 1);
  assert.equal(state.transitionRequests[0].action, "evict");
  assert.equal(state.transitionRequests[0].target_status, "evicted");
  assert.equal(state.transitionRequests[0].reason, "idle_ttl");
  assert.equal(state.transitionRequests[0].execution_backend, "rust_model_mount_instance_lifecycle");
  assert.equal(state.transitionRequests[0].provider_lifecycle_hash, "sha256:provider-load");
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[0].record_id, "instance_old");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.evict");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
});

test("idle TTL eviction fails closed before mutation when Rust lifecycle planner is unavailable", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_old", { expiresAt: "2026-06-03T11:59:59.000Z" }),
    ],
  });
  delete state.planModelMountInstanceLifecycle;

  assert.throws(
    () => evictExpiredInstances(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.instance_lifecycle");
      assert.equal(error.details.operation, "model_idle_evict");
      assert.equal(error.details.operation_kind, "model_mount.instance.evict");
      assert.equal(error.details.rust_core_api, "plan_model_mount_instance_lifecycle");
      assert.equal(error.details.instance_id, "instance_old");
      assert.equal(Object.hasOwn(error.details, "instanceId"), false);
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.deepEqual(state.recordStateCommits, []);
});

test("idle TTL eviction skips writes when no loaded instances expire", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_a", { expiresAt: "2026-06-03T12:00:01.000Z" }),
      loadedFixtureInstance("instance_b", { status: "evicted", expiresAt: "2026-06-03T11:00:00.000Z" }),
    ],
  });

  assert.equal(evictExpiredInstances(state), false);

  assert.deepEqual(state.transitionRequests, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("coalescing duplicate loaded instances commits Rust supersede transition", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_old", { loadedAt: "2026-06-03T11:00:00.000Z" }),
      loadedFixtureInstance("instance_new", { loadedAt: "2026-06-03T11:30:00.000Z" }),
      loadedFixtureInstance("instance_other", {
        endpointId: "endpoint_b",
        modelId: "model_b",
        providerId: "provider_b",
        loadedAt: "2026-06-03T11:15:00.000Z",
      }),
    ],
  });

  assert.equal(coalesceLoadedInstances(state), true);

  const superseded = state.instances.get("instance_old");
  assert.equal(superseded.status, "superseded");
  assert.equal(superseded.action, "supersede");
  assert.equal(superseded.reason, "endpoint_reload");
  assert.equal(superseded.superseded_by, "instance_new");
  assert.equal(state.instances.get("instance_new").status, "loaded");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.equal(state.transitionRequests.length, 1);
  assert.equal(state.transitionRequests[0].action, "supersede");
  assert.equal(state.transitionRequests[0].target_status, "superseded");
  assert.equal(state.transitionRequests[0].superseded_by, "instance_new");
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.supersede");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
});

test("explicit supersede commits Rust supersede transition before returning", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_keep"),
      loadedFixtureInstance("instance_old"),
      loadedFixtureInstance("instance_other", {
        endpointId: "endpoint_b",
        modelId: "model_b",
        providerId: "provider_b",
      }),
    ],
  });

  assert.equal(supersedeLoadedInstances(state, "endpoint_a", "instance_keep"), true);

  const superseded = state.instances.get("instance_old");
  assert.equal(superseded.status, "superseded");
  assert.equal(superseded.superseded_by, "instance_keep");
  assert.equal(state.instances.get("instance_other").status, "loaded");
  assert.equal(state.transitionRequests.length, 1);
  assert.equal(state.transitionRequests[0].superseded_by, "instance_keep");
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_id, "instance_old");
  assert.equal(supersedeLoadedInstances(state, "endpoint_missing", "none"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
});

test("explicit supersede rejects Rust result without superseded binding before commit", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_keep"),
      loadedFixtureInstance("instance_old"),
    ],
  });
  state.planModelMountInstanceLifecycle = function planModelMountInstanceLifecycle(request) {
    this.transitionRequests.push(JSON.parse(JSON.stringify(request)));
    return {
      result: {
        id: request.instance_ref,
        endpoint_id: request.endpoint_ref,
        model_id: request.model_ref,
        provider_id: request.provider_ref,
        action: request.action,
        status: request.target_status,
        backend_id: request.backend_ref,
        driver: request.driver,
        execution_backend: request.execution_backend,
        provider_lifecycle_hash: request.provider_lifecycle_hash,
        evidence_refs: ["rust_model_mount_instance_lifecycle"],
        instance_lifecycle_hash: "sha256:bad",
      },
      executionBackend: "rust_model_mount_instance_lifecycle",
      status: request.target_status,
      evidence_refs: ["rust_model_mount_instance_lifecycle"],
      instance_lifecycle_hash: "sha256:bad",
    };
  };

  assert.throws(
    () => supersedeLoadedInstances(state, "endpoint_a", "instance_keep"),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "model_mount_instance_lifecycle_rust_result_required");
      assert.deepEqual(error.details.mismatches, ["result.superseded_by"]);
      return true;
    },
  );

  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.equal(state.recordStateCommits.length, 0);
});

test("instance lifecycle maintenance requires Rust Agentgres commit after Rust planning", () => {
  const state = fakeState({
    instances: [
      loadedFixtureInstance("instance_old", { expiresAt: "2026-06-03T11:59:59.000Z" }),
    ],
  });
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => evictExpiredInstances(state),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_instance_lifecycle_record_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-instances");
      assert.equal(error.details.record_id, "instance_old");
      return true;
    },
  );

  assert.equal(state.transitionRequests.length, 1);
  assert.equal(state.instances.get("instance_old").status, "loaded");
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
});
