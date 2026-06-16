import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_MOUNTING_STATE_MAPS,
  writeAllModelMountingMaps,
  writeModelMountingMap,
  writeModelMountingVaultRefs,
} from "./state-persistence.mjs";

function fakeState() {
  const state = {
    stateDir: "/state",
    writes: [],
    projections: 0,
    store: {
      writeMap: (dir, map) => state.writes.push([dir, [...map.keys()]]),
    },
    recordStateCommits: [],
    providers: new Map(),
    vault: {
      metadataRecords: () => [
        { id: "vault_a", configured: true },
        { id: "vault_b", configured: false },
      ],
    },
    writeMap(dir, map) {
      this.writes.push([dir, [...map.keys()]]);
    },
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
    writeProjection() {
      this.projections += 1;
    },
    writeVaultRefs() {
      writeModelMountingVaultRefs(this);
    },
  };
  return state;
}

test("retired JS topology map loader table stays empty", () => {
  const state = fakeState();

  assert.deepEqual(MODEL_MOUNTING_STATE_MAPS, []);
  assert.equal(Object.hasOwn(state, "artifacts"), false);
  assert.equal(Object.hasOwn(state, "endpoints"), false);
  assert.equal(Object.hasOwn(state, "instances"), false);
});

test("topology, OAuth, catalog-provider, capability-token, runtime-engine, MCP, conversation, vault-ref, route, and download JS cache maps stay retired", () => {
  assert.deepEqual(MODEL_MOUNTING_STATE_MAPS, []);
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) =>
        dir === "model-providers" ||
        dir === "model-artifacts" ||
        dir === "model-endpoints" ||
        dir === "model-instances" ||
        ["providers", "artifacts", "endpoints", "instances"].includes(property),
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(([dir, property]) => dir === "oauth-sessions" || property === "oauthSessions"),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(([dir, property]) => dir === "oauth-states" || property === "oauthStates"),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(([dir, property]) => dir === "tokens" || property === "tokens"),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "model-catalog-providers" || property === "catalogProviderConfigs",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "runtime-preferences" || property === "runtimeSelections",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "runtime-engine-profiles" || property === "runtimeEngineProfiles",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "mcp-servers" || property === "mcpServers",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "model-conversations" || property === "conversations",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "vault-refs" || property === "vaultRefs",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "model-routes" || property === "routes",
    ),
    false,
  );
  assert.equal(
    MODEL_MOUNTING_STATE_MAPS.some(
      ([dir, property]) => dir === "model-downloads" || property === "downloads",
    ),
    false,
  );
});

test("writeAllModelMountingMaps fails closed as a retired bulk persistence path", () => {
  const state = fakeState();

  assert.throws(
    () => writeAllModelMountingMaps(state),
    (error) => {
      assert.equal(error.code, "model_mount_bulk_map_write_retired");
      assert.equal(error.details.canonical_persistence, "rust_agentgres_record_state_commit");
      return true;
    },
  );

  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("writeModelMountingMap fails closed as a retired per-map persistence path", () => {
  const state = fakeState();
  const map = new Map([["artifact_a", { id: "artifact_a" }]]);

  assert.throws(
    () => writeModelMountingMap(state, "model-artifacts", map),
    (error) => {
      assert.equal(error.code, "model_mount_map_write_retired");
      assert.equal(error.details.dir, "model-artifacts");
      assert.equal(error.details.record_count, 1);
      assert.equal(error.details.canonical_persistence, "rust_agentgres_record_state_commit");
      return true;
    },
  );

  assert.deepEqual(state.writes, []);
});

test("writeModelMountingVaultRefs is retired before JS vault metadata can become truth", () => {
  const state = fakeState();

  assert.throws(
    () => writeModelMountingVaultRefs(state),
    (error) => {
      assert.equal(error.code, "model_mount_vault_ref_js_metadata_write_retired");
      assert.equal(error.details.record_dir, "vault-refs");
      assert.equal(error.details.rust_core_api, "plan_model_mount_vault_control");
      assert.equal(error.details.canonical_persistence, "rust_agentgres_record_state_commit");
      return true;
    },
  );
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 0);
});

test("writeModelMountingVaultRefs retirement does not depend on Rust Agentgres commit configuration", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => writeModelMountingVaultRefs(state),
    (error) => {
      assert.equal(error.code, "model_mount_vault_ref_js_metadata_write_retired");
      assert.equal(error.details.record_dir, "vault-refs");
      assert.equal(error.details.rust_core_api, "plan_model_mount_vault_control");
      return true;
    },
  );

  assert.equal(Object.hasOwn(state, "vaultRefs"), false);
  assert.deepEqual(state.writes, []);
});

test("model instance map writes fail closed through the retired per-map persistence path", () => {
  const state = fakeState();
  const map = new Map([
    ["instance.local", {
      id: "instance.local",
      providerId: "provider.local",
      status: "loaded",
    }],
  ]);

  assert.throws(
    () => writeModelMountingMap(state, "model-instances", map),
    (error) =>
      error.code === "model_mount_map_write_retired" &&
      error.details.dir === "model-instances" &&
      error.details.canonical_persistence === "rust_agentgres_record_state_commit",
  );
  assert.deepEqual(state.writes, []);
});

test("model instance map writes reject Rust-bound records through the retired per-map persistence path", () => {
  const state = fakeState();
  const map = new Map([
    ["instance.local", {
      id: "instance.local",
      providerId: "provider.local",
      status: "loaded",
      model_mount_provider_lifecycle_hash: "sha256:provider-lifecycle",
      model_mount_instance_lifecycle_action: "load",
      model_mount_instance_lifecycle_status: "loaded",
      model_mount_instance_lifecycle_hash: "sha256:instance-lifecycle",
      model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
    }],
    ["instance.remote", {
      id: "instance.remote",
      providerId: "provider.remote",
      status: "loaded",
    }],
  ]);

  assert.throws(
    () => writeModelMountingMap(state, "model-instances", map),
    (error) =>
      error.code === "model_mount_map_write_retired" &&
      error.details.dir === "model-instances" &&
      error.details.record_count === 2,
  );

  assert.deepEqual(state.writes, []);
});

test("model instance map writes reject lifecycle action/status drift through retired per-map persistence", () => {
  const state = fakeState();
  const map = new Map([
    ["instance.local", {
      id: "instance.local",
      providerId: "provider.local",
      status: "evicted",
      model_mount_provider_lifecycle_hash: "sha256:provider-lifecycle",
      model_mount_instance_lifecycle_action: "load",
      model_mount_instance_lifecycle_status: "loaded",
      model_mount_instance_lifecycle_hash: "sha256:instance-lifecycle",
      model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
    }],
  ]);

  assert.throws(
    () => writeModelMountingMap(state, "model-instances", map),
    (error) =>
      error.code === "model_mount_map_write_retired" &&
      error.details.dir === "model-instances",
  );
  assert.deepEqual(state.writes, []);
});
