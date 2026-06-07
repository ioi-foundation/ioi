import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_MOUNTING_STATE_MAPS,
  loadModelMountingMap,
  loadModelMountingMaps,
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
  for (const [, property] of MODEL_MOUNTING_STATE_MAPS) {
    state[property] = new Map();
  }
  return state;
}

test("loadModelMountingMap loads only records with string ids", () => {
  const state = fakeState();
  const loaded = [];
  const target = new Map();

  loadModelMountingMap(state, "model-providers", target, {
    listJson(dir) {
      loaded.push(dir);
      return ["/state/model-providers/provider-a.json", "/state/model-providers/bad.json"];
    },
    readJson(filePath) {
      return filePath.endsWith("bad.json") ? { id: 12 } : { id: "provider_a", label: "A" };
    },
  });

  assert.deepEqual(loaded, ["/state/model-providers"]);
  assert.deepEqual([...target.entries()], [["provider_a", { id: "provider_a", label: "A" }]]);
});

test("loadModelMountingMap applies Rust-admitted tombstone records", () => {
  const state = fakeState();
  const target = new Map([["profile_a", { id: "profile_a", label: "old" }]]);

  loadModelMountingMap(state, "runtime-engine-profiles", target, {
    listJson(dir) {
      return [`${dir}/profile-a.json`];
    },
    readJson() {
      return {
        id: "profile_a",
        deleted: true,
        receiptId: "receipt_remove",
      };
    },
  });

  assert.equal(target.has("profile_a"), false);
});

test("loadModelMountingMaps applies the canonical directory map table", () => {
  const state = fakeState();

  loadModelMountingMaps(state, {
    listJson(dir) {
      return [`${dir}/record.json`];
    },
    readJson(filePath) {
      const dir = filePath.split("/").at(-2);
      return { id: `${dir}.record` };
    },
  });

  for (const [dir, property] of MODEL_MOUNTING_STATE_MAPS) {
    assert.equal(state[property].has(`${dir}.record`), true);
  }
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

test("writeModelMountingMap delegates through the configured store", () => {
  const state = fakeState();
  const map = new Map([["artifact_a", { id: "artifact_a" }]]);

  writeModelMountingMap(state, "model-artifacts", map);

  assert.deepEqual(state.writes, [["model-artifacts", ["artifact_a"]]]);
});

test("writeModelMountingVaultRefs commits metadata through Rust Agentgres record-state", () => {
  const state = fakeState();

  writeModelMountingVaultRefs(state);

  assert.deepEqual(state.writes, []);
  assert.equal(state.vaultRefs.get("vault_a").configured, true);
  assert.equal(state.recordStateCommits.length, 2);
  assert.deepEqual(state.recordStateCommits.map((commit) => commit.record_dir), ["vault-refs", "vault-refs"]);
  assert.deepEqual(state.recordStateCommits.map((commit) => commit.operation_kind), [
    "model_mount.vault_ref.write",
    "model_mount.vault_ref.write",
  ]);
  assert.deepEqual(state.recordStateCommits.map((commit) => commit.record_id), ["vault_a", "vault_b"]);
});

test("writeModelMountingVaultRefs fails closed without Rust Agentgres record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => writeModelMountingVaultRefs(state),
    (error) => {
      assert.equal(error.code, "model_mount_vault_ref_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "vault-refs");
      assert.equal(error.details.vault_ref_id, "vault_a");
      return true;
    },
  );

  assert.equal(state.vaultRefs.size, 0);
  assert.deepEqual(state.writes, []);
});

test("model instance map writes require Rust lifecycle binding for migrated local providers", () => {
  const state = fakeState();
  state.providers.set("provider.local", { id: "provider.local", kind: "ioi_native_local" });
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
      error.code === "model_mount_instance_map_direct_write_forbidden" &&
      error.details.missing.includes("instance.local:model_mount_instance_lifecycle_hash"),
  );
  assert.deepEqual(state.writes, []);
});

test("model instance map writes allow Rust-bound local and non-migrated provider records", () => {
  const state = fakeState();
  state.providers.set("provider.local", { id: "provider.local", kind: "local_folder" });
  state.providers.set("provider.remote", { id: "provider.remote", kind: "openai_compatible" });
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

  writeModelMountingMap(state, "model-instances", map);

  assert.deepEqual(state.writes, [["model-instances", ["instance.local", "instance.remote"]]]);
});

test("model instance map writes reject lifecycle action/status drift for migrated local providers", () => {
  const state = fakeState();
  state.providers.set("provider.local", { id: "provider.local", kind: "ioi_native_local" });
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
      error.code === "model_mount_instance_map_direct_write_forbidden" &&
      error.details.mismatches.includes("instance.local:model_mount_instance_lifecycle_action") &&
      error.details.mismatches.includes("instance.local:model_mount_instance_lifecycle_status"),
  );
});
