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
    vault: {
      metadataRecords: () => [
        { id: "vault_a", configured: true },
        { id: "vault_b", configured: false },
      ],
    },
    writeMap(dir, map) {
      this.writes.push([dir, [...map.keys()]]);
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

test("writeAllModelMountingMaps writes maps in canonical order and refreshes vault refs", () => {
  const state = fakeState();
  state.providers.set("provider_a", { id: "provider_a" });
  state.routes.set("route_a", { id: "route_a" });

  writeAllModelMountingMaps(state);

  assert.deepEqual(state.writes.map(([dir]) => dir), MODEL_MOUNTING_STATE_MAPS.map(([dir]) => dir));
  assert.deepEqual(state.writes.find(([dir]) => dir === "model-providers"), ["model-providers", ["provider_a"]]);
  assert.deepEqual(state.writes.find(([dir]) => dir === "model-routes"), ["model-routes", ["route_a"]]);
  assert.deepEqual(state.writes.find(([dir]) => dir === "vault-refs"), ["vault-refs", ["vault_a", "vault_b"]]);
  assert.equal(state.vaultRefs.get("vault_a").configured, true);
  assert.equal(state.projections, 1);
});

test("writeModelMountingMap delegates through the configured store", () => {
  const state = fakeState();
  const map = new Map([["artifact_a", { id: "artifact_a" }]]);

  writeModelMountingMap(state, "model-artifacts", map);

  assert.deepEqual(state.writes, [["model-artifacts", ["artifact_a"]]]);
});
