import assert from "node:assert/strict";
import test from "node:test";

import { seedModelMountingDefaults } from "./state-seeding.mjs";

function fakeState() {
  const state = {
    artifacts: new Map(),
    endpoints: new Map(),
    providers: new Map(),
    routes: new Map(),
    homeDir: "/home/ioi",
    calls: [],
    backendRegistry() {
      throw new Error("fixture seeding must not read JS backend registry");
    },
    ensureNativeLocalFixtureArtifact(checkedAt) {
      this.calls.push(["ensureNativeLocalFixtureArtifact", checkedAt]);
      return { id: "artifact.native", modelId: "native:model" };
    },
    nowIso() {
      return "2026-06-03T12:00:00.000Z";
    },
    pruneInternalFixtureProjectionRecords() {
      this.calls.push(["pruneInternalFixtureProjectionRecords"]);
    },
    seedBackends(checkedAt) {
      this.calls.push(["seedBackends", checkedAt]);
    },
    upsertDefault(map, record) {
      if (!map.has(record.id)) {
        map.set(record.id, record);
      }
    },
  };
  return state;
}

function deps({ fixturesEnabled = true } = {}) {
  return {
    defaultRouteRecords: () => [{ id: "route.local-first" }],
    discoverAutopilotLlamaServer: (homeDir) => `${homeDir}/llama-server`,
    env: {},
    findExecutable: (name) => `/bin/${name}`,
    hostedProvider: (id) => ({ id }),
    internalFixtureModelsEnabled: () => fixturesEnabled,
    localFixtureArtifactRecords: () => [{ id: "artifact.fixture" }],
    localFixtureEndpointRecord: () => ({ id: "endpoint.fixture" }),
    localFolderProviderRecord: () => ({ id: "provider.local.folder" }),
    nativeFixtureEndpointRecord: ({ artifact }) => ({
      id: "endpoint.native",
      modelId: artifact.modelId,
    }),
    nativeLocalProviderRecord: () => ({ id: "provider.autopilot.local" }),
    runtimeProviderRecords: ({ llamaBinary, vllmBinary }) => [
      { id: "provider.llama-cpp", llamaBinary },
      { id: "provider.vllm", vllmBinary },
    ],
  };
}

test("state seeding preserves default providers, routes, and native fixture records", () => {
  const state = fakeState();

  seedModelMountingDefaults(state, deps());

  assert.deepEqual([...state.providers.keys()], [
    "provider.local.folder",
    "provider.autopilot.local",
    "provider.llama-cpp",
    "provider.vllm",
  ]);
  assert.deepEqual([...state.artifacts.keys()], ["artifact.fixture", "artifact.native"]);
  assert.deepEqual([...state.endpoints.keys()], ["endpoint.fixture", "endpoint.native"]);
  assert.deepEqual([...state.routes.keys()], ["route.local-first"]);
  assert.equal(state.providers.get("provider.llama-cpp").llamaBinary, "/home/ioi/llama-server");
  assert.equal(state.providers.get("provider.vllm").vllmBinary, "/bin/vllm");
  assert.equal(Object.hasOwn(state.endpoints.get("endpoint.native"), "backendCount"), false);
  assert.deepEqual(state.calls, [
    ["ensureNativeLocalFixtureArtifact", "2026-06-03T12:00:00.000Z"],
  ]);
});

test("state seeding prunes disabled fixtures without JS LM Studio artifact fallback", () => {
  const state = fakeState();

  seedModelMountingDefaults(state, deps({ fixturesEnabled: false }));

  assert.deepEqual([...state.artifacts.keys()], []);
  assert.deepEqual([...state.endpoints.keys()], []);
  assert.equal(state.providers.has("provider.lmstudio"), false);
  assert.deepEqual(state.calls, [
    ["pruneInternalFixtureProjectionRecords"],
  ]);
});

test("state seeding has no JS LM Studio discovery or projection-prune hooks", () => {
  const state = fakeState();

  seedModelMountingDefaults(state, deps());

  assert.equal(state.providers.has("provider.lmstudio"), false);
  assert.equal(Object.hasOwn(state, "discoverLmStudioProvider"), false);
  assert.equal(Object.hasOwn(state, "discoverLmStudioArtifacts"), false);
  assert.equal(Object.hasOwn(state, "pruneLmStudioPublicProjectionRecords"), false);
});
