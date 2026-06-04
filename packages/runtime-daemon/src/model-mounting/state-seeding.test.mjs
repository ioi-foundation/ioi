import assert from "node:assert/strict";
import test from "node:test";

import { seedModelMountingDefaults } from "./state-seeding.mjs";

function fakeState({ lmStudioProvider, lmStudioArtifacts = [] } = {}) {
  const state = {
    artifacts: new Map(),
    endpoints: new Map(),
    providers: new Map(),
    routes: new Map(),
    homeDir: "/home/ioi",
    calls: [],
    backendRegistry() {
      return [{ id: "backend.native" }];
    },
    discoverLmStudioArtifacts(provider, checkedAt) {
      this.calls.push(["discoverLmStudioArtifacts", provider.id, checkedAt]);
      return lmStudioArtifacts;
    },
    discoverLmStudioProvider(checkedAt) {
      this.calls.push(["discoverLmStudioProvider", checkedAt]);
      return lmStudioProvider ?? {
        id: "provider.lmstudio",
        status: "absent",
        discovery: { disabledByDefault: true },
      };
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
    pruneLmStudioPublicProjectionRecords() {
      this.calls.push(["pruneLmStudioPublicProjectionRecords"]);
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
    lmStudioDetectedArtifactRecord: (provider, checkedAt) => ({
      id: "artifact.lmstudio.detected",
      providerId: provider.id,
      checkedAt,
    }),
    localFixtureArtifactRecords: () => [{ id: "artifact.fixture" }],
    localFixtureEndpointRecord: () => ({ id: "endpoint.fixture" }),
    localFolderProviderRecord: () => ({ id: "provider.local.folder" }),
    nativeFixtureEndpointRecord: ({ artifact, backendRegistry }) => ({
      id: "endpoint.native",
      modelId: artifact.modelId,
      backendCount: backendRegistry.length,
    }),
    nativeLocalProviderRecord: () => ({ id: "provider.autopilot.local" }),
    runtimeProviderRecords: ({ llamaBinary, vllmBinary }) => [
      { id: "provider.llama-cpp", llamaBinary },
      { id: "provider.vllm", vllmBinary },
    ],
    stableHash: (value) => `hash:${value}`,
  };
}

test("state seeding preserves default providers, routes, and native fixture records", () => {
  const state = fakeState();

  seedModelMountingDefaults(state, deps());

  assert.deepEqual([...state.providers.keys()], [
    "provider.local.folder",
    "provider.autopilot.local",
    "provider.lmstudio",
    "provider.llama-cpp",
    "provider.vllm",
  ]);
  assert.deepEqual([...state.artifacts.keys()], ["artifact.fixture", "artifact.native"]);
  assert.deepEqual([...state.endpoints.keys()], ["endpoint.fixture", "endpoint.native"]);
  assert.deepEqual([...state.routes.keys()], ["route.local-first"]);
  assert.equal(state.providers.get("provider.llama-cpp").llamaBinary, "/home/ioi/llama-server");
  assert.equal(state.providers.get("provider.vllm").vllmBinary, "/bin/vllm");
  assert.equal(state.endpoints.get("endpoint.native").backendCount, 1);
  assert.deepEqual(state.calls, [
    ["discoverLmStudioProvider", "2026-06-03T12:00:00.000Z"],
    ["pruneLmStudioPublicProjectionRecords"],
    ["seedBackends", "2026-06-03T12:00:00.000Z"],
    ["ensureNativeLocalFixtureArtifact", "2026-06-03T12:00:00.000Z"],
    ["discoverLmStudioArtifacts", "provider.lmstudio", "2026-06-03T12:00:00.000Z"],
  ]);
});

test("state seeding prunes disabled fixtures and falls back to detected LM Studio artifact", () => {
  const state = fakeState({
    lmStudioProvider: {
      id: "provider.lmstudio",
      status: "running",
      discovery: {},
    },
  });

  seedModelMountingDefaults(state, deps({ fixturesEnabled: false }));

  assert.deepEqual([...state.artifacts.keys()], ["artifact.lmstudio.detected"]);
  assert.deepEqual([...state.endpoints.keys()], []);
  assert.equal(state.providers.get("provider.lmstudio").status, "running");
  assert.equal(state.artifacts.get("artifact.lmstudio.detected").providerId, "provider.lmstudio");
  assert.deepEqual(state.calls, [
    ["discoverLmStudioProvider", "2026-06-03T12:00:00.000Z"],
    ["pruneInternalFixtureProjectionRecords"],
    ["seedBackends", "2026-06-03T12:00:00.000Z"],
    ["discoverLmStudioArtifacts", "provider.lmstudio", "2026-06-03T12:00:00.000Z"],
  ]);
});

test("state seeding prefers discovered LM Studio artifacts over detected fallback", () => {
  const state = fakeState({
    lmStudioProvider: {
      id: "provider.lmstudio",
      status: "running",
      discovery: {},
    },
    lmStudioArtifacts: [{ id: "artifact.lmstudio.live" }],
  });

  seedModelMountingDefaults(state, deps());

  assert.equal(state.artifacts.has("artifact.lmstudio.live"), true);
  assert.equal(state.artifacts.has("artifact.lmstudio.detected"), false);
});
