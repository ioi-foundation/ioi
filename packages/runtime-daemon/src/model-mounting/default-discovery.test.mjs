import assert from "node:assert/strict";
import test from "node:test";

import {
  ensureNativeLocalFixtureArtifact,
  pruneInternalFixtureProjectionRecords,
} from "./default-discovery.mjs";
import * as defaultDiscovery from "./default-discovery.mjs";

function fakeState() {
  return {
    homeDir: "/home/ioi",
    modelRoot: "/tmp/ioi-model-root",
    artifacts: new Map(),
    endpoints: new Map(),
    instances: new Map(),
    providers: new Map([
      ["provider.fixture", { id: "provider.fixture" }],
      ["provider.lmstudio", { id: "provider.lmstudio" }],
    ]),
    backendRegistry() {
      throw new Error("native fixture artifact must not read JS backend registry");
    },
  };
}

test("native local fixture artifact is a Rust-backed record without JS file materialization", () => {
  const state = fakeState();

  const artifact = ensureNativeLocalFixtureArtifact(state, "2026-06-03T12:00:00.000Z");

  assert.equal(artifact.id, "autopilot.native.fixture");
  assert.equal(artifact.modelId, "autopilot:native-fixture");
  assert.equal(artifact.source, "rust_model_mount_native_local_fixture");
  assert.equal(artifact.format, "rust_backed_fixture");
  assert.equal(artifact.checksum, null);
  assert.equal(artifact.contextWindow, 8192);
  assert.equal(Object.hasOwn(artifact, "backendRegistry"), false);
  assert.equal(Object.hasOwn(artifact, "artifactPath"), false);
});

test("LM Studio default discovery helpers are deleted instead of inert compatibility exports", () => {
  assert.equal(Object.hasOwn(defaultDiscovery, "discoverLmStudioProvider"), false);
  assert.equal(Object.hasOwn(defaultDiscovery, "discoverLmStudioArtifacts"), false);
  assert.equal(Object.hasOwn(defaultDiscovery, "pruneLmStudioPublicProjectionRecords"), false);
});

test("internal fixture pruning removes fixture artifacts, endpoints, and dependent instances", () => {
  const state = fakeState();
  state.artifacts.set("artifact.fixture", { id: "artifact.fixture", modelId: "local:auto", family: "fixture" });
  state.artifacts.set("artifact.real", { id: "artifact.real", modelId: "real:model", family: "real" });
  state.endpoints.set("endpoint.fixture", { id: "endpoint.fixture", providerId: "provider.fixture", modelId: "local:auto" });
  state.endpoints.set("endpoint.real", { id: "endpoint.real", providerId: "provider.real", modelId: "real:model" });
  state.instances.set("instance.fixture", { id: "instance.fixture", endpointId: "endpoint.fixture", modelId: "local:auto" });
  state.instances.set("instance.real", { id: "instance.real", endpointId: "endpoint.real", modelId: "real:model" });

  pruneInternalFixtureProjectionRecords(state);

  assert.deepEqual([...state.artifacts.keys()], ["artifact.real"]);
  assert.deepEqual([...state.endpoints.keys()], ["endpoint.real"]);
  assert.deepEqual([...state.instances.keys()], ["instance.real"]);
});
