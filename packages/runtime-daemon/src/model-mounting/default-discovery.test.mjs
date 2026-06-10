import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ensureNativeLocalFixtureArtifact,
  pruneInternalFixtureProjectionRecords,
} from "./default-discovery.mjs";
import * as defaultDiscovery from "./default-discovery.mjs";

function fakeState() {
  return {
    homeDir: "/home/ioi",
    modelRoot: fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-root-")),
    artifacts: new Map(),
    endpoints: new Map(),
    instances: new Map(),
    providers: new Map([
      ["provider.fixture", { id: "provider.fixture" }],
      ["provider.lmstudio", { id: "provider.lmstudio" }],
    ]),
    backendRegistry() {
      return [{ id: "backend.native" }];
    },
  };
}

const deps = {
  fileSha256: () => "sha256:test",
  parseLocalModelMetadata: () => ({
    family: "autopilot-native",
    format: "gguf",
    quantization: "Q4_K_M",
    contextWindow: 8192,
  }),
};

test("native local fixture artifact materializes deterministic metadata", () => {
  const state = fakeState();

  const artifact = ensureNativeLocalFixtureArtifact(state, "2026-06-03T12:00:00.000Z", deps);

  assert.equal(artifact.id, "autopilot.native.fixture");
  assert.equal(artifact.modelId, "autopilot:native-fixture");
  assert.equal(artifact.checksum, "sha256:test");
  assert.equal(artifact.contextWindow, 8192);
  assert.deepEqual(artifact.backendRegistry, [{ id: "backend.native" }]);
  assert.equal(fs.existsSync(artifact.artifactPath), true);
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
