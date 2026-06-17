import assert from "node:assert/strict";
import test from "node:test";

import {
  ensureNativeLocalFixtureArtifact,
} from "./default-discovery.mjs";
import * as defaultDiscovery from "./default-discovery.mjs";

function fakeState() {
  return {
    homeDir: "/home/ioi",
    modelRoot: "/tmp/ioi-model-root",
    backendRegistry() {
      throw new Error("native fixture artifact must not read JS backend registry");
    },
  };
}

test("native local fixture artifact is a Rust-backed record without JS file materialization", () => {
  const state = fakeState();

  const artifact = ensureNativeLocalFixtureArtifact(state, "2026-06-03T12:00:00.000Z");

  assert.equal(artifact.id, "hypervisor.native.fixture");
  assert.equal(artifact.modelId, "hypervisor:native-fixture");
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
  assert.equal(Object.hasOwn(defaultDiscovery, "pruneInternalFixtureProjectionRecords"), false);
});
