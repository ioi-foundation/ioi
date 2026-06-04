import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  discoverLmStudioArtifacts,
  discoverLmStudioProvider,
  ensureNativeLocalFixtureArtifact,
  pruneInternalFixtureProjectionRecords,
  pruneLmStudioPublicProjectionRecords,
} from "./default-discovery.mjs";

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
  isExecutable: (filePath) => filePath === "/home/ioi/.lmstudio/bin/lms",
  lmStudioArtifact: (provider, model, checkedAt) => ({
    id: `artifact.${model.modelId}`,
    providerId: provider.id,
    checkedAt,
  }),
  lmStudioPublicCliEnabled: () => true,
  parseLmStudioList: () => [{ modelId: "llama-3.2" }],
  parseLocalModelMetadata: () => ({
    family: "autopilot-native",
    format: "gguf",
    quantization: "Q4_K_M",
    contextWindow: 8192,
  }),
  runPublicCommand: (command, args) => ({
    command,
    args,
    status: args.includes("status") ? 0 : 0,
    stdout: args.includes("status") ? "Server is ON" : "model list",
    stderr: "",
  }),
  truncate: (value) => String(value).slice(0, 20),
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

test("LM Studio provider discovery preserves disabled, running, and configured states", () => {
  const state = fakeState();

  const disabled = discoverLmStudioProvider(state, "checked", {
    ...deps,
    lmStudioPublicCliEnabled: () => false,
    env: {},
  });
  assert.equal(disabled.status, "absent");
  assert.equal(disabled.discovery.disabledByDefault, true);

  const running = discoverLmStudioProvider(state, "checked", deps);
  assert.equal(running.status, "running");
  assert.equal(running.discovery.publicCli.path, "/home/ioi/.lmstudio/bin/lms");
  assert.equal(running.discovery.publicCli.serverStatus, "Server is ON");

  const configured = discoverLmStudioProvider(state, "checked", {
    ...deps,
    env: { LM_STUDIO_BASE_URL: "http://127.0.0.1:9999/v1" },
    isExecutable: () => false,
  });
  assert.equal(configured.status, "configured");
  assert.equal(configured.baseUrl, "http://127.0.0.1:9999/v1");
});

test("LM Studio artifact discovery requires enabled public CLI and successful list", () => {
  const provider = { id: "provider.lmstudio", discovery: { publicCli: { path: "/bin/lms" } } };

  assert.deepEqual(discoverLmStudioArtifacts(fakeState(), provider, "checked", deps), [{
    id: "artifact.llama-3.2",
    providerId: "provider.lmstudio",
    checkedAt: "checked",
  }]);
  assert.deepEqual(discoverLmStudioArtifacts(fakeState(), provider, "checked", {
    ...deps,
    lmStudioPublicCliEnabled: () => false,
  }), []);
  assert.deepEqual(discoverLmStudioArtifacts(fakeState(), provider, "checked", {
    ...deps,
    runPublicCommand: () => ({ status: 1, stdout: "", stderr: "blocked" }),
  }), []);
});

test("LM Studio public projection pruning removes artifacts, endpoints, and instances", () => {
  const state = fakeState();
  state.artifacts.set("lmstudio.model", { id: "lmstudio.model", providerId: "provider.lmstudio" });
  state.artifacts.set("other", { id: "other", providerId: "provider.local" });
  state.endpoints.set("endpoint.provider.lmstudio.model", { id: "endpoint.provider.lmstudio.model", providerId: "provider.lmstudio" });
  state.endpoints.set("endpoint.other", { id: "endpoint.other", providerId: "provider.local" });
  state.instances.set("instance.lmstudio", { id: "instance.lmstudio", endpointId: "endpoint.provider.lmstudio.model" });
  state.instances.set("instance.other", { id: "instance.other", endpointId: "endpoint.other" });

  pruneLmStudioPublicProjectionRecords(state);

  assert.deepEqual([...state.artifacts.keys()], ["other"]);
  assert.deepEqual([...state.endpoints.keys()], ["endpoint.other"]);
  assert.deepEqual([...state.instances.keys()], ["instance.other"]);
});

test("internal fixture pruning removes fixture artifacts, endpoints, and dependent instances", () => {
  const state = fakeState();
  state.artifacts.set("artifact.fixture", { id: "artifact.fixture", modelId: "local:auto", family: "fixture" });
  state.artifacts.set("artifact.real", { id: "artifact.real", modelId: "real:model", family: "real" });
  state.endpoints.set("endpoint.fixture", { id: "endpoint.fixture", providerId: "provider.fixture", modelId: "local:auto" });
  state.endpoints.set("endpoint.real", { id: "endpoint.real", providerId: "provider.real", modelId: "real:model" });
  state.instances.set("instance.fixture", { id: "instance.fixture", endpointId: "endpoint.fixture", modelId: "local:auto" });
  state.instances.set("instance.real", { id: "instance.real", endpointId: "endpoint.real", modelId: "real:model" });

  pruneInternalFixtureProjectionRecords(state, {
    isFixtureEndpointCandidate: (endpoint) => endpoint.providerId === "provider.fixture",
    isFixtureModelRecord: (record) => record.family === "fixture",
  });

  assert.deepEqual([...state.artifacts.keys()], ["artifact.real"]);
  assert.deepEqual([...state.endpoints.keys()], ["endpoint.real"]);
  assert.deepEqual([...state.instances.keys()], ["instance.real"]);
});
