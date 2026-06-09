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

test("LM Studio provider discovery is inert until Rust provider inventory owns probing", () => {
  const state = fakeState();
  const commands = [];

  const disabled = discoverLmStudioProvider(state, "checked", {
    ...deps,
    env: {},
    runPublicCommand: (...args) => commands.push(args),
  });
  assert.equal(disabled.status, "absent");
  assert.equal(disabled.discovery.disabledByDefault, true);
  assert.equal(disabled.discovery.publicCli, null);
  assert.equal(disabled.discovery.rustCoreBoundary, "model_mount.provider_inventory");
  assert.deepEqual(disabled.discovery.evidenceRefs, ["lm_studio_public_discovery_retired"]);

  const configured = discoverLmStudioProvider(state, "checked", {
    ...deps,
    env: { LM_STUDIO_BASE_URL: "http://127.0.0.1:9999/v1" },
    runPublicCommand: (...args) => commands.push(args),
  });
  assert.equal(configured.status, "configured");
  assert.equal(configured.baseUrl, "http://127.0.0.1:9999/v1");
  assert.equal(configured.discovery.publicCli, null);
  assert.deepEqual(configured.discovery.evidenceRefs, [
    "lm_studio_base_url_configured",
    "lm_studio_public_discovery_retired",
  ]);
  assert.deepEqual(commands, []);
});

test("LM Studio artifact discovery is retired before public CLI list execution", () => {
  const provider = { id: "provider.lmstudio", discovery: { publicCli: { path: "/bin/lms" } } };
  const commands = [];

  assert.deepEqual(discoverLmStudioArtifacts(fakeState(), provider, "checked", {
    ...deps,
    runPublicCommand: (...args) => commands.push(args),
  }), []);
  assert.deepEqual(commands, []);
});

test("LM Studio public projection pruning is retired before JS map mutation", () => {
  const state = fakeState();
  state.artifacts.set("lmstudio.model", { id: "lmstudio.model", providerId: "provider.lmstudio" });
  state.artifacts.set("other", { id: "other", providerId: "provider.local" });
  state.endpoints.set("endpoint.provider.lmstudio.model", { id: "endpoint.provider.lmstudio.model", providerId: "provider.lmstudio" });
  state.endpoints.set("endpoint.other", { id: "endpoint.other", providerId: "provider.local" });
  state.instances.set("instance.lmstudio", { id: "instance.lmstudio", endpointId: "endpoint.provider.lmstudio.model" });
  state.instances.set("instance.other", { id: "instance.other", endpointId: "endpoint.other" });

  const result = pruneLmStudioPublicProjectionRecords(state);

  assert.equal(result.status, "retired");
  assert.equal(result.rust_core_boundary, "model_mount.provider_inventory_projection");
  assert.deepEqual([...state.artifacts.keys()], ["lmstudio.model", "other"]);
  assert.deepEqual([...state.endpoints.keys()], ["endpoint.provider.lmstudio.model", "endpoint.other"]);
  assert.deepEqual([...state.instances.keys()], ["instance.lmstudio", "instance.other"]);
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
