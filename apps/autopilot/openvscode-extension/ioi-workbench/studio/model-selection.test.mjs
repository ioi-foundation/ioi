import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioModelSelection } = require("./model-selection.js");

function stringValue(value, fallback = "") {
  return typeof value === "string" ? value.trim() || fallback : fallback;
}

function createSelection({ env = {}, projection = {} } = {}) {
  return createStudioModelSelection({
    daemonEndpoint: () => "http://127.0.0.1:4111",
    firstArray: (value) => Array.isArray(value) ? value : [],
    getEnv: (name) => env[name],
    getStudioRuntimeProjection: () => ({
      modelRoute: "route.local-first",
      selectedModel: "",
      reasoningEffort: "",
      ...projection,
    }),
    isAutoStudioModelSelector: (value) => {
      const normalized = stringValue(value, "auto").toLowerCase();
      return normalized === "auto" || normalized === "local:auto" || normalized === "default";
    },
    modelDisplayName: (artifact = {}) => artifact.name || artifact.label || artifact.modelId || artifact.id || "Unknown model",
    modelEndpointForArtifact: (snapshot, artifact) =>
      snapshot.endpoints.find((endpoint) =>
        endpoint.artifactId === artifact.id ||
        endpoint.artifact_id === artifact.id ||
        endpoint.modelId === artifact.modelId ||
        endpoint.model_id === artifact.modelId,
      ),
    modelInstanceForEndpoint: (snapshot, endpoint = {}) =>
      snapshot.instances.find((instance) => instance.endpointId === endpoint.id),
    modelSnapshotFromState: (state = {}) => {
      const snapshot = state.modelMounting || {};
      return {
        artifacts: Array.isArray(snapshot.artifacts) ? snapshot.artifacts : [],
        endpoints: Array.isArray(snapshot.endpoints) ? snapshot.endpoints : [],
        instances: Array.isArray(snapshot.instances) ? snapshot.instances : [],
        routes: Array.isArray(snapshot.routes) ? snapshot.routes : [],
      };
    },
    productModelUnavailable: "__product_model_unavailable__",
    stringValue,
    studioDefaultArtifactMaxOutputTokens: 4096,
    studioDefaultMaxOutputTokens: 4096,
    studioFixtureModelUsageAllowed: () => /^(1|true|yes|on)$/i.test(String(env.IOI_STUDIO_ALLOW_FIXTURE_MODELS || "")),
    studioTextContainsProductFixtureMarker: (value = "") => /local:auto|fixture|stories260k/i.test(stringValue(value)),
  });
}

test("product model selection rejects fixture, external, auto, and embedding-only records", () => {
  const selection = createSelection();

  assert.equal(selection.isFixtureStudioModelRecord({ modelId: "local:auto" }), true);
  assert.equal(selection.isExternalStudioModelRecord({ providerId: "provider.ollama" }), true);
  assert.equal(selection.isProductStudioModelSelection({
    artifact: { id: "real", modelId: "real-chat", capabilities: ["chat"] },
    endpoint: { id: "endpoint-real", modelId: "real-chat", capabilities: ["chat"] },
    route: { id: "route.local-first", modelId: "real-chat" },
  }), true);
  assert.equal(selection.isProductStudioModelSelection({
    artifact: { id: "auto", modelId: "local:auto", capabilities: ["chat"] },
    endpoint: { modelId: "local:auto", capabilities: ["chat"] },
  }), false);
  assert.equal(selection.isProductStudioModelSelection({
    artifact: { id: "embed", modelId: "embedder", capabilities: ["embeddings"] },
    endpoint: { modelId: "embedder", capabilities: ["embeddings"] },
  }), false);
  assert.equal(selection.isProductStudioModelSelection({
    artifact: { id: "ollama", modelId: "llama3", providerId: "provider.ollama", capabilities: ["chat"] },
    endpoint: { modelId: "llama3", capabilities: ["chat"] },
  }), false);
});

test("external provider gate and fixture policy errors respect injected environment", () => {
  const gated = createSelection();
  assert.equal(gated.isExternalStudioModelRecord({ providerId: "provider.lmstudio" }), true);
  assert.equal(gated.studioProductModelSelectionError("route.local-first", "local:auto")?.code, "product_model_unavailable");

  const allowed = createSelection({
    env: {
      IOI_STUDIO_ALLOW_EXTERNAL_MODEL_PROVIDERS: "true",
      IOI_STUDIO_ALLOW_FIXTURE_MODELS: "true",
    },
  });
  assert.equal(allowed.isExternalStudioModelRecord({ providerId: "provider.lmstudio" }), false);
  assert.equal(allowed.studioProductModelSelectionError("route.local-first", "local:auto"), null);
});

test("reasoning effort and token bounds preserve product control defaults", () => {
  const selection = createSelection({
    env: {
      IOI_STUDIO_MAX_OUTPUT_TOKENS: "99999",
      IOI_STUDIO_ARTIFACT_MAX_OUTPUT_TOKENS: "600",
    },
    projection: {
      reasoningEffort: "high",
    },
  });

  assert.equal(selection.normalizeStudioReasoningEffort("provider_default", "low"), "low");
  assert.equal(selection.normalizeStudioReasoningEffort("disabled", "high"), "none");
  assert.equal(selection.normalizeStudioReasoningEffort("xhigh", "none"), "xhigh");
  assert.equal(selection.studioMaxOutputTokens(), 8192);
  assert.equal(selection.studioArtifactMaxOutputTokens(), 600);
  assert.match(selection.studioReasoningEffortOptions("medium"), /value="medium" selected/);
  assert.deepEqual(selection.studioReasoningControlForSelection({
    artifact: { modelId: "qwen/qwen3.5", capabilities: ["chat"] },
  }), {
    supported: true,
    effort: "high",
  });
});

test("preferred model selection favors active product route then mounted quick pick rows", () => {
  const selection = createSelection();
  const state = {
    modelMountingStatus: { status: "ready", endpoint: "http://daemon.local" },
    modelMounting: {
      artifacts: [
        { id: "fixture", modelId: "local:auto", name: "Fixture", capabilities: ["chat"] },
        { id: "real-a", modelId: "real-a", name: "Real A", providerId: "provider.llama", capabilities: ["chat"] },
        { id: "real-b", modelId: "real-b", name: "Real B", providerId: "provider.local", capabilities: ["chat"] },
      ],
      endpoints: [
        { id: "endpoint-a", artifactId: "real-a", modelId: "real-a", status: "loaded" },
        { id: "endpoint-b", artifactId: "real-b", modelId: "real-b", status: "loaded" },
      ],
      instances: [
        { id: "instance-a", endpointId: "endpoint-a", modelId: "real-a", status: "loaded" },
        { id: "instance-b", endpointId: "endpoint-b", modelId: "real-b", status: "ready" },
      ],
      routes: [
        { id: "route.local-first", endpointId: "endpoint-b", modelId: "real-b", status: "ready" },
        { id: "route.other", endpointId: "endpoint-a", modelId: "real-a", status: "ready" },
      ],
    },
  };

  const snapshot = selection.studioSnapshotFromState(state);
  assert.equal(snapshot.selectedModel, "real-b");
  assert.equal(snapshot.modelLabel, "Real B");
  assert.equal(snapshot.modelUnavailable, false);
  assert.equal(snapshot.endpointId, "endpoint-b");

  const rows = selection.mountedModelQuickInputRowsFromState(state);
  assert.deepEqual(rows.map((row) => row.modelId), ["real-a", "real-b"]);
  assert.equal(rows[1].routeId, "route.local-first");
  assert.equal(rows[1].instanceId, "instance-b");
});

test("product selection and loaded instance projection dedupe overview counts", () => {
  const selection = createSelection();
  const snapshot = {
    artifacts: [
      { id: "real-a", modelId: "real-a", name: "Real A", capabilities: ["chat"] },
      { id: "real-a-duplicate", modelId: "real-a", name: "Real A duplicate", capabilities: ["chat"] },
      { id: "fixture", modelId: "local:auto", name: "Fixture", capabilities: ["chat"] },
    ],
    endpoints: [
      { id: "endpoint-a", artifactId: "real-a", modelId: "real-a", routeId: "route-a" },
      { id: "endpoint-a-duplicate", artifactId: "real-a-duplicate", modelId: "real-a", routeId: "route-a-dup" },
    ],
    routes: [
      { id: "route-a", endpointId: "endpoint-a", modelId: "real-a" },
      { id: "route-a-dup", endpointId: "endpoint-a-duplicate", modelId: "real-a" },
    ],
    instances: [
      { id: "instance-a", endpointId: "endpoint-a", modelId: "real-a", status: "loaded" },
      { id: "instance-a", endpointId: "endpoint-a", modelId: "real-a", status: "running" },
      { id: "instance-stopped", endpointId: "endpoint-a", modelId: "real-a", status: "stopped" },
    ],
  };

  const selections = selection.productStudioModelSelectionsFromSnapshot(snapshot);
  assert.equal(selections.length, 1);
  assert.equal(selections[0].artifact.id, "real-a");

  const loaded = selection.loadedProductStudioModelInstances(snapshot, selections);
  assert.deepEqual(loaded.map((instance) => instance.id), ["instance-a"]);
});
