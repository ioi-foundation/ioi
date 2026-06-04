import assert from "node:assert/strict";
import test from "node:test";

import {
  importModel,
  mountEndpoint,
  unmountEndpoint,
} from "./artifact-endpoint-operations.mjs";

function fakeState() {
  return {
    artifacts: new Map(),
    endpoints: new Map(),
    modelRoot: "/models",
    receipts: [],
    writes: [],
    projections: 0,
    now: "2026-06-03T23:30:00.000Z",
    backendRegistry() {
      return [{ id: "backend.native", kind: "native_local" }];
    },
    endpoint(endpointId) {
      const endpoint = this.endpoints.get(endpointId);
      if (!endpoint) throw new Error(`missing endpoint ${endpointId}`);
      return endpoint;
    },
    getModel(modelId) {
      return [...this.artifacts.values()].find((artifact) => artifact.modelId === modelId);
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    modelForProviderMount(modelId, provider, body, now) {
      return {
        id: `provider-artifact.${modelId}`,
        modelId,
        providerId: provider.id,
        capabilities: body.capabilities ?? ["chat"],
        artifactPath: null,
        mountedAt: now,
      };
    },
    nowIso() {
      return this.now;
    },
    provider(providerId) {
      return {
        id: providerId,
        kind: providerId === "provider.fixture" ? "fixture" : "custom_http",
        apiFormat: "openai",
        driver: providerId === "provider.fixture" ? "fixture" : "openai_compatible",
        baseUrl: providerId === "provider.fixture" ? null : "http://127.0.0.1:8080/v1",
        privacyClass: "workspace",
      };
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

const deps = {
  defaultBackendForProvider(provider) {
    return provider.kind === "fixture" ? "backend.native" : "backend.remote";
  },
  driverForProviderKind(kind) {
    return kind === "fixture" ? "fixture" : "openai_compatible";
  },
  importTargetPath(root, modelId, sourcePath) {
    return `${root}/${modelId}/${sourcePath.split("/").pop()}`;
  },
  inspectLocalArtifact(sourcePath) {
    return {
      path: sourcePath,
      sizeBytes: 123,
      checksum: `checksum:${sourcePath}`,
    };
  },
  materializeImportArtifact(root, modelId, sourcePath, importMode) {
    assert.equal(importMode, "copy");
    return `${root}/${modelId}/${sourcePath.split("/").pop()}`;
  },
  normalizeImportMode(value) {
    return value ?? "operator";
  },
  normalizeLoadPolicy(value) {
    return { mode: value ?? "on_demand" };
  },
  normalizeScopes(value, fallback = []) {
    return Array.isArray(value) ? value : fallback;
  },
  parseLocalModelMetadata(filePath) {
    return {
      family: "llama",
      format: filePath.endsWith(".gguf") ? "gguf" : null,
      quantization: "Q4_K_M",
      contextWindow: 8192,
    };
  },
  requiredString(value, field) {
    if (typeof value !== "string" || !value) throw new Error(`${field} is required`);
    return value;
  },
  runtimeError({ status, code, message }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, "_");
  },
  schemaVersion: "schema.artifact-endpoint.test",
  stableHash(value) {
    return `hash:${value}`;
  },
};

test("model import dry-run returns hashes and receipt without mutating artifacts", () => {
  const state = fakeState();

  const result = importModel(
    state,
    { model_id: "llama-test", path: "/tmp/model.gguf", import_mode: "dry_run" },
    deps,
  );

  assert.equal(result.schemaVersion, "schema.artifact-endpoint.test");
  assert.equal(result.status, "dry_run");
  assert.equal(result.sourcePathHash, "hash:/tmp/model.gguf");
  assert.equal(result.targetPathHash, "hash:/models/llama-test/model.gguf");
  assert.equal(result.metadata.family, "llama");
  assert.equal(result.receiptId, "receipt.model_import_dry_run.1");
  assert.equal(state.artifacts.size, 0);
});

test("model import materializes local artifacts and writes projection", () => {
  const state = fakeState();

  const artifact = importModel(
    state,
    { model_id: "llama-test", path: "/tmp/model.gguf", import_mode: "copy", capabilities: ["chat", "embeddings"] },
    deps,
  );

  assert.equal(artifact.id, "import.llama_test");
  assert.equal(artifact.artifactPath, "/models/llama-test/model.gguf");
  assert.deepEqual(artifact.capabilities, ["chat", "embeddings"]);
  assert.equal(artifact.backendRegistry[0].id, "backend.native");
  assert.equal(state.artifacts.get(artifact.id), artifact);
  assert.equal(state.writes.at(-1)[0], "model-artifacts");
  assert.equal(state.receipts.at(-1).kind, "model_import");
  assert.equal(state.projections, 1);
});

test("mount endpoint derives provider, artifact, backend, load policy, and receipt", () => {
  const state = fakeState();
  state.artifacts.set("artifact.llama", {
    id: "artifact.llama",
    providerId: "provider.fixture",
    modelId: "llama-test",
    capabilities: ["chat"],
    artifactPath: "/models/llama-test/model.gguf",
  });

  const endpoint = mountEndpoint(state, { model_id: "llama-test", load_policy: "resident" }, deps);

  assert.equal(endpoint.id, "endpoint.provider_fixture.llama_test");
  assert.equal(endpoint.providerId, "provider.fixture");
  assert.equal(endpoint.baseUrl, "local://ioi-daemon/model-fixture");
  assert.equal(endpoint.backendId, "backend.native");
  assert.deepEqual(endpoint.loadPolicy, { mode: "resident" });
  assert.equal(state.endpoints.get(endpoint.id), endpoint);
  assert.equal(state.receipts.at(-1).kind, "model_mount");
});

test("mount endpoint validates explicit model id and supports provider mount fallback", () => {
  const state = fakeState();

  assert.throws(() => mountEndpoint(state, {}, deps), (error) => error.status === 400 && error.code === "model_id_required");

  const endpoint = mountEndpoint(
    state,
    { model_id: "remote-model", provider_id: "provider.remote", id: "endpoint.remote" },
    deps,
  );
  assert.equal(endpoint.id, "endpoint.remote");
  assert.equal(endpoint.artifactId, "provider-artifact.remote-model");
  assert.equal(endpoint.baseUrl, "http://127.0.0.1:8080/v1");
});

test("unmount endpoint updates status and emits receipt", () => {
  const state = fakeState();
  state.endpoints.set("endpoint.a", {
    id: "endpoint.a",
    providerId: "provider.fixture",
    modelId: "llama-test",
    status: "mounted",
  });

  const result = unmountEndpoint(state, { endpoint_id: "endpoint.a" }, deps);

  assert.equal(result.status, "unmounted");
  assert.equal(result.unmountedAt, state.now);
  assert.equal(state.endpoints.get("endpoint.a").status, "unmounted");
  assert.equal(state.writes.at(-1)[0], "model-endpoints");
  assert.equal(state.receipts.at(-1).kind, "model_unmount");
});
