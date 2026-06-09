import test from "node:test";
import assert from "node:assert/strict";

import {
  customHttpCatalogProviderPort,
  fixtureCatalogProviderPort,
  huggingFaceCatalogBaseUrl,
  huggingFaceCatalogProviderPort,
  localManifestCatalogHealth,
  localManifestCatalogProviderPort,
  ollamaCatalogProviderPort,
} from "./catalog-provider-ports.mjs";

test("fixture catalog provider retires JS fixture search materialization", async () => {
  const port = fixtureCatalogProviderPort();
  const result = await port.search({
    query: "native",
    format: "gguf",
    quantization: "q4",
    searchedAt: "2026-06-03T12:00:00.000Z",
  });

  assert.equal(port.id, "catalog.fixture");
  assert.equal(port.health().status, "available");
  assert.equal(result.status, "configured");
  assert.equal(result.code, "model_catalog_fixture_search_retired");
  assert.equal(result.providerId, "catalog.fixture");
  assert.equal(result.rustCoreBoundary, "model_mount.catalog_provider_search");
  assert.equal(result.evidenceRefs.includes("fixture_catalog_search_js_retired"), true);
  assert.equal(result.evidenceRefs.includes("agentgres_catalog_projection_required"), true);
  assert.deepEqual(result.results, []);
});

test("local manifest catalog projects metadata and retires JS manifest search", async () => {
  const previousManifestPath = process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
  process.env.IOI_MODEL_CATALOG_MANIFEST_PATH = "/models/catalog.json";
  const state = {
    catalogProviderConfig: () => {
      throw new Error("catalogProviderConfig must not feed local manifest port health");
    },
    catalogProviderRuntimeMaterial: () => {
      throw new Error("catalogProviderRuntimeMaterial must not feed local manifest port health");
    },
  };

  try {
    const health = localManifestCatalogHealth(state, ["local_manifest_catalog_adapter"]);
    assert.equal(health.status, "configured");
    assert.equal(health.materialConfigured, true);
    assert.equal(health.runtimeMaterialStatus, "env_gate");
    assert.equal(health.materialVaultRefHash, null);

    const result = await localManifestCatalogProviderPort(state).search({
      query: "demo",
      format: "gguf",
      quantization: "q4",
      searchedAt: "2026-06-03T12:00:00.000Z",
    });

    assert.equal(result.status, "configured");
    assert.equal(result.code, "model_catalog_local_manifest_search_retired");
    assert.equal(result.providerId, "catalog.local_manifest");
    assert.equal(result.rustCoreBoundary, "model_mount.catalog_provider_search");
    assert.equal(result.evidenceRefs.includes("local_manifest_catalog_search_js_retired"), true);
    assert.equal(result.evidenceRefs.includes("agentgres_catalog_projection_required"), true);
    assert.deepEqual(result.results, []);
  } finally {
    if (previousManifestPath === undefined) {
      delete process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
    } else {
      process.env.IOI_MODEL_CATALOG_MANIFEST_PATH = previousManifestPath;
    }
  }
});

test("ollama catalog provider ignores JS provider map and retires bridge search", async () => {
  const providerMap = {
    get() {
      throw new Error("Ollama catalog provider port must not read JS provider inventory");
    },
  };
  let driverCalled = false;
  const port = ollamaCatalogProviderPort({
    providers: providerMap,
    driverForProvider() {
      driverCalled = true;
      throw new Error("Ollama catalog bridge must not call JS provider driver inventory");
    },
  });

  const health = port.health();
  assert.equal(health.status, "gated");
  assert.equal(health.baseUrlHash, null);
  assert.equal(health.rustCoreBoundary, "model_mount.catalog_provider_projection");

  const result = await port.search({ query: "llama", format: "ollama", searchedAt: "2026-06-03T12:00:00.000Z" });
  assert.equal(result.status, "gated");
  assert.equal(result.baseUrlHash, null);
  assert.equal(result.rustCoreBoundary, "model_mount.catalog_provider_search");
  assert.deepEqual(result.results, []);
  assert.equal(result.evidenceRefs.includes("ollama_catalog_js_driver_bridge_retired"), true);
  assert.equal(result.evidenceRefs.includes("ollama_catalog_provider_map_readback_retired"), true);
  assert.equal(driverCalled, false);
});

test("Hugging Face catalog provider projects material-backed health and retires live JS search", async () => {
  const previousBaseUrl = process.env.IOI_MODEL_CATALOG_HF_BASE_URL;
  process.env.IOI_MODEL_CATALOG_HF_BASE_URL = "https://hf.example.test";
  const state = {
    catalogProviderConfig: () => {
      throw new Error("catalogProviderConfig must not feed Hugging Face port health");
    },
    catalogProviderRuntimeMaterial: () => {
      throw new Error("catalogProviderRuntimeMaterial must not feed Hugging Face port health");
    },
  };

  try {
    assert.equal(huggingFaceCatalogBaseUrl(state), "https://hf.example.test");
    const port = huggingFaceCatalogProviderPort(state);
    const health = port.health();
    assert.equal(health.gate, "IOI_MODEL_CATALOG_HF_BASE_URL");
    assert.equal(health.materialConfigured, false);
    assert.equal(health.materialVaultRefHash, null);

    const result = await port.search({
      query: "llama",
      format: "gguf",
      quantization: "q4",
      limit: 5,
      searchedAt: "2026-06-09T12:00:00.000Z",
    });
    assert.equal(result.status, "gated");
    assert.equal(result.code, "model_catalog_live_http_search_retired");
    assert.equal(result.providerId, "catalog.huggingface");
    assert.equal(result.rustCoreBoundary, "model_mount.catalog_provider_search");
    assert.equal(result.evidenceRefs.includes("catalog_live_http_search_js_retired"), true);
    assert.equal(result.evidenceRefs.includes("rust_daemon_core_catalog_search_required"), true);
    assert.deepEqual(result.results, []);
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.IOI_MODEL_CATALOG_HF_BASE_URL;
    } else {
      process.env.IOI_MODEL_CATALOG_HF_BASE_URL = previousBaseUrl;
    }
  }
});

test("custom HTTP catalog provider retires live JS auth and HTTP search", async () => {
  const previousBaseUrl = process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL;
  process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL = "https://catalog.example.test";
  const state = {
    catalogProviderConfig(providerId) {
      assert.equal(providerId, "catalog.custom_http");
      throw new Error("catalogProviderConfig must not feed custom HTTP port health");
    },
    catalogProviderRuntimeMaterial(providerId) {
      assert.equal(providerId, "catalog.custom_http");
      throw new Error("catalogProviderRuntimeMaterial must not feed custom HTTP port health");
    },
  };
  try {
    const port = customHttpCatalogProviderPort(state);

    const result = await port.search({
      query: "llama",
      format: "gguf",
      quantization: "q4",
      limit: 5,
      searchedAt: "2026-06-09T12:00:00.000Z",
    });

    assert.equal(result.status, "configured");
    assert.equal(result.code, "model_catalog_live_http_search_retired");
    assert.equal(result.providerId, "catalog.custom_http");
    assert.match(result.baseUrlHash, /^[0-9a-f]{64}$/);
    assert.equal(result.materialVaultRefHash, null);
    assert.equal(result.runtimeMaterialStatus, "env_gate");
    assert.equal(result.evidenceRefs.includes("catalog_live_http_search_js_retired"), true);
    assert.equal(result.evidenceRefs.includes("agentgres_catalog_projection_required"), true);
    assert.deepEqual(result.results, []);
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL;
    } else {
      process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL = previousBaseUrl;
    }
  }
});
