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

test("fixture catalog provider exposes no JS fixture search surface", () => {
  const port = fixtureCatalogProviderPort();

  assert.equal(port.id, "catalog.fixture");
  assert.equal(port.health().status, "available");
  assert.equal(Object.hasOwn(port, "search"), false);
});

test("local manifest catalog projects metadata with no JS manifest search surface", () => {
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
    assert.equal(health.materialPersistence, "metadata_only");
    assert.equal(health.catalogAuthConfigured, false);
    assert.equal(health.catalogAuthScheme, "bearer");
    assert.equal(health.catalogAuthHeaderNameHash, null);
    assert.equal(health.oauthSessionHash, null);
    assert.equal(health.oauthBoundary, null);

    assert.equal(Object.hasOwn(localManifestCatalogProviderPort(state), "search"), false);
  } finally {
    if (previousManifestPath === undefined) {
      delete process.env.IOI_MODEL_CATALOG_MANIFEST_PATH;
    } else {
      process.env.IOI_MODEL_CATALOG_MANIFEST_PATH = previousManifestPath;
    }
  }
});

test("ollama catalog provider ignores JS provider map and exposes no JS search surface", () => {
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

  assert.equal(Object.hasOwn(port, "search"), false);
  assert.equal(driverCalled, false);
});

test("Hugging Face catalog provider projects material-backed health with no JS search surface", () => {
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
    assert.equal(health.materialPersistence, "metadata_only");
    assert.equal(health.runtimeMaterialStatus, "unconfigured");
    assert.equal(health.materialVaultRefHash, null);
    assert.equal(health.catalogAuthConfigured, false);

    assert.equal(Object.hasOwn(port, "search"), false);
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.IOI_MODEL_CATALOG_HF_BASE_URL;
    } else {
      process.env.IOI_MODEL_CATALOG_HF_BASE_URL = previousBaseUrl;
    }
  }
});

test("custom HTTP catalog provider exposes no JS auth or HTTP search surface", () => {
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

    const health = port.health();
    assert.match(health.baseUrlHash, /^[0-9a-f]{64}$/);
    assert.equal(health.materialVaultRefHash, null);
    assert.equal(health.runtimeMaterialStatus, "env_gate");
    assert.equal(health.materialPersistence, "metadata_only");
    assert.equal(health.catalogAuthConfigured, false);
    assert.equal(health.catalogAuthScheme, "bearer");
    assert.equal(Object.hasOwn(port, "search"), false);
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL;
    } else {
      process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL = previousBaseUrl;
    }
  }
});
