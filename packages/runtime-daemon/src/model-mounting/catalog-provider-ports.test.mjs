import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  fixtureCatalogProviderPort,
  huggingFaceCatalogBaseUrl,
  huggingFaceCatalogProviderPort,
  localManifestCatalogHealth,
  localManifestCatalogProviderPort,
  ollamaCatalogProviderPort,
} from "./catalog-provider-ports.mjs";

test("fixture catalog provider exposes filtered fixture results", async () => {
  const port = fixtureCatalogProviderPort();
  const result = await port.search({
    query: "native",
    format: "gguf",
    quantization: "q4",
    searchedAt: "2026-06-03T12:00:00.000Z",
  });

  assert.equal(port.id, "catalog.fixture");
  assert.equal(result.status, "available");
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].modelId, "autopilot/native-fixture-3b");
});

test("local manifest catalog health and search use configured runtime material", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-"));
  const manifestPath = path.join(tempDir, "catalog.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify({
      models: [
        {
          model_id: "demo/model-7b",
          source_url: "https://catalog.example.test/demo/model-Q4_K_M.gguf",
          tags: ["chat"],
        },
      ],
    }),
  );
  const state = {
    catalogProviderConfig: () => ({ id: "catalog.local_manifest", enabled: true }),
    catalogProviderRuntimeMaterial: () => ({
      manifestPath,
      runtimeMaterialStatus: "bound_runtime_session",
      materialVaultRefHash: "hash-material",
      materialSource: "runtime_memory",
    }),
  };

  const health = localManifestCatalogHealth(state, ["local_manifest_catalog_adapter"]);
  assert.equal(health.status, "configured");
  assert.equal(health.materialConfigured, true);
  assert.equal(health.materialVaultRefHash, "hash-material");

  const result = await localManifestCatalogProviderPort(state).search({
    query: "demo",
    format: "gguf",
    quantization: "q4",
    searchedAt: "2026-06-03T12:00:00.000Z",
  });

  assert.equal(result.status, "available");
  assert.equal(result.results[0].modelId, "demo/model-7b");
});

test("ollama catalog provider reports gated and configured bridge states", async () => {
  const gated = ollamaCatalogProviderPort({ providers: new Map() });
  assert.equal(gated.health().status, "gated");

  const provider = { id: "provider.ollama", baseUrl: "http://127.0.0.1:11434", status: "configured" };
  let driverCalled = false;
  const configured = ollamaCatalogProviderPort({
    providers: new Map([["provider.ollama", provider]]),
    driverForProvider() {
      driverCalled = true;
      throw new Error("Ollama catalog bridge must not call JS provider driver inventory");
    },
  });

  assert.equal(configured.health().status, "configured");
  const result = await configured.search({ query: "llama", format: "ollama", searchedAt: "2026-06-03T12:00:00.000Z" });
  assert.equal(result.status, "configured");
  assert.deepEqual(result.results, []);
  assert.equal(result.evidenceRefs.includes("ollama_catalog_js_driver_bridge_retired"), true);
  assert.equal(driverCalled, false);
});

test("Hugging Face catalog provider projects material-backed health", () => {
  const material = {
    baseUrl: "https://hf.example.test",
    runtimeMaterialStatus: "bound_runtime_session",
    materialVaultRefHash: "hash-material",
    materialSource: "runtime_memory",
  };
  const state = {
    catalogProviderConfig: () => ({ id: "catalog.huggingface", enabled: true }),
    catalogProviderRuntimeMaterial: () => material,
    searchHuggingFaceCatalog: async () => ({ results: [] }),
  };

  assert.equal(huggingFaceCatalogBaseUrl(state), "https://hf.example.test");
  const health = huggingFaceCatalogProviderPort(state).health();
  assert.equal(health.gate, "vault-backed Hugging Face-compatible catalog setup");
  assert.equal(health.materialConfigured, true);
  assert.equal(health.materialVaultRefHash, "hash-material");
});
