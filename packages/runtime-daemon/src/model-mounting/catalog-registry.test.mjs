import test from "node:test";
import assert from "node:assert/strict";

import {
  catalogProviderStatus,
  modelCatalogProviderPorts,
} from "./catalog-registry.mjs";

test("model catalog registry keeps provider ordering stable", () => {
  const ports = modelCatalogProviderPorts({
    state: { id: "state" },
    fixtureCatalogProviderPort: () => ({ id: "catalog.fixture" }),
    localManifestCatalogProviderPort: (state) => ({ id: "catalog.local_manifest", state }),
    ollamaCatalogProviderPort: () => ({ id: "catalog.ollama" }),
    huggingFaceCatalogProviderPort: () => ({ id: "catalog.huggingface" }),
    customHttpCatalogProviderPort: () => ({ id: "catalog.custom_http" }),
  });

  assert.deepEqual(ports.map((port) => port.id), [
    "catalog.fixture",
    "catalog.local_manifest",
    "catalog.ollama",
    "catalog.huggingface",
    "catalog.custom_http",
  ]);
  assert.deepEqual(ports[1].state, { id: "state" });
});

test("catalog provider status merges public health and result fields", () => {
  const status = catalogProviderStatus(
    {
      id: "catalog.custom_http",
      label: "Custom HTTP catalog",
      gate: "configured",
      formats: ["gguf"],
      evidenceRefs: ["model_catalog_provider_port"],
      health: () => ({
        status: "configured",
        baseUrlHash: "health-base",
        materialConfigured: true,
      }),
    },
    {
      status: "available",
      baseUrlHash: "result-base",
      evidenceRefs: ["custom_http_catalog_search"],
    },
  );

  assert.equal(status.id, "catalog.custom_http");
  assert.equal(status.status, "available");
  assert.equal(status.baseUrlHash, "result-base");
  assert.equal(status.materialConfigured, true);
  assert.deepEqual(status.evidenceRefs, ["custom_http_catalog_search"]);
  assert.deepEqual(status.operations, ["search", "resolveVariant", "importUrl", "download", "health"]);
});
