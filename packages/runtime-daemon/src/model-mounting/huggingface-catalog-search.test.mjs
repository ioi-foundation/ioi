import assert from "node:assert/strict";
import test from "node:test";

import {
  recordsFromHuggingFacePayload,
  searchHuggingFaceCatalog,
} from "./huggingface-catalog-search.mjs";

function createState({ config = {}, runtimeMaterial = null } = {}) {
  return {
    catalogProviderConfig(providerId) {
      assert.equal(providerId, "catalog.huggingface");
      return config;
    },
    catalogProviderRuntimeMaterial(providerId) {
      assert.equal(providerId, "catalog.huggingface");
      return runtimeMaterial;
    },
  };
}

function deps(overrides = {}) {
  return {
    catalogAuthFailureFields(error) {
      return { failureHash: `failure:${error.message}` };
    },
    catalogAuthFailureStatus() {
      return "auth_failed";
    },
    catalogAuthProviderFields(evidence) {
      return {
        authScheme: evidence?.authScheme ?? null,
        authHeaderNameHash: evidence?.authHeaderNameHash ?? null,
      };
    },
    catalogEntryWithAuth(entry, evidence) {
      return {
        ...entry,
        authEvidenceRefs: evidence?.evidenceRefs ?? [],
      };
    },
    catalogProviderAuthHeaders() {
      return {
        headers: { authorization: "Bearer redacted" },
        evidence: {
          authScheme: "bearer",
          authHeaderNameHash: "hash:authorization",
          evidenceRefs: ["catalog.auth"],
        },
      };
    },
    catalogProviderConfigHealthFields(providerId, config, runtimeMaterial) {
      return {
        providerId,
        materialConfigured: Boolean(config?.materialConfigured),
        runtimeMaterialStatus: runtimeMaterial?.runtimeMaterialStatus ?? null,
      };
    },
    fetchWithTimeout: async () => ({
      ok: true,
      json: async () => [
        { id: "model-a", siblings: [] },
        { id: "model-b", siblings: [] },
      ],
    }),
    huggingFaceCatalogBaseUrl: () => "https://hf.example.test",
    huggingFaceCatalogEntries(record, { baseUrl, searchedAt }) {
      return [
        {
          id: `${record.id}.gguf`,
          modelId: record.id,
          sourceUrl: `${baseUrl}/${record.id}`,
          format: "gguf",
          quantization: record.id === "model-a" ? "Q4_K_M" : "Q8_0",
          searchedAt,
        },
      ];
    },
    liveModelCatalogEnabled: () => true,
    modelCatalogTimeoutMs: () => 1234,
    normalizeScopes: (value, fallback = []) => Array.isArray(value) ? value : fallback,
    stableHash: (value) => `hash:${value}`,
    ...overrides,
  };
}

test("Hugging Face catalog search returns disabled and gated envelopes", async () => {
  const disabled = await searchHuggingFaceCatalog(
    createState({ config: { enabled: false, materialConfigured: true } }),
    { query: "llama", limit: 5 },
    deps(),
  );

  assert.equal(disabled.status, "disabled");
  assert.equal(disabled.materialConfigured, true);
  assert.equal(disabled.baseUrlHash, "hash:https://hf.example.test");
  assert.deepEqual(disabled.evidenceRefs, [
    "huggingface_catalog_adapter_boundary",
    "network_access_opt_in",
  ]);
  assert.deepEqual(disabled.results, []);

  const gated = await searchHuggingFaceCatalog(
    createState({ runtimeMaterial: { runtimeMaterialStatus: "resolved_from_vault" } }),
    { query: "llama", limit: 5 },
    deps({ liveModelCatalogEnabled: () => false }),
  );

  assert.equal(gated.status, "gated");
  assert.equal(gated.runtimeMaterialStatus, "resolved_from_vault");
  assert.deepEqual(gated.results, []);
});

test("Hugging Face catalog search applies auth, filters, and entry auth projection", async () => {
  const calls = [];
  const result = await searchHuggingFaceCatalog(
    createState(),
    {
      query: "llama",
      format: "gguf",
      quantization: "q4",
      limit: 10,
      searchedAt: "2026-06-04T14:00:00.000Z",
    },
    deps({
      fetchWithTimeout: async (url, options) => {
        calls.push({ url: String(url), options });
        return {
          ok: true,
          json: async () => ({ models: [{ id: "model-a" }, { id: "model-b" }] }),
        };
      },
    }),
  );

  assert.equal(calls[0].url, "https://hf.example.test/api/models?search=llama&limit=10");
  assert.equal(calls[0].options.timeoutMs, 1234);
  assert.deepEqual(calls[0].options.headers, { authorization: "Bearer redacted" });
  assert.equal(result.status, "available");
  assert.equal(result.authScheme, "bearer");
  assert.deepEqual(result.evidenceRefs, [
    "huggingface_catalog_adapter_boundary",
    "network_access_opt_in",
    "huggingface_catalog_search",
    "catalog.auth",
  ]);
  assert.deepEqual(result.results, [{
    id: "model-a.gguf",
    modelId: "model-a",
    sourceUrl: "https://hf.example.test/model-a",
    format: "gguf",
    quantization: "Q4_K_M",
    searchedAt: "2026-06-04T14:00:00.000Z",
    authEvidenceRefs: ["catalog.auth"],
  }]);
});

test("Hugging Face catalog search degrades on HTTP errors and fails closed on exceptions", async () => {
  const degraded = await searchHuggingFaceCatalog(
    createState(),
    { query: "llama", limit: 5 },
    deps({
      fetchWithTimeout: async () => ({ ok: false, status: 503 }),
    }),
  );

  assert.equal(degraded.status, "degraded");
  assert.equal(degraded.errorHash, "hash:http:503");
  assert.equal(degraded.authHeaderNameHash, "hash:authorization");
  assert.deepEqual(degraded.results, []);

  const failed = await searchHuggingFaceCatalog(
    createState(),
    { query: "llama", limit: 5 },
    deps({
      catalogProviderAuthHeaders: () => {
        throw new Error("vault unavailable");
      },
    }),
  );

  assert.equal(failed.status, "auth_failed");
  assert.equal(failed.failureHash, "failure:vault unavailable");
  assert.equal(failed.errorHash, "hash:vault unavailable");
  assert.deepEqual(failed.evidenceRefs, [
    "huggingface_catalog_adapter_boundary",
    "network_access_opt_in",
  ]);
});

test("Hugging Face payload normalization supports array, models, results, and empty payloads", () => {
  assert.deepEqual(recordsFromHuggingFacePayload([{ id: "array" }]), [{ id: "array" }]);
  assert.deepEqual(recordsFromHuggingFacePayload({ models: [{ id: "models" }] }), [{ id: "models" }]);
  assert.deepEqual(recordsFromHuggingFacePayload({ results: [{ id: "results" }] }), [{ id: "results" }]);
  assert.deepEqual(recordsFromHuggingFacePayload({}), []);
  assert.deepEqual(recordsFromHuggingFacePayload(null), []);
});
