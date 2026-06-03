import test from "node:test";
import assert from "node:assert/strict";

import {
  catalogEntryMatches,
  catalogRecordsFromPayload,
  catalogVariantForSource,
  fixtureModelCatalog,
  genericCatalogEntry,
  huggingFaceCatalogEntries,
} from "./catalog-entries.mjs";

test("catalog payload records accept supported envelope shapes", () => {
  assert.deepEqual(catalogRecordsFromPayload([{ id: "direct" }]), [{ id: "direct" }]);
  assert.deepEqual(catalogRecordsFromPayload({ models: [{ id: "model" }] }), [{ id: "model" }]);
  assert.deepEqual(catalogRecordsFromPayload({ results: [{ id: "result" }] }), [{ id: "result" }]);
  assert.deepEqual(catalogRecordsFromPayload({ entries: [{ id: "entry" }] }), [{ id: "entry" }]);
  assert.deepEqual(catalogRecordsFromPayload({ catalog: [{ id: "catalog" }] }), [{ id: "catalog" }]);
  assert.deepEqual(catalogRecordsFromPayload({ nope: [] }), []);
});

test("generic and Hugging Face catalog entries normalize public metadata", () => {
  const searchedAt = "2026-06-03T00:00:00.000Z";
  const generic = genericCatalogEntry(
    {
      model_id: "demo/model-7b",
      source_url: "https://catalog.example.test/demo/model-Q4_K_M.gguf",
      tags: ["chat"],
    },
    { catalogProviderId: "catalog.custom_http", sourceLabelPrefix: "Custom catalog", searchedAt },
  );

  assert.equal(generic.modelId, "demo/model-7b");
  assert.equal(generic.format, "gguf");
  assert.equal(generic.quantization, "Q4_K_M");
  assert.equal(generic.parameterCount, "7B");
  assert.deepEqual(generic.compatibility, ["native_local_fixture", "llama_cpp"]);
  assert.equal(catalogEntryMatches(generic, { query: "demo", format: "gguf", quantization: "q4" }), true);

  const [huggingFace] = huggingFaceCatalogEntries(
    {
      id: "org/model-3b",
      siblings: [{ rfilename: "model-Q8_0.gguf", size: 1234 }],
      tags: ["code"],
    },
    { baseUrl: "https://huggingface.co", searchedAt },
  );

  assert.equal(huggingFace.modelId, "org/model-3b");
  assert.equal(huggingFace.sourceUrl, "https://huggingface.co/org/model-3b/resolve/main/model-Q8_0.gguf");
  assert.equal(huggingFace.quantization, "Q8_0");
  assert.deepEqual(huggingFace.gatedBy, ["IOI_LIVE_MODEL_CATALOG", "IOI_LIVE_MODEL_DOWNLOAD"]);
});

test("fixture catalog variants are enriched with selection receipt fields", () => {
  const fixture = fixtureModelCatalog("2026-06-03T00:00:00.000Z")[0];
  const variant = catalogVariantForSource(fixture.sourceUrl);

  assert.equal(variant.id, fixture.id);
  assert.equal(variant.format, "gguf");
  assert.equal(variant.recommendation.primaryBackend, "native_local_fixture");
  assert.equal(variant.downloadRisk.status, "low");
  assert.ok(variant.selectionReceiptFields.includes("backend_compatibility"));
});
