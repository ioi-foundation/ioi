import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function catalogSearch(state, query = {}) {
  return ModelMountingState.prototype.catalogSearch.call(state, query);
}

function enrichCatalogEntryForState(state, entry, options = {}) {
  return ModelMountingState.prototype.enrichCatalogEntry.call(state, entry, options);
}

function storageSummary(state) {
  return ModelMountingState.prototype.storageSummary.call(state);
}

function fakeState() {
  return {
    artifacts: new Map(),
    lastCatalogSearch: null,
    modelRoot: null,
    now: "2026-06-03T23:00:00.000Z",
    catalogProviderPortCalls: 0,
    enrichCatalogEntryCalls: 0,
    storageSummaryCalls: 0,
    catalogProviderPorts() {
      this.catalogProviderPortCalls += 1;
      return [
        {
          id: "catalog.fixture",
          async search({ query, limit, searchedAt }) {
            return {
              status: "available",
              searchedAt,
              results: [
                { id: "entry.1", modelId: `${query}-one`, sourceUrl: "fixture://one" },
                { id: "entry.2", modelId: `${query}-two`, sourceUrl: "fixture://two" },
              ].slice(0, limit),
            };
          },
        },
      ];
    },
    enrichCatalogEntry(entry) {
      this.enrichCatalogEntryCalls += 1;
      return { ...entry, enriched: true };
    },
    nowIso() {
      return this.now;
    },
  };
}

test("storage summary fails closed before JS filesystem scanning", () => {
  const state = fakeState();
  state.modelRoot = "/tmp/ioi-model-storage-fixture";
  state.artifacts.set("artifact.known", {
    id: "artifact.known",
    artifactPath: "/tmp/ioi-model-storage-fixture/known.gguf",
  });

  assert.throws(
    () => storageSummary(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_storage_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.storage.summary");
      assert.equal(error.details.rust_core_boundary, "model_mount.storage");
      assert.equal(error.details.model_root_hash.length, 64);
      assert.deepEqual(error.details.evidence_refs, [
        "public_model_storage_js_facade_retired",
        "rust_daemon_core_model_storage_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.equal(state.artifacts.has("artifact.known"), true);
});

test("catalog search fails closed before JS provider orchestration", async () => {
  const state = fakeState();

  await assert.rejects(
    () => catalogSearch(state, { query: "  LLAMA  ", format: "GGUF", quantization: "Q4", limit: 1 }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_catalog_search_js_orchestrator_retired");
      assert.equal(error.details.operation_kind, "model_catalog.search");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_search");
      assert.equal(error.details.request_field_count, 4);
      assert.deepEqual(error.details.evidence_refs, [
        "model_catalog_search_js_orchestrator_retired",
        "rust_daemon_core_catalog_search_required",
        "agentgres_catalog_projection_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.equal(state.catalogProviderPortCalls, 0);
  assert.equal(state.enrichCatalogEntryCalls, 0);
  assert.equal(state.lastCatalogSearch, null);
});

test("catalog entry enrichment fails closed before JS storage and artifact materialization", () => {
  const state = fakeState();

  assert.throws(
    () => enrichCatalogEntryForState(state, { id: "entry.1", sizeBytes: 10 }, { maxBytes: 20 }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_catalog_variant_enrichment_js_retired");
      assert.equal(error.details.operation_kind, "model_catalog.variant_enrich");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_variant_projection");
      assert.deepEqual(error.details.evidence_refs, [
        "model_catalog_variant_enrichment_js_retired",
        "rust_daemon_core_catalog_variant_projection_required",
        "agentgres_catalog_projection_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.equal(state.storageSummaryCalls, 0);
  assert.equal(state.enrichCatalogEntryCalls, 0);
});
