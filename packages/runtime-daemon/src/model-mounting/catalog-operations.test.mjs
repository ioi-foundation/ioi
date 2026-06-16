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
  const state = {
    artifacts: new Map(),
    lastCatalogSearch: null,
    modelRoot: null,
    now: "2026-06-03T23:00:00.000Z",
    catalogProviderPortCalls: 0,
    enrichCatalogEntryCalls: 0,
    storageSummaryCalls: 0,
    readProjectionCalls: [],
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
  state.modelMountCore = {
    planReadProjection(request) {
      if (request.projection_kind === "storage_summary") {
        state.readProjectionCalls.push({ operation: "storage_summary" });
        return {
          projection: {
            source: "rust_model_mount_storage_summary_projection",
            rust_core_boundary: "model_mount.storage_projection",
            filesystem_scanned: false,
            record_counts: {
              catalog_imports: 0,
              downloads: 0,
              storage_controls: 0,
            },
            evidence_refs: [
              "rust_daemon_core_model_storage_projection",
              "agentgres_model_storage_replay_required",
              "model_mount_storage_summary_js_facade_retired",
            ],
          },
        };
      }
      if (request.projection_kind === "catalog_search") {
        state.readProjectionCalls.push({ query: request.state.catalog_search });
        return {
          projection: {
            source: "rust_model_mount_catalog_search_projection",
            rust_core_boundary: "model_mount.catalog_search",
            result_count: 1,
            results: [
              {
                model_ref: "model://fixture/qwen3",
                inventory_record_id: "provider_inventory_fixture_list_models",
              },
            ],
            evidence_refs: [
              "rust_daemon_core_catalog_search_projection",
              "agentgres_catalog_search_replay_required",
              "model_catalog_search_js_orchestrator_retired",
            ],
          },
        };
      }
      throw new Error(`unexpected read projection: ${request.projection_kind}`);
    },
  };
  return state;
}

test("storage summary delegates to Rust projection before JS filesystem scanning", () => {
  const state = fakeState();
  state.modelRoot = "/tmp/ioi-model-storage-fixture";
  state.artifacts.set("artifact.known", {
    id: "artifact.known",
    artifactPath: "/tmp/ioi-model-storage-fixture/known.gguf",
  });

  const summary = storageSummary(state);

  assert.equal(summary.source, "rust_model_mount_storage_summary_projection");
  assert.equal(summary.rust_core_boundary, "model_mount.storage_projection");
  assert.equal(summary.filesystem_scanned, false);
  assert.deepEqual(summary.record_counts, {
    catalog_imports: 0,
    downloads: 0,
    storage_controls: 0,
  });
  assert.deepEqual(state.readProjectionCalls, [{ operation: "storage_summary" }]);
  assert.equal(state.artifacts.has("artifact.known"), true);
  assert.equal(state.storageSummaryCalls, 0);
});

test("catalog search delegates to Rust projection before JS provider orchestration", async () => {
  const state = fakeState();

  const search = await catalogSearch(state, { query: "  qwen  ", format: "GGUF", quantization: "Q4", limit: 1 });

  assert.equal(search.source, "rust_model_mount_catalog_search_projection");
  assert.equal(search.rust_core_boundary, "model_mount.catalog_search");
  assert.equal(search.results[0].inventory_record_id, "provider_inventory_fixture_list_models");
  assert.equal(state.readProjectionCalls.length, 1);
  assert.deepEqual(state.readProjectionCalls[0].query, {
    query: "qwen",
    format: "GGUF",
    quantization: "Q4",
    limit: 1,
  });
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
