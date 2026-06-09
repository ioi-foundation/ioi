import assert from "node:assert/strict";
import test from "node:test";

import {
  catalogSearch,
  catalogStatus,
  catalogStatusProjectionInput,
  enrichCatalogEntryForState,
  storageSummary,
} from "./catalog-operations.mjs";

function fakeState() {
  return {
    artifacts: new Map([
      ["artifact.known", { id: "artifact.known", artifactPath: "/models/known.gguf" }],
    ]),
    lastCatalogSearch: null,
    modelRoot: "/models",
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
    storageSummary() {
      this.storageSummaryCalls += 1;
      return storageSummary(this, storageDeps());
    },
  };
}

function storageDeps(env = { IOI_MODEL_STORAGE_QUOTA_BYTES: "12" }) {
  const sizes = new Map([
    ["/models/known.gguf", 5],
    ["/models/orphan.gguf", 10],
  ]);
  return {
    env,
    listModelFiles(root) {
      assert.equal(root, "/models");
      return [...sizes.keys()];
    },
    statSync(filePath) {
      return { size: sizes.get(filePath) };
    },
    stableHash(value) {
      return `hash:${value}`;
    },
  };
}

const deps = {
  catalogProviderStatus(port, result = null) {
    return {
      id: port.id,
      status: result?.status ?? port.status ?? "unknown",
      searchedAt: result?.searchedAt ?? null,
    };
  },
  normalizeLimit(value, fallback, max) {
    const parsed = Number(value ?? fallback);
    return Math.min(max, Number.isFinite(parsed) && parsed > 0 ? parsed : fallback);
  },
  schemaVersion: "schema.catalog-ops.test",
};

test("storage summary counts bytes, quota, and orphan model files", () => {
  const state = fakeState();

  const summary = storageSummary(state, storageDeps());

  assert.equal(summary.rootHash, "hash:/models");
  assert.equal(summary.totalBytes, 15);
  assert.equal(summary.quotaBytes, 12);
  assert.equal(summary.quotaStatus, "over_quota");
  assert.equal(summary.fileCount, 2);
  assert.equal(summary.orphanCount, 1);
  assert.deepEqual(summary.evidenceRefs, ["model_storage_quota_boundary", "artifact_delete_unload_guard"]);
});

test("catalog status fails closed before JS status readback", () => {
  const state = fakeState();
  state.lastCatalogSearch = {
    searchedAt: "2026-06-03T22:59:00.000Z",
    query: "llama",
    filters: { limit: 2 },
    results: [{ id: "entry.1" }, { id: "entry.2" }],
  };

  assert.throws(
    () => catalogStatus(state, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_catalog_status_js_readback_retired");
      assert.equal(error.details.operation_kind, "model_catalog.status");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_status_projection");
      assert.deepEqual(error.details.evidence_refs, [
        "model_catalog_status_js_readback_retired",
        "rust_daemon_core_catalog_status_projection_required",
        "agentgres_catalog_projection_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.equal(state.catalogProviderPortCalls, 0);
  assert.equal(state.storageSummaryCalls, 0);
});

test("catalog status projection input fails closed before JS provider and storage materialization", () => {
  const state = fakeState();
  state.lastCatalogSearch = {
    searchedAt: "2026-06-03T22:59:00.000Z",
    query: "llama",
    filters: { limit: 2 },
    results: [{ id: "entry.1" }, { id: "entry.2" }],
  };

  assert.throws(
    () => catalogStatusProjectionInput(state, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_catalog_status_js_readback_retired");
      assert.equal(error.details.operation_kind, "model_catalog.status");
      return true;
    },
  );
  assert.equal(state.catalogProviderPortCalls, 0);
  assert.equal(state.storageSummaryCalls, 0);
});

test("catalog search fails closed before JS provider orchestration", async () => {
  const state = fakeState();

  await assert.rejects(
    () => catalogSearch(state, { query: "  LLAMA  ", format: "GGUF", quantization: "Q4", limit: 1 }, deps),
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
    () => enrichCatalogEntryForState(state, { id: "entry.1", sizeBytes: 10 }, { maxBytes: 20 }, deps),
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
