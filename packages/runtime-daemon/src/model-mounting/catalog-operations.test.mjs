import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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

test("storage summary counts bytes, quota, and orphan model files", () => {
  const previousQuota = process.env.IOI_MODEL_STORAGE_QUOTA_BYTES;
  const modelRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-storage-"));
  const state = fakeState();
  state.modelRoot = modelRoot;
  const knownPath = path.join(modelRoot, "known.gguf");
  const orphanPath = path.join(modelRoot, "nested", "orphan.gguf");
  fs.mkdirSync(path.dirname(orphanPath), { recursive: true });
  fs.writeFileSync(knownPath, "12345");
  fs.writeFileSync(orphanPath, "1234567890");
  state.artifacts.set("artifact.known", { id: "artifact.known", artifactPath: knownPath });
  process.env.IOI_MODEL_STORAGE_QUOTA_BYTES = "12";
  try {
    const summary = storageSummary(state);

    assert.equal(summary.rootHash.length, 64);
    assert.equal(summary.totalBytes, 15);
    assert.equal(summary.quotaBytes, 12);
    assert.equal(summary.quotaStatus, "over_quota");
    assert.equal(summary.fileCount, 2);
    assert.equal(summary.orphanCount, 1);
    assert.deepEqual(summary.evidenceRefs, ["model_storage_quota_boundary", "artifact_delete_unload_guard"]);
  } finally {
    if (previousQuota === undefined) delete process.env.IOI_MODEL_STORAGE_QUOTA_BYTES;
    else process.env.IOI_MODEL_STORAGE_QUOTA_BYTES = previousQuota;
    fs.rmSync(modelRoot, { recursive: true, force: true });
  }
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
