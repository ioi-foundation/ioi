import assert from "node:assert/strict";
import test from "node:test";

import {
  catalogImportUrl,
  downloadModel,
} from "./catalog-download-operations.mjs";

function fakeState() {
  return {
    artifacts: new Map(),
    downloads: new Map(),
    projections: 0,
    recordStateCommits: [],
    receipts: [],
    writes: [],
    async downloadModel(body) {
      this.downloadBody = body;
      return { status: "queued", id: "download.queued" };
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${this.receipts.length + 1}.${kind}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    nowIso() {
      this.timestamped = true;
      return "2026-06-04T12:00:00.000Z";
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
      };
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

function deps(overrides = {}) {
  return {
    requiredString(value, field) {
      if (typeof value !== "string" || !value.trim()) {
        throw Object.assign(new Error(`${field} required`), { status: 400 });
      }
      return value;
    },
    runtimeError({ status, code, message, details }) {
      return Object.assign(new Error(message), { status, code, details });
    },
    stableHash: (value) => `hash:${value}`,
    ...overrides,
  };
}

function assertNoCatalogDownloadMutation(state) {
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.downloadBody, undefined);
  assert.equal(state.timestamped, undefined);
  assert.equal(state.artifacts.size, 0);
  assert.equal(state.downloads.size, 0);
}

test("catalog import and download mutation facades fail closed until Rust core owns them", async () => {
  const importState = fakeState();

  await assert.rejects(
    () =>
      catalogImportUrl(
        importState,
        {
          source_url: "fixture://qwen/q4",
          model_id: "qwen-test",
          provider_id: "provider.local",
          file_name: "qwen.gguf",
          fixture_content: "fixture bytes",
          transfer_approved: true,
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_download_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.catalog.import_url");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_download");
      assert.deepEqual(error.details.evidence_refs, [
        "public_catalog_download_js_facade_retired",
        "rust_daemon_core_catalog_download_required",
      ]);
      assert.equal(error.details.source_url_hash, "hash:fixture://qwen/q4");
      assert.equal(error.details.model_id, "qwen-test");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      return true;
    },
  );
  assertNoCatalogDownloadMutation(importState);

  const downloadState = fakeState();
  await assert.rejects(
    () =>
      downloadModel(
        downloadState,
        {
          model_id: "qwen-test",
          provider_id: "provider.local",
          source_url: "fixture://qwen/q4",
          source_label: "Fixture catalog",
          catalog_provider_id: "catalog.fixture",
          file_name: "qwen.gguf",
          fixture_content: "fixture bytes",
          bytes_total: 1024,
          max_bytes: 2048,
          queued_only: true,
          expected_checksum: "sha256-test",
          display_name: "Qwen Test",
          context_window: 32768,
          privacy_class: "local_private",
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_catalog_download_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.download.queue");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_download");
      assert.equal(error.details.model_id, "qwen-test");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(error.details.source_url_hash, "hash:fixture://qwen/q4");
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      return true;
    },
  );
  assertNoCatalogDownloadMutation(downloadState);
});

test("catalogImportUrl rejects retired request aliases before Rust-core boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      catalogImportUrl(
        state,
        {
          sourceUrl: "fixture://qwen/q4",
          modelId: "qwen-test",
          providerId: "provider.local",
          fileName: "qwen.gguf",
          fixtureContent: "fixture bytes",
          transferApproved: true,
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_catalog_import_url_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "sourceUrl",
        "modelId",
        "providerId",
        "fileName",
        "fixtureContent",
        "transferApproved",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "source_url",
        "model_id",
        "provider_id",
        "file_name",
        "fixture_content",
        "transfer_approved",
      ]);
      return true;
    },
  );
  assertNoCatalogDownloadMutation(state);
});

test("downloadModel rejects retired identity request aliases before Rust-core boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      downloadModel(
        state,
        {
          modelId: "qwen-test",
          providerId: "provider.local",
          sourceUrl: "fixture://qwen/q4",
          sourceLabel: "Fixture catalog",
          catalogProviderId: "catalog.fixture",
          fileName: "qwen.gguf",
          fixtureContent: "fixture bytes",
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_download_identity_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "modelId",
        "providerId",
        "sourceUrl",
        "sourceLabel",
        "catalogProviderId",
        "fileName",
        "fixtureContent",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "model_id",
        "provider_id",
        "source_url",
        "source_label",
        "catalog_provider_id",
        "file_name",
        "fixture_content",
      ]);
      return true;
    },
  );
  assertNoCatalogDownloadMutation(state);
});

test("downloadModel rejects retired control request aliases before Rust-core boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      downloadModel(
        state,
        {
          model_id: "qwen-test",
          bytesTotal: 1024,
          maxBytes: 2048,
          simulateFailure: true,
          failureReason: "network_timeout",
          queuedOnly: true,
          expectedChecksum: "sha256-test",
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_download_control_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "bytesTotal",
        "maxBytes",
        "simulateFailure",
        "failureReason",
        "queuedOnly",
        "expectedChecksum",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "bytes_total",
        "max_bytes",
        "simulate_failure",
        "failure_reason",
        "queued_only",
        "expected_checksum",
      ]);
      return true;
    },
  );
  assertNoCatalogDownloadMutation(state);
});

test("downloadModel rejects retired metadata request aliases before Rust-core boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      downloadModel(
        state,
        {
          model_id: "qwen-test",
          displayName: "Qwen Test",
          contextWindow: 32768,
          privacyClass: "local_private",
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_download_metadata_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "displayName",
        "contextWindow",
        "privacyClass",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "display_name",
        "context_window",
        "privacy_class",
      ]);
      return true;
    },
  );
  assertNoCatalogDownloadMutation(state);
});
