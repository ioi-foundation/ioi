import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  return {
    artifacts: new Map(),
    projections: 0,
    recordStateCommits: [],
    planRequests: [],
    receipts: [],
    writes: [],
    planStorageControl(request) {
      this.planRequests.push(JSON.parse(JSON.stringify(request)));
      const recordDir = request.operation_kind === "model_mount.catalog.import_url"
        ? "model-catalog-imports"
        : "model-downloads";
      const recordId = request.operation_kind === "model_mount.catalog.import_url"
        ? `catalog_import.${request.body.model_id ?? "source"}`
        : `download.${request.body.model_id}`;
      const status = request.operation_kind === "model_mount.catalog.import_url"
        ? "planned"
        : "queued";
      const record = {
        id: recordId,
        record_id: recordId,
        object: request.operation_kind === "model_mount.catalog.import_url"
          ? "ioi.model_mount_catalog_import"
          : "ioi.model_mount_download",
        status,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        details: {
          model_id: request.body.model_id ?? null,
          provider_id: request.body.provider_id ?? null,
          source_url_hash: request.body.source_url ? `sha256:${request.body.source_url.length}` : null,
          network_transfer_executed: false,
        },
        public_response: {
          object: request.operation_kind === "model_mount.catalog.import_url"
            ? "ioi.model_mount_catalog_import"
            : "ioi.model_mount_download",
          status,
          id: recordId,
          record_id: recordId,
          record_dir: recordDir,
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.storage_control",
          details: {
            model_id: request.body.model_id ?? null,
            provider_id: request.body.provider_id ?? null,
            network_transfer_executed: false,
          },
          js_network_transfer_executed: false,
          js_filesystem_mutation_executed: false,
        },
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "public_model_storage_js_facade_retired",
          "rust_daemon_core_model_storage",
          "agentgres_model_storage_truth_required",
          "public_catalog_download_js_facade_retired",
          "rust_daemon_core_catalog_download",
          "agentgres_catalog_download_truth_required",
        ],
        control_hash: `sha256:storage-control:${request.operation_kind}:${recordId}`,
        authority_hash: `sha256:storage-authority:${recordId}`,
      };
      return {
        record_dir: recordDir,
        record_id: recordId,
        record,
        public_response: record.public_response,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        receipt_refs: request.receipt_refs,
        authority_grant_refs: request.authority_grant_refs,
        authority_receipt_refs: request.authority_receipt_refs,
        evidence_refs: record.evidence_refs,
        control_hash: record.control_hash,
        authority_hash: record.authority_hash,
      };
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
        object_ref: `model_mount://${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:content:${request.operation_kind}:${request.record_id}`,
        admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
      };
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

function assertNoCatalogDownloadMutation(state) {
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.planRequests, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.timestamped, undefined);
  assert.equal(state.artifacts.size, 0);
  assert.equal(Object.hasOwn(state, "downloads"), false);
}

function assertOnlyRustStorageControl(state, expectedCommitCount) {
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, expectedCommitCount);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.artifacts.size, 0);
  assert.equal(Object.hasOwn(state, "downloads"), false);
}

test("catalog import and download mutations commit Rust-authored storage-control records", async () => {
  const importState = fakeState();

  const imported = await ModelMountingState.prototype.catalogImportUrl.call(
    importState,
    {
      source_url: "fixture://qwen/q4",
      model_id: "qwen-test",
      provider_id: "provider.local",
      file_name: "qwen.gguf",
      fixture_content: "fixture bytes",
      transfer_approved: true,
      authority_grant_refs: ["grant://wallet/download"],
      authority_receipt_refs: ["receipt://wallet/download"],
    },
  );
  assert.equal(imported.status, "planned");
  assert.equal(imported.record_dir, "model-catalog-imports");
  assert.equal(imported.rust_core_boundary, "model_mount.storage_control");
  assert.equal(imported.js_network_transfer_executed, false);
  assert.equal(importState.planRequests.length, 1);
  assert.equal(importState.planRequests[0].operation_kind, "model_mount.catalog.import_url");
  assert.equal(importState.planRequests[0].body.source_url, "fixture://qwen/q4");
  assert.deepEqual(importState.planRequests[0].authority_grant_refs, ["grant://wallet/download"]);
  assert.equal(importState.recordStateCommits[0].record_dir, "model-catalog-imports");
  assertOnlyRustStorageControl(importState, 1);

  const downloadState = fakeState();
  const queued = await ModelMountingState.prototype.downloadModel.call(
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
  );
  assert.equal(queued.status, "queued");
  assert.equal(queued.record_dir, "model-downloads");
  assert.equal(queued.js_network_transfer_executed, false);
  assert.equal(downloadState.planRequests.length, 1);
  assert.equal(downloadState.planRequests[0].operation_kind, "model_mount.download.queue");
  assert.equal(downloadState.planRequests[0].body.model_id, "qwen-test");
  assert.equal(downloadState.recordStateCommits[0].record_dir, "model-downloads");
  assertOnlyRustStorageControl(downloadState, 1);
});

test("catalogImportUrl rejects retired request aliases before Rust-core boundary", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      ModelMountingState.prototype.catalogImportUrl.call(
        state,
        {
          sourceUrl: "fixture://qwen/q4",
          modelId: "qwen-test",
          providerId: "provider.local",
          fileName: "qwen.gguf",
          fixtureContent: "fixture bytes",
          transferApproved: true,
        },
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
      ModelMountingState.prototype.downloadModel.call(
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
      ModelMountingState.prototype.downloadModel.call(
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
      ModelMountingState.prototype.downloadModel.call(
        state,
        {
          model_id: "qwen-test",
          displayName: "Qwen Test",
          contextWindow: 32768,
          privacyClass: "local_private",
        },
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
