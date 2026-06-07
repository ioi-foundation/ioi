import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  catalogImportUrl,
  downloadModel,
} from "./catalog-download-operations.mjs";

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ioi-catalog-download-"));
}

function fakeState(root = tempRoot()) {
  return {
    artifacts: new Map(),
    downloads: new Map(),
    lastCatalogSearch: null,
    modelRoot: path.join(root, "models"),
    now: "2026-06-04T12:00:00.000Z",
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
      return this.now;
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
      };
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

function variant(overrides = {}) {
  return {
    id: "variant.fixture.q4",
    sourceLabel: "Fixture catalog",
    format: "gguf",
    quantization: "Q4_K_M",
    family: "qwen",
    contextWindow: 32768,
    license: "fixture",
    compatibility: ["native_local_fixture"],
    architecture: "qwen",
    parameterCount: "9B",
    recommendation: { score: 91, label: "recommended" },
    backendCompatibility: [{ backendKind: "llama_cpp", status: "ready" }],
    downloadRisk: { status: "low" },
    benchmarkReadiness: { chat: true },
    selectionReceiptFields: { selected: true },
    catalogProviderId: "catalog.fixture",
    catalogAuth: { resolvedMaterial: false },
    ...overrides,
  };
}

function deps(overrides = {}) {
  return {
    catalogVariantForSource: () => variant(),
    env: {},
    liveModelCatalogEnabled: () => false,
    liveModelDownloadEnabled: () => false,
    normalizeDownloadPolicy(body, { isFixture, maxBytes, source }) {
      return {
        maxBytes,
        bandwidthLimitBps: null,
        retryLimit: Number(body.retry_limit ?? body.retryLimit ?? 0),
        resume: true,
        approvalDecision: { required: !isFixture, approved: Boolean(body.transfer_approved ?? isFixture) },
        source,
        status: "ready",
      };
    },
    normalizeOptionalBytes(value) {
      const number = Number(value ?? 0);
      return Number.isFinite(number) && number > 0 ? number : null;
    },
    normalizeScopes(value, fallback) {
      return Array.isArray(value) ? value : fallback;
    },
    parseLocalModelMetadata() {
      return { family: "qwen", format: "gguf", quantization: "Q4_K_M", contextWindow: 32768 };
    },
    publicCatalogAuthEvidence(evidence) {
      return evidence ? { resolvedMaterial: Boolean(evidence.resolvedMaterial) } : null;
    },
    publicDownloadSource(source) {
      return String(source).startsWith("fixture://") ? "fixture://redacted" : "remote://redacted";
    },
    randomUUID: () => "uuid-1",
    requiredString(value, field) {
      if (typeof value !== "string" || !value.trim()) throw Object.assign(new Error(`${field} required`), { status: 400 });
      return value;
    },
    runtimeError({ status, code, message, details }) {
      return Object.assign(new Error(message), { status, code, details });
    },
    safeFileName(value) {
      return String(value).replace(/[^a-z0-9._-]+/gi, "_");
    },
    safeId(value) {
      return String(value).toLowerCase().replace(/[^a-z0-9]+/g, ".");
    },
    sourceLabelForUrl: () => "Fixture catalog",
    stableHash: (value) => `hash:${value}`,
    truthy(value) {
      if (typeof value === "boolean") return value;
      if (value == null) return false;
      return !["0", "false", "no", "off"].includes(String(value).toLowerCase());
    },
    ...overrides,
  };
}

test("catalogImportUrl records the catalog receipt and forwards fixture metadata to download", async () => {
  const state = fakeState();

  const result = await catalogImportUrl(
    state,
    { source_url: "fixture://qwen/q4", model_id: "qwen-test" },
    { ...deps(), schemaVersion: "schema.catalog-download.test" },
  );

  assert.equal(result.schemaVersion, "schema.catalog-download.test");
  assert.equal(result.status, "queued");
  assert.equal(result.catalogReceiptId, "receipt.1.model_catalog_import_url");
  assert.equal(state.receipts[0].kind, "model_catalog_import_url");
  assert.equal(state.receipts[0].details.source_url_hash, "hash:fixture://qwen/q4");
  assert.equal(state.receipts[0].details.model_id, "qwen-test");
  assert.equal(state.receipts[0].details.catalog_auth.resolved_material, false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "sourceUrlHash"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "modelId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details.catalog_auth, "resolvedMaterial"), false);
  assert.equal(state.downloadBody.model_id, "qwen-test");
  assert.equal(state.downloadBody.source_url, "fixture://qwen/q4");
  assert.equal(state.downloadBody.transfer_approved, true);
  assert.equal(state.downloadBody.catalog_receipt_id, result.catalogReceiptId);
  assert.match(state.downloadBody.fixture_content, /family=qwen/);
});

test("catalogImportUrl rejects retired request aliases before receipt or download", async () => {
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
        { ...deps(), schemaVersion: "schema.catalog-download.test" },
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
  assert.equal(state.receipts.length, 0);
  assert.equal(state.downloadBody, undefined);
});

test("catalogImportUrl fails closed when a live source is not catalog-gated", async () => {
  const state = fakeState();

  await assert.rejects(
    () => catalogImportUrl(state, { source_url: "https://example.test/model.gguf" }, deps()),
    (error) =>
      error.status === 424 &&
      error.code === "external_blocker" &&
      error.details.source_url_hash === "hash:https://example.test/model.gguf" &&
      error.details.evidence_refs[0] === "network_access_opt_in" &&
      Object.hasOwn(error.details, "sourceUrlHash") === false &&
      Object.hasOwn(error.details, "evidenceRefs") === false,
  );
});

test("downloadModel rejects retired identity request aliases before timestamp or receipt", async () => {
  const state = fakeState();
  let nowCount = 0;
  state.nowIso = () => {
    nowCount += 1;
    return state.now;
  };

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
  assert.equal(nowCount, 0);
  assert.equal(state.receipts.length, 0);
  assert.equal(state.writes.length, 0);
});

test("downloadModel rejects retired control request aliases before timestamp or receipt", async () => {
  const state = fakeState();
  let nowCount = 0;
  state.nowIso = () => {
    nowCount += 1;
    return state.now;
  };

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
  assert.equal(nowCount, 0);
  assert.equal(state.receipts.length, 0);
  assert.equal(state.writes.length, 0);
});

test("downloadModel rejects retired metadata request aliases before timestamp or receipt", async () => {
  const state = fakeState();
  let nowCount = 0;
  state.nowIso = () => {
    nowCount += 1;
    return state.now;
  };

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
  assert.equal(nowCount, 0);
  assert.equal(state.receipts.length, 0);
  assert.equal(state.writes.length, 0);
});

test("downloadModel can queue and simulate failed fixture jobs without materializing files", async () => {
  const state = fakeState();

  const queued = await downloadModel(state, { model_id: "qwen-test", queued_only: true, max_bytes: 100 }, deps());
  assert.equal(queued.status, "queued");
  assert.equal(queued.id, "download_job_uuid-1");
  assert.equal(queued.receiptId, "receipt.1.model_download_queued");
  assert.equal(queued.maxBytes, 100);
  assert.equal(state.receipts[0].details.job_id, "download_job_uuid-1");
  assert.equal(state.receipts[0].details.max_bytes, 100);
  assert.equal(state.receipts[0].details.download_policy.max_bytes, 100);
  assert.equal(Object.hasOwn(state.receipts[0].details, "jobId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "downloadPolicy"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details.download_policy, "maxBytes"), false);
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-downloads");
  assert.equal(state.recordStateCommits[0].record_id, "download_job_uuid-1");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.download.queued");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.1.model_download_queued"]);
  assert.equal(state.recordStateCommits[0].record.receiptId, "receipt.1.model_download_queued");
  assert.equal(state.projections, 1);

  const failed = await downloadModel(state, { model_id: "qwen-fail", simulate_failure: true }, deps());
  assert.equal(failed.status, "failed");
  assert.equal(failed.failureReason, "deterministic_fixture_failure");
  assert.deepEqual(failed.receiptIds, ["receipt.2.model_download_queued", "receipt.3.model_download_failed"]);
  assert.equal(state.receipts[2].details.failure_reason, "deterministic_fixture_failure");
  assert.equal(Object.hasOwn(state.receipts[2].details, "failureReason"), false);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[1].record_dir, "model-downloads");
  assert.equal(state.recordStateCommits[1].record_id, "download_job_uuid-1");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.download.failed");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.3.model_download_failed"]);
  assert.equal(state.projections, 2);
});

test("downloadModel queued jobs fail closed without Rust Agentgres download record-state commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () => downloadModel(state, { model_id: "qwen-test", queued_only: true, max_bytes: 100 }, deps()),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_download_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-downloads");
      assert.equal(error.details.record_id, "download_job_uuid-1");
      assert.equal(error.details.job_id, "download_job_uuid-1");
      assert.equal(error.details.model_id, "qwen-test");
      assert.equal(error.details.provider_id, "provider.autopilot.local");
      return true;
    },
  );

  assert.equal(state.downloads.size, 0);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("downloadModel materializes completed fixture jobs, artifacts, receipts, and projection writes", async () => {
  const state = fakeState();
  const materialized = [];

  const completed = await downloadModel(
    state,
    { model_id: "Qwen Test", source_url: "fixture://qwen/q4", capabilities: ["chat", "tools"] },
    deps({
      materializeFixtureDownload({ targetPath, fixtureContent }) {
        materialized.push({ targetPath, fixtureContent });
        return {
          checksum: "sha256-fixture",
          bytesCompleted: Buffer.byteLength(fixtureContent),
          bytesTotal: Buffer.byteLength(fixtureContent),
          resumeOffset: 0,
          attemptCount: 1,
          retryCount: 0,
        };
      },
    }),
  );

  assert.equal(completed.status, "completed");
  assert.equal(completed.artifactId, "download.qwen.test");
  assert.equal(completed.receiptId, "receipt.3.model_download_completed");
  assert.equal(completed.receiptIds.length, 3);
  assert.equal(state.receipts.at(-1).details.artifact_id, "download.qwen.test");
  assert.equal(state.receipts.at(-1).details.bytes_completed, Buffer.byteLength(materialized[0].fixtureContent));
  assert.equal(state.receipts.at(-1).details.resume_offset, 0);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "artifactId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "bytesCompleted"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "resumeOffset"), false);
  assert.equal(state.artifacts.get("download.qwen.test").source, "fixture://redacted");
  assert.deepEqual(state.artifacts.get("download.qwen.test").capabilities, ["chat", "tools"]);
  assert.equal(state.artifacts.get("download.qwen.test").receiptId, "receipt.3.model_download_completed");
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-artifacts");
  assert.equal(state.recordStateCommits[0].record_id, "download.qwen.test");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.artifact.download");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.3.model_download_completed"]);
  assert.equal(state.recordStateCommits[0].record.receiptId, "receipt.3.model_download_completed");
  assert.equal(state.recordStateCommits[1].record_dir, "model-downloads");
  assert.equal(state.recordStateCommits[1].record_id, "download_job_uuid-1");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.download.completed");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.3.model_download_completed"]);
  assert.equal(state.projections, 1);
  assert.equal(materialized[0].targetPath.endsWith(path.join("models", "downloads", "Qwen_Test", "Qwen_Test.gguf")), true);
});

test("downloadModel completed jobs fail closed without Rust Agentgres artifact record-state commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () =>
      downloadModel(
        state,
        { model_id: "Qwen Test", source_url: "fixture://qwen/q4" },
        deps({
          materializeFixtureDownload({ fixtureContent }) {
            return {
              checksum: "sha256-fixture",
              bytesCompleted: Buffer.byteLength(fixtureContent),
              bytesTotal: Buffer.byteLength(fixtureContent),
              resumeOffset: 0,
              attemptCount: 1,
              retryCount: 0,
            };
          },
        }),
      ),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_artifact_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-artifacts");
      assert.equal(error.details.record_id, "download.qwen.test");
      assert.equal(error.details.artifact_id, "download.qwen.test");
      assert.equal(error.details.model_id, "Qwen Test");
      return true;
    },
  );

  assert.equal(state.artifacts.size, 0);
  assert.equal(state.downloads.size, 0);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("downloadModel records transfer metadata when live materialization fails", async () => {
  const state = fakeState();
  const transfer = { attemptCount: 2, retryCount: 1, resumeMetadataPathHash: "hash:resume" };

  const failed = await downloadModel(
    state,
    { model_id: "remote-test", source_url: "https://example.test/model.gguf", transfer_approved: true },
    deps({
      liveModelDownloadEnabled: () => true,
      async materializeLiveDownload({ onTransferEvent }) {
        onTransferEvent("model_download_retry", { retryCount: 1 });
        const error = new Error("remote timeout");
        error.downloadTransfer = transfer;
        throw error;
      },
      downloadFailureReason: () => "network_timeout",
      failedDownloadCleanupState: () => "retained_partial",
      shouldRetainFailedDownloadPartial: () => true,
    }),
  );

  assert.equal(failed.status, "failed");
  assert.equal(failed.failureReason, "network_timeout");
  assert.equal(failed.attemptCount, 2);
  assert.equal(failed.retryCount, 1);
  assert.equal(state.receipts[2].details.retry_count, 1);
  assert.equal(Object.hasOwn(state.receipts[2].details, "retryCount"), false);
  assert.equal(state.receipts[3].details.attempt_count, 2);
  assert.equal(state.receipts[3].details.retry_count, 1);
  assert.equal(state.receipts[3].details.resume_metadata_path_hash, "hash:resume");
  assert.equal(state.receipts[3].details.transfer.attempt_count, 2);
  assert.equal(Object.hasOwn(state.receipts[3].details, "attemptCount"), false);
  assert.equal(Object.hasOwn(state.receipts[3].details, "resumeMetadataPathHash"), false);
  assert.equal(Object.hasOwn(state.receipts[3].details.transfer, "attemptCount"), false);
  assert.deepEqual(failed.receiptIds, [
    "receipt.1.model_download_queued",
    "receipt.2.model_download_running",
    "receipt.3.model_download_retry",
    "receipt.4.model_download_failed",
  ]);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-downloads");
  assert.equal(state.recordStateCommits[0].record_id, "download_job_uuid-1");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.download.failed");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.4.model_download_failed"]);
});
