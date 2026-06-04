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
  assert.equal(state.receipts[0].details.sourceUrlHash, "hash:fixture://qwen/q4");
  assert.equal(state.downloadBody.model_id, "qwen-test");
  assert.equal(state.downloadBody.source_url, "fixture://qwen/q4");
  assert.equal(state.downloadBody.transfer_approved, true);
  assert.equal(state.downloadBody.catalog_receipt_id, result.catalogReceiptId);
  assert.match(state.downloadBody.fixture_content, /family=qwen/);
});

test("catalogImportUrl fails closed when a live source is not catalog-gated", async () => {
  const state = fakeState();

  await assert.rejects(
    () => catalogImportUrl(state, { source_url: "https://example.test/model.gguf" }, deps()),
    (error) => error.status === 424 && error.code === "external_blocker" && error.details.sourceUrlHash === "hash:https://example.test/model.gguf",
  );
});

test("downloadModel can queue and simulate failed fixture jobs without materializing files", async () => {
  const state = fakeState();

  const queued = await downloadModel(state, { model_id: "qwen-test", queued_only: true, max_bytes: 100 }, deps());
  assert.equal(queued.status, "queued");
  assert.equal(queued.id, "download_job_uuid-1");
  assert.equal(queued.receiptId, "receipt.1.model_download_queued");
  assert.equal(queued.maxBytes, 100);
  assert.equal(state.writes.at(-1)[0], "model-downloads");
  assert.equal(state.projections, 1);

  const failed = await downloadModel(state, { model_id: "qwen-fail", simulate_failure: true }, deps());
  assert.equal(failed.status, "failed");
  assert.equal(failed.failureReason, "deterministic_fixture_failure");
  assert.deepEqual(failed.receiptIds, ["receipt.2.model_download_queued", "receipt.3.model_download_failed"]);
  assert.equal(state.projections, 2);
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
  assert.equal(state.artifacts.get("download.qwen.test").source, "fixture://redacted");
  assert.deepEqual(state.artifacts.get("download.qwen.test").capabilities, ["chat", "tools"]);
  assert.equal(state.writes.at(-2)[0], "model-artifacts");
  assert.equal(state.writes.at(-1)[0], "model-downloads");
  assert.equal(state.projections, 1);
  assert.equal(materialized[0].targetPath.endsWith(path.join("models", "downloads", "Qwen_Test", "Qwen_Test.gguf")), true);
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
  assert.deepEqual(failed.receiptIds, [
    "receipt.1.model_download_queued",
    "receipt.2.model_download_running",
    "receipt.3.model_download_retry",
    "receipt.4.model_download_failed",
  ]);
});
