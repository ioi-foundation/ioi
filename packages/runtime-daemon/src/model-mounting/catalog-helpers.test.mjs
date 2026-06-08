import assert from "node:assert/strict";
import test from "node:test";

import {
  catalogApprovalDecision,
  destructiveConfirmationState,
  normalizeDownloadPolicy,
  normalizeImportMode,
} from "./catalog-helpers.mjs";

test("catalog download policy accepts canonical request fields", () => {
  const policy = normalizeDownloadPolicy(
    {
      transfer_approved: true,
      bandwidth_bps: 4096,
      retry_limit: 3,
      resume: false,
      cleanup_partial: false,
    },
    {
      isFixture: false,
      maxBytes: 8192,
      source: "https://example.test/model.gguf",
    },
  );

  assert.equal(policy.maxBytes, 8192);
  assert.equal(policy.bandwidthLimitBps, 4096);
  assert.equal(policy.retryLimit, 3);
  assert.equal(policy.resume, false);
  assert.equal(policy.cleanupPartialOnCancel, false);
  assert.equal(policy.externalTransferRequired, true);
  assert.equal(policy.externalTransferApproved, true);
  assert.equal(policy.status, "ready");
  assert.deepEqual(
    catalogApprovalDecision({ isFixture: false, body: { transfer_approved: true } }),
    {
      required: true,
      approved: true,
      source: "operator_or_fixture",
    },
  );
});

test("catalog download policy rejects retired request aliases", () => {
  assert.throws(
    () =>
      normalizeDownloadPolicy(
        {
          transferApproved: true,
          bandwidthBps: 1024,
          bandwidthLimitBps: 2048,
          retryLimit: 2,
          resumeDownload: false,
          cleanupPartial: false,
          bandwidth_limit_bps: 4096,
          resume_download: false,
          retries: 4,
        },
        { isFixture: false, maxBytes: 8192, source: "https://example.test/model.gguf" },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_download_policy_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "transferApproved",
        "bandwidthBps",
        "bandwidthLimitBps",
        "retryLimit",
        "resumeDownload",
        "cleanupPartial",
        "bandwidth_limit_bps",
        "resume_download",
        "retries",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "transfer_approved",
        "bandwidth_bps",
        "retry_limit",
        "resume",
        "cleanup_partial",
      ]);
      return true;
    },
  );

  assert.throws(
    () => catalogApprovalDecision({ isFixture: false, body: { transferApproved: true } }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "catalog_download_policy_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["transferApproved"]);
      return true;
    },
  );
});

test("destructive confirmation accepts canonical request fields", () => {
  assert.deepEqual(
    destructiveConfirmationState(
      { confirm_destructive: true },
      { required: true, action: "model_storage_cleanup" },
    ),
    {
      required: true,
      confirmed: true,
      action: "model_storage_cleanup",
      source: "operator_confirmation",
    },
  );
  assert.equal(
    destructiveConfirmationState(
      { confirm_destructive: true },
      { required: true, action: "model_storage_cleanup" },
    ).confirmed,
    true,
  );
});

test("destructive confirmation rejects retired request aliases", () => {
  assert.throws(
    () =>
      destructiveConfirmationState(
        {
          confirmDestructive: true,
          destructiveConfirmed: true,
          destructive_confirmed: true,
        },
        { required: true, action: "model_storage_cleanup" },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "destructive_confirmation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "confirmDestructive",
        "destructiveConfirmed",
        "destructive_confirmed",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "confirm_destructive",
      ]);
      return true;
    },
  );
});

test("catalog import mode errors use canonical details", () => {
  assert.throws(
    () => normalizeImportMode("side-load"),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "bad_request");
      assert.equal(error.details.import_mode, "side_load");
      assert.equal(Object.hasOwn(error.details, "importMode"), false);
      return true;
    },
  );
});
