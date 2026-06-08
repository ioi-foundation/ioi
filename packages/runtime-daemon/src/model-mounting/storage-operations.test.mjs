import assert from "node:assert/strict";
import test from "node:test";

import {
  cancelDownload,
  cleanupModelStorage,
  deleteModelArtifact,
  downloadStatus,
} from "./storage-operations.mjs";

function fakeState() {
  return {
    artifacts: new Map(),
    downloads: new Map(),
    endpoints: new Map(),
    instances: new Map(),
    recordStateCommits: [],
    receipts: [],
    writes: [],
    projections: 0,
    downloadStatus(jobId) {
      return downloadStatus(this, jobId, { notFound: deps.notFound });
    },
    getModel(id) {
      throw new Error(`artifact lookup should not run: ${id}`);
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    nowIso() {
      throw new Error("clock should not run");
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()]]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      throw new Error("record-state commit should not run");
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

const deps = {
  cleanupPartialDownload() {
    throw new Error("partial cleanup should not run");
  },
  destructiveConfirmationState() {
    throw new Error("destructive confirmation should not run");
  },
  fileSizeIfExists() {
    throw new Error("filesystem stat should not run");
  },
  listModelFiles() {
    throw new Error("storage scan should not run");
  },
  notFound(message, details) {
    return Object.assign(new Error(message), { status: 404, details });
  },
  runtimeError({ status, code, message, details }) {
    return Object.assign(new Error(message), { status, code, details });
  },
};

function assertNoMutation(state) {
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
}

test("downloadStatus remains a read projection and uses canonical not-found details", () => {
  const state = fakeState();
  state.downloads.set("job.1", { id: "job.1", status: "queued" });

  assert.equal(downloadStatus(state, "job.1", { notFound: deps.notFound }).id, "job.1");
  assert.throws(
    () => downloadStatus(state, "missing", { notFound: deps.notFound }),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.job_id, "missing");
      assert.equal(Object.hasOwn(error.details, "jobId"), false);
      return true;
    },
  );
});

test("model storage mutation facades fail closed until Rust core owns them", () => {
  const state = fakeState();
  state.downloads.set("job.active", { id: "job.active", status: "running" });
  state.artifacts.set("artifact.llama", { id: "artifact.llama", modelId: "llama-test" });

  const cases = [
    [
      () => cancelDownload(state, "job.active", {}, deps),
      "model_mount.download.cancel",
      { job_id: "job.active" },
    ],
    [
      () => deleteModelArtifact(state, "artifact.llama", {}, deps),
      "model_mount.artifact.delete",
      { artifact_id: "artifact.llama" },
    ],
    [
      () => cleanupModelStorage(state, {}, deps),
      "model_mount.storage.cleanup",
      {},
    ],
  ];

  for (const [run, operationKind, expectedDetails] of cases) {
    assert.throws(run, (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_storage_rust_core_required");
      assert.equal(error.details.operation_kind, operationKind);
      assert.equal(error.details.rust_core_boundary, "model_mount.storage");
      assert.deepEqual(error.details.evidence_refs, [
        "public_model_storage_js_facade_retired",
        "rust_daemon_core_model_storage_required",
      ]);
      for (const [key, value] of Object.entries(expectedDetails)) {
        assert.equal(error.details[key], value);
      }
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    });
  }

  assert.equal(state.downloads.get("job.active").status, "running");
  assert.equal(state.artifacts.has("artifact.llama"), true);
  assertNoMutation(state);
});

test("storage mutations reject retired aliases before Rust-core boundary", () => {
  const state = fakeState();

  assert.throws(
    () => cancelDownload(state, "job.active", { cleanupPartial: false }, deps),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["cleanupPartial"]);
      assert.deepEqual(error.details.canonical_fields, [
        "cleanup_partial",
        "dry_run",
        "remove_orphans",
      ]);
      return true;
    },
  );

  assert.throws(
    () => deleteModelArtifact(state, "artifact.llama", { dryRun: true }, deps),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["dryRun"]);
      return true;
    },
  );

  assert.throws(
    () => cleanupModelStorage(state, { removeOrphans: true }, deps),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["removeOrphans"]);
      return true;
    },
  );

  assertNoMutation(state);
});
