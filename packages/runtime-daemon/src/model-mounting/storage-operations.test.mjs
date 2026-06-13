import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  return {
    artifacts: new Map(),
    downloads: new Map(),
    endpoints: new Map(),
    instances: new Map(),
    recordStateCommits: [],
    planRequests: [],
    readProjectionCalls: [],
    receipts: [],
    writes: [],
    projections: 0,
    readProjectionFacade: {
      downloadStatus(owner, jobId) {
        owner.readProjectionCalls.push({ operation: "download_status", jobId });
        if (jobId === "job.1") {
          return {
            id: "job.1",
            status: "queued",
            rust_core_boundary: "model_mount.storage_control",
            storage_projection_boundary: "model_mount.storage_projection",
          };
        }
        const error = new Error(`Download job not found: ${jobId}`);
        error.status = 404;
        error.code = "not_found";
        error.details = { job_id: jobId };
        throw error;
      },
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
      return "2026-06-13T00:00:00.000Z";
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()]]);
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
    planStorageControl(request) {
      this.planRequests.push(JSON.parse(JSON.stringify(request)));
      const recordDir = request.operation_kind === "model_mount.download.cancel"
        ? "model-downloads"
        : "model-storage-controls";
      const recordId =
        request.body.job_id ??
        (request.body.artifact_id ? `artifact_delete.${request.body.artifact_id}` : "storage_cleanup.default");
      const status = request.operation_kind === "model_mount.download.cancel"
        ? "cancelled"
        : request.operation_kind === "model_mount.artifact.delete"
          ? "delete_planned"
          : "cleanup_planned";
      const record = {
        id: recordId,
        record_id: recordId,
        object: request.operation_kind === "model_mount.download.cancel"
          ? "ioi.model_mount_download"
          : "ioi.model_mount_storage_control",
        status,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        details: {
          job_id: request.body.job_id ?? null,
          artifact_id: request.body.artifact_id ?? null,
          cleanup_partial: request.body.cleanup_partial ?? null,
          dry_run: request.body.dry_run ?? null,
          remove_orphans: request.body.remove_orphans ?? null,
          filesystem_mutation_executed: false,
        },
        public_response: {
          object: request.operation_kind === "model_mount.download.cancel"
            ? "ioi.model_mount_download"
            : "ioi.model_mount_storage_control",
          status,
          id: recordId,
          record_id: recordId,
          record_dir: recordDir,
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.storage_control",
          details: {
            filesystem_mutation_executed: false,
          },
          js_filesystem_mutation_executed: false,
          js_network_transfer_executed: false,
        },
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "public_model_storage_js_facade_retired",
          "rust_daemon_core_model_storage",
          "agentgres_model_storage_truth_required",
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
    writeProjection() {
      this.projections += 1;
    },
  };
}

function assertNoMutation(state) {
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.planRequests, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
}

function assertOnlyRustStorageControl(state, expectedCommitCount) {
  assert.deepEqual(state.receipts, []);
  assert.equal(state.recordStateCommits.length, expectedCommitCount);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
}

test("downloadStatus remains a read projection and uses canonical not-found details", () => {
  const state = fakeState();
  state.downloads = {
    get(jobId) {
      throw new Error(`JS download map read should not run: ${jobId}`);
    },
  };

  assert.equal(ModelMountingState.prototype.downloadStatus.call(state, "job.1").id, "job.1");
  assert.throws(
    () => ModelMountingState.prototype.downloadStatus.call(state, "missing"),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.job_id, "missing");
      assert.equal(Object.hasOwn(error.details, "jobId"), false);
      return true;
    },
  );
  assert.deepEqual(state.readProjectionCalls, [
    { operation: "download_status", jobId: "job.1" },
    { operation: "download_status", jobId: "missing" },
  ]);
});

test("model storage mutations commit Rust-authored storage-control records", () => {
  const state = fakeState();
  state.downloads.set("job.active", { id: "job.active", status: "running" });
  state.artifacts.set("artifact.llama", { id: "artifact.llama", modelId: "llama-test" });

  const cases = [
    [
      () => ModelMountingState.prototype.cancelDownload.call(state, "job.active", {}),
      "model_mount.download.cancel",
      { job_id: "job.active" },
    ],
    [
      () => ModelMountingState.prototype.deleteModelArtifact.call(state, "artifact.llama", {}),
      "model_mount.artifact.delete",
      { artifact_id: "artifact.llama" },
    ],
    [
      () => ModelMountingState.prototype.cleanupModelStorage.call(state, {}),
      "model_mount.storage.cleanup",
      {},
    ],
  ];

  for (const [run, operationKind, expectedDetails] of cases) {
    const result = run();
    assert.equal(result.operation_kind, operationKind);
    assert.equal(result.rust_core_boundary, "model_mount.storage_control");
    assert.equal(result.js_filesystem_mutation_executed, false);
    const request = state.planRequests.at(-1);
    assert.equal(request.operation_kind, operationKind);
    for (const [key, value] of Object.entries(expectedDetails)) {
      assert.equal(request.body[key], value);
    }
  }

  assert.equal(state.downloads.get("job.active").status, "running");
  assert.equal(state.artifacts.has("artifact.llama"), true);
  assertOnlyRustStorageControl(state, 3);
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.record_dir),
    ["model-downloads", "model-storage-controls", "model-storage-controls"],
  );
});

test("storage mutations reject retired aliases before Rust-core boundary", () => {
  const state = fakeState();

  assert.throws(
    () => ModelMountingState.prototype.cancelDownload.call(state, "job.active", { cleanupPartial: false }),
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
    () => ModelMountingState.prototype.deleteModelArtifact.call(state, "artifact.llama", { dryRun: true }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["dryRun"]);
      return true;
    },
  );

  assert.throws(
    () => ModelMountingState.prototype.cleanupModelStorage.call(state, { removeOrphans: true }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["removeOrphans"]);
      return true;
    },
  );

  assertNoMutation(state);
});
