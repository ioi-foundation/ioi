import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  cancelDownload,
  cleanupModelStorage,
  deleteModelArtifact,
  downloadStatus,
} from "./storage-operations.mjs";

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-storage-"));
}

function fakeState(root = tempRoot()) {
  return {
    artifacts: new Map(),
    downloads: new Map(),
    endpoints: new Map(),
    instances: new Map(),
    modelRoot: path.join(root, "models"),
    recordStateCommits: [],
    receipts: [],
    stateDir: path.join(root, "state"),
    writes: [],
    projections: 0,
    now: "2026-06-04T01:00:00.000Z",
    downloadStatus(jobId) {
      return downloadStatus(this, jobId, { notFound: deps.notFound });
    },
    getModel(id) {
      const artifact = this.artifacts.get(id) ?? [...this.artifacts.values()].find((candidate) => candidate.modelId === id);
      if (!artifact) throw new Error(`missing artifact ${id}`);
      return artifact;
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
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

const deps = {
  cleanupPartialDownload(targetPath) {
    fs.rmSync(targetPath, { force: true });
    fs.rmSync(`${targetPath}.part`, { force: true });
    fs.rmSync(`${targetPath}.part.json`, { force: true });
    return "removed_partial";
  },
  destructiveConfirmationState(body = {}, { required, action }) {
    const confirmed = Boolean(body.confirm_destructive);
    return {
      required,
      confirmed: required ? confirmed : true,
      action,
      source: confirmed ? "operator_confirmation" : required ? "not_provided" : "not_required",
    };
  },
  fileSizeIfExists(filePath) {
    try {
      return filePath ? fs.statSync(filePath).size : 0;
    } catch {
      return 0;
    }
  },
  listModelFiles(root) {
    const files = [];
    if (!fs.existsSync(root)) return files;
    for (const name of fs.readdirSync(root)) {
      const filePath = path.join(root, name);
      if (fs.statSync(filePath).isFile()) files.push(filePath);
    }
    return files;
  },
  notFound(message, details) {
    const error = new Error(message);
    error.status = 404;
    error.details = details;
    return error;
  },
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  safeFileName(value) {
    return String(value).replace(/[^a-z0-9._-]+/gi, "_");
  },
  schemaVersion: "schema.storage.test",
  stableHash(value) {
    return `hash:${value}`;
  },
  truthy(value) {
    if (typeof value === "boolean") return value;
    if (value == null) return false;
    return !["0", "false", "no", "off"].includes(String(value).toLowerCase());
  },
};

test("downloadStatus returns jobs and fails closed for missing ids", () => {
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

test("cancelDownload rejects retired cleanup alias before job lookup", () => {
  const state = fakeState();
  let lookupCount = 0;
  state.downloadStatus = () => {
    lookupCount += 1;
    throw new Error("download lookup should not run");
  };

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
  assert.equal(lookupCount, 0);
  assert.equal(state.receipts.length, 0);
});

test("cancelDownload records cleanup and preserves terminal jobs", () => {
  const root = tempRoot();
  const state = fakeState(root);
  const targetPath = path.join(root, "model.gguf");
  fs.writeFileSync(`${targetPath}.part`, "partial");
  fs.writeFileSync(`${targetPath}.part.json`, "{}");
  state.downloads.set("job.active", {
    id: "job.active",
    status: "running",
    modelId: "llama-test",
    providerId: "provider.local",
    targetPath,
    bytesCompleted: 7,
    bytesTotal: 10,
    receiptIds: ["receipt.previous"],
  });
  state.downloads.set("job.done", { id: "job.done", status: "completed" });

  const canceled = cancelDownload(state, "job.active", {}, deps);

  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.cleanupState, "removed_partial");
  assert.equal(canceled.projectedFreedBytes, 9);
  assert.deepEqual(canceled.receiptIds, ["receipt.previous", "receipt.model_download_canceled.1"]);
  assert.equal(state.receipts.at(-1).details.job_id, "job.active");
  assert.equal(state.receipts.at(-1).details.model_id, "llama-test");
  assert.equal(state.receipts.at(-1).details.projected_freed_bytes, 9);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "jobId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "modelId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "projectedFreedBytes"), false);
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-downloads");
  assert.equal(state.recordStateCommits[0].record_id, "job.active");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.download.cancel");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.model_download_canceled.1"]);
  assert.equal(state.recordStateCommits[0].record.receiptId, "receipt.model_download_canceled.1");
  assert.equal(state.projections, 1);
  assert.equal(cancelDownload(state, "job.done", {}, deps).status, "completed");
});

test("cancelDownload fails closed without Rust Agentgres download record-state commit", () => {
  const root = tempRoot();
  const state = fakeState(root);
  const targetPath = path.join(root, "model.gguf");
  fs.writeFileSync(`${targetPath}.part`, "partial");
  state.downloads.set("job.active", {
    id: "job.active",
    status: "running",
    modelId: "llama-test",
    providerId: "provider.local",
    targetPath,
    bytesCompleted: 7,
    bytesTotal: 10,
  });
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => cancelDownload(state, "job.active", {}, deps),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_download_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-downloads");
      assert.equal(error.details.record_id, "job.active");
      assert.equal(error.details.job_id, "job.active");
      assert.equal(error.details.model_id, "llama-test");
      assert.equal(error.details.provider_id, "provider.local");
      return true;
    },
  );

  assert.equal(state.downloads.get("job.active").status, "running");
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("deleteModelArtifact rejects retired dry-run alias before artifact lookup", () => {
  const state = fakeState();
  let lookupCount = 0;
  state.getModel = () => {
    lookupCount += 1;
    throw new Error("artifact lookup should not run");
  };

  assert.throws(
    () => deleteModelArtifact(state, "artifact.llama", { dryRun: true }, deps),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["dryRun"]);
      assert.deepEqual(error.details.canonical_fields, [
        "cleanup_partial",
        "dry_run",
        "remove_orphans",
      ]);
      return true;
    },
  );
  assert.equal(lookupCount, 0);
  assert.equal(state.receipts.length, 0);
});

test("deleteModelArtifact supports dry-run, loaded conflict, and deletion cleanup", () => {
  const root = tempRoot();
  const state = fakeState(root);
  fs.mkdirSync(path.join(state.stateDir, "model-artifacts"), { recursive: true });
  fs.mkdirSync(state.modelRoot, { recursive: true });
  const artifactPath = path.join(state.modelRoot, "model.gguf");
  fs.writeFileSync(artifactPath, "model-bytes");
  fs.writeFileSync(path.join(state.stateDir, "model-artifacts", "artifact.llama.json"), "{}");
  state.artifacts.set("artifact.llama", {
    id: "artifact.llama",
    modelId: "llama-test",
    providerId: "provider.local",
    artifactPath,
  });
  state.endpoints.set("endpoint.llama", {
    id: "endpoint.llama",
    artifactId: "artifact.llama",
    status: "mounted",
  });

  const dryRun = deleteModelArtifact(state, "artifact.llama", { dry_run: true }, deps);
  assert.equal(dryRun.status, "dry_run");
  assert.equal(dryRun.projectedFreedBytes, 11);
  assert.deepEqual(dryRun.affectedEndpointIds, ["endpoint.llama"]);
  assert.equal(state.receipts.at(-1).details.artifact_id, "artifact.llama");
  assert.equal(state.receipts.at(-1).details.artifact_path_hash, `hash:${artifactPath}`);
  assert.deepEqual(state.receipts.at(-1).details.affected_endpoint_ids, ["endpoint.llama"]);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "artifactId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "artifactPathHash"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "affectedEndpointIds"), false);

  state.instances.set("instance.loaded", {
    id: "instance.loaded",
    endpointId: "endpoint.llama",
    status: "loaded",
  });
  assert.throws(
    () => deleteModelArtifact(state, "artifact.llama", {}, deps),
    (error) =>
      error.status === 409 &&
      error.code === "conflict" &&
      error.details.artifact_id === "artifact.llama" &&
      Object.hasOwn(error.details, "artifactId") === false,
  );
  state.instances.clear();

  const deleted = deleteModelArtifact(state, "llama-test", {}, deps);
  assert.equal(deleted.status, "deleted");
  assert.equal(deleted.cleanupState, "removed");
  assert.equal(state.artifacts.has("artifact.llama"), false);
  assert.equal(state.endpoints.get("endpoint.llama").status, "deleted_with_artifact");
  assert.equal(fs.existsSync(artifactPath), false);
  assert.equal(state.receipts.at(-1).details.cleanup_state, "removed");
  assert.deepEqual(state.receipts.at(-1).details.endpoint_ids, ["endpoint.llama"]);
  assert.equal(state.receipts.at(-1).details.projected_freed_bytes, 11);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "cleanupState"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "endpointIds"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "projectedFreedBytes"), false);
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-artifacts");
  assert.equal(state.recordStateCommits[0].record_id, "artifact.llama");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.artifact.delete");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.model_artifact_delete.2"]);
  assert.equal(state.recordStateCommits[0].record.state, "deleted");
  assert.equal(state.recordStateCommits[0].record.cleanupState, "removed");
  assert.equal(state.recordStateCommits[0].record.receiptId, "receipt.model_artifact_delete.2");
  assert.equal(state.recordStateCommits[1].record_dir, "model-endpoints");
  assert.equal(state.recordStateCommits[1].record_id, "endpoint.llama");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.endpoint.delete_with_artifact");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.model_artifact_delete.2"]);
  assert.equal(state.recordStateCommits[1].record.status, "deleted_with_artifact");
  assert.equal(state.recordStateCommits[1].record.receiptId, "receipt.model_artifact_delete.2");
  assert.equal(state.projections, 1);
});

test("deleteModelArtifact fails closed without Rust Agentgres artifact record-state commit", () => {
  const root = tempRoot();
  const state = fakeState(root);
  fs.mkdirSync(state.modelRoot, { recursive: true });
  const artifactPath = path.join(state.modelRoot, "model.gguf");
  fs.writeFileSync(artifactPath, "model-bytes");
  state.artifacts.set("artifact.llama", {
    id: "artifact.llama",
    modelId: "llama-test",
    providerId: "provider.local",
    artifactPath,
  });
  state.endpoints.set("endpoint.llama", {
    id: "endpoint.llama",
    artifactId: "artifact.llama",
    modelId: "llama-test",
    status: "mounted",
  });
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => deleteModelArtifact(state, "artifact.llama", {}, deps),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_artifact_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-artifacts");
      assert.equal(error.details.record_id, "artifact.llama");
      assert.equal(error.details.artifact_id, "artifact.llama");
      assert.equal(error.details.model_id, "llama-test");
      return true;
    },
  );

  assert.equal(state.artifacts.has("artifact.llama"), true);
  assert.equal(state.endpoints.get("endpoint.llama").status, "mounted");
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("cleanupModelStorage rejects retired cleanup alias before scanning", () => {
  const state = fakeState();
  let scanCount = 0;
  const cleanupDeps = {
    ...deps,
    listModelFiles() {
      scanCount += 1;
      throw new Error("storage scan should not run");
    },
  };

  assert.throws(
    () => cleanupModelStorage(state, { removeOrphans: true }, cleanupDeps),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_storage_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["removeOrphans"]);
      assert.deepEqual(error.details.canonical_fields, [
        "cleanup_partial",
        "dry_run",
        "remove_orphans",
      ]);
      return true;
    },
  );
  assert.equal(scanCount, 0);
  assert.equal(state.receipts.length, 0);
});

test("cleanupModelStorage scans, gates destructive cleanup, and removes confirmed orphans", () => {
  const root = tempRoot();
  const state = fakeState(root);
  fs.mkdirSync(state.modelRoot, { recursive: true });
  const knownPath = path.join(state.modelRoot, "known.gguf");
  const orphanPath = path.join(state.modelRoot, "orphan.gguf");
  fs.writeFileSync(knownPath, "known");
  fs.writeFileSync(orphanPath, "orphan");
  state.artifacts.set("artifact.known", { id: "artifact.known", artifactPath: knownPath });

  const scan = cleanupModelStorage(state, {}, deps);
  assert.equal(scan.status, "scanned");
  assert.equal(scan.orphanCount, 1);
  assert.equal(scan.orphanBytes, 6);
  assert.equal(state.receipts.at(-1).details.scanned_file_count, 2);
  assert.equal(state.receipts.at(-1).details.orphan_count, 1);
  assert.equal(state.receipts.at(-1).details.orphan_bytes, 6);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "scannedFileCount"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "orphanCount"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "orphanBytes"), false);

  assert.throws(
    () => cleanupModelStorage(state, { remove_orphans: true }, deps),
    (error) =>
      error.status === 409 &&
      error.code === "destructive_confirmation_required" &&
      error.details.orphan_count === 1 &&
      Object.hasOwn(error.details, "orphanCount") === false,
  );

  const cleaned = cleanupModelStorage(state, { remove_orphans: true, confirm_destructive: true }, deps);
  assert.equal(cleaned.status, "cleaned");
  assert.equal(cleaned.cleanedBytes, 6);
  assert.equal(cleaned.removedOrphanCount, 1);
  assert.equal(state.receipts.at(-1).details.cleaned_bytes, 6);
  assert.equal(state.receipts.at(-1).details.removed_orphan_count, 1);
  assert.equal(state.receipts.at(-1).details.remove_orphans, true);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "cleanedBytes"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "removedOrphanCount"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "removeOrphans"), false);
  assert.equal(fs.existsSync(orphanPath), false);
});
