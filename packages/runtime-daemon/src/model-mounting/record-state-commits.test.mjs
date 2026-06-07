import assert from "node:assert/strict";
import test from "node:test";

import { commitModelMountRecordState } from "./record-state-commits.mjs";

function fakeRecordStateCommitter(requests = []) {
  return function commitRuntimeModelMountRecordState(request) {
    requests.push(request);
    if (!request.operation_kind || request.receipt_refs.length === 0) {
      throw new Error("Rust model-mount record admission requires canonical commit fields.");
    }
    return {
      record_id: request.record_id,
      object_ref: `agentgres://model-mount/${request.record_dir}/${request.record_id}`,
      content_hash: "sha256:model-mount-record-content",
      admission_hash: "sha256:model-mount-record-admission",
      commit_hash: "sha256:model-mount-record-commit",
      written_record: {
        record_path: `${request.record_dir}/${request.record_id}.json`,
      },
      storage_record: {
        object_ref: `agentgres://model-mount/${request.record_dir}/${request.record_id}`,
        content_hash: "sha256:model-mount-record-content",
        admission: {
          admission_hash: "sha256:model-mount-record-admission",
        },
      },
    };
  };
}

test("model-mount record-state commit ignores retired option aliases before Rust admission", () => {
  const requests = [];
  const state = {
    commitRuntimeModelMountRecordState: fakeRecordStateCommitter(requests),
  };

  assert.throws(
    () =>
      commitModelMountRecordState(state, {
        recordDir: "model-records",
        record: { id: "record_alias" },
        operationKind: "model_mount.retired",
        receiptRefs: ["receipt_retired"],
      }),
    /Rust model-mount record admission requires canonical commit fields/,
  );
  assert.equal(requests[0].record_id, "record_alias");
  assert.equal(requests[0].operation_kind, undefined);
  assert.deepEqual(requests[0].receipt_refs, []);
  assert.equal(Object.hasOwn(requests[0], "operationKind"), false);
  assert.equal(Object.hasOwn(requests[0], "receiptRefs"), false);

  const commit = commitModelMountRecordState(state, {
    recordDir: "model-records",
    record: { id: "record_canonical" },
    operation_kind: "model_mount.canonical",
    receipt_refs: ["receipt_canonical"],
  });
  assert.equal(requests.at(-1).operation_kind, "model_mount.canonical");
  assert.deepEqual(requests.at(-1).receipt_refs, ["receipt_canonical"]);
  assert.equal(commit.record_id, "record_canonical");
  assert.equal(commit.commit_hash, "sha256:model-mount-record-commit");
});
