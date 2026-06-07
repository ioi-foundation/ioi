import assert from "node:assert/strict";
import test from "node:test";

import { commitRuntimeArtifactRecord } from "./runtime-artifact-state-commit.mjs";

function fakeStore() {
  return {
    commitRequests: [],
    commitRuntimeArtifactState(request) {
      this.commitRequests.push(request);
      return {
        record: {
          schema_version: "ioi.runtime_artifact_state_commit.v1",
          artifact_id: request.artifact_id,
          operation_kind: request.operation_kind,
          storage_backend_ref: request.storage_backend_ref,
          record: {
            record_path: `artifacts/${request.artifact_id}.json`,
            object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`,
            content_hash: "sha256:artifact-content",
            payload_refs: [`payload://runtime/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`],
            receipt_refs: request.receipt_refs,
            admission: { admission_hash: "sha256:artifact-admission" },
          },
          commit_hash: "sha256:artifact-commit",
        },
        artifact_id: request.artifact_id,
        object_ref: `agentgres://runtime-state/artifacts/${request.artifact_id}/records/artifacts/${request.artifact_id}.json`,
        content_hash: "sha256:artifact-content",
        admission_hash: "sha256:artifact-admission",
        commit_hash: "sha256:artifact-commit",
        written_record: { record_path: `artifacts/${request.artifact_id}.json` },
      };
    },
  };
}

test("runtime artifact state commit sends canonical receipt refs to Rust Agentgres", () => {
  const store = fakeStore();
  const commit = commitRuntimeArtifactRecord(store, {
    id: "artifact_1",
    receipt_refs: ["receipt_array"],
    receipt_id: "receipt_single",
  }, "artifact.test");

  assert.equal(commit.artifact_id, "artifact_1");
  assert.equal(store.commitRequests.length, 1);
  assert.deepEqual(store.commitRequests[0].receipt_refs, ["receipt_array", "receipt_single"]);
  assert.deepEqual(store.commitRequests[0].artifact.receipt_refs, ["receipt_array"]);
  assert.equal(store.commitRequests[0].artifact.receipt_id, "receipt_single");
});

test("runtime artifact state commit rejects retired receipt aliases before Rust commit", () => {
  for (const artifact of [
    { id: "artifact_retired_refs", receiptRefs: ["receipt_retired"] },
    { id: "artifact_retired_id", receiptId: "receipt_retired" },
  ]) {
    const store = fakeStore();

    assert.throws(
      () => commitRuntimeArtifactRecord(store, artifact, "artifact.test"),
      /Runtime artifact state commit requires receipt refs\./,
    );
    assert.equal(store.commitRequests.length, 0);
  }
});
