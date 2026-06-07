export const RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION = "ioi.runtime_artifact_state_commit.v1";
export const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

export function commitRuntimeArtifactRecord(store, artifactRecord, operationKind) {
  if (!artifactRecord?.id) {
    throw new Error("Runtime artifact state commit requires an artifact id.");
  }
  if (typeof store?.commitRuntimeArtifactState !== "function") {
    throw new Error("Runtime artifact state commits require Rust Agentgres admission.");
  }
  const receiptRefs = artifactReceiptRefs(artifactRecord);
  if (receiptRefs.length === 0) {
    throw new Error("Runtime artifact state commit requires receipt refs.");
  }
  return normalizeArtifactStateCommit(store.commitRuntimeArtifactState({
    schema_version: RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION,
    artifact_id: artifactRecord.id,
    operation_kind: operationKind,
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    artifact: artifactRecord,
    receipt_refs: receiptRefs,
  }));
}

export function normalizeArtifactStateCommit(value = {}) {
  const commit = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const storageRecord = commit.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : commit.record?.record ?? {};
  const required = {
    artifact_id: commit.artifact_id ?? commit.record?.artifact_id,
    object_ref: commit.object_ref ?? storageRecord.object_ref,
    content_hash: commit.content_hash ?? storageRecord.content_hash,
    admission_hash: commit.admission_hash ?? storageRecord.admission?.admission_hash,
    commit_hash: commit.commit_hash ?? commit.record?.commit_hash,
    written_record: commit.written_record,
  };
  for (const [field, value] of Object.entries(required)) {
    if (!value) {
      throw new Error(`Rust artifact state commit returned without ${field}.`);
    }
  }
  return {
    ...commit,
    storage_record: storageRecord,
    artifact_id: required.artifact_id,
    object_ref: required.object_ref,
    content_hash: required.content_hash,
    admission_hash: required.admission_hash,
    commit_hash: required.commit_hash,
    written_record: required.written_record,
  };
}

function artifactReceiptRefs(artifactRecord = {}) {
  const refs = [];
  for (const value of [
    ...(Array.isArray(artifactRecord.receipt_refs) ? artifactRecord.receipt_refs : []),
    artifactRecord.receipt_id,
  ]) {
    const text = typeof value === "string" ? value.trim() : "";
    if (text && !refs.includes(text)) refs.push(text);
  }
  return refs;
}
