const RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_model_mount_record_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

export function commitModelMountRecordState(
  state,
  {
    recordDir,
    record,
    operationKind,
    receiptRefs = [],
    unconfiguredCode = "model_mount_record_state_commit_unconfigured",
    unconfiguredMessage = "Model-mount record persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails = {},
    invalidCode = "model_mount_record_state_commit_invalid",
  } = {},
) {
  if (typeof state.commitRuntimeModelMountRecordState !== "function") {
    const error = new Error(unconfiguredMessage);
    error.status = 500;
    error.code = unconfiguredCode;
    error.details = {
      record_dir: recordDir ?? null,
      record_id: record?.id ?? null,
      receipt_id: receiptRefs.find(Boolean) ?? record?.receiptId ?? null,
      ...unconfiguredDetails,
    };
    throw error;
  }
  return normalizeModelMountRecordStateCommit(state.commitRuntimeModelMountRecordState({
    schema_version: RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION,
    record_dir: recordDir,
    record_id: record.id,
    operation_kind: operationKind,
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    record,
    receipt_refs: receiptRefs.filter(Boolean),
  }), { invalidCode });
}

export function normalizeModelMountRecordStateCommit(value = {}, { invalidCode = "model_mount_record_state_commit_invalid" } = {}) {
  const commit = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const storageRecord = commit.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : commit.record?.record ?? {};
  const required = {
    record_id: commit.record_id ?? commit.record?.record_id,
    object_ref: commit.object_ref ?? storageRecord.object_ref,
    content_hash: commit.content_hash ?? storageRecord.content_hash,
    admission_hash: commit.admission_hash ?? storageRecord.admission?.admission_hash,
    commit_hash: commit.commit_hash ?? commit.record?.commit_hash,
    written_record: commit.written_record,
  };
  for (const [field, fieldValue] of Object.entries(required)) {
    if (!fieldValue) {
      const error = new Error(`Rust model-mount record state commit returned without ${field}.`);
      error.status = 502;
      error.code = invalidCode;
      error.details = { field };
      throw error;
    }
  }
  return {
    ...commit,
    storage_record: storageRecord,
    record_id: required.record_id,
    object_ref: required.object_ref,
    content_hash: required.content_hash,
    admission_hash: required.admission_hash,
    commit_hash: required.commit_hash,
    written_record: required.written_record,
  };
}
