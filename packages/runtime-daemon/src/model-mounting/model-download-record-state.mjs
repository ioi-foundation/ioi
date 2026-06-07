import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitModelDownloadRecordState(state, record, operationKind, receiptRefs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "model-downloads",
    record,
    operationKind,
    receiptRefs,
    unconfiguredCode: "model_mount_download_state_commit_unconfigured",
    unconfiguredMessage:
      "Model download lifecycle persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      job_id: record.id,
      model_id: record.modelId ?? null,
      provider_id: record.providerId ?? null,
    },
  });
}
