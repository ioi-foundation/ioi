import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitModelArtifactRecordState(state, record, operation_kind, receipt_refs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "model-artifacts",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_artifact_state_commit_unconfigured",
    unconfiguredMessage:
      "Model artifact persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      artifact_id: record?.id ?? null,
      model_id: record?.modelId ?? null,
    },
  });
}
