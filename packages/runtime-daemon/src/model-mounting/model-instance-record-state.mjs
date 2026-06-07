import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitModelInstanceRecordState(state, record, operation_kind, receipt_refs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "model-instances",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_instance_state_commit_unconfigured",
    unconfiguredMessage:
      "Model instance lifecycle persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      instance_id: record.id,
      endpoint_id: record.endpointId ?? null,
      model_id: record.modelId ?? null,
      provider_id: record.providerId ?? null,
    },
  });
}
