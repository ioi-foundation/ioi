import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitModelEndpointRecordState(state, record, operation_kind, receipt_refs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "model-endpoints",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_endpoint_state_commit_unconfigured",
    unconfiguredMessage:
      "Model endpoint persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      endpoint_id: record?.id ?? null,
      model_id: record?.modelId ?? null,
    },
  });
}
