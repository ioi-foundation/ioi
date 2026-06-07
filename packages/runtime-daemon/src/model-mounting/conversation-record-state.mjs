import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitConversationRecordState(state, record, operation_kind, receipt_refs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "model-conversations",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_conversation_state_commit_unconfigured",
    unconfiguredMessage:
      "Model conversation state persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      response_id: record?.id ?? null,
      receipt_id: record?.receipt_id ?? null,
      stream_receipt_id: record?.stream_receipt_id ?? null,
    },
  });
}
