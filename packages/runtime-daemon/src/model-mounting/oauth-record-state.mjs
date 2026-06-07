import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitOAuthStateRecordState(state, record, operation_kind, receipt_refs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "oauth-states",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_oauth_state_commit_unconfigured",
    unconfiguredMessage:
      "OAuth authorization-state persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: { provider_id: record?.providerId ?? null },
  });
}

export function commitOAuthSessionRecordState(state, record, operation_kind, receipt_refs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "oauth-sessions",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_oauth_session_commit_unconfigured",
    unconfiguredMessage:
      "OAuth session persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: { provider_id: record?.providerId ?? null },
  });
}
