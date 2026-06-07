import { commitModelMountRecordState } from "./record-state-commits.mjs";

export function commitMcpServerRecordState(state, record, operationKind, receiptRefs = []) {
  return commitModelMountRecordState(state, {
    recordDir: "mcp-servers",
    record,
    operationKind,
    receiptRefs,
    unconfiguredCode: "model_mount_mcp_server_state_commit_unconfigured",
    unconfiguredMessage:
      "MCP server persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      server_id: record?.id ?? null,
      source: record?.source ?? null,
    },
  });
}
