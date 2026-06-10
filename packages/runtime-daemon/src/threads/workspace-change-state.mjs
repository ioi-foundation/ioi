import { runtimeError } from "../runtime-http-utils.mjs";

export async function inspectWorkspaceChangeReviewsForThread(store, threadId, request = {}, deps = {}) {
  void store;
  void request;
  void deps;
  throw runtimeError({
    status: 501,
    code: "runtime_workspace_change_control_rust_core_required",
    message: "Workspace change inspection requires direct Rust daemon-core projection.",
    details: {
      rust_core_boundary: "runtime.workspace_change_control",
      operation: "workspace_change_inspection",
      operation_kind: "workspace_change.inspect",
      thread_id: threadId,
      evidence_refs: [
        "workspace_change_inspection_js_facade_retired",
        "workspace_change_inspection_bridge_projection_retired",
        "rust_daemon_core_workspace_change_projection_required",
        "agentgres_workspace_change_truth_required",
      ],
    },
  });
}

export async function controlWorkspaceChangeForThread(store, threadId, request = {}, deps = {}) {
  void store;
  void request;
  void deps;
  throw runtimeError({
    status: 501,
    code: "runtime_workspace_change_control_rust_core_required",
    message: "Workspace change control requires direct Rust daemon-core admission and projection.",
    details: {
      rust_core_boundary: "runtime.workspace_change_control",
      operation: "workspace_change_control",
      operation_kind: "workspace_change_control",
      thread_id: threadId,
      evidence_refs: [
        "workspace_change_control_js_facade_retired",
        "workspace_change_control_bridge_dispatch_retired",
        "workspace_change_control_receipt_synthesis_js_retired",
        "rust_daemon_core_workspace_change_control_required",
        "agentgres_workspace_change_truth_required",
      ],
    },
  });
}
