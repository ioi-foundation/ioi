import { runtimeError } from "../runtime-http-utils.mjs";

export async function inspectManagedSessionsForThread(store, threadId, request = {}, deps = {}) {
  void store;
  void request;
  void deps;
  throw runtimeError({
    status: 501,
    code: "runtime_managed_session_control_rust_core_required",
    message: "Managed session inspection requires direct Rust daemon-core projection.",
    details: {
      rust_core_boundary: "runtime.managed_session_control",
      operation: "managed_session_inspection",
      operation_kind: "managed_session.inspect",
      thread_id: threadId,
      evidence_refs: [
        "managed_session_inspection_js_facade_retired",
        "managed_session_inspection_bridge_projection_retired",
        "rust_daemon_core_managed_session_projection_required",
        "agentgres_managed_session_truth_required",
      ],
    },
  });
}

export async function controlManagedSessionForThread(store, threadId, request = {}, deps = {}) {
  void store;
  void request;
  void deps;
  throw runtimeError({
    status: 501,
    code: "runtime_managed_session_control_rust_core_required",
    message: "Managed session control requires direct Rust daemon-core admission and projection.",
    details: {
      rust_core_boundary: "runtime.managed_session_control",
      operation: "managed_session_control",
      operation_kind: "managed_session_control",
      thread_id: threadId,
      evidence_refs: [
        "managed_session_control_js_facade_retired",
        "managed_session_control_bridge_dispatch_retired",
        "managed_session_control_result_envelope_js_retired",
        "rust_daemon_core_managed_session_control_required",
        "agentgres_managed_session_truth_required",
      ],
    },
  });
}
