export function createWorkspaceTrustState({
  runtimeError,
} = {}) {
  function appendWorkspaceTrustWarningEvent(store, {
    threadId,
    controls,
    request,
    source,
    requestedBy,
    workflowGraphId,
    modeEvent,
    now,
  }) {
    void store;
    void controls;
    void request;
    void source;
    void requestedBy;
    void workflowGraphId;
    void modeEvent;
    void now;
    throwWorkspaceTrustRustCoreRequired({
      operation: "warning",
      controlKind: "workspace_trust_warning",
      threadId,
    });
  }

  function acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request = {}) {
    void store;
    void warningId;
    void request;
    throwWorkspaceTrustRustCoreRequired({
      operation: "acknowledge",
      controlKind: "workspace_trust_acknowledgement",
      threadId,
    });
  }

  function throwWorkspaceTrustRustCoreRequired({
    operation,
    controlKind,
    threadId = null,
  } = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_workspace_trust_control_rust_core_required",
      message: "Workspace trust control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: "runtime.workspace_trust_control",
        operation: "workspace_trust_control",
        operation_kind: "workspace_trust_control",
        requested_operation: operation ?? null,
        requested_control_kind: controlKind ?? null,
        thread_id: threadId,
        evidence_refs: [
          "runtime_workspace_trust_control_js_facade_retired",
          "runtime_workspace_trust_warning_js_facade_retired",
          "runtime_workspace_trust_acknowledgement_js_facade_retired",
          "runtime_workspace_trust_event_append_js_retired",
          "rust_daemon_core_workspace_trust_control_required",
          "agentgres_workspace_trust_truth_required",
        ],
      },
    });
  }

  return {
    acknowledgeWorkspaceTrustWarning,
    appendWorkspaceTrustWarningEvent,
  };
}
