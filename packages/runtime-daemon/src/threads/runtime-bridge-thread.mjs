export async function createRuntimeBridgeThread(store, { request, options, runtimeProfile }, deps = {}) {
  void store;
  void request;
  void options;
  throwRuntimeBridgeThreadRustCoreRequired({
    runtimeError: deps.runtimeError,
    operation: "runtime_bridge_thread_start",
    operationKind: "thread.runtime_bridge.start",
    details: {
      runtime_profile: runtimeProfile,
      evidence_refs: [
        "runtime_bridge_thread_start_js_facade_retired",
        "rust_daemon_core_runtime_bridge_thread_start_required",
        "agentgres_runtime_bridge_thread_start_truth_required",
      ],
    },
  });
}

export async function createRuntimeBridgeTurn(store, { agent, threadId, request, diagnosticsFeedback = null }, deps = {}) {
  void store;
  void request;
  void diagnosticsFeedback;
  throwRuntimeBridgeThreadRustCoreRequired({
    runtimeError: deps.runtimeError,
    operation: "runtime_bridge_turn_submit",
    operationKind: "turn.runtime_bridge.submit",
    details: {
      thread_id: threadId,
      agent_id: agent?.id ?? null,
      runtime_profile: agent?.runtimeProfile ?? null,
      evidence_refs: [
        "runtime_bridge_turn_submit_js_facade_retired",
        "rust_daemon_core_runtime_bridge_turn_required",
        "agentgres_runtime_bridge_turn_truth_required",
      ],
    },
  });
}

function throwRuntimeBridgeThreadRustCoreRequired({ runtimeError, operation, operationKind, details = {} }) {
  throw runtimeError({
    status: 501,
    code: "runtime_bridge_thread_rust_core_required",
    message:
      "Runtime bridge thread start and turn submission require direct Rust daemon-core admission and persistence.",
    details: {
      rust_core_boundary: "runtime.bridge_thread",
      operation,
      operation_kind: operationKind,
      ...details,
    },
  });
}

export async function controlRuntimeBridgeThread(store, { agent, threadId, action, reason }, deps = {}) {
  void store;
  void reason;
  throwRuntimeBridgeThreadRustCoreRequired({
    runtimeError: deps.runtimeError,
    operation: "runtime_bridge_thread_control",
    operationKind: "thread.runtime_bridge.control",
    details: {
      thread_id: threadId,
      agent_id: agent?.id ?? null,
      runtime_profile: agent?.runtimeProfile ?? null,
      action: action ?? null,
      evidence_refs: [
        "runtime_bridge_thread_control_js_facade_retired",
        "rust_daemon_core_runtime_bridge_thread_control_required",
        "agentgres_runtime_bridge_thread_control_truth_required",
      ],
    },
  });
}
