export function createThreadForkState({
  runtimeError = ({ status = 500, code = "runtime_thread_fork_error", message, details }) =>
    Object.assign(new Error(message), { status, code, details }),
} = {}) {
  function forkThread(store, threadId, request = {}) {
    void store;
    const idempotencyKey =
      typeof request.idempotency_key === "string" && request.idempotency_key.trim()
        ? request.idempotency_key
        : null;
    throw runtimeError({
      status: 501,
      code: "runtime_thread_fork_rust_core_required",
      message:
        "Runtime thread fork requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.thread_fork",
        operation: "thread_fork",
        operation_kind: "thread.fork",
        thread_id: threadId,
        ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {}),
        evidence_refs: [
          "runtime_thread_fork_js_facade_retired",
          "rust_daemon_core_thread_fork_required",
          "agentgres_thread_fork_state_truth_required",
        ],
      },
    });
  }

  return {
    forkThread,
  };
}
