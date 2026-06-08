export function createAgent(store, options = {}) {
  throwRuntimeLifecycleRustCoreRequired({
    code: "runtime_agent_create_rust_core_required",
    message: "Agent creation requires direct Rust daemon-core state admission and persistence.",
    boundary: "runtime.agent_create",
    operation: "agent_create",
    operation_kind: "agent.create",
    requested_cwd: options.local?.cwd ?? store.defaultCwd ?? null,
    requested_runtime: options.hosted ? "hosted" : options.runtime ?? null,
    evidence_refs: [
      "runtime_agent_create_js_facade_retired",
      "rust_daemon_core_agent_create_required",
      "agentgres_agent_create_state_truth_required",
    ],
  });
}

export function createRun(_store, agentId, request = {}) {
  throwRuntimeLifecycleRustCoreRequired({
    code: "runtime_run_create_rust_core_required",
    message: "Run creation requires direct Rust daemon-core state admission and persistence.",
    boundary: "runtime.run_create",
    operation: "run_create",
    operation_kind: "run.create",
    agent_id: agentId ?? null,
    requested_mode: request.mode ?? "send",
    evidence_refs: [
      "runtime_run_create_js_facade_retired",
      "rust_daemon_core_run_create_required",
      "agentgres_run_create_state_truth_required",
    ],
  });
}

function throwRuntimeLifecycleRustCoreRequired({
  code,
  message,
  boundary,
  operation,
  operation_kind,
  evidence_refs,
  ...details
}) {
  const error = new Error(message);
  error.status = 501;
  error.code = code;
  error.details = {
    rust_core_boundary: boundary,
    operation,
    operation_kind,
    ...details,
    evidence_refs,
  };
  throw error;
}
