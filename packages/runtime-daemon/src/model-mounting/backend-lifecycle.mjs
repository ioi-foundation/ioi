export function ensureBackendProcess(state, backendId, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
  const backend = state.backend(backendId);
  void endpoint;
  void loadOptions;
  throwBackendProcessSupervisorRetired("model_mount.backend_process.ensure", backend, { reason });
}

export function touchBackendProcess(state, processRecord, { endpoint = null, loadOptions = {}, reason = "health_probe" } = {}, deps = {}) {
  const backend = state.backend(processRecord.backendId);
  void endpoint;
  void loadOptions;
  void deps;
  throwBackendProcessSupervisorRetired("model_mount.backend_process.touch", backend, {
    process_id: processRecord?.id ?? null,
    reason,
  });
}

export function startBackendProcess(state, backend, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}, deps = {}) {
  void state;
  void endpoint;
  void loadOptions;
  void deps;
  throwBackendProcessSupervisorRetired("model_mount.backend_process.start", backend, { reason });
}

export function spawnBackendChildProcess(state, backend, { endpoint = null, loadOptions = {}, reason = "runtime_control", processRef, argsRedacted = [] } = {}, deps = {}) {
  void state;
  void endpoint;
  void loadOptions;
  void processRef;
  void argsRedacted;
  void deps;
  throwBackendProcessSupervisorRetired("model_mount.backend_process.spawn", backend, { reason });
}

export function stopBackendProcess(state, backend, { reason = "runtime_control" } = {}, deps = {}) {
  void state;
  void deps;
  throwBackendProcessSupervisorRetired("model_mount.backend_process.stop", backend, { reason });
}

export function backendHealth(state, backendId, deps = {}) {
  const backend = state.backend(backendId);
  throwBackendLifecycleRustCoreRequired("model_mount.backend.health", backend, deps);
}

export function startBackend(state, backendId, body = {}, deps = {}) {
  const backend = state.backend(backendId);
  void body;
  throwBackendLifecycleRustCoreRequired("model_mount.backend.start", backend, deps);
}

export function stopBackend(state, backendId) {
  const backend = state.backend(backendId);
  throwBackendLifecycleRustCoreRequired("model_mount.backend.stop", backend);
}

export function backendLogs(state, backendId, deps = {}) {
  const backend = state.backend(backendId);
  throwBackendLifecycleRustCoreRequired("model_mount.backend.logs_read", backend, deps);
}

function throwBackendLifecycleRustCoreRequired(operation_kind, backend, deps = {}) {
  const errorFactory = deps.runtimeError ?? (({ code, message, details, status }) => Object.assign(new Error(message), { code, details, status }));
  throw errorFactory({
    status: 501,
    code: "model_mount_backend_lifecycle_rust_core_required",
    message: "Backend lifecycle facade control requires Rust daemon-core model_mount lifecycle ownership.",
    details: {
      backend_id: backend.id,
      backend_kind: backend.kind,
      operation_kind,
      rust_core_boundary: "model_mount.backend_lifecycle",
      evidence_refs: [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_lifecycle_required",
      ],
    },
  });
}

export function backendProcessSupervisorRetiredError(operation_kind, backend = {}, details = {}) {
  const error = new Error("Backend process supervision requires Rust daemon-core model_mount lifecycle ownership.");
  error.status = 501;
  error.code = "model_mount_backend_process_supervisor_retired";
  error.details = {
    backend_id: backend?.id ?? null,
    backend_kind: backend?.kind ?? null,
    operation_kind,
    rust_core_boundary: "model_mount.backend_lifecycle",
    ...details,
    evidence_refs: [
      "js_backend_process_supervisor_retired",
      "rust_daemon_core_backend_process_required",
      "agentgres_backend_process_truth_required",
    ],
  };
  return error;
}

export function throwBackendProcessSupervisorRetired(operation_kind, backend, details = {}) {
  throw backendProcessSupervisorRetiredError(operation_kind, backend, details);
}
