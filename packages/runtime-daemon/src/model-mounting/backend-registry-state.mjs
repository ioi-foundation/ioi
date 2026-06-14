export function seedBackends(state, checkedAt) {
  throwBackendProjectionRustCoreRequired("model_mount.backend.seed", {
    checked_at: checkedAt ?? null,
    evidence_refs: [
      "model_mount_backend_seed_js_map_write_retired",
      "rust_daemon_core_backend_projection_required",
      "agentgres_backend_projection_truth_required",
    ],
  });
}

export function deriveBackendRegistry(state, checkedAt, deps = {}) {
  const {
    backendRegistryRecords,
    discoverAutopilotLlamaServer,
    findExecutable,
    hardwareSnapshot,
    processEnv,
  } = deps;
  const hardware = hardwareSnapshot();
  const llamaBinary = processEnv.IOI_LLAMA_CPP_SERVER_PATH ?? discoverAutopilotLlamaServer(state.homeDir) ?? findExecutable("llama-server");
  const ollamaBinary = processEnv.IOI_OLLAMA_BINARY ?? findExecutable("ollama");
  const vllmBinary = processEnv.IOI_VLLM_BINARY ?? findExecutable("vllm");
  return backendRegistryRecords({
    checkedAt,
    hardware,
    llamaBinary,
    ollamaBinary,
    vllmBinary,
  });
}

export function listBackendProcesses(state) {
  return [...state.backendProcesses.values()]
    .map((processRecord) => state.reconciledBackendProcess(processRecord))
    .sort((left, right) => String(left.startedAt ?? "").localeCompare(String(right.startedAt ?? "")));
}

export function backendProcessForBackend(state, backendId) {
  const processes = state.listBackendProcesses().filter((processRecord) => processRecord.backendId === backendId);
  return processes.at(-1) ?? null;
}

export function reconciledBackendProcess(state, processRecord, deps = {}) {
  const { normalizeScopes } = deps;
  if (!processRecord) return null;
  if (processRecord.status === "started" && processRecord.bootId && processRecord.bootId !== state.bootId) {
    return {
      ...processRecord,
      status: "stale_recovered",
      processStatus: "stale_recovered",
      stale: true,
      staleReason: "daemon_boot_mismatch",
      evidenceRefs: [
        ...normalizeScopes(processRecord.evidenceRefs, []),
        "supervisor_stale_process_detection",
        "agentgres_process_projection_replay",
      ],
    };
  }
  return {
    stale: false,
    ...processRecord,
  };
}

export function writeBackendLog(state, endpointId, event, deps = {}) {
  const {
    randomUUID,
    redact,
  } = deps;
  const record = {
    id: `backend_log_${randomUUID()}`,
    endpointId,
    backendId: event.backendId ?? event.backend ?? endpointId,
    createdAt: state.nowIso(),
    ...redact(event),
    persistenceStatus: "not_persisted",
    evidenceRefs: [
      "model_mount_backend_log_js_writer_retired",
      "rust_daemon_core_backend_lifecycle",
      "agentgres_backend_lifecycle_truth_required",
    ],
  };
  return record;
}

function throwBackendProjectionRustCoreRequired(operationKind, details = {}) {
  const error = new Error("Model backend projection requires direct Rust daemon-core projection.");
  error.status = 501;
  error.code = "model_mount_backend_projection_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.backend_projection",
    operation_kind: operationKind,
    ...details,
  };
  throw error;
}
