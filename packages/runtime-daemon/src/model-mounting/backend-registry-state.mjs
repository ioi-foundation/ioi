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
