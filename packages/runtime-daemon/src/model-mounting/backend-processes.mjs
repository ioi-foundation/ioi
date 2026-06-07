export function backend(state, backendId, deps = {}) {
  const { notFound } = deps;
  const record = state.backendRegistry().find((item) => item.id === backendId);
  if (!record) throw notFound(`Model backend not found: ${backendId}`, { backend_id: backendId });
  return record;
}

export function backendProcessSnapshot(processRecord) {
  if (!processRecord) {
    return {
      status: "not_started",
      processStatus: "not_started",
      evidenceRefs: ["supervisor_process_not_started"],
    };
  }
  return {
    id: processRecord.id,
    backendId: processRecord.backendId,
    backendKind: processRecord.backendKind,
    status: processRecord.status,
    processStatus: processRecord.processStatus ?? processRecord.status,
    pidHash: processRecord.pidHash ?? null,
    pidTracked: processRecord.pidTracked ?? "process_ref_hash",
    supervisorKind: processRecord.supervisorKind ?? null,
    spawned: Boolean(processRecord.spawned),
    spawnStatus: processRecord.spawnStatus ?? null,
    startedAt: processRecord.startedAt ?? null,
    stoppedAt: processRecord.stoppedAt ?? null,
    lastHealthAt: processRecord.lastHealthAt ?? null,
    argsHash: processRecord.argsHash ?? null,
    argsRedacted: processRecord.argsRedacted ?? [],
    startupTimeoutMs: processRecord.startupTimeoutMs ?? null,
    healthProbe: processRecord.healthProbe ?? null,
    stale: Boolean(processRecord.stale),
    staleReason: processRecord.staleReason ?? null,
    evidenceRefs: processRecord.evidenceRefs ?? [],
  };
}
