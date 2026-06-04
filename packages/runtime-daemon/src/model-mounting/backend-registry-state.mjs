import fs from "node:fs";
import path from "node:path";

export function seedBackends(state, checkedAt) {
  for (const backend of state.deriveBackendRegistry(checkedAt)) {
    const previous = state.backends.get(backend.id);
    state.backends.set(backend.id, previous ? { ...previous, ...backend } : backend);
  }
}

export function backendRegistry(state) {
  const derived = new Map(state.deriveBackendRegistry(state.nowIso()).map((backend) => [backend.id, backend]));
  for (const [id, backend] of state.backends.entries()) {
    derived.set(id, {
      ...derived.get(id),
      ...backend,
      hardware: backend.hardware ?? derived.get(id)?.hardware,
      evidenceRefs: backend.evidenceRefs ?? derived.get(id)?.evidenceRefs ?? [],
    });
  }
  return [...derived.values()]
    .map((backend) => {
      const processRecord = state.backendProcessForBackend(backend.id);
      return {
        ...backend,
        processStatus: processRecord?.processStatus ?? processRecord?.status ?? backend.processStatus,
        process: processRecord
          ? {
              id: processRecord.id,
              status: processRecord.status,
              processStatus: processRecord.processStatus ?? processRecord.status,
              pidHash: processRecord.pidHash ?? null,
              supervisorKind: processRecord.supervisorKind ?? null,
              spawned: Boolean(processRecord.spawned),
              spawnStatus: processRecord.spawnStatus ?? null,
              startedAt: processRecord.startedAt ?? null,
              stoppedAt: processRecord.stoppedAt ?? null,
              lastHealthAt: processRecord.lastHealthAt ?? null,
              argsHash: processRecord.argsHash ?? null,
              argsRedacted: processRecord.argsRedacted ?? [],
              startupTimeoutMs: processRecord.startupTimeoutMs ?? null,
              stale: Boolean(processRecord.stale),
              staleReason: processRecord.staleReason ?? null,
              receiptId: processRecord.lastReceiptId ?? null,
            }
          : null,
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));
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
    providers: state.providers,
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
    safeFileName,
  } = deps;
  const record = {
    id: `backend_log_${randomUUID()}`,
    endpointId,
    backendId: event.backendId ?? event.backend ?? endpointId,
    createdAt: state.nowIso(),
    ...redact(event),
  };
  const filePath = path.join(state.stateDir, "backend-logs", `${safeFileName(endpointId)}.jsonl`);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
  if (record.backendId && record.backendId !== endpointId) {
    const backendPath = path.join(state.stateDir, "backend-logs", `${safeFileName(record.backendId)}.jsonl`);
    fs.appendFileSync(backendPath, `${JSON.stringify(record)}\n`);
  }
  return record;
}
