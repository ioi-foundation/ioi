import childProcess from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";

export function ensureBackendProcess(state, backendId, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
  const backend = state.backend(backendId);
  if (!state.backendSupportsSupervision(backend)) {
    return null;
  }
  const existing = state.backendProcessForBackend(backendId);
  if (existing?.status === "started") {
    return state.touchBackendProcess(existing, { endpoint, loadOptions, reason });
  }
  return state.startBackendProcess(backend, { endpoint, loadOptions, reason });
}

export function touchBackendProcess(state, processRecord, { endpoint = null, loadOptions = {}, reason = "health_probe" } = {}, deps = {}) {
  const { normalizeScopes, stableHash } = deps;
  const backend = state.backend(processRecord.backendId);
  const argsRedacted = state.backendProcessArgs(backend, { endpoint, loadOptions });
  const updated = {
    ...processRecord,
    status: processRecord.stale ? "stale_recovered" : processRecord.status,
    processStatus: processRecord.stale ? "stale_recovered" : processRecord.processStatus ?? processRecord.status,
    lastHealthAt: state.nowIso(),
    updatedAt: state.nowIso(),
    argsHash: stableHash(argsRedacted.join("\0")),
    argsRedacted,
    reason,
  };
  state.backendProcesses.set(updated.id, updated);
  state.writeMap("backend-processes", state.backendProcesses);
  return state.reconciledBackendProcess(updated, { normalizeScopes });
}

export function startBackendProcess(state, backend, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}, deps = {}) {
  const { processEnv = process.env, redact, safeId, stableHash } = deps;
  const now = state.nowIso();
  const argsRedacted = state.backendProcessArgs(backend, { endpoint, loadOptions });
  const processRef = `supervised://${safeId(backend.id)}/${crypto.randomUUID()}`;
  const childProcessInfo = state.spawnBackendChildProcess(backend, {
    endpoint,
    loadOptions,
    reason,
    processRef,
    argsRedacted,
  });
  const startupTimeoutMs = Number(loadOptions.startupTimeoutMs ?? processEnv.IOI_MODEL_BACKEND_STARTUP_TIMEOUT_MS ?? 15000);
  const processRecord = {
    id: `backend_process_${safeId(backend.id)}_${Date.now()}`,
    backendId: backend.id,
    backendKind: backend.kind,
    status: "started",
    processStatus: "started",
    supervisorKind: backend.kind === "native_local" ? "deterministic_fixture_process" : "external_process",
    bootId: state.bootId,
    processRefHash: stableHash(processRef),
    pidHash: childProcessInfo.pidHash ?? stableHash(processRef).slice(0, 16),
    pidTracked: backend.kind === "native_local" ? "deterministic_fixture_process_ref" : "process_ref_hash",
    spawned: childProcessInfo.spawned,
    spawnStatus: childProcessInfo.status,
    spawnErrorHash: childProcessInfo.errorHash ?? null,
    childProcessKey: childProcessInfo.childProcessKey ?? null,
    baseUrl: backend.baseUrl ?? null,
    binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
    argsRedacted,
    argsHash: stableHash(argsRedacted.join("\0")),
    loadOptions: redact(loadOptions),
    endpointId: endpoint?.id ?? null,
    modelId: endpoint?.modelId ?? null,
    startupTimeoutMs,
    healthProbe: backend.baseUrl ? `${backend.baseUrl}/health`.replace(/\/v1\/health$/, "/health") : "local://health",
    startedAt: now,
    updatedAt: now,
    lastHealthAt: now,
    stoppedAt: null,
    stale: false,
    reason,
    evidenceRefs: [
      "ModelBackendDriver.process_supervision",
      backend.kind === "native_local" ? "deterministic_native_local_fixture_process" : `${backend.kind}_process_supervisor`,
      "bounded_backend_log_capture",
      "startup_timeout_guard",
      ...childProcessInfo.evidenceRefs,
    ],
  };
  state.backendProcesses.set(processRecord.id, processRecord);
  state.writeMap("backend-processes", state.backendProcesses);
  state.writeBackendLog(backend.id, {
    backendId: backend.id,
    event: "backend_process_start",
    backendKind: backend.kind,
    processId: processRecord.id,
    pidHash: processRecord.pidHash,
    argsHash: processRecord.argsHash,
    reason,
  });
  return processRecord;
}

export function spawnBackendChildProcess(state, backend, { endpoint = null, loadOptions = {}, reason = "runtime_control", processRef, argsRedacted = [] } = {}, deps = {}) {
  const {
    llamaCppLibraryPathEnv,
    normalizeScopes,
    processEnv = process.env,
    spawn = childProcess.spawn,
    stableHash,
  } = deps;
  if (!["llama_cpp", "ollama", "vllm"].includes(backend.kind)) {
    return { spawned: false, status: "not_required", evidenceRefs: [] };
  }
  if (!backend.binaryPath) {
    return { spawned: false, status: "binary_absent", evidenceRefs: [`${backend.kind}_binary_absent`] };
  }
  if (backend.kind === "llama_cpp" && !endpoint?.artifactPath && !loadOptions.modelPath && !loadOptions.model_path) {
    return {
      spawned: false,
      status: "waiting_for_model",
      evidenceRefs: ["llama_cpp_start_requires_model_artifact"],
    };
  }
  const spawnArgs = state.backendProcessSpawnArgs(backend, { endpoint, loadOptions });
  try {
    const child = spawn(backend.binaryPath, spawnArgs, {
      cwd: state.cwd,
      env: {
        ...processEnv,
        IOI_MODEL_BACKEND_BASE_URL: backend.baseUrl ?? "",
        IOI_MODEL_BACKEND_REASON: reason,
        ...(backend.kind === "llama_cpp" ? { LD_LIBRARY_PATH: llamaCppLibraryPathEnv(backend.binaryPath, processEnv.LD_LIBRARY_PATH) } : {}),
        ...(backend.kind === "ollama" ? { OLLAMA_HOST: backend.baseUrl ?? "http://127.0.0.1:11434" } : {}),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const pidHash = stableHash(`${processRef}:${child.pid ?? "unknown"}`).slice(0, 16);
    const processKey = stableHash(`${backend.id}:${pidHash}:${Date.now()}`).slice(0, 16);
    state.backendChildProcesses.set(processKey, child);
    const recordOutput = (stream, chunk) => {
      state.writeBackendLog(backend.id, {
        backendId: backend.id,
        event: `backend_process_${stream}`,
        backendKind: backend.kind,
        pidHash,
        bytes: Buffer.byteLength(chunk),
        outputHash: stableHash(String(chunk)),
        argsHash: stableHash(argsRedacted.join("\0")),
      });
    };
    child.stdout?.on("data", (chunk) => recordOutput("stdout", chunk));
    child.stderr?.on("data", (chunk) => recordOutput("stderr", chunk));
    child.once("exit", (code, signal) => {
      state.backendChildProcesses.delete(processKey);
      const existing = state.backendProcessForBackend(backend.id);
      if (existing?.pidHash !== pidHash || existing.status === "stopped") return;
      const updated = {
        ...existing,
        status: code === 0 ? "exited" : "degraded",
        processStatus: code === 0 ? "exited" : "degraded",
        exitCode: code,
        signal,
        stoppedAt: state.nowIso(),
        updatedAt: state.nowIso(),
        evidenceRefs: [...normalizeScopes(existing.evidenceRefs, []), `${backend.kind}_process_exit_observed`],
      };
      state.backendProcesses.set(updated.id, updated);
      state.writeMap("backend-processes", state.backendProcesses);
      state.writeBackendLog(backend.id, {
        backendId: backend.id,
        event: "backend_process_exit",
        backendKind: backend.kind,
        pidHash,
        exitCode: code,
        signal,
      });
    });
    child.once("error", (error) => {
      state.writeBackendLog(backend.id, {
        backendId: backend.id,
        event: "backend_process_spawn_error",
        backendKind: backend.kind,
        pidHash,
        errorHash: stableHash(error?.message ?? "spawn error"),
      });
    });
    return {
      spawned: true,
      status: "spawned",
      pidHash,
      childProcessKey: processKey,
      evidenceRefs: [`${backend.kind}_binary_spawn`, `${backend.kind}_spawn_args_redacted`],
    };
  } catch (error) {
    return {
      spawned: false,
      status: "spawn_failed",
      errorHash: stableHash(error?.message ?? "spawn failed"),
      evidenceRefs: [`${backend.kind}_binary_spawn_failed`],
    };
  }
}

export function stopBackendProcess(state, backend, { reason = "runtime_control" } = {}, deps = {}) {
  const { normalizeScopes } = deps;
  const existing = state.backendProcessForBackend(backend.id);
  if (!existing) return null;
  const child = existing.childProcessKey ? state.backendChildProcesses.get(existing.childProcessKey) : null;
  if (child && !child.killed) {
    try {
      child.kill("SIGTERM");
    } catch {
      // Stop receipts record intent even if the subprocess has already exited.
    }
  }
  const updated = {
    ...existing,
    status: "stopped",
    processStatus: "stopped",
    stoppedAt: state.nowIso(),
    updatedAt: state.nowIso(),
    reason,
    evidenceRefs: [...normalizeScopes(existing.evidenceRefs, []), "clean_backend_stop"],
  };
  state.backendProcesses.set(updated.id, updated);
  state.writeMap("backend-processes", state.backendProcesses);
  state.writeBackendLog(backend.id, {
    backendId: backend.id,
    event: "backend_process_stop",
    backendKind: backend.kind,
    processId: updated.id,
    pidHash: updated.pidHash,
    reason,
  });
  return updated;
}

export function backendHealth(state, backendId, deps = {}) {
  const { hardwareSnapshot } = deps;
  const backend = state.backend(backendId);
  const checkedAt = state.nowIso();
  const processRecord = state.backendProcessForBackend(backendId);
  const status =
    backend.status === "blocked" || backend.status === "absent"
      ? backend.status
      : processRecord?.status === "stale_recovered"
        ? "degraded"
        : "available";
  const hardware = hardwareSnapshot();
  const processSnapshot = state.backendProcessSnapshot(processRecord);
  const receipt = state.lifecycleReceipt("backend_health", {
    backendId,
    modelId: backend.label,
    state: status,
    evidenceRefs: backend.evidenceRefs ?? [],
    hardware,
    process: processSnapshot,
  });
  const updated = {
    ...backend,
    status,
    checkedAt,
    lastReceiptId: receipt.id,
    lastHealthReceiptId: receipt.id,
    processStatus: processSnapshot.processStatus,
    process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
  };
  state.backends.set(backendId, updated);
  state.writeMap("model-backends", state.backends);
  return updated;
}

export function startBackend(state, backendId, body = {}, deps = {}) {
  const { normalizeLoadOptions, runtimeError } = deps;
  const backend = state.backend(backendId);
  if (backend.status === "blocked" && !backend.binaryPath && !String(backend.baseUrl ?? "").startsWith("local://")) {
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "Backend cannot be started until its binary path or base URL is configured.",
      details: { backendId, backendKind: backend.kind, evidenceRefs: backend.evidenceRefs ?? [] },
    });
  }
  const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? state.runtimeDefaultLoadOptions(backendId) ?? {});
  const processRecord = state.ensureBackendProcess(backendId, { loadOptions, reason: "backend_start" });
  const processSnapshot = state.backendProcessSnapshot(processRecord);
  const receipt = state.lifecycleReceipt("backend_start", {
    backendId,
    modelId: backend.label,
    state: "available",
    evidenceRefs: backend.evidenceRefs ?? [],
    process: processSnapshot,
  });
  const updated = {
    ...backend,
    status: "available",
    processStatus: processSnapshot.processStatus ?? (backend.processStatus === "stateless_http" ? "stateless_http" : "started"),
    process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
    startedAt: state.nowIso(),
    lastReceiptId: receipt.id,
  };
  if (processRecord?.id) {
    state.backendProcesses.set(processRecord.id, { ...processRecord, lastReceiptId: receipt.id });
    state.writeMap("backend-processes", state.backendProcesses);
  }
  state.backends.set(backendId, updated);
  state.writeMap("model-backends", state.backends);
  state.writeBackendLog(backendId, {
    backendId,
    event: "backend_start",
    backendKind: backend.kind,
    receiptId: receipt.id,
    processId: processRecord?.id ?? null,
    pidHash: processRecord?.pidHash ?? null,
  });
  return updated;
}

export function stopBackend(state, backendId) {
  const backend = state.backend(backendId);
  const processRecord = state.stopBackendProcess(backend, { reason: "backend_stop" });
  const processSnapshot = state.backendProcessSnapshot(processRecord);
  const receipt = state.lifecycleReceipt("backend_stop", {
    backendId,
    modelId: backend.label,
    state: "stopped",
    evidenceRefs: backend.evidenceRefs ?? [],
    process: processSnapshot,
  });
  const updated = {
    ...backend,
    status: backend.kind === "fixture" ? "available" : "stopped",
    processStatus: backend.kind === "fixture" ? "stateless" : processSnapshot.processStatus ?? "stopped",
    process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
    stoppedAt: state.nowIso(),
    lastReceiptId: receipt.id,
  };
  if (processRecord?.id) {
    state.backendProcesses.set(processRecord.id, { ...processRecord, lastReceiptId: receipt.id });
    state.writeMap("backend-processes", state.backendProcesses);
  }
  state.backends.set(backendId, updated);
  state.writeMap("model-backends", state.backends);
  state.writeBackendLog(backendId, {
    backendId,
    event: "backend_stop",
    backendKind: backend.kind,
    receiptId: receipt.id,
  });
  return updated;
}

export function backendLogs(state, backendId, deps = {}) {
  const { listFiles, parseJsonMaybe, readLines, safeFileName } = deps;
  state.backend(backendId);
  const logDir = path.join(state.stateDir, "backend-logs");
  const records = [];
  for (const filePath of listFiles(logDir, ".jsonl")) {
    for (const line of readLines(filePath)) {
      const record = parseJsonMaybe(line);
      if (record?.backendId === backendId || record?.backend === backendId || filePath.endsWith(`${safeFileName(backendId)}.jsonl`)) {
        records.push(record);
      }
    }
  }
  const resolved = records.sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? ""))).slice(-200);
  state.lifecycleReceipt("backend_logs_read", {
    backendId,
    modelId: state.backend(backendId).label,
    state: "read",
    logCount: resolved.length,
    evidenceRefs: ["backend_log_projection"],
  });
  return resolved;
}
