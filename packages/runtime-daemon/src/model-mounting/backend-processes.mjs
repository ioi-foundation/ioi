export function backend(state, backendId, deps = {}) {
  const { notFound } = deps;
  const record = state.backendRegistry().find((item) => item.id === backendId);
  if (!record) throw notFound(`Model backend not found: ${backendId}`, { backendId });
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

export function backendProcessArgs(state, backend, { endpoint = null, loadOptions = {} } = {}, deps = {}) {
  const { llamaCppGpuLayersArg, stableHash } = deps;
  const artifactPathHash = endpoint?.artifactPath ? stableHash(endpoint.artifactPath).slice(0, 16) : null;
  const modelArg = endpoint?.modelId ?? "runtime-engine-profile";
  const contextLength = loadOptions.contextLength ?? state.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
  const parallel = loadOptions.parallel ?? state.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
  const gpu = loadOptions.gpu ?? state.runtimeDefaultLoadOptions(backend.id).gpu ?? null;
  const identifier = loadOptions.identifier ?? state.runtimeDefaultLoadOptions(backend.id).identifier ?? null;
  const args = [];
  if (backend.kind === "llama_cpp") {
    args.push("llama-server", "--model", artifactPathHash ? `artifact:${artifactPathHash}` : modelArg);
    if (contextLength) args.push("--ctx-size", String(contextLength));
    if (parallel) args.push("--parallel", String(parallel));
    if (gpu) args.push("--gpu-layers", llamaCppGpuLayersArg(gpu));
  } else if (backend.kind === "vllm") {
    args.push("vllm", "serve", artifactPathHash ? `artifact:${artifactPathHash}` : modelArg);
    if (contextLength) args.push("--max-model-len", String(contextLength));
    if (parallel) args.push("--tensor-parallel-size", String(parallel));
    if (loadOptions.dtype) args.push("--dtype", String(loadOptions.dtype));
    if (loadOptions.gpuMemoryUtilization) args.push("--gpu-memory-utilization", String(loadOptions.gpuMemoryUtilization));
  } else if (backend.kind === "ollama") {
    args.push("ollama", "serve");
  } else if (backend.kind === "native_local") {
    args.push("ioi-native-local-fixture", "--model", modelArg);
    if (contextLength) args.push("--context", String(contextLength));
    if (parallel) args.push("--parallel", String(parallel));
    if (gpu) args.push("--gpu", String(gpu));
  } else {
    args.push(String(backend.kind ?? "backend"), "--model", modelArg);
  }
  if (identifier) args.push("--identifier", stableHash(identifier).slice(0, 12));
  return args;
}

export function backendProcessSpawnArgs(state, backend, { endpoint = null, loadOptions = {} } = {}, deps = {}) {
  const { backendBindAddress, llamaCppGpuLayersArg } = deps;
  if (backend.kind === "ollama") return ["serve"];
  if (backend.kind === "vllm") {
    const args = ["serve", endpoint?.artifactPath ?? loadOptions.modelPath ?? loadOptions.model_path ?? endpoint?.modelId ?? loadOptions.model ?? "runtime-engine-profile"];
    const bind = backendBindAddress(backend.baseUrl);
    if (bind.host) args.push("--host", bind.host);
    if (bind.port) args.push("--port", String(bind.port));
    const contextLength = loadOptions.contextLength ?? loadOptions.maxModelLen ?? state.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
    const parallel = loadOptions.parallel ?? loadOptions.tensorParallelSize ?? state.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
    if (contextLength) args.push("--max-model-len", String(contextLength));
    if (parallel) args.push("--tensor-parallel-size", String(parallel));
    if (loadOptions.dtype) args.push("--dtype", String(loadOptions.dtype));
    if (loadOptions.gpuMemoryUtilization) args.push("--gpu-memory-utilization", String(loadOptions.gpuMemoryUtilization));
    return args;
  }
  if (backend.kind !== "llama_cpp") return backendProcessArgs(state, backend, { endpoint, loadOptions }, deps).slice(1);
  const args = [];
  const modelPath = endpoint?.artifactPath ?? loadOptions.modelPath ?? loadOptions.model_path ?? null;
  if (modelPath) args.push("--model", modelPath);
  const contextLength = loadOptions.contextLength ?? state.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
  const parallel = loadOptions.parallel ?? state.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
  const gpu = loadOptions.gpu ?? state.runtimeDefaultLoadOptions(backend.id).gpu ?? null;
  if (contextLength) args.push("--ctx-size", String(contextLength));
  if (parallel) args.push("--parallel", String(parallel));
  if (gpu) args.push("--n-gpu-layers", llamaCppGpuLayersArg(gpu));
  const embeddingEnabled = loadOptions.embeddings ?? loadOptions.embedding ?? false;
  if (embeddingEnabled) args.push("--embedding");
  const bind = backendBindAddress(backend.baseUrl);
  if (bind.host) args.push("--host", bind.host);
  if (bind.port) args.push("--port", String(bind.port));
  return args;
}

export function backendSupportsSupervision(backend) {
  return ["native_local", "llama_cpp", "ollama", "vllm"].includes(backend.kind);
}
