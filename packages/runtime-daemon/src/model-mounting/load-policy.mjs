import { truthy } from "./io.mjs";

export function normalizeLoadPolicy(value = {}) {
  if (typeof value === "string") {
    return { mode: value, idleTtlSeconds: 900, autoEvict: value === "idle_evict" };
  }
  const ttlSeconds = value.ttl_seconds ?? value.ttlSeconds ?? value.ttl ?? value.idle_ttl_seconds ?? value.idleTtlSeconds ?? 900;
  return {
    mode: value.mode ?? "on_demand",
    idleTtlSeconds: Number(ttlSeconds),
    autoEvict: value.auto_evict ?? value.autoEvict ?? true,
    memoryPressureEvict: value.memory_pressure_evict ?? value.memoryPressureEvict ?? true,
  };
}

export function normalizeLoadOptions(value = {}, loadPolicy = {}) {
  const source = typeof value === "object" && value ? value : {};
  const ttl = source.ttl_seconds ?? source.ttlSeconds ?? source.ttl ?? loadPolicy.idleTtlSeconds ?? null;
  const gpu = source.gpu_offload ?? source.gpuOffload ?? source.gpu ?? null;
  const contextLength = source.context_length ?? source.contextLength ?? null;
  const parallel = source.parallelism ?? source.parallel ?? null;
  const identifier = source.identifier ?? source.instance_identifier ?? source.instanceIdentifier ?? null;
  return {
    estimateOnly: truthy(source.estimate_only ?? source.estimateOnly ?? false),
    gpu: gpu === null || gpu === undefined || gpu === "" ? null : String(gpu),
    contextLength: contextLength === null || contextLength === undefined || contextLength === "" ? null : Number(contextLength),
    parallel: parallel === null || parallel === undefined || parallel === "" ? null : Number(parallel),
    ttlSeconds: ttl === null || ttl === undefined || ttl === "" ? null : Number(ttl),
    identifier: identifier === null || identifier === undefined || identifier === "" ? null : String(identifier),
    modelPath: source.model_path ?? source.modelPath ?? null,
    model: source.model ?? null,
    dtype: source.dtype ?? null,
    tensorParallelSize:
      source.tensor_parallel_size === null || source.tensor_parallel_size === undefined || source.tensor_parallel_size === ""
        ? source.tensorParallelSize === null || source.tensorParallelSize === undefined || source.tensorParallelSize === ""
          ? null
          : Number(source.tensorParallelSize)
        : Number(source.tensor_parallel_size),
    gpuMemoryUtilization:
      source.gpu_memory_utilization === null || source.gpu_memory_utilization === undefined || source.gpu_memory_utilization === ""
        ? source.gpuMemoryUtilization === null || source.gpuMemoryUtilization === undefined || source.gpuMemoryUtilization === ""
          ? null
          : Number(source.gpuMemoryUtilization)
        : Number(source.gpu_memory_utilization),
    maxModelLen:
      source.max_model_len === null || source.max_model_len === undefined || source.max_model_len === ""
        ? source.maxModelLen === null || source.maxModelLen === undefined || source.maxModelLen === ""
          ? null
          : Number(source.maxModelLen)
        : Number(source.max_model_len),
  };
}

export function normalizeRuntimeEngineDefaultLoadOptions(value = {}) {
  const normalized = normalizeLoadOptions(value, {});
  const defaults = {};
  if (normalized.gpu !== null) defaults.gpu = normalized.gpu;
  if (normalized.contextLength !== null) defaults.contextLength = normalized.contextLength;
  if (normalized.parallel !== null) defaults.parallel = normalized.parallel;
  if (normalized.ttlSeconds !== null) defaults.ttlSeconds = normalized.ttlSeconds;
  if (normalized.identifier !== null) defaults.identifier = normalized.identifier;
  return defaults;
}

export function hasExplicitTtlOption(value = {}) {
  if (!value || typeof value !== "object") return false;
  return (
    value.ttl_seconds !== undefined ||
    value.ttlSeconds !== undefined ||
    value.ttl !== undefined ||
    value.idle_ttl_seconds !== undefined ||
    value.idleTtlSeconds !== undefined
  );
}

export function lmStudioLoadOptionArgs(loadOptions = {}) {
  const args = [];
  if (loadOptions.gpu !== null && loadOptions.gpu !== undefined) args.push("--gpu", String(loadOptions.gpu));
  if (loadOptions.contextLength) args.push("--context-length", String(loadOptions.contextLength));
  if (loadOptions.parallel) args.push("--parallel", String(loadOptions.parallel));
  if (loadOptions.ttlSeconds) args.push("--ttl", String(loadOptions.ttlSeconds));
  if (loadOptions.identifier) args.push("--identifier", String(loadOptions.identifier));
  return args;
}

export function expiresAt(nowIso, loadPolicy) {
  if (!loadPolicy.autoEvict && loadPolicy.mode !== "idle_evict") return null;
  return new Date(Date.parse(nowIso) + Number(loadPolicy.idleTtlSeconds ?? 900) * 1000).toISOString();
}
