export function storageSummary(state, deps = {}) {
  const {
    env = process.env,
    listModelFiles,
    statSync,
    stableHash,
  } = deps;
  const files = listModelFiles(state.modelRoot);
  const totalBytes = files.reduce((total, filePath) => total + statSync(filePath).size, 0);
  const knownPaths = new Set([...state.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
  const orphanCount = files.filter((filePath) => !knownPaths.has(filePath)).length;
  const quotaBytes = Number(env.IOI_MODEL_STORAGE_QUOTA_BYTES ?? 0) || null;
  return {
    rootHash: stableHash(state.modelRoot),
    totalBytes,
    quotaBytes,
    quotaStatus: quotaBytes && totalBytes > quotaBytes ? "over_quota" : "ok",
    fileCount: files.length,
    orphanCount,
    destructiveActionsRequireUnload: true,
    evidenceRefs: ["model_storage_quota_boundary", "artifact_delete_unload_guard"],
  };
}

export function catalogStatus(state, deps = {}) {
  void state;
  throwCatalogStatusReadbackRetired(deps);
}

export function catalogStatusProjectionInput(state, deps = {}) {
  void state;
  throwCatalogStatusReadbackRetired(deps);
}

export async function catalogSearch(state, query = {}, deps = {}) {
  const {
    runtimeError = defaultRuntimeError,
  } = deps;
  void state;
  throw runtimeError({
    status: 501,
    code: "model_catalog_search_js_orchestrator_retired",
    message: "Model catalog search orchestration is retired in JS; use Rust daemon-core catalog search/projection.",
    details: {
      operation_kind: "model_catalog.search",
      rust_core_boundary: "model_mount.catalog_provider_search",
      request_field_count: Object.keys(query ?? {}).length,
      evidence_refs: [
        "model_catalog_search_js_orchestrator_retired",
        "rust_daemon_core_catalog_search_required",
        "agentgres_catalog_projection_required",
      ],
    },
  });
}

export function enrichCatalogEntryForState(state, entry, options = {}, deps = {}) {
  const { enrichCatalogEntry } = deps;
  const storage = state.storageSummary();
  const artifacts = [...state.artifacts.values()];
  return enrichCatalogEntry(entry, {
    storage,
    artifacts,
    maxBytes: options.maxBytes ?? null,
  });
}

function catalogAdapterBoundary() {
  return {
    port: "ModelCatalogProviderPort",
    operations: ["search", "resolveVariant", "importUrl", "download", "health"],
    evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
  };
}

function catalogFilters() {
  return {
    formats: ["gguf", "mlx", "safetensors"],
    quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
    compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
  };
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}

function throwCatalogStatusReadbackRetired(deps = {}) {
  const { runtimeError = defaultRuntimeError } = deps;
  throw runtimeError({
    status: 501,
    code: "model_catalog_status_js_readback_retired",
    message: "Model catalog status readback is retired in JS; use Rust daemon-core catalog status/projection.",
    details: {
      operation_kind: "model_catalog.status",
      rust_core_boundary: "model_mount.catalog_provider_status_projection",
      evidence_refs: [
        "model_catalog_status_js_readback_retired",
        "rust_daemon_core_catalog_status_projection_required",
        "agentgres_catalog_projection_required",
      ],
    },
  });
}
