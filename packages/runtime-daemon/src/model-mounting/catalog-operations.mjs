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
  const input = catalogStatusProjectionInput(state, deps);
  return {
    schemaVersion: input.schema_version,
    checkedAt: input.checked_at,
    providers: input.providers,
    adapterBoundary: catalogAdapterBoundary(),
    filters: catalogFilters(),
    storage: input.storage,
    lastSearch: input.last_search
      ? {
          searchedAt: input.last_search.searched_at,
          query: input.last_search.query,
          filters: input.last_search.filters,
          resultCount: input.last_search.result_count,
        }
      : null,
    results: input.results,
  };
}

export function catalogStatusProjectionInput(state, deps = {}) {
  const {
    catalogProviderStatus,
    schemaVersion,
  } = deps;
  const lastSearch = state.lastCatalogSearch;
  const providers = state.catalogProviderPorts().map((port) => catalogProviderStatus(port));
  return {
    schema_version: schemaVersion,
    checked_at: state.nowIso(),
    providers,
    storage: state.storageSummary(),
    last_search: lastSearch
      ? {
          searched_at: lastSearch.searchedAt,
          query: lastSearch.query,
          filters: lastSearch.filters,
          result_count: lastSearch.results.length,
        }
      : null,
    results: lastSearch?.results ?? [],
  };
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
