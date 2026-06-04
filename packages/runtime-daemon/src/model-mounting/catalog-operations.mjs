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
  const {
    catalogProviderStatus,
    schemaVersion,
  } = deps;
  const lastSearch = state.lastCatalogSearch;
  const providers = state.catalogProviderPorts().map((port) => catalogProviderStatus(port));
  return {
    schemaVersion,
    checkedAt: state.nowIso(),
    providers,
    adapterBoundary: catalogAdapterBoundary(),
    filters: {
      formats: ["gguf", "mlx", "safetensors"],
      quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
      compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
    },
    storage: state.storageSummary(),
    lastSearch: lastSearch
      ? {
          searchedAt: lastSearch.searchedAt,
          query: lastSearch.query,
          filters: lastSearch.filters,
          resultCount: lastSearch.results.length,
        }
      : null,
    results: lastSearch?.results ?? [],
  };
}

export async function catalogSearch(state, query = {}, deps = {}) {
  const {
    catalogProviderStatus,
    normalizeLimit,
    schemaVersion,
  } = deps;
  const searchedAt = state.nowIso();
  const text = String(query.q ?? query.query ?? "autopilot").trim().toLowerCase();
  const requestedFormat = query.format === undefined || query.format === "" ? null : String(query.format).toLowerCase();
  const requestedQuantization = query.quantization === undefined || query.quantization === "" ? null : String(query.quantization).toLowerCase();
  const limit = normalizeLimit(query.limit, 20, 100);
  const providerResults = [];
  for (const port of state.catalogProviderPorts()) {
    const result = await port.search({
      state,
      query: text,
      format: requestedFormat,
      quantization: requestedQuantization,
      limit,
      searchedAt,
    });
    providerResults.push({
      ...catalogProviderStatus(port, result),
      results: (Array.isArray(result.results) ? result.results : []).map((entry) => state.enrichCatalogEntry(entry)),
    });
  }
  const results = providerResults.flatMap((provider) => provider.results).slice(0, limit);
  const search = {
    schemaVersion,
    searchedAt,
    query: text,
    filters: {
      format: requestedFormat,
      quantization: requestedQuantization,
      limit,
    },
    adapterBoundary: catalogAdapterBoundary(),
    providers: providerResults.map(({ results: _results, ...provider }) => provider),
    results,
  };
  state.lastCatalogSearch = search;
  return search;
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
