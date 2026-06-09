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
  void state;
  void entry;
  void options;
  throwCatalogVariantEnrichmentRetired(deps);
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}

function throwCatalogVariantEnrichmentRetired(deps = {}) {
  const { runtimeError = defaultRuntimeError } = deps;
  throw runtimeError({
    status: 501,
    code: "model_catalog_variant_enrichment_js_retired",
    message: "Model catalog variant enrichment is retired in JS; use Rust daemon-core catalog projection/search.",
    details: {
      operation_kind: "model_catalog.variant_enrich",
      rust_core_boundary: "model_mount.catalog_variant_projection",
      evidence_refs: [
        "model_catalog_variant_enrichment_js_retired",
        "rust_daemon_core_catalog_variant_projection_required",
        "agentgres_catalog_projection_required",
      ],
    },
  });
}
