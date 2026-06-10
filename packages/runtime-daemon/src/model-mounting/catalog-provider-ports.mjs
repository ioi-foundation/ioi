import {
  liveModelCatalogEnabled,
  liveModelDownloadEnabled,
} from "./environment.mjs";
import {
  stableHash,
} from "./io.mjs";

export function fixtureCatalogProviderPort() {
  const evidenceRefs = ["fixture_model_catalog", "model_catalog_provider_port"];
  return {
    id: "catalog.fixture",
    label: "Fixture catalog",
    gate: "always_on",
    formats: ["gguf"],
    evidenceRefs,
    health: () => ({ status: "available", evidenceRefs }),
    search: async () => retiredFixtureCatalogSearchResult(evidenceRefs),
  };
}

export function localManifestCatalogProviderPort(state) {
  const evidenceRefs = ["local_manifest_catalog_adapter", "model_catalog_provider_port"];
  return {
    id: "catalog.local_manifest",
    label: "Local manifest catalog",
    gate: "IOI_MODEL_CATALOG_MANIFEST_PATH or catalog provider setup",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => localManifestCatalogHealth(state, evidenceRefs),
    search: async () => {
      const health = localManifestCatalogHealth(state, evidenceRefs);
      return retiredLocalManifestCatalogSearchResult(health, evidenceRefs);
    },
  };
}

export function ollamaCatalogProviderPort(state) {
  void state;
  const evidenceRefs = ["ollama_catalog_list_bridge", "model_catalog_provider_port"];
  return {
    id: "catalog.ollama",
    label: "Ollama catalog bridge",
    providerId: "provider.ollama",
    gate: "OLLAMA_HOST",
    formats: ["ollama"],
    evidenceRefs,
    health: () => ({
      status: "gated",
      baseUrlHash: null,
      rustCoreBoundary: "model_mount.catalog_provider_projection",
      evidenceRefs,
    }),
    search: async ({ query, format, quantization, searchedAt }) => {
      void query;
      void quantization;
      void searchedAt;
      void format;
      return {
        status: "gated",
        baseUrlHash: null,
        rustCoreBoundary: "model_mount.catalog_provider_search",
        evidenceRefs: [
          ...evidenceRefs,
          "ollama_catalog_js_driver_bridge_retired",
          "ollama_catalog_provider_map_readback_retired",
          "rust_daemon_core_provider_inventory_required",
        ],
        results: [],
      };
    },
  };
}

export function huggingFaceCatalogProviderPort(state) {
  const baseUrl = huggingFaceCatalogBaseUrl(state);
  const evidenceRefs = ["huggingface_catalog_adapter_boundary", "network_access_opt_in", "model_catalog_provider_port"];
  void state;
  const configFields = catalogProviderPortHealthDefaults(null, null);
  return {
    id: "catalog.huggingface",
    label: "Hugging Face-compatible catalog",
    gate: "IOI_LIVE_MODEL_CATALOG",
    downloadGate: "IOI_LIVE_MODEL_DOWNLOAD",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => ({
      ...configFields,
      status: liveModelCatalogEnabled() ? "configured" : "gated",
      baseUrlHash: stableHash(baseUrl),
      gate: "IOI_MODEL_CATALOG_HF_BASE_URL",
      materialConfigured: Boolean(configFields.materialConfigured),
      runtimeMaterialStatus: configFields.runtimeMaterialStatus,
      materialVaultRefHash: configFields.materialVaultRefHash,
      vaultMaterialSource: configFields.vaultMaterialSource,
      liveDownloadStatus: liveModelDownloadEnabled() ? "configured" : "gated",
      evidenceRefs,
    }),
    search: async () => {
      const health = huggingFaceCatalogProviderPort(state).health();
      return retiredLiveCatalogSearchResult("catalog.huggingface", health, evidenceRefs);
    },
  };
}

export function customHttpCatalogProviderPort(state) {
  const evidenceRefs = ["custom_http_catalog_adapter", "model_catalog_provider_port"];
  return {
    id: "catalog.custom_http",
    label: "Custom HTTP catalog",
    gate: "IOI_MODEL_CATALOG_CUSTOM_BASE_URL or catalog provider setup",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => customHttpCatalogHealth(state, evidenceRefs),
    search: async () => {
      const health = customHttpCatalogHealth(state, evidenceRefs);
      return retiredLiveCatalogSearchResult("catalog.custom_http", health, evidenceRefs);
    },
  };
}

export function retiredLiveCatalogSearchResult(providerId, health = {}, evidenceRefs = []) {
  const status = health.status === "disabled" || health.status === "gated" || health.status === "unconfigured"
    ? health.status
    : "configured";
  return {
    ...health,
    status,
    code: "model_catalog_live_http_search_retired",
    operationKind: "model_catalog.live_http_search",
    providerId,
    rustCoreBoundary: "model_mount.catalog_provider_search",
    evidenceRefs: [
      ...evidenceRefs,
      "catalog_live_http_search_js_retired",
      "rust_daemon_core_catalog_search_required",
      "agentgres_catalog_projection_required",
    ],
    results: [],
  };
}

export function retiredLocalManifestCatalogSearchResult(health = {}, evidenceRefs = []) {
  const status = health.status === "disabled" || health.status === "unconfigured"
    ? health.status
    : "configured";
  return {
    ...health,
    status,
    code: "model_catalog_local_manifest_search_retired",
    operationKind: "model_catalog.local_manifest_search",
    providerId: "catalog.local_manifest",
    rustCoreBoundary: "model_mount.catalog_provider_search",
    evidenceRefs: [
      ...evidenceRefs,
      "local_manifest_catalog_search_js_retired",
      "rust_daemon_core_catalog_search_required",
      "agentgres_catalog_projection_required",
    ],
    results: [],
  };
}

export function retiredFixtureCatalogSearchResult(evidenceRefs = []) {
  return {
    status: "configured",
    code: "model_catalog_fixture_search_retired",
    operationKind: "model_catalog.fixture_search",
    providerId: "catalog.fixture",
    rustCoreBoundary: "model_mount.catalog_provider_search",
    evidenceRefs: [
      ...evidenceRefs,
      "fixture_catalog_search_js_retired",
      "rust_daemon_core_catalog_search_required",
      "agentgres_catalog_projection_required",
    ],
    results: [],
  };
}

export function huggingFaceCatalogBaseUrl(state) {
  void state;
  const fallback = process.env.IOI_MODEL_CATALOG_HF_BASE_URL ?? "https://huggingface.co";
  return fallback;
}

export function localManifestCatalogPath(state) {
  void state;
  return process.env.IOI_MODEL_CATALOG_MANIFEST_PATH ?? "";
}

export function customHttpCatalogBaseUrl(state) {
  void state;
  return process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL ?? "";
}

export function localManifestCatalogHealth(state, evidenceRefs) {
  void state;
  const manifestPath = localManifestCatalogPath(state);
  const configFields = catalogProviderPortHealthDefaults(null, null);
  if (!manifestPath) {
    return {
      ...configFields,
      status: "unconfigured",
      gate: "IOI_MODEL_CATALOG_MANIFEST_PATH",
      evidenceRefs,
    };
  }
  return {
    ...configFields,
    status: "configured",
    gate: "IOI_MODEL_CATALOG_MANIFEST_PATH",
    manifestPathHash: stableHash(manifestPath),
    materialConfigured: true,
    runtimeMaterialStatus: "env_gate",
    materialVaultRefHash: configFields.materialVaultRefHash,
    vaultMaterialSource: configFields.vaultMaterialSource,
    evidenceRefs,
  };
}

export function customHttpCatalogHealth(state, evidenceRefs) {
  void state;
  const baseUrl = customHttpCatalogBaseUrl(state);
  const configFields = catalogProviderPortHealthDefaults(null, null);
  if (!baseUrl) {
    return {
      ...configFields,
      status: "unconfigured",
      gate: "IOI_MODEL_CATALOG_CUSTOM_BASE_URL",
      evidenceRefs,
    };
  }
  return {
    ...configFields,
    status: "configured",
    gate: "IOI_MODEL_CATALOG_CUSTOM_BASE_URL",
    baseUrlHash: stableHash(baseUrl),
    materialConfigured: true,
    runtimeMaterialStatus: "env_gate",
    materialVaultRefHash: configFields.materialVaultRefHash,
    vaultMaterialSource: configFields.vaultMaterialSource,
    evidenceRefs,
  };
}

function catalogProviderPortHealthDefaults(config = null, material = null) {
  const materialConfigured = Boolean(config?.materialConfigured ?? material?.manifestPath ?? material?.baseUrl);
  return {
    enabled: config?.enabled ?? true,
    configHash: config?.configHash ?? null,
    manifestPathHash: config?.manifestPathHash ?? null,
    baseUrlHash: config?.baseUrlHash ?? null,
    authVaultRefHash: config?.authVaultRefHash ?? material?.authVaultRefHash ?? null,
    catalogAuthConfigured: Boolean(config?.catalogAuthConfigured ?? config?.authVaultRefHash ?? false),
    catalogAuthScheme: config?.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: config?.catalogAuthHeaderNameHash ?? null,
    oauthSessionHash: config?.oauthSessionHash ?? null,
    oauthBoundary: config?.oauthBoundary ?? null,
    materialVaultRefHash: config?.materialVaultRefHash ?? material?.materialVaultRefHash ?? null,
    materialConfigured,
    materialPersistence: config?.materialPersistence ?? "metadata_only",
    runtimeMaterialStatus: materialConfigured
      ? material?.runtimeMaterialStatus
        ? material.runtimeMaterialStatus
        : material?.manifestPath || material?.baseUrl
          ? "bound_runtime_session"
          : config?.runtimeMaterialStatus ?? "missing_runtime_material"
      : "unconfigured",
    vaultMaterialSource: material?.materialSource ?? config?.vaultMaterialSource ?? null,
    errorHash: material?.errorHash ?? config?.errorHash ?? null,
  };
}
