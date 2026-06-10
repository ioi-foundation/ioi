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
