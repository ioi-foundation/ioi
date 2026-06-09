import fs from "node:fs";
import path from "node:path";

import {
  catalogEntryMatches,
  fixtureModelCatalog,
  localManifestCatalogEntries,
} from "./catalog-entries.mjs";
import {
  catalogProviderConfigHealthFields,
} from "./catalog-projections.mjs";
import { catalogProviderStatus } from "./catalog-registry.mjs";
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
    search: async ({ query, format, quantization, searchedAt }) => ({
      status: "available",
      evidenceRefs,
      results: fixtureModelCatalog(searchedAt).filter((entry) => catalogEntryMatches(entry, { query, format, quantization })),
    }),
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
    search: async ({ query, format, quantization, searchedAt }) => {
      const health = localManifestCatalogHealth(state, evidenceRefs);
      if (health.status !== "configured" && health.status !== "available") {
        return { ...health, results: [] };
      }
      try {
        const manifestPath = localManifestCatalogPath(state);
        const results = localManifestCatalogEntries(manifestPath, searchedAt).filter((entry) => catalogEntryMatches(entry, { query, format, quantization }));
        return { ...health, status: "available", results };
      } catch (error) {
        return {
          ...health,
          status: "degraded",
          errorHash: stableHash(error?.message ?? "manifest catalog failed"),
          results: [],
        };
      }
    },
  };
}

export function ollamaCatalogProviderPort(state) {
  const evidenceRefs = ["ollama_catalog_list_bridge", "model_catalog_provider_port"];
  const provider = state.providers.get("provider.ollama");
  return {
    id: "catalog.ollama",
    label: "Ollama catalog bridge",
    providerId: "provider.ollama",
    gate: "OLLAMA_HOST",
    formats: ["ollama"],
    evidenceRefs,
    health: () => ({
      status: provider && provider.status !== "blocked" ? "configured" : "gated",
      baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null,
      evidenceRefs,
    }),
    search: async ({ query, format, quantization, searchedAt }) => {
      void query;
      void quantization;
      void searchedAt;
      if (format && format !== "ollama") return { ...catalogProviderStatus({ id: "catalog.ollama", label: "Ollama catalog bridge", evidenceRefs }), status: "configured", results: [] };
      if (!provider || provider.status === "blocked") {
        return { status: "gated", baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null, evidenceRefs, results: [] };
      }
      return {
        status: "configured",
        baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null,
        evidenceRefs: [
          ...evidenceRefs,
          "ollama_catalog_js_driver_bridge_retired",
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
  const config = state?.catalogProviderConfig?.("catalog.huggingface") ?? null;
  const material = state?.catalogProviderRuntimeMaterial?.("catalog.huggingface") ?? null;
  const configFields = catalogProviderConfigHealthFields("catalog.huggingface", config, material);
  return {
    id: "catalog.huggingface",
    label: "Hugging Face-compatible catalog",
    gate: "IOI_LIVE_MODEL_CATALOG",
    downloadGate: "IOI_LIVE_MODEL_DOWNLOAD",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => ({
      ...configFields,
      status: config?.enabled === false ? "disabled" : liveModelCatalogEnabled() ? "configured" : "gated",
      baseUrlHash: stableHash(baseUrl),
      gate: material?.baseUrl ? "vault-backed Hugging Face-compatible catalog setup" : "IOI_MODEL_CATALOG_HF_BASE_URL",
      materialConfigured: Boolean(material?.baseUrl || configFields.materialConfigured),
      runtimeMaterialStatus: material?.baseUrl ? material.runtimeMaterialStatus ?? "bound_runtime_session" : configFields.runtimeMaterialStatus,
      materialVaultRefHash: material?.materialVaultRefHash ?? configFields.materialVaultRefHash,
      vaultMaterialSource: material?.materialSource ?? configFields.vaultMaterialSource,
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

export function huggingFaceCatalogBaseUrl(state) {
  const fallback = process.env.IOI_MODEL_CATALOG_HF_BASE_URL ?? "https://huggingface.co";
  return state?.catalogProviderConfig?.("catalog.huggingface")?.enabled === false
    ? fallback
    : state?.catalogProviderRuntimeMaterial?.("catalog.huggingface")?.baseUrl ?? fallback;
}

export function localManifestCatalogPath(state) {
  const config = state?.catalogProviderConfig?.("catalog.local_manifest") ?? null;
  if (config && config.enabled === false) return "";
  return state?.catalogProviderRuntimeMaterial?.("catalog.local_manifest")?.manifestPath ?? process.env.IOI_MODEL_CATALOG_MANIFEST_PATH ?? "";
}

export function customHttpCatalogBaseUrl(state) {
  const config = state?.catalogProviderConfig?.("catalog.custom_http") ?? null;
  if (config && config.enabled === false) return "";
  return state?.catalogProviderRuntimeMaterial?.("catalog.custom_http")?.baseUrl ?? process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL ?? "";
}

export function localManifestCatalogHealth(state, evidenceRefs) {
  const config = state?.catalogProviderConfig?.("catalog.local_manifest") ?? null;
  const material = state?.catalogProviderRuntimeMaterial?.("catalog.local_manifest") ?? null;
  const manifestPath = localManifestCatalogPath(state);
  const configFields = catalogProviderConfigHealthFields("catalog.local_manifest", config, material);
  if (config?.enabled === false) {
    return { ...configFields, status: "disabled", gate: "catalog provider setup", evidenceRefs };
  }
  if (!manifestPath) {
    return {
      ...configFields,
      status: config?.materialConfigured ? "metadata_only" : "unconfigured",
      gate: "IOI_MODEL_CATALOG_MANIFEST_PATH or catalog provider setup",
      evidenceRefs,
    };
  }
  const resolved = path.resolve(manifestPath);
  return {
    ...configFields,
    status: fs.existsSync(resolved) ? "configured" : "degraded",
    gate: material?.manifestPath ? "vault-backed catalog provider setup" : "IOI_MODEL_CATALOG_MANIFEST_PATH",
    manifestPathHash: stableHash(resolved),
    materialConfigured: true,
    runtimeMaterialStatus: material?.manifestPath ? material.runtimeMaterialStatus ?? "bound_runtime_session" : "env_gate",
    materialVaultRefHash: material?.materialVaultRefHash ?? configFields.materialVaultRefHash,
    vaultMaterialSource: material?.materialSource ?? configFields.vaultMaterialSource,
    evidenceRefs,
  };
}

export function customHttpCatalogHealth(state, evidenceRefs) {
  const config = state?.catalogProviderConfig?.("catalog.custom_http") ?? null;
  const material = state?.catalogProviderRuntimeMaterial?.("catalog.custom_http") ?? null;
  const baseUrl = customHttpCatalogBaseUrl(state);
  const configFields = catalogProviderConfigHealthFields("catalog.custom_http", config, material);
  if (config?.enabled === false) {
    return { ...configFields, status: "disabled", gate: "catalog provider setup", evidenceRefs };
  }
  if (!baseUrl) {
    return {
      ...configFields,
      status: config?.materialConfigured ? "metadata_only" : "unconfigured",
      gate: "IOI_MODEL_CATALOG_CUSTOM_BASE_URL or catalog provider setup",
      evidenceRefs,
    };
  }
  return {
    ...configFields,
    status: "configured",
    gate: material?.baseUrl ? "vault-backed catalog provider setup" : "IOI_MODEL_CATALOG_CUSTOM_BASE_URL",
    baseUrlHash: stableHash(baseUrl),
    materialConfigured: true,
    runtimeMaterialStatus: material?.baseUrl ? material.runtimeMaterialStatus ?? "bound_runtime_session" : "env_gate",
    materialVaultRefHash: material?.materialVaultRefHash ?? configFields.materialVaultRefHash,
    vaultMaterialSource: material?.materialSource ?? configFields.vaultMaterialSource,
    evidenceRefs,
  };
}
