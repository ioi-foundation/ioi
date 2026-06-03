import fs from "node:fs";
import path from "node:path";

import {
  catalogEntryMatches,
  catalogRecordsFromPayload,
  fixtureModelCatalog,
  genericCatalogEntry,
  localManifestCatalogEntries,
  ollamaArtifactCatalogEntry,
} from "./catalog-entries.mjs";
import {
  catalogAuthFailureFields,
  catalogAuthFailureStatus,
  catalogAuthProviderFields,
  catalogEntryWithAuth,
  catalogProviderConfigHealthFields,
} from "./catalog-projections.mjs";
import { catalogProviderStatus } from "./catalog-registry.mjs";
import { catalogProviderAuthHeaders } from "./catalog-provider-config.mjs";
import {
  liveModelCatalogEnabled,
  liveModelDownloadEnabled,
  modelCatalogTimeoutMs,
} from "./environment.mjs";
import {
  fetchWithTimeout,
  normalizeScopes,
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
      if (format && format !== "ollama") return { ...catalogProviderStatus({ id: "catalog.ollama", label: "Ollama catalog bridge", evidenceRefs }), status: "configured", results: [] };
      if (!provider || provider.status === "blocked") {
        return { status: "gated", baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null, evidenceRefs, results: [] };
      }
      try {
        const artifacts = await state.driverForProvider(provider).listModels({ state, provider });
        const results = artifacts
          .map((artifact) => ollamaArtifactCatalogEntry(artifact, searchedAt))
          .filter((entry) => catalogEntryMatches(entry, { query, format, quantization }));
        return { status: "available", baseUrlHash: stableHash(provider.baseUrl), evidenceRefs, results };
      } catch (error) {
        return {
          status: "degraded",
          baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null,
          errorHash: stableHash(error?.message ?? "ollama catalog failed"),
          evidenceRefs,
          results: [],
        };
      }
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
    search: async ({ query, format, quantization, limit, searchedAt }) => state.searchHuggingFaceCatalog({ query, format, quantization, limit, searchedAt }),
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
    search: async ({ query, format, quantization, limit, searchedAt }) => {
      const health = customHttpCatalogHealth(state, evidenceRefs);
      const baseUrl = customHttpCatalogBaseUrl(state);
      if (!baseUrl) return { ...health, results: [] };
      try {
        const auth = await catalogProviderAuthHeaders("catalog.custom_http", state);
        const url = new URL("/catalog/search", baseUrl);
        if (query) url.searchParams.set("q", query);
        if (format) url.searchParams.set("format", format);
        if (quantization) url.searchParams.set("quantization", quantization);
        url.searchParams.set("limit", String(limit));
        const response = await fetchWithTimeout(url, { timeoutMs: modelCatalogTimeoutMs(), headers: auth.headers });
        if (!response.ok) {
          return {
            ...health,
            ...catalogAuthProviderFields(auth.evidence),
            status: "degraded",
            baseUrlHash: stableHash(baseUrl),
            errorHash: stableHash(`http:${response.status}`),
            evidenceRefs: [...evidenceRefs, ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
            results: [],
          };
        }
        const payload = await response.json();
        const records = catalogRecordsFromPayload(payload);
        const results = records
          .map((record) =>
            genericCatalogEntry(record, {
              catalogProviderId: "catalog.custom_http",
              sourceLabelPrefix: "Custom catalog",
              searchedAt,
            }),
          )
          .filter(Boolean)
          .map((entry) => catalogEntryWithAuth(entry, auth.evidence))
          .filter((entry) => catalogEntryMatches(entry, { query, format, quantization }))
          .slice(0, limit);
        return {
          ...health,
          ...catalogAuthProviderFields(auth.evidence),
          status: "available",
          baseUrlHash: stableHash(baseUrl),
          evidenceRefs: [...evidenceRefs, "custom_http_catalog_search", ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
          results,
        };
      } catch (error) {
        return {
          ...health,
          ...catalogAuthFailureFields(error),
          status: catalogAuthFailureStatus(error),
          baseUrlHash: stableHash(baseUrl),
          errorHash: stableHash(error?.message ?? "custom catalog failed"),
          evidenceRefs,
          results: [],
        };
      }
    },
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
