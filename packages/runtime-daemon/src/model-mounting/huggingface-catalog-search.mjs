import { huggingFaceCatalogEntries } from "./catalog-entries.mjs";
import {
  catalogAuthFailureFields,
  catalogAuthFailureStatus,
  catalogAuthProviderFields,
  catalogEntryWithAuth,
  catalogProviderConfigHealthFields,
} from "./catalog-projections.mjs";
import { catalogProviderAuthHeaders } from "./catalog-provider-config.mjs";
import { huggingFaceCatalogBaseUrl } from "./catalog-provider-ports.mjs";
import {
  liveModelCatalogEnabled,
  modelCatalogTimeoutMs,
} from "./environment.mjs";
import {
  fetchWithTimeout,
  normalizeScopes,
  stableHash,
} from "./io.mjs";

export async function searchHuggingFaceCatalog(
  state,
  { query, format, quantization, limit, searchedAt } = {},
  deps = {},
) {
  const {
    catalogAuthFailureFields: catalogAuthFailureFieldsDep = catalogAuthFailureFields,
    catalogAuthFailureStatus: catalogAuthFailureStatusDep = catalogAuthFailureStatus,
    catalogAuthProviderFields: catalogAuthProviderFieldsDep = catalogAuthProviderFields,
    catalogEntryWithAuth: catalogEntryWithAuthDep = catalogEntryWithAuth,
    catalogProviderAuthHeaders: catalogProviderAuthHeadersDep = catalogProviderAuthHeaders,
    catalogProviderConfigHealthFields: catalogProviderConfigHealthFieldsDep = catalogProviderConfigHealthFields,
    fetchWithTimeout: fetchWithTimeoutDep = fetchWithTimeout,
    huggingFaceCatalogBaseUrl: huggingFaceCatalogBaseUrlDep = huggingFaceCatalogBaseUrl,
    huggingFaceCatalogEntries: huggingFaceCatalogEntriesDep = huggingFaceCatalogEntries,
    liveModelCatalogEnabled: liveModelCatalogEnabledDep = liveModelCatalogEnabled,
    modelCatalogTimeoutMs: modelCatalogTimeoutMsDep = modelCatalogTimeoutMs,
    normalizeScopes: normalizeScopesDep = normalizeScopes,
    stableHash: stableHashDep = stableHash,
  } = deps;
  const baseUrl = huggingFaceCatalogBaseUrlDep(state);
  const config = state.catalogProviderConfig("catalog.huggingface");
  const runtimeMaterial = state.catalogProviderRuntimeMaterial("catalog.huggingface");
  const evidenceRefs = ["huggingface_catalog_adapter_boundary", "network_access_opt_in"];
  if (config?.enabled === false) {
    const fields = catalogProviderConfigHealthFieldsDep("catalog.huggingface", config, runtimeMaterial);
    return {
      ...fields,
      status: "disabled",
      baseUrlHash: stableHashDep(baseUrl),
      evidenceRefs,
      results: [],
    };
  }
  if (!liveModelCatalogEnabledDep()) {
    return {
      ...catalogProviderConfigHealthFieldsDep("catalog.huggingface", config, runtimeMaterial),
      status: "gated",
      baseUrlHash: stableHashDep(baseUrl),
      evidenceRefs,
      results: [],
    };
  }
  try {
    const auth = await catalogProviderAuthHeadersDep("catalog.huggingface", state);
    const url = new URL("/api/models", baseUrl);
    if (query) url.searchParams.set("search", query);
    url.searchParams.set("limit", String(limit));
    const response = await fetchWithTimeoutDep(url, {
      timeoutMs: modelCatalogTimeoutMsDep(),
      headers: auth.headers,
    });
    if (!response.ok) {
      return {
        status: "degraded",
        baseUrlHash: stableHashDep(baseUrl),
        ...catalogAuthProviderFieldsDep(auth.evidence),
        evidenceRefs: [
          ...evidenceRefs,
          ...normalizeScopesDep(auth.evidence?.evidenceRefs, []),
        ],
        errorHash: stableHashDep(`http:${response.status}`),
        results: [],
      };
    }
    const payload = await response.json();
    const records = recordsFromHuggingFacePayload(payload);
    const results = records
      .flatMap((record) => huggingFaceCatalogEntriesDep(record, { baseUrl, searchedAt }))
      .filter((entry) => {
        if (format && entry.format !== format) return false;
        if (quantization && !String(entry.quantization ?? "").toLowerCase().includes(quantization)) {
          return false;
        }
        return true;
      })
      .slice(0, limit);
    return {
      status: "available",
      baseUrlHash: stableHashDep(baseUrl),
      ...catalogAuthProviderFieldsDep(auth.evidence),
      evidenceRefs: [
        ...evidenceRefs,
        "huggingface_catalog_search",
        ...normalizeScopesDep(auth.evidence?.evidenceRefs, []),
      ],
      results: results.map((entry) => catalogEntryWithAuthDep(entry, auth.evidence)),
    };
  } catch (error) {
    return {
      status: catalogAuthFailureStatusDep(error),
      baseUrlHash: stableHashDep(baseUrl),
      evidenceRefs,
      ...catalogAuthFailureFieldsDep(error),
      errorHash: stableHashDep(error?.message ?? "catalog search failed"),
      results: [],
    };
  }
}

export function recordsFromHuggingFacePayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.models)) return payload.models;
  if (Array.isArray(payload?.results)) return payload.results;
  return [];
}
