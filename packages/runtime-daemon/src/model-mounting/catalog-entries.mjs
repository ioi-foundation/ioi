import path from "node:path";

import {
  catalogBackendCompatibility,
  catalogBenchmarkReadiness,
  catalogCompatibilityForFormat,
  catalogDownloadRisk,
  catalogRecommendation,
  huggingFaceResolveUrl,
  inferModelArchitecture,
  inferParameterCount,
  modelCatalogFileFormat,
  modelIdFromSourceUrl,
  parseModelQuantization,
  sourceLabelForUrl,
} from "./catalog-helpers.mjs";
import { publicCatalogAuthEvidence } from "./catalog-projections.mjs";
import {
  normalizeScopes,
  readJson,
  safeId,
  stableHash,
} from "./io.mjs";
import { publicDownloadSource } from "./download-helpers.mjs";

export function fixtureModelCatalog(searchedAt) {
  return [
    {
      id: "catalog.fixture.autopilot-native-3b-q4",
      providerId: "provider.autopilot.local",
      modelId: "autopilot/native-fixture-3b",
      family: "autopilot-native-fixture",
      architecture: "llama",
      parameterCount: "3B",
      format: "gguf",
      quantization: "Q4_K_M",
      sizeBytes: 96 * 1024 * 1024,
      contextWindow: 4096,
      sourceUrl: "fixture://catalog/autopilot-native-3b-q4",
      sourceUrlHash: stableHash("fixture://catalog/autopilot-native-3b-q4"),
      sourceLabel: "Fixture catalog / native local 3B Q4",
      license: "fixture-local-dev",
      compatibility: ["native_local_fixture", "llama_cpp"],
      tags: ["chat", "code", "local"],
      discoveredAt: searchedAt,
    },
    {
      id: "catalog.fixture.embedding-nomic-q8",
      providerId: "provider.autopilot.local",
      modelId: "autopilot/nomic-embed-fixture",
      family: "nomic-embed-fixture",
      architecture: "nomic",
      parameterCount: "fixture",
      format: "gguf",
      quantization: "Q8_0",
      sizeBytes: 32 * 1024 * 1024,
      contextWindow: 2048,
      sourceUrl: "fixture://catalog/nomic-embed-q8",
      sourceUrlHash: stableHash("fixture://catalog/nomic-embed-q8"),
      sourceLabel: "Fixture catalog / embedding Q8",
      license: "fixture-local-dev",
      compatibility: ["native_local_fixture", "embeddings"],
      tags: ["embedding", "local"],
      discoveredAt: searchedAt,
    },
  ];
}

export function localManifestCatalogEntries(manifestPath, searchedAt) {
  const payload = readJson(path.resolve(manifestPath));
  return catalogRecordsFromPayload(payload)
    .map((record) =>
      genericCatalogEntry(record, {
        catalogProviderId: "catalog.local_manifest",
        sourceLabelPrefix: "Local manifest",
        searchedAt,
      }),
    )
    .filter(Boolean);
}

export function catalogRecordsFromPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.models)) return payload.models;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.entries)) return payload.entries;
  if (Array.isArray(payload?.catalog)) return payload.catalog;
  return [];
}

export function huggingFaceCatalogEntries(record, { baseUrl, searchedAt }) {
  const repoId = String(record.modelId ?? record.id ?? record.repo_id ?? record.repoId ?? "").trim();
  if (!repoId) return [];
  const files = huggingFaceFileCandidates(record);
  const candidates = files.length > 0 ? files : [{ path: null, sizeBytes: Number(record.size ?? record.downloadsSize ?? 0) || null }];
  return candidates
    .map((file) => huggingFaceCatalogEntry(record, file, { baseUrl, repoId, searchedAt }))
    .filter(Boolean);
}

export function huggingFaceFileCandidates(record) {
  const rawFiles = [
    ...(Array.isArray(record.siblings) ? record.siblings : []),
    ...(Array.isArray(record.files) ? record.files : []),
    ...(Array.isArray(record.downloads) ? record.downloads : []),
  ];
  return rawFiles
    .map((file) => ({
      path: file.rfilename ?? file.path ?? file.name ?? file.file ?? file.filename ?? null,
      sizeBytes: Number(file.size ?? file.sizeBytes ?? file.lfs?.size ?? 0) || null,
      downloadUrl: file.downloadUrl ?? file.download_url ?? file.url ?? null,
    }))
    .filter((file) => file.path && modelCatalogFileFormat(file.path));
}

export function huggingFaceCatalogEntry(record, file, { baseUrl, repoId, searchedAt }) {
  const filePath = file.path ?? `${safeId(repoId)}.gguf`;
  const format = modelCatalogFileFormat(filePath);
  if (!format) return null;
  const quantization = parseModelQuantization(filePath) ?? parseModelQuantization(record.modelId ?? record.id ?? "") ?? null;
  const sourceUrl = file.downloadUrl ?? huggingFaceResolveUrl(baseUrl, repoId, filePath);
  const tags = normalizeScopes(record.tags, []);
  return {
    id: `catalog.huggingface.${safeId(repoId)}.${safeId(filePath)}`,
    providerId: "provider.autopilot.local",
    catalogProviderId: "catalog.huggingface",
    modelId: repoId,
    family: String(record.pipeline_tag ?? record.pipelineTag ?? record.library_name ?? "huggingface"),
    architecture: record.config?.architectures?.[0] ?? record.architecture ?? inferModelArchitecture([repoId, filePath, ...(tags ?? [])].join(" ")),
    parameterCount: inferParameterCount([repoId, filePath].join(" ")),
    format,
    quantization,
    sizeBytes: file.sizeBytes,
    contextWindow: Number(record.contextWindow ?? record.context_window ?? 0) || null,
    sourceUrl,
    sourceUrlHash: stableHash(sourceUrl),
    sourceLabel: `Hugging Face / ${repoId}${filePath ? ` / ${filePath}` : ""}`,
    license: record.cardData?.license ?? record.license ?? null,
    compatibility: catalogCompatibilityForFormat(format),
    tags: [...new Set([...tags, format, quantization].filter(Boolean))],
    variantPath: filePath,
    gatedBy: ["IOI_LIVE_MODEL_CATALOG", "IOI_LIVE_MODEL_DOWNLOAD"],
    discoveredAt: searchedAt,
  };
}

export function genericCatalogEntry(record, { catalogProviderId, sourceLabelPrefix, searchedAt }) {
  const modelId = String(record.model_id ?? record.modelId ?? record.id ?? record.name ?? "").trim();
  const sourceUrl = String(record.source_url ?? record.sourceUrl ?? record.download_url ?? record.downloadUrl ?? record.url ?? "").trim();
  if (!modelId || !sourceUrl) return null;
  const format = String(record.format ?? modelCatalogFileFormat(sourceUrl) ?? "").toLowerCase() || "gguf";
  const quantization = record.quantization ?? parseModelQuantization([sourceUrl, modelId].join(" ")) ?? null;
  const tags = normalizeScopes(record.tags, []);
  return {
    id: String(record.catalog_id ?? record.catalogId ?? `catalog.${safeId(catalogProviderId)}.${safeId(modelId)}.${safeId(sourceUrl)}`),
    providerId: String(record.provider_id ?? record.providerId ?? "provider.autopilot.local"),
    catalogProviderId,
    modelId,
    family: String(record.family ?? record.pipeline_tag ?? record.pipelineTag ?? sourceLabelPrefix.toLowerCase().replace(/\s+/g, "_")),
    architecture: record.architecture ?? inferModelArchitecture([modelId, sourceUrl, ...tags].join(" ")),
    parameterCount: record.parameter_count ?? record.parameterCount ?? inferParameterCount([modelId, sourceUrl].join(" ")),
    format,
    quantization,
    sizeBytes: Number(record.size_bytes ?? record.sizeBytes ?? record.size ?? 0) || null,
    contextWindow: Number(record.context_window ?? record.contextWindow ?? 0) || null,
    sourceUrl,
    sourceUrlHash: stableHash(sourceUrl),
    sourceLabel: String(record.source_label ?? record.sourceLabel ?? `${sourceLabelPrefix} / ${modelId}`),
    license: record.license ?? null,
    compatibility: normalizeScopes(record.compatibility, catalogCompatibilityForFormat(format)),
    tags: [...new Set([...tags, format, quantization].filter(Boolean))],
    variantPath: record.variant_path ?? record.variantPath ?? null,
    discoveredAt: searchedAt,
  };
}

export function ollamaArtifactCatalogEntry(artifact, searchedAt) {
  const sourceUrl = `ollama://models/${encodeURIComponent(artifact.modelId)}`;
  return {
    id: `catalog.ollama.${safeId(artifact.modelId)}`,
    providerId: artifact.providerId ?? "provider.ollama",
    catalogProviderId: "catalog.ollama",
    modelId: artifact.modelId,
    family: artifact.family ?? "ollama",
    architecture: inferModelArchitecture(artifact.modelId),
    parameterCount: inferParameterCount(artifact.modelId),
    format: "ollama",
    quantization: artifact.quantization ?? null,
    sizeBytes: artifact.sizeBytes ?? null,
    contextWindow: artifact.contextWindow ?? null,
    sourceUrl,
    sourceUrlHash: stableHash(sourceUrl),
    sourceLabel: `Ollama / ${artifact.modelId}`,
    license: null,
    compatibility: ["ollama"],
    tags: ["ollama", ...(artifact.capabilities ?? [])],
    discoveredAt: searchedAt,
  };
}

export function catalogEntryMatches(entry, { query, format, quantization }) {
  const haystack = [entry.modelId, entry.family, entry.format, entry.quantization, entry.sourceLabel, ...(entry.tags ?? [])].join(" ").toLowerCase();
  if (query && !haystack.includes(query)) return false;
  if (format && entry.format !== format) return false;
  if (quantization && !String(entry.quantization ?? "").toLowerCase().includes(quantization)) return false;
  return true;
}

export function catalogVariantForSource(source, body = {}) {
  const catalogEntry = fixtureModelCatalog(new Date(0).toISOString()).find((entry) => entry.sourceUrl === source);
  const publicSource = publicDownloadSource(source);
  const variant = {
    id: body.variant_id ?? body.variantId ?? catalogEntry?.id ?? `variant.${safeId(publicSource)}`,
    catalogProviderId: body.catalog_provider_id ?? body.catalogProviderId ?? catalogEntry?.catalogProviderId ?? null,
    family: body.family ?? catalogEntry?.family ?? modelIdFromSourceUrl(publicSource),
    architecture: body.architecture ?? catalogEntry?.architecture ?? inferModelArchitecture(publicSource),
    parameterCount: body.parameter_count ?? body.parameterCount ?? catalogEntry?.parameterCount ?? inferParameterCount(publicSource),
    format: body.format ?? catalogEntry?.format ?? modelCatalogFileFormat(publicSource) ?? "gguf",
    quantization: body.quantization ?? catalogEntry?.quantization ?? parseModelQuantization(publicSource) ?? "Q4_K_M",
    sizeBytes: Number(body.size_bytes ?? body.sizeBytes ?? catalogEntry?.sizeBytes ?? 0),
    contextWindow: Number(body.context_window ?? body.contextWindow ?? catalogEntry?.contextWindow ?? 4096),
    sourceLabel: body.source_label ?? body.sourceLabel ?? catalogEntry?.sourceLabel ?? sourceLabelForUrl(source),
    sourceUrl: publicSource,
    sourceUrlHash: stableHash(source),
    license: body.license ?? catalogEntry?.license ?? null,
    compatibility: normalizeScopes(body.compatibility, catalogEntry?.compatibility ?? ["native_local_fixture"]),
    catalogAuth: publicCatalogAuthEvidence(body.catalogAuth ?? catalogEntry?.catalogAuth ?? null),
  };
  return enrichCatalogEntry(variant, { maxBytes: body.max_bytes ?? body.maxBytes ?? null });
}

export function enrichCatalogEntry(entry, { storage = {}, artifacts = [], maxBytes = null } = {}) {
  const architecture = entry.architecture ?? inferModelArchitecture([entry.modelId, entry.family, entry.variantPath, ...(entry.tags ?? [])].join(" "));
  const parameterCount = entry.parameterCount ?? inferParameterCount([entry.modelId, entry.variantPath, entry.sourceLabel].join(" "));
  const compatibility = normalizeScopes(entry.compatibility, catalogCompatibilityForFormat(entry.format));
  const backendCompatibility = catalogBackendCompatibility({ ...entry, architecture, parameterCount, compatibility });
  const benchmarkReadiness = catalogBenchmarkReadiness({ ...entry, compatibility });
  const downloadRisk = catalogDownloadRisk(entry, { storage, artifacts, maxBytes });
  const recommendation = catalogRecommendation({ backendCompatibility, benchmarkReadiness, downloadRisk });
  return {
    ...entry,
    architecture,
    parameterCount,
    compatibility,
    backendCompatibility,
    downloadRisk,
    benchmarkReadiness,
    recommendation,
    selectionReceiptFields: [
      "variant_id",
      "source_url_hash",
      "source_label",
      "format",
      "quantization",
      "architecture",
      "parameter_count",
      "backend_compatibility",
      "download_risk",
      "benchmark_readiness",
      "approval_decision",
    ],
  };
}
