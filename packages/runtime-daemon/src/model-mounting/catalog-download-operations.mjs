import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { catalogVariantForSource } from "./catalog-entries.mjs";
import {
  assertDownloadPolicyAllowed,
  catalogApprovalDecision,
  modelIdFromSourceUrl,
  normalizeDownloadPolicy,
  sourceLabelForUrl,
} from "./catalog-helpers.mjs";
import { catalogProviderAuthHeaders } from "./catalog-provider-config.mjs";
import { publicCatalogAuthEvidence } from "./catalog-projections.mjs";
import {
  downloadFailureReason,
  failedDownloadCleanupState,
  materializeFixtureDownload,
  materializeLiveDownload,
  publicDownloadSource,
  shouldRetainFailedDownloadPartial,
} from "./download-helpers.mjs";
import {
  liveModelCatalogEnabled,
  liveModelDownloadEnabled,
  modelDownloadTimeoutMs,
} from "./environment.mjs";
import {
  normalizeOptionalBytes,
  normalizeScopes,
  runtimeError,
  safeFileName,
  safeId,
  stableHash,
  truthy,
} from "./io.mjs";
import { parseLocalModelMetadata } from "./local-system-probes.mjs";
import { requiredString } from "./provider-registry.mjs";

export async function catalogImportUrl(state, body = {}, deps = {}) {
  const {
    catalogApprovalDecision: approvalDecision = catalogApprovalDecision,
    catalogVariantForSource: variantForSource = catalogVariantForSource,
    liveModelCatalogEnabled: catalogEnabled = liveModelCatalogEnabled,
    liveModelDownloadEnabled: downloadEnabled = liveModelDownloadEnabled,
    modelIdFromSourceUrl: modelIdForSource = modelIdFromSourceUrl,
    publicCatalogAuthEvidence: publicCatalogAuth = publicCatalogAuthEvidence,
    requiredString: requireString = requiredString,
    runtimeError: makeRuntimeError = runtimeError,
    safeFileName: makeSafeFileName = safeFileName,
    schemaVersion,
    stableHash: hash = stableHash,
  } = deps;
  const sourceUrl = requireString(body.source_url ?? body.sourceUrl ?? body.url, "source_url");
  const isFixture = sourceUrl.startsWith("fixture://");
  if (!isFixture && !catalogEnabled()) {
    throw makeRuntimeError({
      status: 424,
      code: "external_blocker",
      message: "Live catalog imports are gated. Use fixture:// URLs or set IOI_LIVE_MODEL_CATALOG=1.",
      details: { sourceUrlHash: hash(sourceUrl), evidenceRefs: ["network_access_opt_in"] },
    });
  }
  if (!isFixture && !downloadEnabled()) {
    throw makeRuntimeError({
      status: 424,
      code: "external_blocker",
      message: "Live catalog downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1 to materialize remote artifacts.",
      details: { sourceUrlHash: hash(sourceUrl), evidenceRefs: ["network_download_opt_in"] },
    });
  }
  const modelId = body.model_id ?? body.modelId ?? modelIdForSource(sourceUrl);
  const lastCatalogEntry = state.lastCatalogSearch?.results?.find((entry) => entry.sourceUrl === sourceUrl || entry.sourceUrlHash === hash(sourceUrl));
  const variant = variantForSource(sourceUrl, { ...(lastCatalogEntry ?? {}), ...body });
  const receipt = state.lifecycleReceipt("model_catalog_import_url", {
    modelId,
    providerId: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
    sourceUrlHash: hash(sourceUrl),
    sourceLabel: variant.sourceLabel,
    format: variant.format,
    quantization: variant.quantization,
    license: variant.license,
    compatibility: variant.compatibility,
    architecture: variant.architecture,
    parameterCount: variant.parameterCount,
    recommendation: variant.recommendation,
    backendCompatibility: variant.backendCompatibility,
    downloadRisk: variant.downloadRisk,
    benchmarkReadiness: variant.benchmarkReadiness,
    selectionReceiptFields: variant.selectionReceiptFields,
    catalogProviderId: variant.catalogProviderId,
    catalogAuth: publicCatalogAuth(variant.catalogAuth),
    approvalDecision: approvalDecision({ isFixture, body }),
    liveDownloadGate: isFixture ? "fixture" : "IOI_LIVE_MODEL_DOWNLOAD",
  });
  const download = await state.downloadModel({
    ...body,
    model_id: modelId,
    provider_id: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
    source_url: sourceUrl,
    source_label: variant.sourceLabel,
    file_name: body.file_name ?? body.fileName ?? `${makeSafeFileName(modelId)}.${variant.format}`,
    ...(isFixture
      ? {
          fixture_content:
            body.fixture_content ??
            body.fixtureContent ??
            [`family=${variant.family}`, `quantization=${variant.quantization}`, `context=${variant.contextWindow}`, ""].join("\n"),
        }
      : {}),
    format: variant.format,
    quantization: variant.quantization,
    family: variant.family,
    context_window: variant.contextWindow,
    license: variant.license,
    compatibility: variant.compatibility,
    architecture: variant.architecture,
    parameter_count: variant.parameterCount,
    recommendation_score: variant.recommendation?.score,
    download_risk_status: variant.downloadRisk?.status,
    backend_compatibility: variant.backendCompatibility,
    benchmark_readiness: variant.benchmarkReadiness,
    selection_receipt_fields: variant.selectionReceiptFields,
    transfer_approved: Boolean(body.transfer_approved ?? body.transferApproved ?? isFixture),
    variant_id: variant.id,
    catalog_provider_id: variant.catalogProviderId,
    catalog_receipt_id: receipt.id,
  });
  return {
    schemaVersion,
    status: download.status,
    catalogReceiptId: receipt.id,
    download,
  };
}

export async function downloadModel(state, body = {}, deps = {}) {
  const {
    assertDownloadPolicyAllowed: assertPolicyAllowed = assertDownloadPolicyAllowed,
    catalogProviderAuthHeaders: authHeadersForCatalogProvider = catalogProviderAuthHeaders,
    catalogVariantForSource: variantForSource = catalogVariantForSource,
    downloadFailureReason: failureReasonForDownload = downloadFailureReason,
    env = process.env,
    failedDownloadCleanupState: failedCleanupState = failedDownloadCleanupState,
    materializeFixtureDownload: materializeFixture = materializeFixtureDownload,
    materializeLiveDownload: materializeLive = materializeLiveDownload,
    mkdirSync = fs.mkdirSync,
    modelDownloadTimeoutMs: downloadTimeoutMs = modelDownloadTimeoutMs,
    normalizeDownloadPolicy: normalizePolicy = normalizeDownloadPolicy,
    normalizeOptionalBytes: normalizeBytes = normalizeOptionalBytes,
    normalizeScopes: normalizeScopeList = normalizeScopes,
    parseLocalModelMetadata: parseMetadata = parseLocalModelMetadata,
    publicCatalogAuthEvidence: publicCatalogAuth = publicCatalogAuthEvidence,
    publicDownloadSource: publicSource = publicDownloadSource,
    randomUUID = () => crypto.randomUUID(),
    requiredString: requireString = requiredString,
    runtimeError: makeRuntimeError = runtimeError,
    safeFileName: makeSafeFileName = safeFileName,
    safeId: makeSafeId = safeId,
    shouldRetainFailedDownloadPartial: shouldRetainPartial = shouldRetainFailedDownloadPartial,
    sourceLabelForUrl: labelForSource = sourceLabelForUrl,
    stableHash: hash = stableHash,
    truthy: isTruthy = truthy,
    liveModelDownloadEnabled: downloadEnabled = liveModelDownloadEnabled,
  } = deps;
  const now = state.nowIso();
  const modelId = requireString(body.model_id ?? body.modelId, "model_id");
  const providerId = body.provider_id ?? body.providerId ?? "provider.autopilot.local";
  const source = body.source_url ?? body.sourceUrl ?? body.source ?? "deterministic_fixture_download";
  const isFixture = String(source).startsWith("fixture://") || source === "deterministic_fixture_download";
  if (!isFixture && !downloadEnabled()) {
    throw makeRuntimeError({
      status: 424,
      code: "external_blocker",
      message: "Live model downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1.",
      details: { sourceUrlHash: hash(source), evidenceRefs: ["network_download_opt_in"] },
    });
  }
  const sourceLabel = body.source_label ?? body.sourceLabel ?? labelForSource(source);
  const variantMetadata = variantForSource(source, body);
  const catalogProviderId = body.catalog_provider_id ?? body.catalogProviderId ?? variantMetadata.catalogProviderId ?? null;
  const catalogAuth = !isFixture && catalogProviderId
    ? await authHeadersForCatalogProvider(catalogProviderId, state)
    : { headers: {}, evidence: null };
  const catalogAuthReceipt = publicCatalogAuth(catalogAuth.evidence);
  const targetDir = path.join(state.modelRoot, "downloads", makeSafeFileName(modelId));
  const targetPath = path.join(targetDir, body.file_name ?? body.fileName ?? `${makeSafeFileName(modelId)}.gguf`);
  const fixtureContent = String(body.fixture_content ?? body.fixtureContent ?? `deterministic model bytes for ${modelId}\n`);
  const bytesTotal = Number(body.bytes_total ?? body.bytesTotal ?? (isFixture ? Buffer.byteLength(fixtureContent) : 0));
  const maxBytes = normalizeBytes(body.max_bytes ?? body.maxBytes ?? env.IOI_MODEL_DOWNLOAD_MAX_BYTES);
  const downloadPolicy = normalizePolicy(body, { isFixture, maxBytes, source });
  assertPolicyAllowed(downloadPolicy, source);
  const jobBase = {
    id: `download_job_${randomUUID()}`,
    modelId,
    providerId,
    source: publicSource(source),
    sourceHash: hash(source),
    sourceUrlHash: hash(source),
    sourceLabel,
    variant: variantMetadata,
    targetPath,
    targetPathHash: hash(targetPath),
    bytesTotal,
    bytesCompleted: 0,
    progress: 0,
    maxBytes,
    downloadPolicy,
    bandwidthLimitBps: downloadPolicy.bandwidthLimitBps,
    retryLimit: downloadPolicy.retryLimit,
    resumeDownload: downloadPolicy.resume,
    createdAt: now,
    updatedAt: now,
    receiptIds: [],
    receiptId: null,
  };
  const queuedReceipt = state.lifecycleReceipt("model_download_queued", {
    jobId: jobBase.id,
    modelId,
    providerId,
    sourceHash: hash(source),
    sourceLabel,
    variant: variantMetadata,
    catalogProviderId,
    catalogAuth: catalogAuthReceipt,
    recommendation: variantMetadata.recommendation,
    backendCompatibility: variantMetadata.backendCompatibility,
    downloadRisk: variantMetadata.downloadRisk,
    benchmarkReadiness: variantMetadata.benchmarkReadiness,
    selectionReceiptFields: variantMetadata.selectionReceiptFields,
    approvalDecision: downloadPolicy.approvalDecision,
    downloadPolicy,
    targetPathHash: hash(targetPath),
    maxBytes,
    downloadMode: isFixture ? "fixture" : "live_network",
  });
  if (isTruthy(body.fail ?? body.simulate_failure ?? body.simulateFailure)) {
    const failed = {
      ...jobBase,
      artifactId: null,
      status: "failed",
      failureReason: body.failure_reason ?? body.failureReason ?? "deterministic_fixture_failure",
      updatedAt: state.nowIso(),
      receiptIds: [queuedReceipt.id],
      receiptId: queuedReceipt.id,
    };
    const failedReceipt = state.lifecycleReceipt("model_download_failed", {
      jobId: failed.id,
      modelId,
      providerId,
      failureReason: failed.failureReason,
      downloadPolicy,
    });
    const storedFailed = { ...failed, receiptIds: [...failed.receiptIds, failedReceipt.id], receiptId: failedReceipt.id };
    state.downloads.set(storedFailed.id, storedFailed);
    state.writeMap("model-downloads", state.downloads);
    state.writeProjection();
    return storedFailed;
  }
  if (isTruthy(body.queued_only ?? body.queuedOnly)) {
    const queued = {
      ...jobBase,
      artifactId: null,
      status: "queued",
      receiptIds: [queuedReceipt.id],
      receiptId: queuedReceipt.id,
    };
    state.downloads.set(queued.id, queued);
    state.writeMap("model-downloads", state.downloads);
    state.writeProjection();
    return queued;
  }
  mkdirSync(targetDir, { recursive: true });
  const runningReceipt = state.lifecycleReceipt("model_download_running", {
    jobId: jobBase.id,
    modelId,
    providerId,
    bytesTotal,
    bytesCompleted: 0,
    maxBytes,
    sourceHash: hash(source),
    sourceLabel,
    downloadMode: isFixture ? "fixture" : "live_network",
    downloadPolicy,
    catalogProviderId,
    catalogAuth: catalogAuthReceipt,
  });
  const transferReceiptIds = [];
  const recordTransferEvent = (operation, details = {}) => {
    const receipt = state.lifecycleReceipt(operation, {
      jobId: jobBase.id,
      modelId,
      providerId,
      sourceHash: hash(source),
      sourceLabel,
      targetPathHash: hash(targetPath),
      downloadMode: isFixture ? "fixture" : "live_network",
      downloadPolicy,
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
      ...details,
    });
    transferReceiptIds.push(receipt.id);
    return receipt;
  };
  let materialized;
  try {
    materialized = isFixture
      ? materializeFixture({ targetPath, fixtureContent })
      : await materializeLive({
          source,
          targetPath,
          expectedChecksum: body.checksum ?? body.expected_checksum ?? body.expectedChecksum ?? null,
          maxBytes,
          resume: downloadPolicy.resume,
          bandwidthLimitBps: downloadPolicy.bandwidthLimitBps,
          retryLimit: downloadPolicy.retryLimit,
          timeoutMs: downloadTimeoutMs(),
          headers: catalogAuth.headers,
          onTransferEvent: recordTransferEvent,
        });
  } catch (error) {
    const failureReason = failureReasonForDownload(error);
    const transfer = error?.downloadTransfer ?? null;
    const cleanupState = failedCleanupState(targetPath, {
      retainPartial: shouldRetainPartial(downloadPolicy, failureReason),
    });
    const failedReceipt = state.lifecycleReceipt("model_download_failed", {
      jobId: jobBase.id,
      modelId,
      providerId,
      failureReason,
      sourceHash: hash(source),
      sourceLabel,
      errorHash: hash(error?.message ?? "download failed"),
      cleanupState,
      transfer,
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
      attemptCount: transfer?.attemptCount ?? null,
      retryCount: transfer?.retryCount ?? null,
      resumeMetadataPathHash: transfer?.resumeMetadataPathHash ?? hash(`${targetPath}.part.json`),
      downloadPolicy,
    });
    const failed = {
      ...jobBase,
      artifactId: null,
      status: "failed",
      failureReason,
      cleanupState,
      transfer,
      attemptCount: transfer?.attemptCount ?? null,
      retryCount: transfer?.retryCount ?? null,
      resumeMetadataPathHash: transfer?.resumeMetadataPathHash ?? hash(`${targetPath}.part.json`),
      updatedAt: state.nowIso(),
      receiptIds: [queuedReceipt.id, runningReceipt.id, ...transferReceiptIds, failedReceipt.id],
      receiptId: failedReceipt.id,
    };
    state.downloads.set(failed.id, failed);
    state.writeMap("model-downloads", state.downloads);
    state.writeProjection();
    return failed;
  }
  const checksum = materialized.checksum;
  const completedBytes = materialized.bytesCompleted;
  const metadata = parseMetadata(targetPath);
  const artifact = state.artifacts.get(`download.${makeSafeId(modelId)}`) ?? {
    id: `download.${makeSafeId(modelId)}`,
    providerId,
    modelId,
    displayName: body.display_name ?? body.displayName ?? modelId,
    family: body.family ?? metadata.family ?? "download",
    format: body.format ?? variantMetadata.format ?? metadata.format ?? "gguf",
    quantization: body.quantization ?? variantMetadata.quantization ?? metadata.quantization ?? null,
    sizeBytes: completedBytes,
    checksum,
    contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
    capabilities: normalizeScopeList(body.capabilities, ["chat"]),
    privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
    source: publicSource(source),
    sourceLabel,
    sourceUrlHash: hash(source),
    license: body.license ?? variantMetadata.license ?? null,
    compatibility: body.compatibility ?? variantMetadata.compatibility ?? [],
    artifactPath: targetPath,
    metadata,
    state: "installed",
    discoveredAt: now,
  };
  const job = {
    ...jobBase,
    artifactId: artifact.id,
    status: "completed",
    checksum,
    progress: 1,
    bytesTotal: materialized.bytesTotal || completedBytes,
    bytesCompleted: completedBytes,
    resumeOffset: materialized.resumeOffset ?? 0,
    attemptCount: materialized.attemptCount ?? 1,
    retryCount: materialized.retryCount ?? 0,
    resumeMetadataPathHash: materialized.resumeMetadataPathHash ?? hash(`${targetPath}.part.json`),
    transfer: materialized.transfer ?? null,
    updatedAt: state.nowIso(),
    receiptIds: [queuedReceipt.id, runningReceipt.id, ...transferReceiptIds],
    receiptId: runningReceipt.id,
  };
  state.artifacts.set(artifact.id, artifact);
  state.downloads.set(job.id, job);
  const receipt = state.lifecycleReceipt("model_download_completed", {
    jobId: job.id,
    artifactId: artifact.id,
    modelId,
    providerId: artifact.providerId,
    bytesTotal: materialized.bytesTotal || completedBytes,
    bytesCompleted: completedBytes,
    maxBytes,
    checksum,
    sourceHash: hash(source),
    sourceLabel,
    variant: variantMetadata,
    recommendation: variantMetadata.recommendation,
    backendCompatibility: variantMetadata.backendCompatibility,
    downloadRisk: variantMetadata.downloadRisk,
    benchmarkReadiness: variantMetadata.benchmarkReadiness,
    selectionReceiptFields: variantMetadata.selectionReceiptFields,
    approvalDecision: downloadPolicy.approvalDecision,
    downloadPolicy,
    resumeOffset: materialized.resumeOffset ?? 0,
    attemptCount: materialized.attemptCount ?? 1,
    retryCount: materialized.retryCount ?? 0,
    resumeMetadataPathHash: materialized.resumeMetadataPathHash ?? hash(`${targetPath}.part.json`),
    transfer: materialized.transfer ?? null,
    downloadMode: isFixture ? "fixture" : "live_network",
    catalogProviderId,
    catalogAuth: catalogAuthReceipt,
  });
  const completed = { ...job, receiptId: receipt.id, receiptIds: [...job.receiptIds, receipt.id] };
  state.downloads.set(completed.id, completed);
  state.writeMap("model-artifacts", state.artifacts);
  state.writeMap("model-downloads", state.downloads);
  state.writeProjection();
  return completed;
}
