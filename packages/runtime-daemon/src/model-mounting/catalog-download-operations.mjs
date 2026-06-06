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

const RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES = [
  "sourceUrl",
  "modelId",
  "providerId",
  "fileName",
  "fixtureContent",
  "transferApproved",
];

const CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS = [
  "source_url",
  "model_id",
  "provider_id",
  "file_name",
  "fixture_content",
  "transfer_approved",
];

const RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES = [
  "modelId",
  "providerId",
  "sourceUrl",
  "sourceLabel",
  "catalogProviderId",
  "fileName",
  "fixtureContent",
];

const CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS = [
  "model_id",
  "provider_id",
  "source_url",
  "source_label",
  "catalog_provider_id",
  "file_name",
  "fixture_content",
];

function catalogDownloadErrorDetails(sourceHash, evidenceRefs) {
  return { source_url_hash: sourceHash, evidence_refs: evidenceRefs };
}

function catalogAuthReceiptDetails(evidence) {
  if (!evidence) return null;
  return {
    auth_vault_ref_hash: evidence.authVaultRefHash ?? evidence.auth_vault_ref_hash ?? null,
    resolved_material: Boolean(evidence.resolvedMaterial ?? evidence.resolved_material ?? evidence.catalogAuthResolved ?? evidence.catalog_auth_resolved),
    catalog_auth_scheme: evidence.catalogAuthScheme ?? evidence.catalog_auth_scheme ?? "bearer",
    catalog_auth_header_name_hash: evidence.catalogAuthHeaderNameHash ?? evidence.catalog_auth_header_name_hash ?? null,
    evidence_refs: evidence.evidenceRefs ?? evidence.evidence_refs ?? [],
    oauth_boundary: evidence.oauthBoundary ?? evidence.oauth_boundary ?? null,
  };
}

function downloadPolicyReceiptDetails(policy) {
  if (!policy) return null;
  return {
    max_bytes: policy.maxBytes ?? policy.max_bytes ?? null,
    bandwidth_limit_bps: policy.bandwidthLimitBps ?? policy.bandwidth_limit_bps ?? null,
    retry_limit: policy.retryLimit ?? policy.retry_limit ?? null,
    resume: Boolean(policy.resume),
    approval_decision: policy.approvalDecision ?? policy.approval_decision ?? null,
    source: policy.source ?? null,
    status: policy.status ?? null,
  };
}

function transferReceiptDetails(transfer) {
  if (!transfer) return null;
  return {
    source_hash: transfer.sourceHash ?? transfer.source_hash ?? null,
    partial_path_hash: transfer.partialPathHash ?? transfer.partial_path_hash ?? null,
    target_path_hash: transfer.targetPathHash ?? transfer.target_path_hash ?? null,
    resume_metadata_path_hash: transfer.resumeMetadataPathHash ?? transfer.resume_metadata_path_hash ?? null,
    retry_limit: transfer.retryLimit ?? transfer.retry_limit ?? null,
    resume: transfer.resume ?? null,
    bandwidth_limit_bps: transfer.bandwidthLimitBps ?? transfer.bandwidth_limit_bps ?? null,
    status: transfer.status ?? null,
    attempt_count: transfer.attemptCount ?? transfer.attempt_count ?? null,
    retry_count: transfer.retryCount ?? transfer.retry_count ?? null,
    failure_reason: transfer.failureReason ?? transfer.failure_reason ?? null,
    bytes_completed: transfer.bytesCompleted ?? transfer.bytes_completed ?? null,
    bytes_total: transfer.bytesTotal ?? transfer.bytes_total ?? null,
    resumed: transfer.resumed ?? null,
    resume_offset: transfer.resumeOffset ?? transfer.resume_offset ?? null,
  };
}

function transferEventReceiptDetails(details = {}) {
  const canonical = {
    ...(details.attempt !== undefined ? { attempt: details.attempt } : {}),
    ...(details.nextAttempt !== undefined ? { next_attempt: details.nextAttempt } : {}),
    ...(details.retryLimit !== undefined ? { retry_limit: details.retryLimit } : {}),
    ...(details.retryCount !== undefined ? { retry_count: details.retryCount } : {}),
    ...(details.failureReason !== undefined ? { failure_reason: details.failureReason } : {}),
    ...(details.bytesCompleted !== undefined ? { bytes_completed: details.bytesCompleted } : {}),
    ...(details.bytesTotal !== undefined ? { bytes_total: details.bytesTotal } : {}),
    ...(details.partialPathHash !== undefined ? { partial_path_hash: details.partialPathHash } : {}),
    ...(details.resumeMetadataPathHash !== undefined ? { resume_metadata_path_hash: details.resumeMetadataPathHash } : {}),
    ...(details.resumeEnabled !== undefined ? { resume_enabled: details.resumeEnabled } : {}),
    ...(details.resumeOffset !== undefined ? { resume_offset: details.resumeOffset } : {}),
  };
  for (const [key, value] of Object.entries(details)) {
    if (/^[a-z0-9_]+$/.test(key) && !Object.hasOwn(canonical, key)) canonical[key] = value;
  }
  return canonical;
}

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
  assertCanonicalCatalogImportUrlRequestBody(body);
  const sourceUrl = requireString(body.source_url ?? body.url, "source_url");
  const isFixture = sourceUrl.startsWith("fixture://");
  if (!isFixture && !catalogEnabled()) {
    throw makeRuntimeError({
      status: 424,
      code: "external_blocker",
      message: "Live catalog imports are gated. Use fixture:// URLs or set IOI_LIVE_MODEL_CATALOG=1.",
      details: catalogDownloadErrorDetails(hash(sourceUrl), ["network_access_opt_in"]),
    });
  }
  if (!isFixture && !downloadEnabled()) {
    throw makeRuntimeError({
      status: 424,
      code: "external_blocker",
      message: "Live catalog downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1 to materialize remote artifacts.",
      details: catalogDownloadErrorDetails(hash(sourceUrl), ["network_download_opt_in"]),
    });
  }
  const modelId = body.model_id ?? modelIdForSource(sourceUrl);
  const lastCatalogEntry = state.lastCatalogSearch?.results?.find((entry) => entry.sourceUrl === sourceUrl || entry.sourceUrlHash === hash(sourceUrl));
  const variant = variantForSource(sourceUrl, { ...(lastCatalogEntry ?? {}), ...body });
  const receipt = state.lifecycleReceipt("model_catalog_import_url", {
    model_id: modelId,
    provider_id: body.provider_id ?? "provider.autopilot.local",
    source_url_hash: hash(sourceUrl),
    source_label: variant.sourceLabel,
    format: variant.format,
    quantization: variant.quantization,
    license: variant.license,
    compatibility: variant.compatibility,
    architecture: variant.architecture,
    parameter_count: variant.parameterCount,
    recommendation: variant.recommendation,
    backend_compatibility: variant.backendCompatibility,
    download_risk: variant.downloadRisk,
    benchmark_readiness: variant.benchmarkReadiness,
    selection_receipt_fields: variant.selectionReceiptFields,
    catalog_provider_id: variant.catalogProviderId,
    catalog_auth: catalogAuthReceiptDetails(publicCatalogAuth(variant.catalogAuth)),
    approval_decision: approvalDecision({ isFixture, body }),
    live_download_gate: isFixture ? "fixture" : "IOI_LIVE_MODEL_DOWNLOAD",
  });
  const download = await state.downloadModel({
    ...body,
    model_id: modelId,
    provider_id: body.provider_id ?? "provider.autopilot.local",
    source_url: sourceUrl,
    source_label: variant.sourceLabel,
    file_name: body.file_name ?? `${makeSafeFileName(modelId)}.${variant.format}`,
    ...(isFixture
      ? {
          fixture_content:
            body.fixture_content ??
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
    transfer_approved: Boolean(body.transfer_approved ?? isFixture),
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

function assertCanonicalCatalogImportUrlRequestBody(body = {}) {
  const retiredAliases = RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "model_catalog_import_url_request_aliases_retired",
    message: "Model catalog import URL request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS,
    },
  });
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
  assertCanonicalModelDownloadIdentityRequestBody(body);
  const now = state.nowIso();
  const modelId = requireString(body.model_id, "model_id");
  const providerId = body.provider_id ?? "provider.autopilot.local";
  const source = body.source_url ?? body.source ?? "deterministic_fixture_download";
  const isFixture = String(source).startsWith("fixture://") || source === "deterministic_fixture_download";
  if (!isFixture && !downloadEnabled()) {
    throw makeRuntimeError({
      status: 424,
      code: "external_blocker",
      message: "Live model downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1.",
      details: catalogDownloadErrorDetails(hash(source), ["network_download_opt_in"]),
    });
  }
  const sourceLabel = body.source_label ?? labelForSource(source);
  const variantMetadata = variantForSource(source, body);
  const catalogProviderId = body.catalog_provider_id ?? variantMetadata.catalogProviderId ?? null;
  const catalogAuth = !isFixture && catalogProviderId
    ? await authHeadersForCatalogProvider(catalogProviderId, state)
    : { headers: {}, evidence: null };
  const catalogAuthReceipt = publicCatalogAuth(catalogAuth.evidence);
  const targetDir = path.join(state.modelRoot, "downloads", makeSafeFileName(modelId));
  const targetPath = path.join(targetDir, body.file_name ?? `${makeSafeFileName(modelId)}.gguf`);
  const fixtureContent = String(body.fixture_content ?? `deterministic model bytes for ${modelId}\n`);
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
    job_id: jobBase.id,
    model_id: modelId,
    provider_id: providerId,
    source_hash: hash(source),
    source_label: sourceLabel,
    variant: variantMetadata,
    catalog_provider_id: catalogProviderId,
    catalog_auth: catalogAuthReceiptDetails(catalogAuthReceipt),
    recommendation: variantMetadata.recommendation,
    backend_compatibility: variantMetadata.backendCompatibility,
    download_risk: variantMetadata.downloadRisk,
    benchmark_readiness: variantMetadata.benchmarkReadiness,
    selection_receipt_fields: variantMetadata.selectionReceiptFields,
    approval_decision: downloadPolicy.approvalDecision,
    download_policy: downloadPolicyReceiptDetails(downloadPolicy),
    target_path_hash: hash(targetPath),
    max_bytes: maxBytes,
    download_mode: isFixture ? "fixture" : "live_network",
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
      job_id: failed.id,
      model_id: modelId,
      provider_id: providerId,
      failure_reason: failed.failureReason,
      download_policy: downloadPolicyReceiptDetails(downloadPolicy),
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
    job_id: jobBase.id,
    model_id: modelId,
    provider_id: providerId,
    bytes_total: bytesTotal,
    bytes_completed: 0,
    max_bytes: maxBytes,
    source_hash: hash(source),
    source_label: sourceLabel,
    download_mode: isFixture ? "fixture" : "live_network",
    download_policy: downloadPolicyReceiptDetails(downloadPolicy),
    catalog_provider_id: catalogProviderId,
    catalog_auth: catalogAuthReceiptDetails(catalogAuthReceipt),
  });
  const transferReceiptIds = [];
  const recordTransferEvent = (operation, details = {}) => {
    const receipt = state.lifecycleReceipt(operation, {
      job_id: jobBase.id,
      model_id: modelId,
      provider_id: providerId,
      source_hash: hash(source),
      source_label: sourceLabel,
      target_path_hash: hash(targetPath),
      download_mode: isFixture ? "fixture" : "live_network",
      download_policy: downloadPolicyReceiptDetails(downloadPolicy),
      catalog_provider_id: catalogProviderId,
      catalog_auth: catalogAuthReceiptDetails(catalogAuthReceipt),
      ...transferEventReceiptDetails(details),
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
      job_id: jobBase.id,
      model_id: modelId,
      provider_id: providerId,
      failure_reason: failureReason,
      source_hash: hash(source),
      source_label: sourceLabel,
      error_hash: hash(error?.message ?? "download failed"),
      cleanup_state: cleanupState,
      transfer: transferReceiptDetails(transfer),
      catalog_provider_id: catalogProviderId,
      catalog_auth: catalogAuthReceiptDetails(catalogAuthReceipt),
      attempt_count: transfer?.attemptCount ?? null,
      retry_count: transfer?.retryCount ?? null,
      resume_metadata_path_hash: transfer?.resumeMetadataPathHash ?? hash(`${targetPath}.part.json`),
      download_policy: downloadPolicyReceiptDetails(downloadPolicy),
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
    job_id: job.id,
    artifact_id: artifact.id,
    model_id: modelId,
    provider_id: artifact.providerId,
    bytes_total: materialized.bytesTotal || completedBytes,
    bytes_completed: completedBytes,
    max_bytes: maxBytes,
    checksum,
    source_hash: hash(source),
    source_label: sourceLabel,
    variant: variantMetadata,
    recommendation: variantMetadata.recommendation,
    backend_compatibility: variantMetadata.backendCompatibility,
    download_risk: variantMetadata.downloadRisk,
    benchmark_readiness: variantMetadata.benchmarkReadiness,
    selection_receipt_fields: variantMetadata.selectionReceiptFields,
    approval_decision: downloadPolicy.approvalDecision,
    download_policy: downloadPolicyReceiptDetails(downloadPolicy),
    resume_offset: materialized.resumeOffset ?? 0,
    attempt_count: materialized.attemptCount ?? 1,
    retry_count: materialized.retryCount ?? 0,
    resume_metadata_path_hash: materialized.resumeMetadataPathHash ?? hash(`${targetPath}.part.json`),
    transfer: transferReceiptDetails(materialized.transfer),
    download_mode: isFixture ? "fixture" : "live_network",
    catalog_provider_id: catalogProviderId,
    catalog_auth: catalogAuthReceiptDetails(catalogAuthReceipt),
  });
  const completed = { ...job, receiptId: receipt.id, receiptIds: [...job.receiptIds, receipt.id] };
  state.downloads.set(completed.id, completed);
  state.writeMap("model-artifacts", state.artifacts);
  state.writeMap("model-downloads", state.downloads);
  state.writeProjection();
  return completed;
}

function assertCanonicalModelDownloadIdentityRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "model_download_identity_request_aliases_retired",
    message: "Model download identity request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS,
    },
  });
}
