import fs from "node:fs";
import path from "node:path";

export function cancelDownload(state, jobId, body = {}, deps = {}) {
  const {
    cleanupPartialDownload,
    destructiveConfirmationState,
    fileSizeIfExists,
    truthy,
  } = deps;
  const job = state.downloadStatus(jobId);
  if (["completed", "failed", "canceled"].includes(job.status)) {
    return job;
  }
  const cleanupPartial = truthy(body.cleanup_partial ?? body.cleanupPartial ?? true);
  const destructiveConfirmation = destructiveConfirmationState(body, { required: cleanupPartial, action: "download_cancel_cleanup" });
  const partialPath = job.targetPath ? `${job.targetPath}.part` : null;
  const metadataPath = partialPath ? `${partialPath}.json` : null;
  const projectedFreedBytes = cleanupPartial
    ? fileSizeIfExists(job.targetPath) + fileSizeIfExists(partialPath) + fileSizeIfExists(metadataPath)
    : 0;
  let cleanupState = cleanupPartial ? "not_needed" : "retained_partial";
  if (cleanupPartial && job.targetPath) {
    cleanupState = cleanupPartialDownload(job.targetPath);
  }
  const receipt = state.lifecycleReceipt("model_download_canceled", {
    jobId,
    modelId: job.modelId,
    providerId: job.providerId,
    bytesCompleted: job.bytesCompleted,
    bytesTotal: job.bytesTotal,
    cleanupPartial,
    cleanupState,
    projectedFreedBytes,
    destructiveConfirmation,
    downloadPolicy: job.downloadPolicy ?? null,
  });
  const canceled = {
    ...job,
    status: "canceled",
    cleanupState,
    projectedFreedBytes,
    destructiveConfirmation,
    updatedAt: state.nowIso(),
    receiptId: receipt.id,
    receiptIds: [...(job.receiptIds ?? []), receipt.id],
  };
  state.downloads.set(jobId, canceled);
  state.writeMap("model-downloads", state.downloads);
  state.writeProjection();
  return canceled;
}

export function downloadStatus(state, jobId, deps = {}) {
  const { notFound } = deps;
  const job = state.downloads.get(jobId);
  if (!job) throw notFound(`Download job not found: ${jobId}`, { jobId });
  return job;
}

export function deleteModelArtifact(state, id, body = {}, deps = {}) {
  const {
    destructiveConfirmationState,
    fileSizeIfExists,
    runtimeError,
    safeFileName,
    schemaVersion,
    stableHash,
    truthy,
  } = deps;
  const artifact = state.getModel(id);
  const endpointIds = [...state.endpoints.values()].filter((endpoint) => endpoint.artifactId === artifact.id).map((endpoint) => endpoint.id);
  const instanceIds = [...state.instances.values()]
    .filter((instance) => endpointIds.includes(instance.endpointId) && instance.status === "loaded")
    .map((instance) => instance.id);
  const projectedFreedBytes = fileSizeIfExists(artifact.artifactPath);
  const destructiveConfirmation = destructiveConfirmationState(body, { required: projectedFreedBytes > 0 || endpointIds.length > 0, action: "model_artifact_delete" });
  if (truthy(body.dry_run ?? body.dryRun)) {
    const receipt = state.lifecycleReceipt("model_artifact_delete_dry_run", {
      artifactId: artifact.id,
      modelId: artifact.modelId,
      providerId: artifact.providerId,
      artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
      affectedEndpointIds: endpointIds,
      affectedInstanceIds: instanceIds,
      projectedFreedBytes,
      destructiveConfirmation,
    });
    return {
      schemaVersion,
      status: "dry_run",
      artifactId: artifact.id,
      modelId: artifact.modelId,
      affectedEndpointIds: endpointIds,
      affectedInstanceIds: instanceIds,
      projectedFreedBytes,
      destructiveConfirmation,
      receiptId: receipt.id,
    };
  }
  if (instanceIds.length > 0) {
    throw runtimeError({
      status: 409,
      code: "conflict",
      message: "Model artifact is loaded. Unload linked instances before deleting it.",
      details: { artifactId: artifact.id, instanceIds },
    });
  }
  for (const endpointId of endpointIds) {
    const endpoint = state.endpoints.get(endpointId);
    state.endpoints.set(endpointId, { ...endpoint, status: "deleted_with_artifact", deletedAt: state.nowIso() });
  }
  state.artifacts.delete(artifact.id);
  fs.rmSync(path.join(state.stateDir, "model-artifacts", `${safeFileName(artifact.id)}.json`), { force: true });
  let cleanupState = "not_applicable";
  if (artifact.artifactPath && artifact.artifactPath.startsWith(state.modelRoot)) {
    try {
      fs.rmSync(artifact.artifactPath, { force: true });
      cleanupState = "removed";
    } catch {
      cleanupState = "failed";
    }
  }
  const receipt = state.lifecycleReceipt("model_artifact_delete", {
    artifactId: artifact.id,
    modelId: artifact.modelId,
    providerId: artifact.providerId,
    artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
    endpointIds,
    affectedEndpointIds: endpointIds,
    affectedInstanceIds: instanceIds,
    projectedFreedBytes,
    cleanupState,
    destructiveConfirmation,
  });
  state.writeMap("model-artifacts", state.artifacts);
  state.writeMap("model-endpoints", state.endpoints);
  state.writeProjection();
  return {
    schemaVersion,
    status: "deleted",
    artifactId: artifact.id,
    modelId: artifact.modelId,
    cleanupState,
    affectedEndpointIds: endpointIds,
    affectedInstanceIds: instanceIds,
    projectedFreedBytes,
    destructiveConfirmation,
    receiptId: receipt.id,
  };
}

export function cleanupModelStorage(state, body = {}, deps = {}) {
  const {
    destructiveConfirmationState,
    fileSizeIfExists,
    listModelFiles,
    runtimeError,
    schemaVersion,
    stableHash,
    truthy,
  } = deps;
  const knownPaths = new Set([...state.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
  const files = listModelFiles(state.modelRoot);
  const orphans = files.filter((filePath) => !knownPaths.has(filePath));
  const orphanBytes = orphans.reduce((total, filePath) => total + fileSizeIfExists(filePath), 0);
  const removeOrphans = truthy(body.remove_orphans ?? body.removeOrphans ?? false);
  const destructiveConfirmation = destructiveConfirmationState(body, { required: removeOrphans && orphans.length > 0, action: "model_storage_cleanup" });
  if (removeOrphans && destructiveConfirmation.required && !destructiveConfirmation.confirmed) {
    throw runtimeError({
      status: 409,
      code: "destructive_confirmation_required",
      message: "Confirm destructive cleanup before removing orphan model files.",
      details: { orphanCount: orphans.length, projectedFreedBytes: orphanBytes },
    });
  }
  let cleanupState = "scan_only";
  let cleanedBytes = 0;
  let removedOrphanCount = 0;
  if (removeOrphans) {
    cleanupState = "removed_orphans";
    for (const orphan of orphans) {
      const size = fileSizeIfExists(orphan);
      try {
        fs.rmSync(orphan, { force: true });
        cleanedBytes += size;
        removedOrphanCount += 1;
      } catch {
        cleanupState = "partial_cleanup_failed";
      }
    }
  }
  const receipt = state.lifecycleReceipt("model_storage_cleanup", {
    modelId: "model-storage",
    scannedFileCount: files.length,
    orphanCount: orphans.length,
    orphanPathHashes: orphans.map((filePath) => stableHash(filePath)),
    orphanBytes,
    removeOrphans,
    cleanedBytes,
    removedOrphanCount,
    projectedFreedBytes: orphanBytes,
    cleanupState,
    destructiveConfirmation,
  });
  return {
    schemaVersion,
    status: removeOrphans ? "cleaned" : "scanned",
    scannedFileCount: files.length,
    orphanCount: orphans.length,
    orphanBytes,
    removeOrphans,
    cleanedBytes,
    removedOrphanCount,
    projectedFreedBytes: orphanBytes,
    cleanupState,
    destructiveConfirmation,
    receiptId: receipt.id,
  };
}
