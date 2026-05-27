import fs from "node:fs";
import path from "node:path";
import {
  stableHash,
  fileSha256,
  sleep,
  fetchWithTimeout,
  fileSizeIfExists,
  writeJson,
  normalizeNonNegativeInteger,
} from "./io.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1";

export function materializeFixtureDownload({ targetPath, fixtureContent }) {
  fs.writeFileSync(targetPath, fixtureContent);
  const bytesCompleted = fs.statSync(targetPath).size;
  return {
    bytesTotal: bytesCompleted,
    bytesCompleted,
    checksum: fileSha256(targetPath),
    resumeOffset: 0,
  };
}

export async function materializeLiveDownload({
  source,
  targetPath,
  expectedChecksum,
  maxBytes,
  resume,
  bandwidthLimitBps,
  retryLimit = 0,
  timeoutMs,
  headers = {},
  onTransferEvent,
}) {
  const partialPath = `${targetPath}.part`;
  const metadataPath = `${partialPath}.json`;
  const maxAttempts = Math.max(1, normalizeNonNegativeInteger(retryLimit, 0) + 1);
  const transferBase = {
    sourceHash: stableHash(source),
    partialPathHash: stableHash(partialPath),
    targetPathHash: stableHash(targetPath),
    resumeMetadataPathHash: stableHash(metadataPath),
    retryLimit: maxAttempts - 1,
    resume,
    bandwidthLimitBps: bandwidthLimitBps ?? null,
  };
  let lastError;
  for (let attemptIndex = 0; attemptIndex < maxAttempts; attemptIndex += 1) {
    try {
      const result = await materializeLiveDownloadAttempt({
        source,
        targetPath,
        partialPath,
        metadataPath,
        expectedChecksum,
        maxBytes,
        resume,
        bandwidthLimitBps,
        timeoutMs,
        headers,
        attemptIndex,
        maxAttempts,
        transferBase,
        onTransferEvent,
      });
      return {
        ...result,
        attemptCount: attemptIndex + 1,
        retryCount: attemptIndex,
        resumeMetadataPathHash: transferBase.resumeMetadataPathHash,
        transfer: {
          ...transferBase,
          status: "completed",
          attemptCount: attemptIndex + 1,
          retryCount: attemptIndex,
          bytesCompleted: result.bytesCompleted,
          bytesTotal: result.bytesTotal,
          resumed: result.resumeOffset > 0,
        },
      };
    } catch (error) {
      lastError = error;
      const failureReason = downloadFailureReason(error);
      const canRetry = attemptIndex + 1 < maxAttempts && isRetriableDownloadFailure(failureReason);
      const transfer = {
        ...transferBase,
        status: canRetry ? "retry_pending" : "failed",
        attemptCount: attemptIndex + 1,
        retryCount: attemptIndex,
        failureReason,
        bytesCompleted: error?.downloadTransfer?.bytesCompleted ?? fileSizeIfExists(partialPath),
        bytesTotal: error?.downloadTransfer?.bytesTotal ?? 0,
        resumed: Boolean(error?.downloadTransfer?.resumeOffset),
      };
      writeDownloadResumeMetadata(metadataPath, transfer);
      error.downloadTransfer = transfer;
      if (!canRetry) break;
      onTransferEvent?.("model_download_retry", {
        attempt: attemptIndex + 1,
        nextAttempt: attemptIndex + 2,
        retryLimit: maxAttempts - 1,
        failureReason,
        bytesCompleted: transfer.bytesCompleted,
        bytesTotal: transfer.bytesTotal,
        partialPathHash: transferBase.partialPathHash,
        resumeMetadataPathHash: transferBase.resumeMetadataPathHash,
        resumeEnabled: resume,
      });
      if (!resume) fs.rmSync(partialPath, { force: true });
      await sleep(downloadRetryBackoffMs(attemptIndex));
    }
  }
  throw lastError;
}

export async function materializeLiveDownloadAttempt({
  source,
  targetPath,
  partialPath,
  metadataPath,
  expectedChecksum,
  maxBytes,
  resume,
  bandwidthLimitBps,
  timeoutMs,
  headers = {},
  attemptIndex,
  maxAttempts,
  transferBase,
  onTransferEvent,
}) {
  const resumeOffset = resume && fs.existsSync(partialPath) ? fs.statSync(partialPath).size : 0;
  const requestHeaders = { ...headers, ...(resumeOffset > 0 ? { Range: `bytes=${resumeOffset}-` } : {}) };
  writeDownloadResumeMetadata(metadataPath, {
    ...transferBase,
    status: "running",
    attemptCount: attemptIndex + 1,
    retryLimit: maxAttempts - 1,
    resumeOffset,
    bytesCompleted: resumeOffset,
  });
  if (resumeOffset > 0) {
    onTransferEvent?.("model_download_resume", {
      attempt: attemptIndex + 1,
      retryLimit: maxAttempts - 1,
      resumeOffset,
      partialPathHash: transferBase.partialPathHash,
      resumeMetadataPathHash: transferBase.resumeMetadataPathHash,
    });
  }
  const response = await fetchWithTimeout(source, { timeoutMs, headers: requestHeaders });
  if (!response.ok) {
    throw new Error(`live_download_http_${response.status}`);
  }
  const contentLength = Number(response.headers.get("content-length") ?? 0) || 0;
  const bytesTotal = response.status === 206 ? resumeOffset + contentLength : contentLength || 0;
  if (maxBytes && bytesTotal && bytesTotal > maxBytes) {
    throw new Error("live_download_size_limit_exceeded");
  }
  const appending = resumeOffset > 0 && response.status === 206;
  if (!appending) fs.rmSync(partialPath, { force: true });
  const stream = fs.createWriteStream(partialPath, { flags: appending ? "a" : "w" });
  let bytesCompleted = appending ? resumeOffset : 0;
  let lastMetadataWrite = Date.now();
  const startedAt = Date.now();
  try {
    for await (const chunk of response.body) {
      const buffer = Buffer.from(chunk);
      bytesCompleted += buffer.length;
      if (maxBytes && bytesCompleted > maxBytes) {
        throw new Error("live_download_size_limit_exceeded");
      }
      if (!stream.write(buffer)) {
        await new Promise((resolve) => stream.once("drain", resolve));
      }
      if (Date.now() - lastMetadataWrite > 250) {
        writeDownloadResumeMetadata(metadataPath, {
          ...transferBase,
          status: "running",
          attemptCount: attemptIndex + 1,
          retryLimit: maxAttempts - 1,
          resumeOffset,
          bytesCompleted,
          bytesTotal,
        });
        lastMetadataWrite = Date.now();
      }
      if (bandwidthLimitBps) {
        const elapsedMs = Math.max(1, Date.now() - startedAt);
        const expectedElapsedMs = ((bytesCompleted - resumeOffset) / bandwidthLimitBps) * 1000;
        if (expectedElapsedMs > elapsedMs) {
          await sleep(Math.min(250, expectedElapsedMs - elapsedMs));
        }
      }
    }
  } catch (error) {
    error.downloadTransfer = {
      ...transferBase,
      status: "attempt_failed",
      attemptCount: attemptIndex + 1,
      retryLimit: maxAttempts - 1,
      resumeOffset,
      bytesCompleted,
      bytesTotal,
    };
    throw error;
  } finally {
    await new Promise((resolve, reject) => stream.end((error) => (error ? reject(error) : resolve())));
  }
  fs.renameSync(partialPath, targetPath);
  const checksum = fileSha256(targetPath);
  if (expectedChecksum && checksum !== expectedChecksum) {
    fs.rmSync(targetPath, { force: true });
    throw new Error("live_download_checksum_mismatch");
  }
  fs.rmSync(metadataPath, { force: true });
  return {
    bytesTotal: bytesTotal || bytesCompleted,
    bytesCompleted,
    checksum,
    resumeOffset: appending ? resumeOffset : 0,
  };
}

export function writeDownloadResumeMetadata(metadataPath, metadata) {
  const safeMetadata = {
    schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    status: metadata.status,
    sourceHash: metadata.sourceHash,
    partialPathHash: metadata.partialPathHash,
    targetPathHash: metadata.targetPathHash,
    resumeMetadataPathHash: metadata.resumeMetadataPathHash,
    attemptCount: metadata.attemptCount ?? null,
    retryCount: metadata.retryCount ?? null,
    retryLimit: metadata.retryLimit ?? null,
    resume: Boolean(metadata.resume),
    resumeOffset: metadata.resumeOffset ?? null,
    resumed: Boolean(metadata.resumed),
    bytesCompleted: metadata.bytesCompleted ?? 0,
    bytesTotal: metadata.bytesTotal ?? 0,
    bandwidthLimitBps: metadata.bandwidthLimitBps ?? null,
    failureReason: metadata.failureReason ?? null,
    updatedAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
  writeJson(metadataPath, safeMetadata);
}

export function isRetriableDownloadFailure(failureReason) {
  if (failureReason === "network_download_failed" || failureReason === "network_timeout") return true;
  const httpStatus = Number(String(failureReason).match(/^http_([0-9]+)$/)?.[1] ?? 0);
  return httpStatus === 408 || httpStatus === 409 || httpStatus === 425 || httpStatus === 429 || httpStatus >= 500;
}

export function downloadRetryBackoffMs(attemptIndex) {
  const configured = Number(process.env.IOI_MODEL_DOWNLOAD_RETRY_BACKOFF_MS ?? 25);
  return Math.max(0, configured || 0) * Math.max(1, attemptIndex + 1);
}

export function shouldRetainFailedDownloadPartial(downloadPolicy, failureReason) {
  if (!downloadPolicy?.resume) return false;
  return isRetriableDownloadFailure(failureReason);
}

export function failedDownloadCleanupState(targetPath, { retainPartial } = {}) {
  if (!retainPartial) return cleanupPartialDownload(targetPath);
  if (fs.existsSync(targetPath)) {
    try {
      fs.rmSync(targetPath, { force: true });
    } catch {
      return "cleanup_failed";
    }
  }
  return fs.existsSync(`${targetPath}.part`) ? "retained_partial" : "not_needed";
}

export function cleanupPartialDownload(targetPath) {
  let cleanupState = "not_needed";
  for (const filePath of [targetPath, `${targetPath}.part`, `${targetPath}.part.json`]) {
    if (!fs.existsSync(filePath)) continue;
    try {
      fs.rmSync(filePath, { force: true });
      cleanupState = "removed_partial";
    } catch {
      cleanupState = "cleanup_failed";
    }
  }
  return cleanupState;
}

export function downloadFailureReason(error) {
  const message = String(error?.message ?? error ?? "download_failed");
  if (message.includes("checksum")) return "checksum_mismatch";
  if (message.includes("size_limit_exceeded")) return "size_limit_exceeded";
  if (message.includes("AbortError") || message.includes("aborted")) return "network_timeout";
  const http = message.match(/live_download_http_([0-9]+)/)?.[1];
  if (http) return `http_${http}`;
  return "network_download_failed";
}

export function publicDownloadSource(source) {
  const text = String(source ?? "");
  if (text.startsWith("fixture://")) return text.split("?")[0];
  try {
    const url = new URL(text);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return text;
  }
}
