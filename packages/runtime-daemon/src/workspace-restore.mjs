import crypto from "node:crypto";

export const WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES = 256 * 1024;
export const WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES = 32 * 1024;

export function workspaceSnapshotContentDraftsByPath(value) {
  const drafts = new Map();
  for (const draft of normalizeArray(value)) {
    const relativePath = optionalString(draft?.path);
    if (!relativePath) continue;
    drafts.set(relativePath, draft);
  }
  return drafts;
}

export function workspaceSnapshotFileForPatch(entry = {}, draft = {}, options = {}) {
  const pathValue = optionalString(entry.path) ?? "unknown";
  const beforeHash = optionalString(entry.beforeHash ?? entry.before_hash);
  const afterHash = optionalString(entry.afterHash ?? entry.after_hash);
  const beforeExists = Boolean(entry.beforeExists ?? entry.before_exists);
  const afterExists = Object.hasOwn(entry, "afterExists") || Object.hasOwn(entry, "after_exists")
    ? Boolean(entry.afterExists ?? entry.after_exists)
    : true;
  const beforeSizeBytes = Number(entry.beforeSizeBytes ?? entry.before_size_bytes ?? 0) || 0;
  const afterSizeBytes = Number(entry.afterSizeBytes ?? entry.after_size_bytes ?? 0) || 0;
  const beforeMtimeMs = nullableNumber(entry.beforeMtimeMs ?? entry.before_mtime_ms);
  const afterMtimeMs = nullableNumber(entry.afterMtimeMs ?? entry.after_mtime_ms);
  const maxContentBytes = Number(options.maxContentBytes ?? WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES) || WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES;
  const beforeCapture = workspaceSnapshotCaptureSide({
    exists: beforeExists,
    contentHash: beforeHash,
    content: Object.hasOwn(draft ?? {}, "beforeContent") ? draft.beforeContent : draft?.before_content,
    maxContentBytes,
  });
  const afterCapture = workspaceSnapshotCaptureSide({
    exists: afterExists,
    contentHash: afterHash,
    content: Object.hasOwn(draft ?? {}, "afterContent") ? draft.afterContent : draft?.after_content,
    maxContentBytes,
  });
  const publicFile = {
    path: pathValue,
    created: Boolean(entry.created),
    deleted: beforeExists && !afterExists,
    changed: beforeHash !== afterHash,
    before: {
      exists: beforeExists,
      contentHash: beforeHash,
      sizeBytes: beforeExists ? beforeSizeBytes : 0,
      mtimeMs: beforeMtimeMs,
      contentCaptured: beforeCapture.captured,
      contentBytes: beforeCapture.contentBytes,
      omittedReason: beforeCapture.omittedReason,
    },
    after: {
      exists: afterExists,
      contentHash: afterHash,
      sizeBytes: afterExists ? afterSizeBytes : 0,
      mtimeMs: afterMtimeMs,
      contentCaptured: afterCapture.captured,
      contentBytes: afterCapture.contentBytes,
      omittedReason: afterCapture.omittedReason,
    },
    receiptRefs: [],
    artifactRefs: [],
  };
  return {
    publicFile,
    contentFile: {
      ...publicFile,
      before: {
        ...publicFile.before,
        content: beforeCapture.content,
      },
      after: {
        ...publicFile.after,
        content: afterCapture.content,
      },
      encoding: optionalString(draft?.encoding) ?? "utf8",
    },
    contentCaptured: beforeCapture.captured && afterCapture.captured,
  };
}

export function workspaceRestoreOperationCounts(operations) {
  const list = normalizeArray(operations);
  const applyStatuses = list.map((operation) => operation.applyStatus ?? operation.apply_status ?? operation.status);
  return {
    fileCount: list.length,
    readyCount: list.filter((operation) => operation.status === "ready").length,
    noopCount: list.filter((operation) => operation.status === "noop").length,
    conflictCount: list.filter((operation) => operation.status === "conflict").length,
    blockedCount: list.filter((operation) => operation.status === "blocked").length,
    appliedCount: applyStatuses.filter((status) => status === "applied" || status === "applied_with_override").length,
    applyNoopCount: applyStatuses.filter((status) => status === "noop").length,
    applyBlockedCount: applyStatuses.filter((status) => status === "blocked").length,
    failedCount: applyStatuses.filter((status) => status === "failed").length,
  };
}

export function parseJsonObject(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(String(value ?? ""));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function workspaceSnapshotCaptureSide({ exists, contentHash, content, maxContentBytes }) {
  if (!exists) {
    return {
      captured: true,
      content: null,
      contentBytes: 0,
      omittedReason: null,
    };
  }
  if (typeof content !== "string") {
    return {
      captured: false,
      content: null,
      contentBytes: 0,
      omittedReason: "snapshot_content_missing",
    };
  }
  const contentBytes = Buffer.byteLength(content, "utf8");
  if (contentBytes > maxContentBytes) {
    return {
      captured: false,
      content: null,
      contentBytes,
      omittedReason: "snapshot_content_size_limit_exceeded",
    };
  }
  if (contentHash && doctorHash(content) !== contentHash) {
    return {
      captured: false,
      content: null,
      contentBytes,
      omittedReason: "snapshot_content_hash_mismatch",
    };
  }
  return {
    captured: true,
    content,
    contentBytes,
    omittedReason: null,
  };
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function nullableNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value ?? "")).digest("hex");
}
