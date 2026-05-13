import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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

export function workspaceRestorePreviewOperation({ workspaceRoot, file = {}, maxDiffBytes }) {
  const target = resolveWorkspaceSnapshotPath(workspaceRoot, file.path);
  const before = file.before && typeof file.before === "object" ? file.before : {};
  const after = file.after && typeof file.after === "object" ? file.after : {};
  const current = readWorkspaceRestoreCurrent(target.absolutePath);
  const beforeExists = Boolean(before.exists);
  const afterExists = Boolean(after.exists);
  const desiredContent = beforeExists && typeof before.content === "string" ? before.content : "";
  const desiredHash = beforeExists ? optionalString(before.contentHash) : null;
  const afterHash = afterExists ? optionalString(after.contentHash) : null;
  const currentMatchesSnapshotPost =
    current.exists === afterExists && (!afterExists || current.contentHash === afterHash);
  const currentMatchesRestoreTarget =
    current.exists === beforeExists && (!beforeExists || current.contentHash === desiredHash);
  const contentAvailable = !beforeExists || typeof before.content === "string";
  const operation = currentMatchesRestoreTarget
    ? "noop"
    : beforeExists
      ? current.exists
        ? "replace"
        : "create"
      : "delete";
  const status = currentMatchesRestoreTarget
    ? "noop"
    : !contentAvailable || current.blocked
      ? "blocked"
      : currentMatchesSnapshotPost
        ? "ready"
        : "conflict";
  const diff = status === "ready"
    ? workspaceRestoreDiffPreview({
        relativePath: target.relativePath,
        before: current.exists ? current.content : "",
        after: beforeExists ? desiredContent : "",
        maxBytes: maxDiffBytes,
      })
    : { text: "", bytes: 0, truncated: false };
  return {
    path: target.relativePath,
    operation,
    status,
    currentExists: current.exists,
    current_exists: current.exists,
    currentHash: current.contentHash,
    current_hash: current.contentHash,
    currentBytes: current.contentBytes,
    current_bytes: current.contentBytes,
    targetExists: beforeExists,
    target_exists: beforeExists,
    targetHash: desiredHash,
    target_hash: desiredHash,
    snapshotAfterExists: afterExists,
    snapshot_after_exists: afterExists,
    snapshotAfterHash: afterHash,
    snapshot_after_hash: afterHash,
    currentMatchesSnapshotPost,
    current_matches_snapshot_post: currentMatchesSnapshotPost,
    currentMatchesRestoreTarget,
    current_matches_restore_target: currentMatchesRestoreTarget,
    blockedReason: current.blockedReason ?? (!contentAvailable ? "snapshot_restore_target_content_missing" : null),
    blocked_reason: current.blockedReason ?? (!contentAvailable ? "snapshot_restore_target_content_missing" : null),
    diff: diff.text,
    diffBytes: diff.bytes,
    diff_bytes: diff.bytes,
    diffHash: doctorHash(diff.text),
    diff_hash: doctorHash(diff.text),
    diffTruncated: diff.truncated,
    diff_truncated: diff.truncated,
  };
}

export function workspaceRestoreApplyOperations({
  workspaceRoot,
  files,
  maxDiffBytes = WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
  allowConflicts = false,
} = {}) {
  const plans = normalizeArray(files).map((file) => ({
    file,
    preview: workspaceRestorePreviewOperation({ workspaceRoot, file, maxDiffBytes }),
  }));
  const blockedPreflight = plans.some(({ preview }) =>
    preview.status === "blocked" || (preview.status === "conflict" && !allowConflicts),
  );
  if (blockedPreflight) {
    return plans.map(({ preview }) => ({
      ...preview,
      applyStatus: "blocked",
      apply_status: "blocked",
      applyReason: workspaceRestoreApplyBlockReason(preview, allowConflicts),
      apply_reason: workspaceRestoreApplyBlockReason(preview, allowConflicts),
    }));
  }
  return plans.map(({ file, preview }) =>
    applyWorkspaceRestoreFile({ workspaceRoot, file, preview, allowConflicts }),
  );
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

function applyWorkspaceRestoreFile({ workspaceRoot, file = {}, preview = {}, allowConflicts = false }) {
  const target = resolveWorkspaceSnapshotPath(workspaceRoot, file.path);
  const before = file.before && typeof file.before === "object" ? file.before : {};
  const targetExists = Boolean(before.exists);
  try {
    if (preview.status === "noop") {
      const current = readWorkspaceRestoreCurrent(target.absolutePath);
      return workspaceRestoreAppliedOperation(preview, current, "noop");
    }
    if (!targetExists) {
      if (fs.existsSync(target.absolutePath)) fs.unlinkSync(target.absolutePath);
    } else {
      if (typeof before.content !== "string") {
        return {
          ...preview,
          applyStatus: "failed",
          apply_status: "failed",
          applyReason: "snapshot_restore_target_content_missing",
          apply_reason: "snapshot_restore_target_content_missing",
        };
      }
      fs.mkdirSync(path.dirname(target.absolutePath), { recursive: true });
      fs.writeFileSync(target.absolutePath, before.content, "utf8");
    }
    const current = readWorkspaceRestoreCurrent(target.absolutePath);
    const applyStatus = preview.status === "conflict" && allowConflicts ? "applied_with_override" : "applied";
    return workspaceRestoreAppliedOperation(preview, current, applyStatus);
  } catch (error) {
    return {
      ...preview,
      applyStatus: "failed",
      apply_status: "failed",
      applyReason: "workspace_restore_write_failed",
      apply_reason: "workspace_restore_write_failed",
      errorMessage: String(error?.message ?? error),
      error_message: String(error?.message ?? error),
    };
  }
}

function workspaceRestoreAppliedOperation(preview, current, applyStatus) {
  return {
    ...preview,
    applyStatus,
    apply_status: applyStatus,
    appliedExists: current.exists,
    applied_exists: current.exists,
    appliedHash: current.contentHash,
    applied_hash: current.contentHash,
    appliedBytes: current.contentBytes,
    applied_bytes: current.contentBytes,
    appliedMatchesTarget:
      current.exists === Boolean(preview.targetExists ?? preview.target_exists) &&
      (!current.exists || current.contentHash === (preview.targetHash ?? preview.target_hash)),
    applied_matches_target:
      current.exists === Boolean(preview.targetExists ?? preview.target_exists) &&
      (!current.exists || current.contentHash === (preview.targetHash ?? preview.target_hash)),
  };
}

function workspaceRestoreApplyBlockReason(preview, allowConflicts) {
  if (preview.status === "blocked") return preview.blockedReason ?? preview.blocked_reason ?? "workspace_restore_preview_blocked";
  if (preview.status === "conflict" && !allowConflicts) return "workspace_restore_conflict_requires_override";
  return null;
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

function readWorkspaceRestoreCurrent(absolutePath) {
  if (!fs.existsSync(absolutePath)) {
    return {
      exists: false,
      content: "",
      contentHash: null,
      contentBytes: 0,
      blocked: false,
      blockedReason: null,
    };
  }
  const stat = fs.lstatSync(absolutePath);
  if (!stat.isFile()) {
    return {
      exists: true,
      content: "",
      contentHash: null,
      contentBytes: stat.size,
      blocked: true,
      blockedReason: stat.isSymbolicLink() ? "current_path_is_symbolic_link" : "current_path_not_regular_file",
    };
  }
  if (stat.size > WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES) {
    return {
      exists: true,
      content: "",
      contentHash: null,
      contentBytes: stat.size,
      blocked: true,
      blockedReason: "current_content_size_limit_exceeded",
    };
  }
  const content = fs.readFileSync(absolutePath, "utf8");
  return {
    exists: true,
    content,
    contentHash: doctorHash(content),
    contentBytes: Buffer.byteLength(content, "utf8"),
    blocked: false,
    blockedReason: null,
  };
}

function resolveWorkspaceSnapshotPath(workspaceRoot, selectedPath) {
  const relativeInput = optionalString(selectedPath);
  if (!relativeInput || path.isAbsolute(relativeInput) || relativeInput.includes("\0")) {
    throw policyError("Workspace snapshot path must be a safe workspace-relative path.", {
      workspaceRoot,
      path: selectedPath ?? null,
    });
  }
  const root = path.resolve(workspaceRoot);
  const absolutePath = path.resolve(root, relativeInput);
  if (!isPathInside(root, absolutePath)) {
    throw policyError("Workspace snapshot path escaped the workspace root.", {
      workspaceRoot,
      path: selectedPath,
    });
  }
  return {
    absolutePath,
    relativePath: (path.relative(root, absolutePath) || ".").replaceAll("\\", "/"),
  };
}

function workspaceRestoreDiffPreview({ relativePath, before, after, maxBytes }) {
  if (before === after) return { text: "", bytes: 0, truncated: false };
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-workspace-restore-diff-"));
  const beforePath = path.join(tmpRoot, "current");
  const afterPath = path.join(tmpRoot, "restore");
  try {
    fs.writeFileSync(beforePath, before, "utf8");
    fs.writeFileSync(afterPath, after, "utf8");
    let raw = "";
    try {
      raw = execFileSync("git", [
        "diff",
        "--no-index",
        "--no-color",
        "--",
        beforePath,
        afterPath,
      ], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      raw = String(error?.stdout ?? error?.stderr ?? "");
    }
    const labeled = raw
      .replaceAll(beforePath, `a/${relativePath}`)
      .replaceAll(afterPath, `b/${relativePath}`);
    const buffer = Buffer.from(labeled, "utf8");
    const limit = Math.max(1, Number(maxBytes) || WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES);
    const text = buffer.byteLength > limit ? buffer.subarray(0, limit).toString("utf8") : labeled;
    return {
      text,
      bytes: buffer.byteLength,
      truncated: buffer.byteLength > limit,
    };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

function isPathInside(rootPath, candidatePath) {
  const relativePath = path.relative(path.resolve(rootPath), path.resolve(candidatePath));
  return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
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

function policyError(message, details) {
  const error = new Error(message);
  error.status = 403;
  error.code = "policy";
  error.details = details;
  return error;
}
