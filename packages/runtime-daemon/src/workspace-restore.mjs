export const WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES = 256 * 1024;
export const WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES = 32 * 1024;

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

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}
