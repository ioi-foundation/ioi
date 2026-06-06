export const WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES = 256 * 1024;
export const WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES = 32 * 1024;

export function workspaceRestoreOperationCounts(operations) {
  const list = normalizeArray(operations);
  const applyStatuses = list.map((operation) => operation.apply_status ?? operation.status);
  return {
    file_count: list.length,
    ready_count: list.filter((operation) => operation.status === "ready").length,
    noop_count: list.filter((operation) => operation.status === "noop").length,
    conflict_count: list.filter((operation) => operation.status === "conflict").length,
    blocked_count: list.filter((operation) => operation.status === "blocked").length,
    applied_count: applyStatuses.filter((status) => status === "applied" || status === "applied_with_override").length,
    apply_noop_count: applyStatuses.filter((status) => status === "noop").length,
    apply_blocked_count: applyStatuses.filter((status) => status === "blocked").length,
    failed_count: applyStatuses.filter((status) => status === "failed").length,
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
