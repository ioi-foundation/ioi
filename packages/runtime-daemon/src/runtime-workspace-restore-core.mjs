export const WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_preview_operations_request.v1";
export const WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_apply_operations_request.v1";
export const WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_snapshot_capture_request.v1";
export const WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_apply_policy_request.v1";
export const WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_snapshot_list_request.v1";
export const WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_snapshot_content_package_request.v1";
export const WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_snapshot_restore_preview_request.v1";
export const WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_snapshot_restore_apply_request.v1";
export const RUST_WORKSPACE_RESTORE_BACKEND = "rust_workspace_restore";
export const WORKSPACE_RESTORE_APPLY_POLICY_API_METHOD = "planWorkspaceRestoreApplyPolicy";
export const WORKSPACE_RESTORE_PREVIEW_OPERATIONS_API_METHOD =
  "previewWorkspaceRestoreOperations";
export const WORKSPACE_RESTORE_APPLY_OPERATIONS_API_METHOD = "applyWorkspaceRestoreOperations";
export const WORKSPACE_SNAPSHOT_CAPTURE_API_METHOD = "captureWorkspaceSnapshotFiles";
export const WORKSPACE_SNAPSHOT_LIST_API_METHOD = "projectWorkspaceSnapshotList";
export const WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_API_METHOD =
  "projectWorkspaceSnapshotContentPackage";
export const WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_API_METHOD = "previewWorkspaceSnapshotRestore";
export const WORKSPACE_SNAPSHOT_RESTORE_APPLY_API_METHOD = "applyWorkspaceSnapshotRestore";

const RETIRED_WORKSPACE_RESTORE_CORE_REQUEST_FIELDS = [
  "changedFiles",
  "contentDrafts",
  "workspaceSnapshotDrafts",
  "maxContentBytes",
  "workflowGraphId",
  "workflowNodeId",
  "idempotencyKey",
  "approvalDecision",
  "policyDecision",
  "confirmRestoreApply",
  "applyConfirmed",
  "approvalGranted",
  "allowConflicts",
  "overrideConflicts",
  "restoreConflictPolicy",
  "conflictPolicy",
  "restorePolicy",
];

export function createRuntimeWorkspaceRestoreCore(options = {}) {
  return new RuntimeWorkspaceRestoreCore(options);
}

export class RuntimeWorkspaceRestoreCore {
  constructor(options = {}) {
    assertNoRetiredWorkspaceRestoreCoreOption("command", options.command);
    assertNoRetiredWorkspaceRestoreCoreOption("args", options.args);
    assertNoRetiredWorkspaceRestoreCoreOption("env", options.env);
    assertNoRetiredWorkspaceRestoreCoreOption("daemonCoreInvoker", options.daemonCoreInvoker);
    assertNoRetiredWorkspaceRestoreCoreOption("daemonCoreApi", options.daemonCoreApi);
    this.daemonCoreWorkspaceRestoreApi = workspaceRestoreApi(options.daemonCoreWorkspaceRestoreApi);
  }

  planApplyPolicy(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_RESTORE_APPLY_POLICY_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  previewOperations(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_RESTORE_PREVIEW_OPERATIONS_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
        files: normalizeRestoreFilesForCore(request?.files),
      },
    });
  }

  applyOperations(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_RESTORE_APPLY_OPERATIONS_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
        files: normalizeRestoreFilesForCore(request?.files),
      },
    });
  }

  captureSnapshotFiles(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_SNAPSHOT_CAPTURE_API_METHOD, {
      thread_id: optionalString(request?.thread_id),
      turn_id: optionalString(request?.turn_id),
      workspace_root: optionalString(request?.workspace_root),
      tool_call_id: optionalString(request?.tool_call_id),
      workflow_graph_id: optionalString(request?.workflow_graph_id),
      workflow_node_id: optionalString(request?.workflow_node_id),
      request: {
        schema_version: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
        changed_files: normalizeSnapshotChangedFilesForCore(request?.changed_files),
        content_drafts: normalizeSnapshotContentDraftsForCore(request?.content_drafts),
        max_content_bytes: Number(request?.max_content_bytes ?? 0) || undefined,
      },
    });
  }

  projectWorkspaceSnapshotList(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_SNAPSHOT_LIST_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectWorkspaceSnapshotContentPackage(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  previewSnapshotRestore(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  applySnapshotRestore(request = {}) {
    assertCanonicalWorkspaceRestoreCoreRequest(request);
    return this.invokeRustWorkspaceRestoreApi(WORKSPACE_SNAPSHOT_RESTORE_APPLY_API_METHOD, {
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  invokeRustWorkspaceRestoreApi(method, request) {
    const invoke = this.daemonCoreWorkspaceRestoreApi?.[method];
    if (typeof invoke !== "function") {
      throw new RuntimeWorkspaceRestoreCoreError(
        `Workspace restore requires daemonCoreWorkspaceRestoreApi.${method} for Rust daemon-core snapshot, restore, admission, and projection.`,
        "workspace_restore_core_direct_workspace_restore_api_unconfigured",
        {
          boundary: `daemonCoreWorkspaceRestoreApi.${method}`,
          backend: RUST_WORKSPACE_RESTORE_BACKEND,
        },
      );
    }
    const response = invoke.call(this.daemonCoreWorkspaceRestoreApi, request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeWorkspaceRestoreCoreError(
        error.message ?? "Rust workspace restore core rejected the request.",
        error.code ?? "workspace_restore_core_direct_workspace_restore_api_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class RuntimeWorkspaceRestoreCoreError extends Error {
  constructor(message, code = "workspace_restore_core_error", details = {}) {
    super(message);
    this.name = "RuntimeWorkspaceRestoreCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function assertCanonicalWorkspaceRestoreCoreRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_WORKSPACE_RESTORE_CORE_REQUEST_FIELDS.filter((field) =>
    Object.hasOwn(record, field),
  );
  for (const file of Array.isArray(record.files) ? record.files : []) {
    const before = objectRecord(file?.before) ?? {};
    const after = objectRecord(file?.after) ?? {};
    if (Object.hasOwn(before, "contentHash") || Object.hasOwn(after, "contentHash")) {
      retiredAliases.push("files.*.contentHash");
      break;
    }
  }
  if (retiredAliases.length === 0) return;
  throw new RuntimeWorkspaceRestoreCoreError(
    "Workspace restore core request aliases are retired; use canonical snake_case Rust daemon-core fields.",
    "workspace_restore_core_request_aliases_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
    },
  );
}

function assertNoRetiredWorkspaceRestoreCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeWorkspaceRestoreCoreError(
    "Workspace restore command compatibility options are retired; use daemonCoreWorkspaceRestoreApi for direct Rust daemon-core workspace restore APIs.",
    "workspace_restore_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

function normalizeSnapshotChangedFilesForCore(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => objectRecord(entry))
    .filter(Boolean)
    .map((entry) => ({
      path: optionalString(entry.path) ?? "",
      created: Boolean(entry.created),
      before_hash: optionalString(entry.before_hash),
      after_hash: optionalString(entry.after_hash),
      before_exists: Boolean(entry.before_exists),
      after_exists: Object.hasOwn(entry, "after_exists") ? Boolean(entry.after_exists) : undefined,
      before_size_bytes: finiteNumber(entry.before_size_bytes),
      after_size_bytes: finiteNumber(entry.after_size_bytes),
      before_mtime_ms: finiteNumber(entry.before_mtime_ms),
      after_mtime_ms: finiteNumber(entry.after_mtime_ms),
    }));
}

function normalizeSnapshotContentDraftsForCore(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => objectRecord(entry))
    .filter(Boolean)
    .map((entry) => ({
      path: optionalString(entry.path) ?? "",
      before_content: typeof entry.before_content === "string" ? entry.before_content : undefined,
      after_content: typeof entry.after_content === "string" ? entry.after_content : undefined,
      encoding: optionalString(entry.encoding) ?? "utf8",
    }));
}

function normalizeRestoreFilesForCore(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => objectRecord(entry))
    .filter(Boolean)
    .map((entry) => ({
      path: optionalString(entry.path) ?? "",
      before: normalizeRestoreSideForCore(entry.before),
      after: normalizeRestoreSideForCore(entry.after),
    }));
}

function normalizeRestoreSideForCore(value) {
  const side = objectRecord(value) ?? {};
  return {
    exists: Boolean(side.exists),
    content_hash: optionalString(side.content_hash),
    content: typeof side.content === "string" ? side.content : undefined,
  };
}

function finiteNumber(value) {
  if (value === null || value === undefined || value === "") return undefined;
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function workspaceRestoreApi(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
}
