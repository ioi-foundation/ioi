export const WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
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

export function createWorkspaceRestoreRunnerFromEnv(env = process.env, options = {}) {
  assertNoWorkspaceRestoreCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  assertNoWorkspaceRestoreCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_WORKSPACE_RESTORE_COMMAND,
  );
  return new RustWorkspaceRestoreRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
  });
}

export function assertNoWorkspaceRestoreCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new WorkspaceRestoreRunnerError(
    "Workspace restore command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "workspace_restore_command_args_retired",
    { retired_args: value },
  );
}

export function assertNoWorkspaceRestoreCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new WorkspaceRestoreRunnerError(
    "Workspace restore binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core workspace restore admission.",
    "workspace_restore_command_selection_retired",
    { retired_command: value },
  );
}

export class RustWorkspaceRestoreRunner {
  constructor(options = {}) {
    assertNoWorkspaceRestoreCommandArgs(options.args);
    assertNoWorkspaceRestoreCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  planApplyPolicy(request) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "plan_workspace_restore_apply_policy",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeWorkspaceRestorePolicyBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  previewOperations(request) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "preview_workspace_restore_operations",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
        files: normalizeRestoreFilesForBridge(request?.files),
      },
    };
    return normalizeWorkspaceRestoreOperationsBridgeResult(this.invokeDaemonCore(bridgeRequest)).operations;
  }

  applyOperations(request) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "apply_workspace_restore_operations",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
        files: normalizeRestoreFilesForBridge(request?.files),
      },
    };
    return normalizeWorkspaceRestoreOperationsBridgeResult(this.invokeDaemonCore(bridgeRequest)).operations;
  }

  captureSnapshotFiles(request) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "capture_workspace_snapshot_files",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      thread_id: optionalString(request?.thread_id),
      turn_id: optionalString(request?.turn_id),
      workspace_root: optionalString(request?.workspace_root),
      tool_call_id: optionalString(request?.tool_call_id),
      workflow_graph_id: optionalString(request?.workflow_graph_id),
      workflow_node_id: optionalString(request?.workflow_node_id),
      request: {
        schema_version: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
        changed_files: normalizeSnapshotChangedFilesForBridge(request?.changed_files),
        content_drafts: normalizeSnapshotContentDraftsForBridge(request?.content_drafts),
        max_content_bytes: Number(request?.max_content_bytes ?? 0) || undefined,
      },
    };
    return normalizeWorkspaceSnapshotCaptureBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  listSnapshots(request = {}) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "project_workspace_snapshot_list",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeWorkspaceSnapshotListBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  workspaceSnapshotContentPackage(request = {}) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "project_workspace_snapshot_content_package",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeWorkspaceSnapshotContentPackageBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  previewSnapshotRestore(request = {}) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "preview_workspace_snapshot_restore",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeWorkspaceRestorePreviewBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  applySnapshotRestore(request = {}) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "apply_workspace_snapshot_restore",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeWorkspaceRestoreApplyBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new WorkspaceRestoreRunnerError(
        "Workspace restore requires daemonCoreInvoker for direct Rust daemon-core restore planning and execution.",
        "workspace_restore_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new WorkspaceRestoreRunnerError(
        error.message ?? "Rust workspace restore core rejected the request.",
        error.code ?? "workspace_restore_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class WorkspaceRestoreRunnerError extends Error {
  constructor(message, code = "workspace_restore_runner_error", details = {}) {
    super(message);
    this.name = "WorkspaceRestoreRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeWorkspaceRestorePolicyBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const plan = objectRecord(result.plan) ?? {};
  const approval = objectRecord(result.approval) ?? objectRecord(plan.approval) ?? {};
  const operationPolicies = arrayOfObjects(result.operation_policies) ?? arrayOfObjects(plan.operation_policies) ?? [];
  const policyDecisionRefs =
    stringArray(result.policy_decision_refs) ?? stringArray(plan.policy_decision_refs) ?? [];
  const normalized = {
    source: result.source ?? "rust_workspace_restore_policy_command",
    backend: result.backend ?? RUST_WORKSPACE_RESTORE_BACKEND,
    plan,
    approval: {
      required: approval.required !== false,
      satisfied: Boolean(approval.satisfied),
      source: optionalString(approval.source) ?? "missing",
    },
    allow_conflicts: Boolean(result.allow_conflicts ?? plan.allow_conflicts),
    conflict_policy: optionalString(result.conflict_policy ?? plan.conflict_policy) ?? "clean_preview_only",
    hard_blocked: Boolean(result.hard_blocked ?? plan.hard_blocked),
    conflict_blocked: Boolean(result.conflict_blocked ?? plan.conflict_blocked),
    policy_status: optionalString(result.policy_status ?? plan.policy_status) ?? "blocked",
    apply_status: optionalString(result.apply_status ?? plan.apply_status) ?? null,
    policy_decision_refs: policyDecisionRefs,
    operation_policies: operationPolicies,
    summary: optionalString(result.summary ?? plan.summary) ?? null,
  };
  return normalized;
}

export function normalizeWorkspaceRestoreOperationsBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  return {
    source: result.source ?? "rust_workspace_restore_operations_command",
    backend: result.backend ?? RUST_WORKSPACE_RESTORE_BACKEND,
    operation: optionalString(result.operation) ?? null,
    operations: normalizeWorkspaceRestoreOperations(result.operations),
  };
}

export function normalizeWorkspaceSnapshotCaptureBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const capture = objectRecord(result.capture) ?? {};
  const files = normalizeSnapshotCapturedFiles(result.files ?? capture.files);
  const contentFiles = normalizeSnapshotCapturedFiles(result.content_files ?? capture.content_files);
  const capturedFileCount = Number(result.captured_file_count ?? capture.captured_file_count ?? 0) || 0;
  const omittedFileCount = Number(result.omitted_file_count ?? capture.omitted_file_count ?? 0) || 0;
  return {
    source: result.source ?? "rust_workspace_snapshot_capture_command",
    backend: result.backend ?? RUST_WORKSPACE_RESTORE_BACKEND,
    snapshot_record: normalizeWorkspaceSnapshotRecord(result.snapshot_record),
    snapshot_event: normalizeWorkspaceSnapshotEvent(result.snapshot_event),
    files,
    content_files: contentFiles,
    captured_file_count: capturedFileCount,
    omitted_file_count: omittedFileCount,
    content_captured: Boolean(result.content_captured ?? capture.content_captured),
  };
}

export function normalizeWorkspaceSnapshotListBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const projection = objectRecord(result.projection) ?? result;
  const snapshots = arrayOfObjects(projection.snapshots) ?? [];
  return {
    schema_version: optionalString(projection.schema_version) ?? "ioi.runtime.workspace_snapshot.v1",
    object: optionalString(projection.object) ?? "ioi.runtime_workspace_snapshot_list",
    thread_id: optionalString(projection.thread_id) ?? null,
    snapshot_count: Number(projection.snapshot_count ?? snapshots.length) || 0,
    snapshots,
    evidence_refs: stringArray(result.evidence_refs ?? projection.evidence_refs),
  };
}

export function normalizeWorkspaceSnapshotContentPackageBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const projection = objectRecord(result.projection) ?? result;
  return {
    schema_version:
      optionalString(projection.schema_version) ?? "ioi.runtime.workspace_snapshot_content_package.v1",
    object: optionalString(projection.object) ?? "ioi.runtime_workspace_snapshot_content_package",
    thread_id: optionalString(projection.thread_id) ?? null,
    snapshot_id: optionalString(projection.snapshot_id) ?? null,
    snapshot: objectRecord(projection.snapshot) ?? null,
    content_files: normalizeSnapshotCapturedFiles(projection.content_files),
    file_count: Number(projection.file_count ?? 0) || 0,
    receipt_refs: stringArray(projection.receipt_refs),
    artifact_refs: stringArray(projection.artifact_refs),
    restore: objectRecord(projection.restore) ?? null,
    evidence_refs: stringArray(result.evidence_refs ?? projection.evidence_refs),
  };
}

export function normalizeWorkspaceRestorePreviewBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const preview = objectRecord(result.restore_preview) ?? result;
  return {
    schema_version: optionalString(preview.schema_version) ?? "ioi.runtime.workspace_restore_preview.v1",
    object: optionalString(preview.object) ?? "ioi.runtime_workspace_restore_preview",
    thread_id: optionalString(preview.thread_id) ?? null,
    snapshot_id: optionalString(preview.snapshot_id) ?? null,
    preview_status: optionalString(preview.preview_status) ?? "blocked",
    preview_supported: preview.preview_supported !== false,
    apply_supported: preview.apply_supported !== false,
    file_count: Number(preview.file_count ?? 0) || 0,
    ready_count: Number(preview.ready_count ?? 0) || 0,
    noop_count: Number(preview.noop_count ?? 0) || 0,
    conflict_count: Number(preview.conflict_count ?? 0) || 0,
    blocked_count: Number(preview.blocked_count ?? 0) || 0,
    operations: normalizeWorkspaceRestoreOperations(preview.operations),
    receipt_refs: stringArray(preview.receipt_refs),
    artifact_refs: stringArray(preview.artifact_refs),
    rollback_refs: stringArray(preview.rollback_refs),
    event: objectRecord(preview.event) ?? null,
    restore_preview_event: objectRecord(preview.restore_preview_event) ?? null,
    summary: optionalString(preview.summary) ?? null,
    evidence_refs: stringArray(result.evidence_refs ?? preview.evidence_refs),
  };
}

export function normalizeWorkspaceRestoreApplyBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const apply = objectRecord(result.restore_apply) ?? result;
  return {
    schema_version: optionalString(apply.schema_version) ?? "ioi.runtime.workspace_restore_apply.v1",
    object: optionalString(apply.object) ?? "ioi.runtime_workspace_restore_apply",
    thread_id: optionalString(apply.thread_id) ?? null,
    snapshot_id: optionalString(apply.snapshot_id) ?? null,
    preview_status: optionalString(apply.preview_status) ?? "blocked",
    apply_status: optionalString(apply.apply_status) ?? "blocked",
    apply_supported: apply.apply_supported !== false,
    approval_required: apply.approval_required !== false,
    approval_satisfied: Boolean(apply.approval_satisfied),
    file_count: Number(apply.file_count ?? 0) || 0,
    applied_count: Number(apply.applied_count ?? 0) || 0,
    apply_noop_count: Number(apply.apply_noop_count ?? 0) || 0,
    apply_blocked_count: Number(apply.apply_blocked_count ?? 0) || 0,
    failed_count: Number(apply.failed_count ?? 0) || 0,
    operations: normalizeWorkspaceRestoreOperations(apply.operations),
    policy_decision_refs: stringArray(apply.policy_decision_refs),
    receipt_refs: stringArray(apply.receipt_refs),
    artifact_refs: stringArray(apply.artifact_refs),
    rollback_refs: stringArray(apply.rollback_refs),
    event: objectRecord(apply.event) ?? null,
    restore_apply_event: objectRecord(apply.restore_apply_event) ?? null,
    summary: optionalString(apply.summary) ?? null,
    evidence_refs: stringArray(result.evidence_refs ?? apply.evidence_refs),
  };
}

function normalizeWorkspaceSnapshotRecord(value) {
  const record = objectRecord(value);
  if (!record) return null;
  return {
    schema_version: optionalString(record.schema_version) ?? null,
    snapshot_id: optionalString(record.snapshot_id) ?? null,
    snapshot_hash: optionalString(record.snapshot_hash) ?? null,
    snapshot_kind: optionalString(record.snapshot_kind) ?? null,
    file_count: Number(record.file_count ?? 0) || 0,
    changed_file_count: Number(record.changed_file_count ?? 0) || 0,
    created_file_count: Number(record.created_file_count ?? 0) || 0,
    deleted_file_count: Number(record.deleted_file_count ?? 0) || 0,
    restore: objectRecord(record.restore) ?? null,
    trigger: objectRecord(record.trigger) ?? null,
    files: normalizeSnapshotCapturedFiles(record.files),
    content_files: normalizeSnapshotCapturedFiles(record.content_files),
    receipt_refs: stringArray(record.receipt_refs),
    artifact_refs: stringArray(record.artifact_refs),
    summary: optionalString(record.summary) ?? null,
  };
}

function normalizeWorkspaceSnapshotEvent(value) {
  const event = objectRecord(value);
  if (!event) return null;
  return {
    schema_version: optionalString(event.schema_version) ?? null,
    event_id: optionalString(event.event_id) ?? null,
    event_stream_id: optionalString(event.event_stream_id) ?? null,
    event_kind: optionalString(event.event_kind) ?? null,
    status: optionalString(event.status) ?? null,
    actor: optionalString(event.actor) ?? null,
    component_kind: optionalString(event.component_kind) ?? null,
    thread_id: optionalString(event.thread_id) ?? null,
    turn_id: optionalString(event.turn_id) ?? null,
    workspace_root: optionalString(event.workspace_root) ?? null,
    workflow_graph_id: optionalString(event.workflow_graph_id) ?? null,
    workflow_node_id: optionalString(event.workflow_node_id) ?? null,
    tool_call_id: optionalString(event.tool_call_id) ?? null,
    snapshot_id: optionalString(event.snapshot_id) ?? null,
    artifact_refs: stringArray(event.artifact_refs),
    receipt_refs: stringArray(event.receipt_refs),
    payload_schema_version: optionalString(event.payload_schema_version) ?? null,
    payload_summary: objectRecord(event.payload_summary) ?? null,
  };
}

function normalizeWorkspaceRestoreOperations(value) {
  if (!Array.isArray(value)) return [];
  return value.map((operation) => normalizeWorkspaceRestoreOperation(operation)).filter(Boolean);
}

function normalizeSnapshotChangedFilesForBridge(value) {
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

function normalizeSnapshotContentDraftsForBridge(value) {
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

function normalizeRestoreFilesForBridge(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => objectRecord(entry))
    .filter(Boolean)
    .map((entry) => ({
      path: optionalString(entry.path) ?? "",
      before: normalizeRestoreSideForBridge(entry.before),
      after: normalizeRestoreSideForBridge(entry.after),
    }));
}

function normalizeRestoreSideForBridge(value) {
  const side = objectRecord(value) ?? {};
  return {
    exists: Boolean(side.exists),
    content_hash: optionalString(side.content_hash),
    content: typeof side.content === "string" ? side.content : undefined,
  };
}

function normalizeSnapshotCapturedFiles(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => normalizeSnapshotCapturedFile(entry)).filter(Boolean);
}

function normalizeSnapshotCapturedFile(value) {
  const record = objectRecord(value);
  if (!record) return null;
  return {
    path: optionalString(record.path) ?? "unknown",
    created: Boolean(record.created),
    deleted: Boolean(record.deleted),
    changed: Boolean(record.changed),
    before: normalizeSnapshotCapturedSide(record.before),
    after: normalizeSnapshotCapturedSide(record.after),
    receipt_refs: stringArray(record.receipt_refs),
    artifact_refs: stringArray(record.artifact_refs),
    encoding: optionalString(record.encoding) ?? undefined,
  };
}

function normalizeSnapshotCapturedSide(value) {
  const side = objectRecord(value) ?? {};
  const normalized = {
    exists: Boolean(side.exists),
    content_hash: optionalString(side.content_hash),
    size_bytes: Number(side.size_bytes ?? 0) || 0,
    mtime_ms: finiteNumber(side.mtime_ms),
    content_captured: Boolean(side.content_captured),
    content_bytes: Number(side.content_bytes ?? 0) || 0,
    omitted_reason: optionalString(side.omitted_reason),
  };
  if (typeof side.content === "string") {
    normalized.content = side.content;
  }
  return normalized;
}

function normalizeWorkspaceRestoreOperation(value) {
  const record = objectRecord(value);
  if (!record) return null;
  const normalized = {
    path: optionalString(record.path) ?? "unknown",
    operation: optionalString(record.operation) ?? "noop",
    status: optionalString(record.status) ?? "blocked",
    current_exists: Boolean(record.current_exists),
    current_hash: optionalString(record.current_hash),
    current_bytes: Number(record.current_bytes ?? 0) || 0,
    target_exists: Boolean(record.target_exists),
    target_hash: optionalString(record.target_hash),
    snapshot_after_exists: Boolean(record.snapshot_after_exists),
    snapshot_after_hash: optionalString(record.snapshot_after_hash),
    current_matches_snapshot_post: Boolean(record.current_matches_snapshot_post),
    current_matches_restore_target: Boolean(record.current_matches_restore_target),
    blocked_reason: optionalString(record.blocked_reason),
    diff: typeof record.diff === "string" ? record.diff : "",
    diff_bytes: Number(record.diff_bytes ?? 0) || 0,
    diff_hash: optionalString(record.diff_hash) ?? null,
    diff_truncated: Boolean(record.diff_truncated),
  };
  const applyStatus = optionalString(record.apply_status);
  if (applyStatus) {
    normalized.apply_status = applyStatus;
  }
  const applyReason = optionalString(record.apply_reason);
  if (applyReason) {
    normalized.apply_reason = applyReason;
  }
  if (Object.hasOwn(record, "applied_exists")) {
    normalized.applied_exists = Boolean(record.applied_exists);
  }
  const appliedHash = optionalString(record.applied_hash);
  if (appliedHash) {
    normalized.applied_hash = appliedHash;
  }
  if (Object.hasOwn(record, "applied_bytes")) {
    normalized.applied_bytes = Number(record.applied_bytes ?? 0) || 0;
  }
  if (Object.hasOwn(record, "applied_matches_target")) {
    normalized.applied_matches_target = Boolean(record.applied_matches_target);
  }
  const errorMessage = optionalString(record.error_message);
  if (errorMessage) {
    normalized.error_message = errorMessage;
  }
  return normalized;
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

function arrayOfObjects(value) {
  if (!Array.isArray(value)) return null;
  return value.filter((entry) => objectRecord(entry));
}

function stringArray(value) {
  if (!Array.isArray(value)) return null;
  return value.filter((entry) => typeof entry === "string" && entry.trim()).map((entry) => entry.trim());
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
