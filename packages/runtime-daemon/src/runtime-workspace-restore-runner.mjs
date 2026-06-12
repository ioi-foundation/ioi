import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

export const WORKSPACE_RESTORE_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_preview_operations_request.v1";
export const WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_apply_operations_request.v1";
export const WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_snapshot_capture_request.v1";
export const WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_apply_policy_request.v1";
export const RUST_WORKSPACE_RESTORE_BACKEND = "rust_workspace_restore";

export function createWorkspaceRestoreRunnerFromEnv(env = process.env, options = {}) {
  assertNoWorkspaceRestoreCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustWorkspaceRestoreRunner({
    command: options.command ?? env[WORKSPACE_RESTORE_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
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

export class RustWorkspaceRestoreRunner {
  constructor(options = {}) {
    assertNoWorkspaceRestoreCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.invokeBridge = createDaemonCoreCommandInvoker({
      command: this.command,
      spawnSyncImpl: options.spawnSyncImpl,
      mockResult: options.mockResult,
      mockSource: "rust_workspace_restore_mock",
      defaultBackend: RUST_WORKSPACE_RESTORE_BACKEND,
      ErrorClass: WorkspaceRestoreRunnerError,
      env: WORKSPACE_RESTORE_COMMAND_ENV,
      unconfiguredMessage:
        "Workspace restore requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core restore planning and execution.",
      unconfiguredCode: "workspace_restore_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust workspace restore bridge command.",
      spawnFailedCode: "workspace_restore_bridge_spawn_failed",
      commandFailedMessage: "Rust workspace restore bridge command failed.",
      commandFailedCode: "workspace_restore_bridge_failed",
      invalidJsonMessage: "Rust workspace restore bridge command returned invalid JSON.",
      invalidJsonCode: "workspace_restore_bridge_invalid_json",
      rejectedMessage: "Rust workspace restore core rejected the request.",
      rejectedCode: "workspace_restore_bridge_rejected",
    });
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
    return normalizeWorkspaceRestorePolicyBridgeResult(this.invokeBridge(bridgeRequest));
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
    return normalizeWorkspaceRestoreOperationsBridgeResult(this.invokeBridge(bridgeRequest)).operations;
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
    return normalizeWorkspaceRestoreOperationsBridgeResult(this.invokeBridge(bridgeRequest)).operations;
  }

  captureSnapshotFiles(request) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION,
      operation: "capture_workspace_snapshot_files",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        schema_version: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
        changed_files: normalizeSnapshotChangedFilesForBridge(request?.changed_files),
        content_drafts: normalizeSnapshotContentDraftsForBridge(request?.content_drafts),
        max_content_bytes: Number(request?.max_content_bytes ?? 0) || undefined,
      },
    };
    return normalizeWorkspaceSnapshotCaptureBridgeResult(this.invokeBridge(bridgeRequest));
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
    files,
    content_files: contentFiles,
    captured_file_count: capturedFileCount,
    omitted_file_count: omittedFileCount,
    content_captured: Boolean(result.content_captured ?? capture.content_captured),
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
