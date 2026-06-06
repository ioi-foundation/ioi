import { spawnSync } from "node:child_process";

export const WORKSPACE_RESTORE_COMMAND_ENV = "IOI_WORKSPACE_RESTORE_COMMAND";
export const WORKSPACE_RESTORE_COMMAND_ARGS_ENV = "IOI_WORKSPACE_RESTORE_COMMAND_ARGS";
export const WORKSPACE_RESTORE_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
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
  return new RustWorkspaceRestoreRunner({
    command: options.command ?? env[WORKSPACE_RESTORE_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[WORKSPACE_RESTORE_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustWorkspaceRestoreRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
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
        changed_files: normalizeSnapshotChangedFilesForBridge(request?.changed_files ?? request?.changedFiles),
        content_drafts: normalizeSnapshotContentDraftsForBridge(
          request?.content_drafts ?? request?.contentDrafts ?? request?.workspace_snapshot_drafts ?? request?.workspaceSnapshotDrafts,
        ),
        max_content_bytes: Number(request?.max_content_bytes ?? request?.maxContentBytes ?? 0) || undefined,
      },
    };
    return normalizeWorkspaceSnapshotCaptureBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_workspace_restore_mock",
        backend: request.backend ?? RUST_WORKSPACE_RESTORE_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new WorkspaceRestoreRunnerError(
        "Workspace restore requires IOI_WORKSPACE_RESTORE_COMMAND for Rust restore planning and execution.",
        "workspace_restore_bridge_unconfigured",
        {
          env: WORKSPACE_RESTORE_COMMAND_ENV,
          argsEnv: WORKSPACE_RESTORE_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new WorkspaceRestoreRunnerError(
        "Failed to spawn Rust workspace restore bridge command.",
        "workspace_restore_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new WorkspaceRestoreRunnerError(
        "Rust workspace restore bridge command failed.",
        "workspace_restore_bridge_failed",
        {
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new WorkspaceRestoreRunnerError(
        "Rust workspace restore bridge command returned invalid JSON.",
        "workspace_restore_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new WorkspaceRestoreRunnerError(
        parsed.error?.message ?? "Rust workspace restore core rejected the request.",
        parsed.error?.code ?? "workspace_restore_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
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
    allowConflicts: Boolean(result.allow_conflicts ?? plan.allow_conflicts),
    allow_conflicts: Boolean(result.allow_conflicts ?? plan.allow_conflicts),
    conflictPolicy: optionalString(result.conflict_policy ?? plan.conflict_policy) ?? "clean_preview_only",
    conflict_policy: optionalString(result.conflict_policy ?? plan.conflict_policy) ?? "clean_preview_only",
    hardBlocked: Boolean(result.hard_blocked ?? plan.hard_blocked),
    hard_blocked: Boolean(result.hard_blocked ?? plan.hard_blocked),
    conflictBlocked: Boolean(result.conflict_blocked ?? plan.conflict_blocked),
    conflict_blocked: Boolean(result.conflict_blocked ?? plan.conflict_blocked),
    policyStatus: optionalString(result.policy_status ?? plan.policy_status) ?? "blocked",
    policy_status: optionalString(result.policy_status ?? plan.policy_status) ?? "blocked",
    applyStatus: optionalString(result.apply_status ?? plan.apply_status) ?? null,
    apply_status: optionalString(result.apply_status ?? plan.apply_status) ?? null,
    policyDecisionRefs,
    policy_decision_refs: policyDecisionRefs,
    operationPolicies,
    operation_policies: operationPolicies,
    summary: optionalString(result.summary ?? plan.summary) ?? null,
  };
  normalized.operationPolicyByPath = new Map(
    operationPolicies
      .map((entry) => [optionalString(entry.path), optionalString(entry.apply_reason ?? entry.applyReason)])
      .filter(([path, reason]) => path && reason),
  );
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
    contentFiles,
    content_files: contentFiles,
    capturedFileCount,
    captured_file_count: capturedFileCount,
    omittedFileCount,
    omitted_file_count: omittedFileCount,
    contentCaptured: Boolean(result.content_captured ?? capture.content_captured),
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
      before_hash: optionalString(entry.before_hash ?? entry.beforeHash),
      after_hash: optionalString(entry.after_hash ?? entry.afterHash),
      before_exists: Boolean(entry.before_exists ?? entry.beforeExists),
      after_exists: Object.hasOwn(entry, "after_exists") || Object.hasOwn(entry, "afterExists")
        ? Boolean(entry.after_exists ?? entry.afterExists)
        : undefined,
      before_size_bytes: finiteNumber(entry.before_size_bytes ?? entry.beforeSizeBytes),
      after_size_bytes: finiteNumber(entry.after_size_bytes ?? entry.afterSizeBytes),
      before_mtime_ms: finiteNumber(entry.before_mtime_ms ?? entry.beforeMtimeMs),
      after_mtime_ms: finiteNumber(entry.after_mtime_ms ?? entry.afterMtimeMs),
    }));
}

function normalizeSnapshotContentDraftsForBridge(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => objectRecord(entry))
    .filter(Boolean)
    .map((entry) => ({
      path: optionalString(entry.path) ?? "",
      before_content: typeof entry.before_content === "string" ? entry.before_content : entry.beforeContent,
      after_content: typeof entry.after_content === "string" ? entry.after_content : entry.afterContent,
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
    content_hash: optionalString(side.content_hash ?? side.contentHash),
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
    receiptRefs: stringArray(record.receipt_refs ?? record.receiptRefs) ?? [],
    receipt_refs: stringArray(record.receipt_refs ?? record.receiptRefs) ?? [],
    artifactRefs: stringArray(record.artifact_refs ?? record.artifactRefs) ?? [],
    artifact_refs: stringArray(record.artifact_refs ?? record.artifactRefs) ?? [],
    encoding: optionalString(record.encoding) ?? undefined,
  };
}

function normalizeSnapshotCapturedSide(value) {
  const side = objectRecord(value) ?? {};
  const normalized = {
    exists: Boolean(side.exists),
    contentHash: optionalString(side.content_hash ?? side.contentHash),
    content_hash: optionalString(side.content_hash ?? side.contentHash),
    sizeBytes: Number(side.size_bytes ?? side.sizeBytes ?? 0) || 0,
    size_bytes: Number(side.size_bytes ?? side.sizeBytes ?? 0) || 0,
    mtimeMs: finiteNumber(side.mtime_ms ?? side.mtimeMs),
    mtime_ms: finiteNumber(side.mtime_ms ?? side.mtimeMs),
    contentCaptured: Boolean(side.content_captured ?? side.contentCaptured),
    content_captured: Boolean(side.content_captured ?? side.contentCaptured),
    contentBytes: Number(side.content_bytes ?? side.contentBytes ?? 0) || 0,
    content_bytes: Number(side.content_bytes ?? side.contentBytes ?? 0) || 0,
    omittedReason: optionalString(side.omitted_reason ?? side.omittedReason),
    omitted_reason: optionalString(side.omitted_reason ?? side.omittedReason),
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
    currentExists: Boolean(record.current_exists ?? record.currentExists),
    current_exists: Boolean(record.current_exists ?? record.currentExists),
    currentHash: optionalString(record.current_hash ?? record.currentHash),
    current_hash: optionalString(record.current_hash ?? record.currentHash),
    currentBytes: Number(record.current_bytes ?? record.currentBytes ?? 0) || 0,
    current_bytes: Number(record.current_bytes ?? record.currentBytes ?? 0) || 0,
    targetExists: Boolean(record.target_exists ?? record.targetExists),
    target_exists: Boolean(record.target_exists ?? record.targetExists),
    targetHash: optionalString(record.target_hash ?? record.targetHash),
    target_hash: optionalString(record.target_hash ?? record.targetHash),
    snapshotAfterExists: Boolean(record.snapshot_after_exists ?? record.snapshotAfterExists),
    snapshot_after_exists: Boolean(record.snapshot_after_exists ?? record.snapshotAfterExists),
    snapshotAfterHash: optionalString(record.snapshot_after_hash ?? record.snapshotAfterHash),
    snapshot_after_hash: optionalString(record.snapshot_after_hash ?? record.snapshotAfterHash),
    currentMatchesSnapshotPost: Boolean(
      record.current_matches_snapshot_post ?? record.currentMatchesSnapshotPost,
    ),
    current_matches_snapshot_post: Boolean(
      record.current_matches_snapshot_post ?? record.currentMatchesSnapshotPost,
    ),
    currentMatchesRestoreTarget: Boolean(
      record.current_matches_restore_target ?? record.currentMatchesRestoreTarget,
    ),
    current_matches_restore_target: Boolean(
      record.current_matches_restore_target ?? record.currentMatchesRestoreTarget,
    ),
    blockedReason: optionalString(record.blocked_reason ?? record.blockedReason),
    blocked_reason: optionalString(record.blocked_reason ?? record.blockedReason),
    diff: typeof record.diff === "string" ? record.diff : "",
    diffBytes: Number(record.diff_bytes ?? record.diffBytes ?? 0) || 0,
    diff_bytes: Number(record.diff_bytes ?? record.diffBytes ?? 0) || 0,
    diffHash: optionalString(record.diff_hash ?? record.diffHash) ?? null,
    diff_hash: optionalString(record.diff_hash ?? record.diffHash) ?? null,
    diffTruncated: Boolean(record.diff_truncated ?? record.diffTruncated),
    diff_truncated: Boolean(record.diff_truncated ?? record.diffTruncated),
  };
  const applyStatus = optionalString(record.apply_status ?? record.applyStatus);
  if (applyStatus) {
    normalized.applyStatus = applyStatus;
    normalized.apply_status = applyStatus;
  }
  const applyReason = optionalString(record.apply_reason ?? record.applyReason);
  if (applyReason) {
    normalized.applyReason = applyReason;
    normalized.apply_reason = applyReason;
  }
  if (Object.hasOwn(record, "applied_exists") || Object.hasOwn(record, "appliedExists")) {
    normalized.appliedExists = Boolean(record.applied_exists ?? record.appliedExists);
    normalized.applied_exists = Boolean(record.applied_exists ?? record.appliedExists);
  }
  const appliedHash = optionalString(record.applied_hash ?? record.appliedHash);
  if (appliedHash) {
    normalized.appliedHash = appliedHash;
    normalized.applied_hash = appliedHash;
  }
  if (Object.hasOwn(record, "applied_bytes") || Object.hasOwn(record, "appliedBytes")) {
    normalized.appliedBytes = Number(record.applied_bytes ?? record.appliedBytes ?? 0) || 0;
    normalized.applied_bytes = Number(record.applied_bytes ?? record.appliedBytes ?? 0) || 0;
  }
  if (Object.hasOwn(record, "applied_matches_target") || Object.hasOwn(record, "appliedMatchesTarget")) {
    normalized.appliedMatchesTarget = Boolean(record.applied_matches_target ?? record.appliedMatchesTarget);
    normalized.applied_matches_target = Boolean(record.applied_matches_target ?? record.appliedMatchesTarget);
  }
  const errorMessage = optionalString(record.error_message ?? record.errorMessage);
  if (errorMessage) {
    normalized.errorMessage = errorMessage;
    normalized.error_message = errorMessage;
  }
  return normalized;
}

function parseCommandArgs(value) {
  if (!value) return [];
  if (Array.isArray(value)) return normalizeArgs(value);
  return String(value)
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeArgs(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry)).filter((entry) => entry.length > 0);
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
