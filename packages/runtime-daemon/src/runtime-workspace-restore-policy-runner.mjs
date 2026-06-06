import { spawnSync } from "node:child_process";

export const WORKSPACE_RESTORE_POLICY_COMMAND_ENV = "IOI_WORKSPACE_RESTORE_POLICY_COMMAND";
export const WORKSPACE_RESTORE_POLICY_COMMAND_ARGS_ENV = "IOI_WORKSPACE_RESTORE_POLICY_COMMAND_ARGS";
export const WORKSPACE_RESTORE_POLICY_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
export const WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.workspace_restore_apply_policy_request.v1";
export const RUST_WORKSPACE_RESTORE_BACKEND = "rust_workspace_restore";

export function createWorkspaceRestorePolicyRunnerFromEnv(env = process.env, options = {}) {
  return new RustWorkspaceRestorePolicyRunner({
    command: options.command ?? env[WORKSPACE_RESTORE_POLICY_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[WORKSPACE_RESTORE_POLICY_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustWorkspaceRestorePolicyRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  planApplyPolicy(request) {
    const bridgeRequest = {
      schema_version: WORKSPACE_RESTORE_POLICY_COMMAND_SCHEMA_VERSION,
      operation: "plan_workspace_restore_apply_policy",
      backend: RUST_WORKSPACE_RESTORE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeWorkspaceRestorePolicyBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_workspace_restore_policy_mock",
        backend: request.backend ?? RUST_WORKSPACE_RESTORE_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new WorkspaceRestorePolicyRunnerError(
        "Workspace restore apply policy requires IOI_WORKSPACE_RESTORE_POLICY_COMMAND for Rust policy planning.",
        "workspace_restore_policy_bridge_unconfigured",
        {
          env: WORKSPACE_RESTORE_POLICY_COMMAND_ENV,
          argsEnv: WORKSPACE_RESTORE_POLICY_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new WorkspaceRestorePolicyRunnerError(
        "Failed to spawn Rust workspace restore policy bridge command.",
        "workspace_restore_policy_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new WorkspaceRestorePolicyRunnerError(
        "Rust workspace restore policy bridge command failed.",
        "workspace_restore_policy_bridge_failed",
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
      throw new WorkspaceRestorePolicyRunnerError(
        "Rust workspace restore policy bridge command returned invalid JSON.",
        "workspace_restore_policy_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new WorkspaceRestorePolicyRunnerError(
        parsed.error?.message ?? "Rust workspace restore policy core rejected the request.",
        parsed.error?.code ?? "workspace_restore_policy_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class WorkspaceRestorePolicyRunnerError extends Error {
  constructor(message, code = "workspace_restore_policy_runner_error", details = {}) {
    super(message);
    this.name = "WorkspaceRestorePolicyRunnerError";
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
