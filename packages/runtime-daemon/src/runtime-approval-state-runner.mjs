import { spawnSync } from "node:child_process";

export const APPROVAL_STATE_COMMAND_ENV = "IOI_STEP_MODULE_COMMAND";
export const APPROVAL_STATE_COMMAND_ARGS_ENV = "IOI_STEP_MODULE_COMMAND_ARGS";
export const APPROVAL_STATE_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
export const APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-request-state-update-request.v1";
export const RUST_APPROVAL_STATE_BACKEND = "rust_authority";

export function createRuntimeApprovalStateRunnerFromEnv(env = process.env, options = {}) {
  return new RustRuntimeApprovalStateRunner({
    command: options.command ?? env[APPROVAL_STATE_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[APPROVAL_STATE_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustRuntimeApprovalStateRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  planApprovalRequestStateUpdate(request = {}) {
    return normalizeApprovalRequestStateUpdateBridgeResult(this.invokeBridge({
      schema_version: APPROVAL_STATE_COMMAND_SCHEMA_VERSION,
      operation: "plan_approval_request_state_update",
      backend: RUST_APPROVAL_STATE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      },
    }));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_approval_state_mock",
        backend: request.backend ?? RUST_APPROVAL_STATE_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new RuntimeApprovalStateRunnerError(
        "Runtime approval state updates require IOI_STEP_MODULE_COMMAND for Rust authority planning.",
        "approval_state_bridge_unconfigured",
        {
          env: APPROVAL_STATE_COMMAND_ENV,
          argsEnv: APPROVAL_STATE_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new RuntimeApprovalStateRunnerError(
        "Failed to spawn Rust approval state bridge command.",
        "approval_state_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new RuntimeApprovalStateRunnerError(
        "Rust approval state bridge command failed.",
        "approval_state_bridge_failed",
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
      throw new RuntimeApprovalStateRunnerError(
        "Rust approval state bridge command returned invalid JSON.",
        "approval_state_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new RuntimeApprovalStateRunnerError(
        parsed.error?.message ?? "Rust approval state core rejected the request.",
        parsed.error?.code ?? "approval_state_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class RuntimeApprovalStateRunnerError extends Error {
  constructor(message, code = "approval_state_runner_error", details = {}) {
    super(message);
    this.name = "RuntimeApprovalStateRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeApprovalRequestStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_approval_request_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_APPROVAL_STATE_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: optionalString(result.operation_kind ?? record.operation_kind) ?? "approval.required",
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
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

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
