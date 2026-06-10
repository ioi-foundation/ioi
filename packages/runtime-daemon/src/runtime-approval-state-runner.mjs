import { spawnSync } from "node:child_process";

export const APPROVAL_STATE_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const APPROVAL_STATE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-request-state-update-request.v1";
export const APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-decision-state-update-request.v1";
export const APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.approval-revoke-state-update-request.v1";
export const RUST_APPROVAL_STATE_BACKEND = "rust_authority";

export function createRuntimeApprovalStateRunnerFromEnv(env = process.env, options = {}) {
  assertNoApprovalStateCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustRuntimeApprovalStateRunner({
    command: options.command ?? env[APPROVAL_STATE_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoApprovalStateCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeApprovalStateRunnerError(
    "Runtime approval state command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "approval_state_command_args_retired",
    { retired_args: value },
  );
}

export class RustRuntimeApprovalStateRunner {
  constructor(options = {}) {
    assertNoApprovalStateCommandArgs(options.args);
    this.command = optionalString(options.command);
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

  planApprovalDecisionStateUpdate(request = {}) {
    return normalizeApprovalDecisionStateUpdateBridgeResult(this.invokeBridge({
      schema_version: APPROVAL_STATE_COMMAND_SCHEMA_VERSION,
      operation: "plan_approval_decision_state_update",
      backend: RUST_APPROVAL_STATE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      },
    }));
  }

  planApprovalRevokeStateUpdate(request = {}) {
    return normalizeApprovalRevokeStateUpdateBridgeResult(this.invokeBridge({
      schema_version: APPROVAL_STATE_COMMAND_SCHEMA_VERSION,
      operation: "plan_approval_revoke_state_update",
      backend: RUST_APPROVAL_STATE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
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
        "Runtime approval state updates require IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core authority planning.",
        "approval_state_bridge_unconfigured",
        {
          env: APPROVAL_STATE_COMMAND_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, [], {
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

function requiredApprovalBridgeOperationKind(result, record, expectedOperationKind, codePrefix) {
  const expectedOperationKinds = Array.isArray(expectedOperationKind)
    ? expectedOperationKind
    : [expectedOperationKind];
  const operationKind = optionalString(result.operation_kind ?? record.operation_kind);
  if (!operationKind) {
    throw new RuntimeApprovalStateRunnerError(
      "Rust approval state bridge result did not include an operation kind.",
      `${codePrefix}_operation_kind_missing`,
      { operationKind: expectedOperationKinds[0], expectedOperationKinds },
    );
  }
  if (!expectedOperationKinds.includes(operationKind)) {
    throw new RuntimeApprovalStateRunnerError(
      "Rust approval state bridge result included an unexpected operation kind.",
      `${codePrefix}_operation_kind_mismatch`,
      { expectedOperationKind: expectedOperationKinds[0], expectedOperationKinds, operationKind },
    );
  }
  return operationKind;
}

export function normalizeApprovalRequestStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_approval_request_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_APPROVAL_STATE_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredApprovalBridgeOperationKind(
      result,
      record,
      "approval.required",
      "approval_request_state_update",
    ),
    target_kind: optionalString(result.target_kind ?? record.target_kind) ?? "run",
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeApprovalDecisionStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_approval_decision_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_APPROVAL_STATE_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredApprovalBridgeOperationKind(
      result,
      record,
      ["approval.approve", "approval.reject"],
      "approval_decision_state_update",
    ),
    target_kind: optionalString(result.target_kind ?? record.target_kind) ?? "run",
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeApprovalRevokeStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_approval_revoke_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_APPROVAL_STATE_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredApprovalBridgeOperationKind(
      result,
      record,
      "approval.revoke",
      "approval_revoke_state_update",
    ),
    target_kind: optionalString(result.target_kind ?? record.target_kind) ?? "run",
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
