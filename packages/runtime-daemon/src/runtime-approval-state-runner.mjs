import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

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
    daemonCoreInvoker: options.daemonCoreInvoker,
    spawnSyncImpl: options.spawnSyncImpl,
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
    this.invokeBridge = createDaemonCoreCommandInvoker({
      command: this.command,
      daemonCoreInvoker: options.daemonCoreInvoker,
      spawnSyncImpl: options.spawnSyncImpl,
      ErrorClass: RuntimeApprovalStateRunnerError,
      env: APPROVAL_STATE_COMMAND_ENV,
      unconfiguredMessage:
        "Runtime approval state updates require IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core authority planning.",
      unconfiguredCode: "approval_state_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust approval state bridge command.",
      spawnFailedCode: "approval_state_bridge_spawn_failed",
      commandFailedMessage: "Rust approval state bridge command failed.",
      commandFailedCode: "approval_state_bridge_failed",
      invalidJsonMessage: "Rust approval state bridge command returned invalid JSON.",
      invalidJsonCode: "approval_state_bridge_invalid_json",
      rejectedMessage: "Rust approval state core rejected the request.",
      rejectedCode: "approval_state_bridge_rejected",
    });
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
