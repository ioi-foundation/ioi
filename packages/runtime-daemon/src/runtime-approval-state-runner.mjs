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
  assertNoApprovalStateCommandSelection(options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND);
  return new RustRuntimeApprovalStateRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
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

export function assertNoApprovalStateCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeApprovalStateRunnerError(
    "Runtime approval state binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core authority planning.",
    "approval_state_command_selection_retired",
    { retired_command: value },
  );
}

export class RustRuntimeApprovalStateRunner {
  constructor(options = {}) {
    assertNoApprovalStateCommandArgs(options.args);
    assertNoApprovalStateCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  planApprovalRequestStateUpdate(request = {}) {
    return normalizeApprovalRequestStateUpdateBridgeResult(this.invokeDaemonCore({
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
    return normalizeApprovalDecisionStateUpdateBridgeResult(this.invokeDaemonCore({
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
    return normalizeApprovalRevokeStateUpdateBridgeResult(this.invokeDaemonCore({
      schema_version: APPROVAL_STATE_COMMAND_SCHEMA_VERSION,
      operation: "plan_approval_revoke_state_update",
      backend: RUST_APPROVAL_STATE_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      },
    }));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeApprovalStateRunnerError(
        "Runtime approval state updates require daemonCoreInvoker for direct Rust daemon-core authority planning.",
        "approval_state_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeApprovalStateRunnerError(
        error.message ?? "Rust approval state core rejected the request.",
        error.code ?? "approval_state_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
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

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
