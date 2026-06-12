export const CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-request.v1";
export const CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-satisfaction-request.v1";
export const CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-satisfaction-projection-request.v1";
export const CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-block-request.v1";
export const RUST_CODING_TOOL_APPROVAL_BACKEND = "rust_authority";

export function createCodingToolApprovalRunnerFromEnv(env = process.env, options = {}) {
  assertNoCodingToolApprovalCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  assertNoCodingToolApprovalCommandSelection(options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND);
  return new RustCodingToolApprovalRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
  });
}

export function assertNoCodingToolApprovalCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new CodingToolApprovalRunnerError(
    "Coding-tool approval command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "coding_tool_approval_command_args_retired",
    { retired_args: value },
  );
}

export function assertNoCodingToolApprovalCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new CodingToolApprovalRunnerError(
    "Coding-tool approval binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core authority planning.",
    "coding_tool_approval_command_selection_retired",
    { retired_command: value },
  );
}

export class RustCodingToolApprovalRunner {
  constructor(options = {}) {
    assertNoCodingToolApprovalCommandArgs(options.args);
    assertNoCodingToolApprovalCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  planApprovalManifest(request = {}) {
    const bridgeRequest = {
      schema_version: CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_manifest",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolApprovalBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  planApprovalSatisfaction(request = {}) {
    const bridgeRequest = {
      schema_version: CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_satisfaction",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolApprovalSatisfactionBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  projectApprovalSatisfaction(request = {}) {
    const bridgeRequest = {
      schema_version: CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
      operation: "project_coding_tool_approval_satisfaction",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolApprovalSatisfactionProjectionBridgeResult(
      this.invokeDaemonCore(bridgeRequest),
    );
  }

  planApprovalBlock(request = {}) {
    const bridgeRequest = {
      schema_version: CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_block",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolApprovalBlockBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new CodingToolApprovalRunnerError(
        "Coding-tool approval requires daemonCoreInvoker for direct Rust daemon-core authority planning.",
        "coding_tool_approval_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new CodingToolApprovalRunnerError(
        error.message ?? "Rust coding-tool approval core rejected the request.",
        error.code ?? "coding_tool_approval_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class CodingToolApprovalRunnerError extends Error {
  constructor(message, code = "coding_tool_approval_runner_error", details = {}) {
    super(message);
    this.name = "CodingToolApprovalRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeCodingToolApprovalBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const plan = objectRecord(result.plan) ?? {};
  const manifest = objectRecord(result.manifest) ?? objectRecord(plan.manifest) ?? null;
  const workflowPolicy =
    objectRecord(result.workflow_policy) ??
    objectRecord(plan.workflow_policy) ??
    objectRecord(manifest?.workflow_policy) ??
    null;
  const approvalRequired = Boolean(result.approval_required ?? plan.approval_required ?? manifest);
  return {
    source: result.source ?? "rust_coding_tool_approval_command",
    backend: result.backend ?? RUST_CODING_TOOL_APPROVAL_BACKEND,
    plan,
    approval_required: approvalRequired,
    workflow_policy: workflowPolicy,
    manifest,
    input_hash: optionalString(result.input_hash ?? plan.input_hash ?? manifest?.input_hash),
  };
}

export function normalizeCodingToolApprovalSatisfactionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? {};
  return {
    source: result.source ?? "rust_coding_tool_approval_satisfaction_command",
    backend: result.backend ?? RUST_CODING_TOOL_APPROVAL_BACKEND,
    record,
    status: optionalString(result.status ?? record.status),
    operation_kind: optionalString(result.operation_kind ?? record.operation_kind),
    satisfied: Boolean(result.satisfied ?? record.satisfied),
    approval_id: optionalString(result.approval_id ?? record.approval_id),
    decision_event_id: optionalString(result.decision_event_id ?? record.decision_event_id),
    decision_seq: Number.isInteger(result.decision_seq ?? record.decision_seq)
      ? result.decision_seq ?? record.decision_seq
      : null,
    lease_id: optionalString(result.lease_id ?? record.lease_id),
    expires_at: optionalString(result.expires_at ?? record.expires_at),
    reason: optionalString(result.reason ?? record.reason) ?? "approval_not_satisfied",
    receipt_refs: arrayOfStrings(result.receipt_refs ?? record.receipt_refs),
    policy_decision_refs: arrayOfStrings(result.policy_decision_refs ?? record.policy_decision_refs),
    expected_head: optionalString(result.expected_head ?? record.expected_head),
    state_root_before: optionalString(result.state_root_before ?? record.state_root_before),
  };
}

export function normalizeCodingToolApprovalSatisfactionProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? {};
  return {
    source: result.source ?? "rust_coding_tool_approval_satisfaction_projection_command",
    backend: result.backend ?? RUST_CODING_TOOL_APPROVAL_BACKEND,
    record,
    status: optionalString(result.status ?? record.status),
    operation_kind: optionalString(result.operation_kind ?? record.operation_kind),
    thread_id: optionalString(result.thread_id ?? record.thread_id),
    approval_id: optionalString(result.approval_id ?? record.approval_id),
    approval_request:
      objectRecord(result.approval_request) ?? objectRecord(record.approval_request) ?? null,
    latest_decision:
      objectRecord(result.latest_decision) ?? objectRecord(record.latest_decision) ?? null,
    lease_state: objectRecord(result.lease_state) ?? objectRecord(record.lease_state) ?? null,
    expected_head: optionalString(result.expected_head ?? record.expected_head),
    state_root_before: optionalString(result.state_root_before ?? record.state_root_before),
  };
}

export function normalizeCodingToolApprovalBlockBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? {};
  const event = objectRecord(result.event) ?? objectRecord(record.event) ?? null;
  const blockedResult = objectRecord(result.result) ?? objectRecord(record.result) ?? null;
  return {
    source: result.source ?? "rust_coding_tool_approval_block_command",
    backend: result.backend ?? RUST_CODING_TOOL_APPROVAL_BACKEND,
    record,
    status: optionalString(result.status ?? record.status) ?? "blocked",
    operation_kind: optionalString(result.operation_kind ?? record.operation_kind),
    thread_id: optionalString(result.thread_id ?? record.thread_id),
    turn_id: optionalString(result.turn_id ?? record.turn_id),
    tool_id: optionalString(result.tool_id ?? record.tool_id),
    tool_call_id: optionalString(result.tool_call_id ?? record.tool_call_id),
    workflow_graph_id: optionalString(result.workflow_graph_id ?? record.workflow_graph_id),
    workflow_node_id: optionalString(result.workflow_node_id ?? record.workflow_node_id),
    approval_id: optionalString(result.approval_id ?? record.approval_id),
    reason: optionalString(result.reason ?? record.reason) ?? "approval_not_satisfied",
    receipt_refs: arrayOfStrings(result.receipt_refs ?? record.receipt_refs),
    policy_decision_refs: arrayOfStrings(result.policy_decision_refs ?? record.policy_decision_refs),
    artifact_refs: arrayOfStrings(result.artifact_refs ?? record.artifact_refs),
    rollback_refs: arrayOfStrings(result.rollback_refs ?? record.rollback_refs),
    result: blockedResult,
    event,
  };
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function arrayOfStrings(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string" && item.trim()) : [];
}
