export const CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-request.v1";
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
